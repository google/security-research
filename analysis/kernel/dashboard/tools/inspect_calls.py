#!/usr/bin/env python3
"""1-Hop & Multi-Hop Callgraph Inspector with Indirect Dispatch Resolution.

Answers the fundamental developer questions during bug triage and navigation:
  1. "Who calls this?" (--callers)
     - Discovers direct callers from CodeQL edge graphs.
     - Discovers indirect callers dispatched via function-pointer structs
       (e.g., inode_operations->link) using the precomputed ops_targets table.
  2. "What does this call?" (--callees)
     - Discovers direct function calls made from within the target function.
     - Discovers indirect dispatch sites (e.g. dir->i_op->link) and resolves
       them to candidate implementations.
  3. "Both directions" (--both, default)
     - Provides 360-degree local context around any function or source line.
"""

import argparse
from collections import defaultdict
import json
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    clean_file_path,
    ensure_indexes,
    get_enclosing_function,
    get_function_by_name,
    is_syscall_root,
    open_databases,
)
from tools.lib.metadata import (
    add_common_cli_args,
    handle_common_cli_setup,
    is_line_covered_by_syzkaller,
)
from tools.lib.privilege import (
    GateList,
    get_call_site_gates,
    load_condition_gates,
)

__all__ = [
    "clean_file_path",
    "ensure_indexes",
    "get_enclosing_function",
    "get_function_by_name",
    "is_line_covered_by_syzkaller",
    "check_is_syscall_root",
    "load_condition_gates",
    "get_call_site_gates",
    "get_callers_for_function",
    "build_caller_tree",
    "get_callees_for_function",
    "build_callee_tree",
    "inspect_function_calls",
    "format_summary",
    "format_list",
    "main",
]


def check_is_syscall_root(fn_name: str) -> bool:
    """Check whether fn_name is a syscall entry point."""
    return is_syscall_root(fn_name, None)


def _site_annotations(
    caller_fn: str,
    clean_file: str,
    site_line: Optional[int],
    options: Dict[str, Any],
) -> Tuple[GateList, bool]:
    """Compute capability gates and Syzkaller coverage for a call site."""
    call_gates = options.get("call_gates")
    func_gates = options.get("func_gates")
    syzk_conn = options.get("syzk_conn")

    gates: GateList = []
    if call_gates is not None and func_gates is not None:
        gates = get_call_site_gates(
            call_gates,
            func_gates,
            clean_file,
            site_line,
            caller_fn=caller_fn,
        )
    syzk_covered = bool(
        syzk_conn
        and site_line
        and is_line_covered_by_syzkaller(syzk_conn, clean_file, site_line)
    )
    return gates, syzk_covered


def _query_direct_callers(
    cur: sqlite3.Cursor,
    function_name: str,
    seen: Set[Tuple[str, str, int, str]],
    options: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Query direct callers from CodeQL edges and locations tables."""
    cur.execute(
        "SELECT DISTINCT s.message AS caller_fn, s.uri AS caller_file,"
        " s.startLine AS caller_line, t.startLine AS call_site_line"
        " FROM edges e"
        " JOIN locations s ON e.source_location_id = s.id"
        " JOIN locations t ON e.target_location_id = t.id"
        " WHERE (t.message = ? OR t.message = ?)"
        ' AND s.message NOT LIKE "call to %"',
        (function_name, f"call to {function_name}"),
    )
    results: List[Dict[str, Any]] = []
    for caller_fn, caller_file, caller_line, call_site_line in cur.fetchall():
        clean_file = clean_file_path(caller_file)
        key = (caller_fn, clean_file, call_site_line, "direct")
        if key in seen:
            continue
        seen.add(key)
        gates, syzk_covered = _site_annotations(
            caller_fn, clean_file, call_site_line, options
        )
        results.append({
            "caller": caller_fn,
            "file": clean_file,
            "line": caller_line,
            "call_site_line": call_site_line,
            "call_type": "direct",
            "dispatch": None,
            "is_syscall": check_is_syscall_root(caller_fn),
            "gates": gates,
            "syzk_covered": syzk_covered,
        })
    return results


def _resolve_indirect_caller_loc(
    cur: sqlite3.Cursor, expr_file: str, expr_line: int
) -> Tuple[str, str, int]:
    """Resolve enclosing function for an indirect call expression site."""
    clean_expr = clean_file_path(expr_file)
    cur.execute(
        "SELECT function_name, file_path, start_line"
        " FROM function_locations"
        " WHERE (file_path = ? OR file_path LIKE ?)"
        " AND ? BETWEEN start_line AND end_line LIMIT 1",
        (clean_expr, f"%/{clean_expr}", expr_line),
    )
    fn_row = cur.fetchone()
    if fn_row:
        return fn_row[0], clean_file_path(fn_row[1]), fn_row[2]
    return "unknown", clean_expr, expr_line


def _query_indirect_callers(
    cur: sqlite3.Cursor,
    function_name: str,
    seen: Set[Tuple[str, str, int, str]],
    options: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Query indirect function-pointer callers from ops_targets table."""
    cur.execute(
        "SELECT DISTINCT o.parent, o.field, o.exprcall_file, o.exprcall_line"
        " FROM ops_targets o WHERE o.target = ?",
        (function_name,),
    )
    results: List[Dict[str, Any]] = []
    for row in cur.fetchall():
        caller_fn, caller_file, caller_line = _resolve_indirect_caller_loc(
            cur, row[2], row[3]
        )
        dispatch = f"{row[0]}->{row[1]}"
        key = (caller_fn, caller_file, row[3], dispatch)
        if key in seen:
            continue
        seen.add(key)
        gates, syzk_covered = _site_annotations(
            caller_fn, caller_file, row[3], options
        )
        results.append({
            "caller": caller_fn,
            "file": caller_file,
            "line": caller_line,
            "call_site_line": row[3],
            "call_type": "indirect",
            "dispatch": dispatch,
            "is_syscall": check_is_syscall_root(caller_fn),
            "gates": gates,
            "syzk_covered": syzk_covered,
        })
    return results


def get_callers_for_function(
    conn: sqlite3.Connection,
    function_name: str,
    **options: Any,
) -> List[Dict[str, Any]]:
    """Find direct callers and indirect ops dispatchers targeting function."""
    cur = conn.cursor()
    seen: Set[Tuple[str, str, int, str]] = set()
    results = _query_direct_callers(cur, function_name, seen, options)
    results.extend(_query_indirect_callers(cur, function_name, seen, options))
    results.sort(
        key=lambda x: (
            x["call_type"],
            x["caller"],
            x.get("call_site_line") or 0,
        )
    )
    return results


def build_caller_tree(
    conn: sqlite3.Connection,
    target_fn: str,
    **options: Any,
) -> List[Dict[str, Any]]:
    """Recursively traverse callers up to max_depth hops."""
    max_depth: int = options.get("max_depth", 1)
    current_depth: int = options.get("current_depth", 1)
    visited: Set[str] = (
        set(options["visited"]) if options.get("visited") else set()
    )
    if target_fn in visited or current_depth > max_depth:
        return []

    visited.add(target_fn)
    sub_opts = {
        k: v
        for k, v in options.items()
        if k in ("call_gates", "func_gates", "syzk_conn")
    }
    callers = get_callers_for_function(conn, target_fn, **sub_opts)

    for c in callers:
        c["depth"] = current_depth
        if current_depth < max_depth:
            c["callers"] = build_caller_tree(
                conn,
                c["caller"],
                max_depth=max_depth,
                current_depth=current_depth + 1,
                visited=set(visited),
                **sub_opts,
            )
        else:
            c["callers"] = []

    return callers


def _query_direct_callees(
    cur: sqlite3.Cursor,
    function_name: str,
    clean_file: str,
    span: Tuple[int, int],
    options: Dict[str, Any],
) -> Dict[int, List[Dict[str, Any]]]:
    """Query direct outgoing calls made inside function_name's line span."""
    cur.execute(
        "SELECT DISTINCT s.startLine AS call_site_line,"
        " t.message AS callee_name, t.uri AS callee_file,"
        " t.startLine AS callee_line"
        " FROM locations s"
        " JOIN edges e ON e.source_location_id = s.id"
        " JOIN locations t ON e.target_location_id = t.id"
        " WHERE (s.uri = ? OR s.uri = ?)"
        " AND s.startLine BETWEEN ? AND ?"
        " AND s.message LIKE 'call to %'"
        " ORDER BY s.startLine, callee_name",
        (clean_file, f"linux/{clean_file}", span[0], span[1]),
    )
    calls_by_line: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    seen_direct: Set[Tuple[int, str, str]] = set()
    for cs_line, callee_fn, callee_f, callee_l in cur.fetchall():
        clean_callee_f = clean_file_path(callee_f) if callee_f else "unknown"
        key = (cs_line, callee_fn, clean_callee_f)
        if key in seen_direct:
            continue
        seen_direct.add(key)
        gates, syzk_covered = _site_annotations(
            function_name, clean_file, cs_line, options
        )
        calls_by_line[cs_line].append({
            "call_site_line": cs_line,
            "call_type": "direct",
            "callee": callee_fn,
            "file": clean_callee_f,
            "line": callee_l,
            "dispatch": None,
            "candidates": [],
            "gates": gates,
            "syzk_covered": syzk_covered,
        })
    return calls_by_line


def _dedup_candidates(
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Deduplicate indirect dispatch candidates while preserving order."""
    uniq: List[Dict[str, Any]] = []
    seen_tgt: Set[Tuple[str, str, int]] = set()
    for cand in candidates:
        tgt_k = (cand["target"], cand["file"], cand["line"])
        if tgt_k not in seen_tgt:
            seen_tgt.add(tgt_k)
            uniq.append(cand)
    return uniq


def _query_indirect_callees(
    cur: sqlite3.Cursor,
    function_name: str,
    clean_file: str,
    span: Tuple[int, int],
    options: Dict[str, Any],
) -> Dict[int, List[Dict[str, Any]]]:
    """Query indirect function-pointer dispatch sites inside function_name."""
    cur.execute(
        "SELECT exprcall_line, parent, field, target, target_file, target_start"
        " FROM ops_targets"
        " WHERE (exprcall_file = ? OR exprcall_file = ?)"
        " AND exprcall_line BETWEEN ? AND ?"
        " ORDER BY exprcall_line, target",
        (clean_file, f"linux/{clean_file}", span[0], span[1]),
    )
    grouped: Dict[Tuple[int, str, str], List[Dict[str, Any]]] = defaultdict(
        list
    )
    for row in cur.fetchall():
        grouped[(row[0], row[1], row[2])].append({
            "target": row[3],
            "file": clean_file_path(row[4]) if row[4] else "unknown",
            "line": row[5],
        })

    by_line: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for (expr_l, parent, field), candidates in grouped.items():
        gates, syzk_covered = _site_annotations(
            function_name, clean_file, expr_l, options
        )
        by_line[expr_l].append({
            "call_site_line": expr_l,
            "call_type": "indirect",
            "callee": None,
            "file": None,
            "line": None,
            "dispatch": f"{parent}->{field}",
            "candidates": _dedup_candidates(candidates),
            "gates": gates,
            "syzk_covered": syzk_covered,
        })
    return by_line


def get_callees_for_function(
    conn: sqlite3.Connection,
    function_name: str,
    file_path: str,
    start_line: int,
    end_line: int,
    **options: Any,
) -> List[Dict[str, Any]]:
    """Find direct calls and indirect dispatch sites inside function_name."""
    cur = conn.cursor()
    clean_file = clean_file_path(file_path)
    span = (start_line, end_line)
    calls_by_line = _query_direct_callees(
        cur, function_name, clean_file, span, options
    )
    indirect_by_line = _query_indirect_callees(
        cur, function_name, clean_file, span, options
    )
    for line, items in indirect_by_line.items():
        calls_by_line[line].extend(items)

    ordered_callees: List[Dict[str, Any]] = []
    for line in sorted(calls_by_line.keys()):
        ordered_callees.extend(calls_by_line[line])
    return ordered_callees


def build_callee_tree(
    conn: sqlite3.Connection,
    function_name: str,
    file_path: str,
    start_line: int,
    end_line: int,
    **options: Any,
) -> List[Dict[str, Any]]:
    """Recursively traverse callees up to max_depth hops."""
    max_depth: int = options.get("max_depth", 1)
    current_depth: int = options.get("current_depth", 1)
    visited: Set[str] = (
        set(options["visited"]) if options.get("visited") else set()
    )
    if function_name in visited or current_depth > max_depth:
        return []

    visited.add(function_name)
    sub_opts = {
        k: v
        for k, v in options.items()
        if k in ("call_gates", "func_gates", "syzk_conn")
    }
    callees = get_callees_for_function(
        conn, function_name, file_path, start_line, end_line, **sub_opts
    )

    for c in callees:
        c["depth"] = current_depth
        c["callees"] = []
        if current_depth < max_depth and c["call_type"] == "direct":
            target_fn = c.get("callee")
            if target_fn and target_fn not in visited:
                fn_info = get_function_by_name(conn, target_fn)
                if fn_info:
                    c["callees"] = build_callee_tree(
                        conn,
                        fn_info[0],
                        fn_info[1],
                        fn_info[2],
                        fn_info[3],
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                        visited=set(visited),
                        **sub_opts,
                    )

    return callees


def _resolve_inspect_target(
    conn: sqlite3.Connection,
    function_name: Optional[str],
    file_path: Optional[str],
    line_number: Optional[int],
) -> Optional[Dict[str, Any]]:
    """Resolve function_name or file_path:line_number to target_info dict."""
    if file_path and line_number is not None:
        fn_row = get_enclosing_function(conn, file_path, line_number)
        if fn_row:
            return {
                "function": fn_row[0],
                "file": clean_file_path(fn_row[1]),
                "start_line": fn_row[2],
                "end_line": fn_row[3],
                "query_line": line_number,
            }
    elif function_name:
        fn_row = get_function_by_name(conn, function_name)
        if fn_row:
            return {
                "function": fn_row[0],
                "file": clean_file_path(fn_row[1]),
                "start_line": fn_row[2],
                "end_line": fn_row[3],
                "query_line": fn_row[2],
            }
    return None


def inspect_function_calls(
    db_path: str,
    function_name: Optional[str] = None,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    **options: Any,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Main programmatic interface for function caller and callee inspection."""
    verbose = options.get("verbose", False)
    conn, syzk_conn = open_databases(
        db_path,
        syzkaller_db=options.get("syzkaller_db"),
        verbose=verbose,
    )
    target_info = _resolve_inspect_target(
        conn, function_name, file_path, line_number
    )
    if not target_info:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        target_repr = function_name or f"{file_path}:{line_number}"
        raise ValueError(
            f"Target function '{target_repr}' not found in database."
        )

    call_gates, func_gates, _ = load_condition_gates(conn, verbose=verbose)
    tree_opts = {
        "max_depth": options.get("depth", 1),
        "call_gates": call_gates,
        "func_gates": func_gates,
        "syzk_conn": syzk_conn,
    }
    callers = (
        build_caller_tree(conn, target_info["function"], **tree_opts)
        if options.get("show_callers", True)
        else []
    )
    callees = (
        build_callee_tree(
            conn,
            target_info["function"],
            target_info["file"],
            target_info["start_line"],
            target_info["end_line"],
            **tree_opts,
        )
        if options.get("show_callees", True)
        else []
    )

    conn.close()
    if syzk_conn:
        syzk_conn.close()
    return target_info, callers, callees


def _item_prefix_and_tags(
    item: Dict[str, Any], fmt_opts: Dict[str, Any]
) -> Tuple[str, str, str]:
    """Return (indent, tree_prefix, gate_and_coverage_tags) for a tree item."""
    indent = "  " * (fmt_opts.get("indent_level", 1) - 1)
    prefix = f"{indent}└── " if fmt_opts.get("is_last") else f"{indent}├── "
    gate_str = (
        f" [GATED: {', '.join(g['cap_str'] for g in item['gates'])}]"
        if item.get("gates")
        else ""
    )
    cov_str = " [COVERED]" if item.get("syzk_covered") else ""
    return indent, prefix, f"{gate_str}{cov_str}"


def _format_caller_item(
    c: Dict[str, Any], out: List[str], **fmt_opts: Any
) -> None:
    """Format single caller entry and any recursive sub-callers."""
    _indent, prefix, tags = _item_prefix_and_tags(c, fmt_opts)
    cs_line = c.get("call_site_line")
    line_str = f" [calls at line {cs_line}]" if cs_line else ""
    type_str = f" [via {c['dispatch']}]" if c.get("dispatch") else " [direct]"
    syscall_str = " [Syscall Entry]" if c.get("is_syscall") else ""

    out.append(
        f"{prefix}{c['caller']} ({c['file']}:{c['line']})"
        f"{line_str}{type_str}{syscall_str}{tags}"
    )

    sub_callers = c.get("callers", [])
    indent_level = fmt_opts.get("indent_level", 1)
    for sub_idx, sub in enumerate(sub_callers):
        _format_caller_item(
            sub,
            out,
            indent_level=indent_level + 1,
            is_last=sub_idx == len(sub_callers) - 1,
            candidate_limit=fmt_opts.get("candidate_limit", 10),
            show_all=fmt_opts.get("show_all", False),
        )


def _format_indirect_callee(
    c: Dict[str, Any], out: List[str], fmt_opts: Dict[str, Any]
) -> None:
    """Format an indirect dispatch callee site and its candidate targets."""
    indent, prefix, tags = _item_prefix_and_tags(c, fmt_opts)
    cs_line = c.get("call_site_line", "?")
    disp = c.get("dispatch", "indirect dispatch")
    candidates = c.get("candidates", [])
    out.append(
        f"{prefix}[Line {cs_line}] ->{disp} [indirect dispatch:"
        f" {len(candidates)} candidate(s)]{tags}"
    )
    limit = fmt_opts.get("candidate_limit", 10)
    show_all = fmt_opts.get("show_all", False)
    display_cands = candidates if show_all else candidates[:limit]
    sub_indent = indent + ("    " if fmt_opts.get("is_last") else "│   ") + "  "
    for cand in display_cands:
        out.append(
            f"{sub_indent}* {cand['target']} ({cand['file']}:{cand['line']})"
        )
    if not show_all and len(candidates) > limit:
        rem = len(candidates) - limit
        out.append(
            f"{sub_indent}... and {rem} more candidate(s) (use --all to show"
            " all)"
        )


def _format_callee_item(
    c: Dict[str, Any], out: List[str], **fmt_opts: Any
) -> None:
    """Format single callee site (direct function or indirect dispatch site)."""
    if c["call_type"] != "direct":
        _format_indirect_callee(c, out, fmt_opts)
        return

    _indent, prefix, tags = _item_prefix_and_tags(c, fmt_opts)
    cs_line = c.get("call_site_line", "?")
    out.append(
        f"{prefix}[Line {cs_line}] {c['callee']}"
        f" ({c['file']}:{c['line']}){tags}"
    )
    sub_callees = c.get("callees", [])
    indent_level = fmt_opts.get("indent_level", 1)
    for sub_idx, sub in enumerate(sub_callees):
        _format_callee_item(
            sub,
            out,
            indent_level=indent_level + 1,
            is_last=sub_idx == len(sub_callees) - 1,
            candidate_limit=fmt_opts.get("candidate_limit", 10),
            show_all=fmt_opts.get("show_all", False),
        )


def _format_callers_section(
    callers: List[Dict[str, Any]], out: List[str], **fmt_opts: Any
) -> None:
    """Append incoming callers section to summary report lines."""
    direct_callers = [c for c in callers if c.get("call_type") == "direct"]
    indirect_callers = [c for c in callers if c.get("call_type") == "indirect"]
    out.extend([
        "-" * 72,
        (
            f"INCOMING CALLERS (Total: {len(callers)} |"
            f" Direct: {len(direct_callers)} |"
            f" Indirect: {len(indirect_callers)}):"
        ),
        "-" * 72,
    ])
    if not callers:
        out.append(
            "  (No callers found in database - possible top-level entry,"
            " syscall root, or dead code)"
        )
        return

    if direct_callers:
        out.append("Direct Callers:")
        for idx, c in enumerate(direct_callers):
            _format_caller_item(
                c,
                out,
                indent_level=1,
                is_last=idx == len(direct_callers) - 1,
                **fmt_opts,
            )

    if indirect_callers:
        if direct_callers:
            out.append("")
        out.append("Indirect Dispatchers (via ops_targets):")
        for idx, c in enumerate(indirect_callers):
            _format_caller_item(
                c,
                out,
                indent_level=1,
                is_last=idx == len(indirect_callers) - 1,
                **fmt_opts,
            )


def _format_callees_section(
    callees: List[Dict[str, Any]], out: List[str], **fmt_opts: Any
) -> None:
    """Append outgoing callees section to summary report lines."""
    direct_callees = [c for c in callees if c.get("call_type") == "direct"]
    indirect_callees = [c for c in callees if c.get("call_type") == "indirect"]
    out.extend([
        "-" * 72,
        (
            f"OUTGOING CALLEES (Total Call Sites: {len(callees)} |"
            f" Direct: {len(direct_callees)} |"
            f" Indirect Sites: {len(indirect_callees)}):"
        ),
        "-" * 72,
    ])
    if not callees:
        out.append("  (No outgoing function calls found within function body)")
        return

    for idx, c in enumerate(callees):
        _format_callee_item(
            c,
            out,
            indent_level=1,
            is_last=idx == len(callees) - 1,
            **fmt_opts,
        )


def format_summary(
    target_info: Dict[str, Any],
    callers: List[Dict[str, Any]],
    callees: List[Dict[str, Any]],
    **options: Any,
) -> str:
    """Format human-readable caller/callee inspection report."""
    s, e = target_info["start_line"], target_info["end_line"]
    out = [
        "=" * 72,
        f"FUNCTION CALL INSPECTION: '{target_info['function']}'",
        "=" * 72,
        f"Location: {target_info['file']}:{s} - {e} (lines {s}-{e})",
    ]
    fmt_opts = {
        "candidate_limit": options.get("candidate_limit", 10),
        "show_all": options.get("show_all", False),
    }
    if options.get("show_callers", True):
        _format_callers_section(callers, out, **fmt_opts)
    if options.get("show_callees", True):
        _format_callees_section(callees, out, **fmt_opts)

    out.append("=" * 72)
    return "\n".join(out)


def _emit_flat_callers(
    caller_list: List[Dict[str, Any]],
    target_name: str,
    has_multihop: bool,
    out: List[str],
) -> None:
    """Recursively append flat caller lines to out."""
    for c in caller_list:
        depth = c.get("depth", 1)
        c_type, c_fn, c_file = c["call_type"], c["caller"], c["file"]
        cs = c.get("call_site_line") or c["line"]
        disp = f" via {c['dispatch']}" if c.get("dispatch") else ""
        depth_prefix = f"[hop {depth}] " if has_multihop else ""
        out.append(
            f"CALLER {depth_prefix}[{c_type:<8}] {c_fn:<30}"
            f" ({c_file}:{cs}){disp} -> {target_name}"
        )
        if c.get("callers"):
            _emit_flat_callers(c["callers"], c_fn, has_multihop, out)


def _emit_flat_callees(
    callee_list: List[Dict[str, Any]],
    caller_name: str,
    has_multihop: bool,
    out: List[str],
) -> None:
    """Recursively append flat callee lines to out."""
    for c in callee_list:
        depth = c.get("depth", 1)
        cs = c.get("call_site_line", 0)
        depth_prefix = f"[hop {depth}] " if has_multihop else ""
        if c["call_type"] == "direct":
            callee_fn = c["callee"]
            out.append(
                f"CALLEE {depth_prefix}[direct  ] {caller_name}"
                f" (line {cs}) -> {callee_fn} ({c['file']}:{c['line']})"
            )
            if c.get("callees"):
                _emit_flat_callees(c["callees"], callee_fn, has_multihop, out)
        else:
            disp = c.get("dispatch", "")
            for cand in c.get("candidates", []):
                out.append(
                    f"CALLEE {depth_prefix}[indirect] {caller_name}"
                    f" (line {cs}) -> {disp} -> {cand['target']}"
                    f" ({cand['file']}:{cand['line']})"
                )


def format_list(
    target_info: Dict[str, Any],
    callers: List[Dict[str, Any]],
    callees: List[Dict[str, Any]],
    **options: Any,
) -> str:
    """Format flat list of caller and callee relationships across all depths."""
    out: List[str] = []
    root_fn = target_info["function"]
    has_multihop = (
        options.get("max_depth", 1) > 1
        or any(c.get("callers") for c in callers)
        or any(c.get("callees") for c in callees)
    )
    if options.get("show_callers", True):
        _emit_flat_callers(callers, root_fn, has_multihop, out)
    if options.get("show_callees", True):
        _emit_flat_callees(callees, root_fn, has_multihop, out)
    return "\n".join(out)


def main() -> None:
    """CLI entry point for inspect_calls."""
    parser = argparse.ArgumentParser(
        description=(
            "Inspect 1-hop and multi-hop function callers and callees in the"
            " Linux kernel, resolving both direct edges and indirect"
            " function-pointer dispatch tables (ops_targets)."
        )
    )
    add_common_cli_args(parser, include_reachability_flags=False)
    parser.add_argument(
        "--callers",
        action="store_true",
        help="Inspect callers (who calls this function?)",
    )
    parser.add_argument(
        "--callees",
        action="store_true",
        help="Inspect callees (what does this function call?)",
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Inspect both callers and callees (default)",
    )
    parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=1,
        help="Call hierarchy traversal depth (default: 1)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help=(
            "Maximum indirect candidates to display per dispatch site"
            " (default: 10)"
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Show all indirect candidates without truncation",
    )
    parser.add_argument(
        "--format",
        choices=["summary", "tree", "list", "json"],
        default="summary",
        help="Output format: summary, tree, list, json (default: summary)",
    )

    args = parser.parse_args()
    if (
        handle_common_cli_setup(args, parser, resolve_function_to_line=False)
        is None
    ):
        return

    if not args.function and not (args.file and args.line is not None):
        parser.print_help()
        sys.exit(
            "\nError: Please specify target with --function <name> or"
            " (--file <path> --line <number>)."
        )

    show_callers = args.callers
    show_callees = args.callees
    if (not show_callers and not show_callees) or args.both:
        show_callers = True
        show_callees = True

    try:
        target_info, callers, callees = inspect_function_calls(
            args.db,
            function_name=args.function,
            file_path=args.file,
            line_number=args.line,
            syzkaller_db=args.syzkaller_db,
            depth=args.depth,
            show_callers=show_callers,
            show_callees=show_callees,
            verbose=args.verbose,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error, OSError) as e:
        sys.exit(f"Error: {e}")

    if args.format in ("summary", "tree"):
        print(
            format_summary(
                target_info,
                callers,
                callees,
                show_callers=show_callers,
                show_callees=show_callees,
                candidate_limit=args.limit,
                show_all=args.all,
            )
        )
    elif args.format == "list":
        print(
            format_list(
                target_info,
                callers,
                callees,
                show_callers=show_callers,
                show_callees=show_callees,
                max_depth=args.depth,
            )
        )
    elif args.format == "json":
        print(
            json.dumps(
                {
                    "target": target_info,
                    "callers": callers,
                    "callees": callees,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
