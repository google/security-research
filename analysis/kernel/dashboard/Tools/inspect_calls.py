#!/usr/bin/env python3
"""
Tools/inspect_calls.py: 1-Hop & Multi-Hop Callgraph Inspector with Indirect Dispatch Resolution.

Answers the fundamental developer questions during bug triage and code navigation:
  1. "Who calls this?" (--callers)
     - Discovers direct callers from CodeQL edge graphs.
     - Discovers indirect callers dispatched via function-pointer structs (e.g., inode_operations->link)
       using the precomputed ops_targets table.
  2. "What does this call?" (--callees)
     - Discovers direct function calls made from within the target function span.
     - Discovers indirect dispatch sites (e.g. dir->i_op->link) and resolves them to candidate implementations.
  3. "Both directions" (--both, default)
     - Provides complete 360-degree local context around any function or source line.

Beats grep/cscope/LSP by resolving kernel function-pointer tables that text searches cannot see.
"""

import argparse
from collections import defaultdict
import json
import os
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Import shared utilities from Tools.find_paths or fallback
try:
    from Tools.find_paths import (
        ensure_indexes,
        get_enclosing_function,
        is_line_covered_by_syzkaller,
        is_syscall_root,
    )
except ImportError:
    try:
        from find_paths import (
            ensure_indexes,
            get_enclosing_function,
            is_line_covered_by_syzkaller,
            is_syscall_root,
        )
    except ImportError:
        def ensure_indexes(conn, verbose=False):
            pass

        def get_enclosing_function(conn, file_path, line_number):
            clean_p = file_path.lstrip("/").replace("linux/", "")
            cur = conn.cursor()
            cur.execute("""
                SELECT function_name, file_path, start_line, end_line
                FROM function_locations
                WHERE (file_path = ? OR file_path LIKE ?)
                  AND ? BETWEEN start_line AND end_line
                ORDER BY (end_line - start_line) ASC
                LIMIT 1
            """, (clean_p, f"%/{clean_p}", line_number))
            return cur.fetchone()

        def is_line_covered_by_syzkaller(syzk_conn, file_path, line_number):
            return False

        def is_syscall_root(fn_name, target_syscall=None):
            return fn_name.startswith("__do_sys_") or fn_name.startswith("__se_sys_")

def check_is_syscall_root(fn_name: str) -> bool:
    try:
        return is_syscall_root(fn_name, None)
    except TypeError:
        return is_syscall_root(fn_name)

# Import condition gates helper if available
try:
    from Tools.check_privilege import load_condition_gates, get_call_site_gates
except ImportError:
    try:
        from check_privilege import load_condition_gates, get_call_site_gates
    except ImportError:
        def load_condition_gates(conn, verbose=False):
            return {}, {}, {}

        def get_call_site_gates(call_gates, func_gates, file_path, line_number, caller_fn=None):
            return []


def clean_file_path(path: str) -> str:
    """Normalize file path by stripping leading slashes and repository prefixes."""
    return path.lstrip("/").replace("linux/", "")


def get_function_by_name(
    conn: sqlite3.Connection, function_name: str
) -> Optional[Tuple[str, str, int, int]]:
    """Look up canonical file and line span for a function name."""
    cur = conn.cursor()
    cur.execute("""
        SELECT function_name, file_path, start_line, end_line
        FROM function_locations
        WHERE function_name = ?
        LIMIT 1
    """, (function_name,))
    row = cur.fetchone()
    if row:
        return (row[0], clean_file_path(row[1]), row[2], row[3])
    return None


def get_callers_for_function(
    conn: sqlite3.Connection,
    function_name: str,
    call_gates: Optional[Dict[Tuple[str, int], List[Dict[str, Any]]]] = None,
    func_gates: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    syzk_conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """
    Find all direct callers and indirect ops dispatchers targeting function_name.
    Returns structured list of caller records with gating and coverage metadata.
    """
    cur = conn.cursor()
    results = []
    seen = set()

    # 1. Direct callers from locations & edges
    cur.execute("""
        SELECT DISTINCT s.message AS caller_fn,
                        s.uri AS caller_file,
                        s.startLine AS caller_line,
                        t.startLine AS call_site_line
        FROM edges e
        JOIN locations s ON e.source_location_id = s.id
        JOIN locations t ON e.target_location_id = t.id
        WHERE (t.message = ? OR t.message = ?)
          AND s.message NOT LIKE "call to %"
    """, (function_name, f"call to {function_name}"))

    for caller_fn, caller_file, caller_line, call_site_line in cur.fetchall():
        clean_file = clean_file_path(caller_file)
        key = (caller_fn, clean_file, call_site_line, "direct")
        if key in seen:
            continue
        seen.add(key)

        gates = []
        if call_gates is not None and func_gates is not None:
            gates = get_call_site_gates(
                call_gates, func_gates, clean_file, call_site_line, caller_fn=caller_fn
            )

        syzk_covered = False
        if syzk_conn and call_site_line:
            syzk_covered = is_line_covered_by_syzkaller(syzk_conn, clean_file, call_site_line)

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

    # 2. Indirect callers from ops_targets table
    cur.execute("""
        SELECT DISTINCT o.parent, o.field, o.exprcall_file, o.exprcall_line
        FROM ops_targets o
        WHERE o.target = ?
    """, (function_name,))

    for parent, field, expr_file, expr_line in cur.fetchall():
        clean_expr_file = clean_file_path(expr_file)
        # Find enclosing function of this call site
        cur.execute("""
            SELECT function_name, file_path, start_line
            FROM function_locations
            WHERE (file_path = ? OR file_path LIKE ?)
              AND ? BETWEEN start_line AND end_line
            LIMIT 1
        """, (clean_expr_file, f"%/{clean_expr_file}", expr_line))
        fn_row = cur.fetchone()
        if fn_row:
            caller_fn, caller_file, caller_line = fn_row[0], clean_file_path(fn_row[1]), fn_row[2]
        else:
            caller_fn = "unknown"
            caller_file = clean_expr_file
            caller_line = expr_line

        key = (caller_fn, caller_file, expr_line, f"{parent}->{field}")
        if key in seen:
            continue
        seen.add(key)

        gates = []
        if call_gates is not None and func_gates is not None:
            gates = get_call_site_gates(
                call_gates, func_gates, caller_file, expr_line, caller_fn=caller_fn
            )

        syzk_covered = False
        if syzk_conn and expr_line:
            syzk_covered = is_line_covered_by_syzkaller(syzk_conn, caller_file, expr_line)

        results.append({
            "caller": caller_fn,
            "file": caller_file,
            "line": caller_line,
            "call_site_line": expr_line,
            "call_type": "indirect",
            "dispatch": f"{parent}->{field}",
            "is_syscall": check_is_syscall_root(caller_fn),
            "gates": gates,
            "syzk_covered": syzk_covered,
        })

    # Sort results: indirect vs direct, then caller name
    results.sort(key=lambda x: (x["call_type"], x["caller"], x.get("call_site_line") or 0))
    return results


def build_caller_tree(
    conn: sqlite3.Connection,
    target_fn: str,
    max_depth: int = 1,
    current_depth: int = 1,
    visited: Optional[Set[str]] = None,
    call_gates: Optional[Dict[Tuple[str, int], List[Dict[str, Any]]]] = None,
    func_gates: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    syzk_conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """Recursively traverse callers up to max_depth hops."""
    if visited is None:
        visited = set()
    if target_fn in visited or current_depth > max_depth:
        return []

    visited.add(target_fn)
    callers = get_callers_for_function(
        conn, target_fn, call_gates=call_gates, func_gates=func_gates, syzk_conn=syzk_conn
    )

    for c in callers:
        c["depth"] = current_depth
        if current_depth < max_depth:
            c["callers"] = build_caller_tree(
                conn,
                c["caller"],
                max_depth=max_depth,
                current_depth=current_depth + 1,
                visited=set(visited),
                call_gates=call_gates,
                func_gates=func_gates,
                syzk_conn=syzk_conn,
            )
        else:
            c["callers"] = []

    return callers


def get_callees_for_function(
    conn: sqlite3.Connection,
    function_name: str,
    file_path: str,
    start_line: int,
    end_line: int,
    call_gates: Optional[Dict[Tuple[str, int], List[Dict[str, Any]]]] = None,
    func_gates: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    syzk_conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """
    Find all direct calls and indirect dispatch sites made from within function_name's body.
    Returns chronologically ordered list of call sites.
    """
    cur = conn.cursor()
    clean_file = clean_file_path(file_path)
    calls_by_line: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

    # 1. Direct function calls originating inside this function span
    cur.execute("""
        SELECT DISTINCT s.startLine AS call_site_line,
                        t.message AS callee_name,
                        t.uri AS callee_file,
                        t.startLine AS callee_line
        FROM locations s
        JOIN edges e ON e.source_location_id = s.id
        JOIN locations t ON e.target_location_id = t.id
        WHERE (s.uri = ? OR s.uri = ?)
          AND s.startLine BETWEEN ? AND ?
          AND s.message LIKE 'call to %'
        ORDER BY s.startLine, callee_name
    """, (clean_file, f"linux/{clean_file}", start_line, end_line))

    seen_direct = set()
    for cs_line, callee_fn, callee_f, callee_l in cur.fetchall():
        clean_callee_f = clean_file_path(callee_f) if callee_f else "unknown"
        key = (cs_line, callee_fn, clean_callee_f)
        if key in seen_direct:
            continue
        seen_direct.add(key)

        gates = []
        if call_gates is not None and func_gates is not None:
            gates = get_call_site_gates(
                call_gates, func_gates, clean_file, cs_line, caller_fn=function_name
            )

        syzk_covered = False
        if syzk_conn and cs_line:
            syzk_covered = is_line_covered_by_syzkaller(syzk_conn, clean_file, cs_line)

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

    # 2. Indirect dispatch sites from ops_targets table
    cur.execute("""
        SELECT exprcall_line, parent, field, target, target_file, target_start
        FROM ops_targets
        WHERE (exprcall_file = ? OR exprcall_file = ?)
          AND exprcall_line BETWEEN ? AND ?
        ORDER BY exprcall_line, target
    """, (clean_file, f"linux/{clean_file}", start_line, end_line))

    indirect_grouped: Dict[Tuple[int, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for expr_l, parent, field, tgt, tgt_f, tgt_s in cur.fetchall():
        clean_tgt_f = clean_file_path(tgt_f) if tgt_f else "unknown"
        indirect_grouped[(expr_l, parent, field)].append({
            "target": tgt,
            "file": clean_tgt_f,
            "line": tgt_s,
        })

    for (expr_l, parent, field), candidates in indirect_grouped.items():
        # Deduplicate candidates
        uniq_candidates = []
        seen_tgt = set()
        for cand in candidates:
            tgt_k = (cand["target"], cand["file"], cand["line"])
            if tgt_k not in seen_tgt:
                seen_tgt.add(tgt_k)
                uniq_candidates.append(cand)

        gates = []
        if call_gates is not None and func_gates is not None:
            gates = get_call_site_gates(
                call_gates, func_gates, clean_file, expr_l, caller_fn=function_name
            )

        syzk_covered = False
        if syzk_conn and expr_l:
            syzk_covered = is_line_covered_by_syzkaller(syzk_conn, clean_file, expr_l)

        calls_by_line[expr_l].append({
            "call_site_line": expr_l,
            "call_type": "indirect",
            "callee": None,
            "file": None,
            "line": None,
            "dispatch": f"{parent}->{field}",
            "candidates": uniq_candidates,
            "gates": gates,
            "syzk_covered": syzk_covered,
        })

    # Flatten and order by call_site_line
    ordered_callees = []
    for line in sorted(calls_by_line.keys()):
        ordered_callees.extend(calls_by_line[line])

    return ordered_callees


def build_callee_tree(
    conn: sqlite3.Connection,
    function_name: str,
    file_path: str,
    start_line: int,
    end_line: int,
    max_depth: int = 1,
    current_depth: int = 1,
    visited: Optional[Set[str]] = None,
    call_gates: Optional[Dict[Tuple[str, int], List[Dict[str, Any]]]] = None,
    func_gates: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    syzk_conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """Recursively traverse callees up to max_depth hops."""
    if visited is None:
        visited = set()
    if function_name in visited or current_depth > max_depth:
        return []

    visited.add(function_name)
    callees = get_callees_for_function(
        conn,
        function_name,
        file_path,
        start_line,
        end_line,
        call_gates=call_gates,
        func_gates=func_gates,
        syzk_conn=syzk_conn,
    )

    for c in callees:
        c["depth"] = current_depth
        c["callees"] = []
        if current_depth < max_depth and c["call_type"] == "direct":
            target_fn = c.get("callee")
            if target_fn and target_fn not in visited:
                fn_info = get_function_by_name(conn, target_fn)
                if fn_info:
                    sub_fn, sub_file, sub_start, sub_end = fn_info
                    c["callees"] = build_callee_tree(
                        conn,
                        sub_fn,
                        sub_file,
                        sub_start,
                        sub_end,
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                        visited=set(visited),
                        call_gates=call_gates,
                        func_gates=func_gates,
                        syzk_conn=syzk_conn,
                    )

    return callees


def inspect_function_calls(
    db_path: str,
    function_name: Optional[str] = None,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    syzkaller_db: Optional[str] = None,
    depth: int = 1,
    show_callers: bool = True,
    show_callees: bool = True,
    verbose: bool = False,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Main programmatic interface for function caller and callee inspection.
    Returns:
      (target_info, callers_list, callees_list)
    """
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"Database file not found: {db_path}")

    conn = sqlite3.connect(db_path)
    ensure_indexes(conn, verbose=verbose)

    syzk_conn = (
        sqlite3.connect(syzkaller_db)
        if syzkaller_db and os.path.isfile(syzkaller_db)
        else None
    )

    # Resolve target function
    target_info = None
    if file_path and line_number is not None:
        fn_row = get_enclosing_function(conn, file_path, line_number)
        if fn_row:
            target_info = {
                "function": fn_row[0],
                "file": clean_file_path(fn_row[1]),
                "start_line": fn_row[2],
                "end_line": fn_row[3],
                "query_line": line_number,
            }
    elif function_name:
        fn_row = get_function_by_name(conn, function_name)
        if fn_row:
            target_info = {
                "function": fn_row[0],
                "file": clean_file_path(fn_row[1]),
                "start_line": fn_row[2],
                "end_line": fn_row[3],
                "query_line": fn_row[2],
            }

    if not target_info:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        target_repr = function_name or f"{file_path}:{line_number}"
        raise ValueError(f"Target function '{target_repr}' not found in database.")

    call_gates, func_gates, _ = load_condition_gates(conn, verbose=verbose)

    fn_name = target_info["function"]
    f_file = target_info["file"]
    s_line = target_info["start_line"]
    e_line = target_info["end_line"]

    callers = []
    if show_callers:
        callers = build_caller_tree(
            conn,
            fn_name,
            max_depth=depth,
            call_gates=call_gates,
            func_gates=func_gates,
            syzk_conn=syzk_conn,
        )

    callees = []
    if show_callees:
        callees = build_callee_tree(
            conn,
            fn_name,
            f_file,
            s_line,
            e_line,
            max_depth=depth,
            call_gates=call_gates,
            func_gates=func_gates,
            syzk_conn=syzk_conn,
        )

    conn.close()
    if syzk_conn:
        syzk_conn.close()

    return target_info, callers, callees


def format_summary(
    target_info: Dict[str, Any],
    callers: List[Dict[str, Any]],
    callees: List[Dict[str, Any]],
    show_callers: bool = True,
    show_callees: bool = True,
    candidate_limit: int = 10,
    show_all: bool = False,
) -> str:
    """Format human-readable caller/callee inspection report."""
    out = []
    fn = target_info["function"]
    f = target_info["file"]
    s = target_info["start_line"]
    e = target_info["end_line"]

    out.append("=" * 72)
    out.append(f"FUNCTION CALL INSPECTION: '{fn}'")
    out.append("=" * 72)
    out.append(f"Location: {f}:{s} - {e} (lines {s}-{e})")

    # Callers Section
    if show_callers:
        direct_callers = [c for c in callers if c.get("call_type") == "direct"]
        indirect_callers = [c for c in callers if c.get("call_type") == "indirect"]
        out.append("-" * 72)
        out.append(f"INCOMING CALLERS (Total: {len(callers)} | Direct: {len(direct_callers)} | Indirect: {len(indirect_callers)}):")
        out.append("-" * 72)

        if not callers:
            out.append("  (No callers found in database - possible top-level entry, syscall root, or dead code)")
        else:
            if direct_callers:
                out.append("Direct Callers:")
                for idx, c in enumerate(direct_callers):
                    is_last = (idx == len(direct_callers) - 1) and not indirect_callers
                    _format_caller_item(c, out, indent_level=1, is_last=(idx == len(direct_callers) - 1), candidate_limit=candidate_limit, show_all=show_all)

            if indirect_callers:
                if direct_callers:
                    out.append("")
                out.append("Indirect Dispatchers (via ops_targets):")
                for idx, c in enumerate(indirect_callers):
                    _format_caller_item(c, out, indent_level=1, is_last=(idx == len(indirect_callers) - 1), candidate_limit=candidate_limit, show_all=show_all)

    # Callees Section
    if show_callees:
        direct_callees = [c for c in callees if c.get("call_type") == "direct"]
        indirect_callees = [c for c in callees if c.get("call_type") == "indirect"]
        out.append("-" * 72)
        out.append(f"OUTGOING CALLEES (Total Call Sites: {len(callees)} | Direct: {len(direct_callees)} | Indirect Sites: {len(indirect_callees)}):")
        out.append("-" * 72)

        if not callees:
            out.append("  (No outgoing function calls found within function body)")
        else:
            for idx, c in enumerate(callees):
                is_last = (idx == len(callees) - 1)
                _format_callee_item(c, out, indent_level=1, is_last=is_last, candidate_limit=candidate_limit, show_all=show_all)

    out.append("=" * 72)
    return "\n".join(out)


def _format_caller_item(
    c: Dict[str, Any],
    out: List[str],
    indent_level: int = 1,
    is_last: bool = False,
    candidate_limit: int = 10,
    show_all: bool = False,
) -> None:
    """Format single caller entry and any recursive sub-callers."""
    indent = "  " * (indent_level - 1)
    prefix = f"{indent}└── " if is_last else f"{indent}├── "
    fn = c["caller"]
    f = c["file"]
    cs_line = c.get("call_site_line")
    line_str = f" [calls at line {cs_line}]" if cs_line else ""
    type_str = f" [via {c['dispatch']}]" if c.get("dispatch") else " [direct]"
    syscall_str = " [Syscall Entry]" if c.get("is_syscall") else ""

    gate_str = ""
    if c.get("gates"):
        gate_str = f" [GATED: {', '.join(g['cap_str'] for g in c['gates'])}]"

    cov_str = " [COVERED]" if c.get("syzk_covered") else ""

    out.append(f"{prefix}{fn} ({f}:{c['line']}){line_str}{type_str}{syscall_str}{gate_str}{cov_str}")

    # Recursive sub-callers if depth > 1
    sub_callers = c.get("callers", [])
    for sub_idx, sub in enumerate(sub_callers):
        sub_is_last = (sub_idx == len(sub_callers) - 1)
        _format_caller_item(sub, out, indent_level=indent_level + 1, is_last=sub_is_last, candidate_limit=candidate_limit, show_all=show_all)


def _format_callee_item(
    c: Dict[str, Any],
    out: List[str],
    indent_level: int = 1,
    is_last: bool = False,
    candidate_limit: int = 10,
    show_all: bool = False,
) -> None:
    """Format single callee site (direct function or indirect dispatch site)."""
    indent = "  " * (indent_level - 1)
    prefix = f"{indent}└── " if is_last else f"{indent}├── "
    cs_line = c.get("call_site_line", "?")

    gate_str = ""
    if c.get("gates"):
        gate_str = f" [GATED: {', '.join(g['cap_str'] for g in c['gates'])}]"

    cov_str = " [COVERED]" if c.get("syzk_covered") else ""

    if c["call_type"] == "direct":
        callee = c["callee"]
        f = c["file"]
        l = c["line"]
        out.append(f"{prefix}[Line {cs_line}] {callee} ({f}:{l}){gate_str}{cov_str}")
        sub_callees = c.get("callees", [])
        for sub_idx, sub in enumerate(sub_callees):
            sub_is_last = (sub_idx == len(sub_callees) - 1)
            _format_callee_item(sub, out, indent_level=indent_level + 1, is_last=sub_is_last, candidate_limit=candidate_limit, show_all=show_all)
    else:
        disp = c.get("dispatch", "indirect dispatch")
        candidates = c.get("candidates", [])
        total_cands = len(candidates)
        out.append(f"{prefix}[Line {cs_line}] ->{disp} [indirect dispatch: {total_cands} candidate(s)]{gate_str}{cov_str}")

        display_cands = candidates if show_all else candidates[:candidate_limit]
        sub_indent = indent + ("    " if is_last else "│   ") + "  "
        for cand in display_cands:
            out.append(f"{sub_indent}* {cand['target']} ({cand['file']}:{cand['line']})")

        if not show_all and total_cands > candidate_limit:
            remaining = total_cands - candidate_limit
            out.append(f"{sub_indent}... and {remaining} more candidate(s) (use --all to show all)")


def format_list(
    target_info: Dict[str, Any],
    callers: List[Dict[str, Any]],
    callees: List[Dict[str, Any]],
    show_callers: bool = True,
    show_callees: bool = True,
    max_depth: int = 1,
) -> str:
    """Format flat list of caller and callee relationships for easy grep/piping across all depths."""
    out = []
    root_fn = target_info["function"]
    has_multihop = (
        max_depth > 1
        or any(c.get("callers") for c in callers)
        or any(c.get("callees") for c in callees)
    )

    def _emit_callers(caller_list: List[Dict[str, Any]], target_name: str):
        for c in caller_list:
            depth = c.get("depth", 1)
            c_type = c["call_type"]
            c_fn = c["caller"]
            c_file = c["file"]
            cs = c.get("call_site_line") or c["line"]
            disp = f" via {c['dispatch']}" if c.get("dispatch") else ""
            depth_prefix = f"[hop {depth}] " if has_multihop else ""
            out.append(f"CALLER {depth_prefix}[{c_type:<8}] {c_fn:<30} ({c_file}:{cs}){disp} -> {target_name}")
            sub_callers = c.get("callers", [])
            if sub_callers:
                _emit_callers(sub_callers, c_fn)

    def _emit_callees(callee_list: List[Dict[str, Any]], caller_name: str):
        for c in callee_list:
            depth = c.get("depth", 1)
            cs = c.get("call_site_line", 0)
            depth_prefix = f"[hop {depth}] " if has_multihop else ""
            if c["call_type"] == "direct":
                callee_fn = c["callee"]
                callee_f = c["file"]
                callee_l = c["line"]
                out.append(f"CALLEE {depth_prefix}[direct  ] {caller_name} (line {cs}) -> {callee_fn} ({callee_f}:{callee_l})")
                sub_callees = c.get("callees", [])
                if sub_callees:
                    _emit_callees(sub_callees, callee_fn)
            else:
                disp = c.get("dispatch", "")
                for cand in c.get("candidates", []):
                    t = cand["target"]
                    tf = cand["file"]
                    tl = cand["line"]
                    out.append(f"CALLEE {depth_prefix}[indirect] {caller_name} (line {cs}) -> {disp} -> {t} ({tf}:{tl})")

    if show_callers:
        _emit_callers(callers, root_fn)

    if show_callees:
        _emit_callees(callees, root_fn)

    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Inspect 1-hop and multi-hop function callers and callees in the Linux kernel, "
            "resolving both direct edges and indirect function-pointer dispatch tables (ops_targets)."
        )
    )
    parser.add_argument("--db", required=True, help="Path to CodeQL SQLite database")
    parser.add_argument(
        "--syzkaller-db", default=None, help="Path to Syzkaller coverage database (optional)"
    )
    parser.add_argument(
        "--function", "-fn", help="Target function name to inspect (e.g. shmem_link or vfs_link)"
    )
    parser.add_argument("--file", "-f", help="Target source file (e.g. mm/shmem.c)")
    parser.add_argument(
        "--line", "-l", type=int, help="Line number within the target source file"
    )
    parser.add_argument(
        "--callers", action="store_true", help="Inspect callers (who calls this function?)"
    )
    parser.add_argument(
        "--callees", action="store_true", help="Inspect callees (what does this function call?)"
    )
    parser.add_argument(
        "--both", action="store_true", help="Inspect both callers and callees (default)"
    )
    parser.add_argument(
        "--depth", "-d", type=int, default=1, help="Call hierarchy traversal depth (default: 1)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum indirect candidates to display per dispatch site (default: 10)",
    )
    parser.add_argument(
        "--all", action="store_true", help="Show all indirect candidates without truncation"
    )
    parser.add_argument(
        "--format",
        choices=["summary", "tree", "list", "json"],
        default="summary",
        help="Output format: summary, tree, list, json (default: summary)",
    )
    parser.add_argument(
        "--ensure-indexes",
        action="store_true",
        help="Ensure fast SQLite indexes exist on database and exit",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print debug information"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.db):
        sys.exit(f"Error: Database file not found: {args.db}")

    if args.syzkaller_db and not os.path.isfile(args.syzkaller_db):
        sys.exit(f"Error: Syzkaller database file not found: {args.syzkaller_db}")

    if args.ensure_indexes:
        conn = sqlite3.connect(args.db)
        ensure_indexes(conn, verbose=True)
        conn.close()
        print("Indexes verified successfully.")
        return

    if not args.function and not (args.file and args.line is not None):
        parser.print_help()
        sys.exit("\nError: Please specify target with --function <name> or (--file <path> --line <number>).")

    # Determine direction modes
    show_callers = args.callers
    show_callees = args.callees
    if not show_callers and not show_callees:
        show_callers = True
        show_callees = True
    elif args.both:
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
    except Exception as e:
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
        data = {
            "target": target_info,
            "depth": args.depth,
            "callers": callers if show_callers else [],
            "callees": callees if show_callees else [],
        }
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
