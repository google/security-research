#!/usr/bin/env python3
"""1-Hop and multi-hop function caller/callee inspection library."""

from collections import defaultdict
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    clean_file_path,
    column_exists,
    find_preferred_function_location,
    get_enclosing_function,
    get_function_by_name,
    get_functions_by_name,
    is_node_visited,
    is_syscall_root,
    mark_node_visited,
    open_databases,
    query_async_callers,
    query_direct_edge_rows,
    query_span_outgoing_calls,
    resolve_edge_caller,
    table_exists,
)
from tools.lib.metadata import (
    format_ambiguous_symbol_error,
    is_line_covered_by_syzkaller,
)
from tools.lib.ops import inspect_function_ops_with_conn
from tools.lib.privilege import (
    GateList,
    deduplicate_gates,
    get_call_site_gates,
    load_condition_gates,
    load_ops_acquisition_gates,
)

__all__ = [
    "build_callee_tree",
    "build_caller_tree",
    "check_is_syscall_root",
    "get_callees_for_function",
    "get_callers_for_function",
    "inspect_function_calls",
    "query_async_callees",
]


def check_is_syscall_root(fn_name: str) -> bool:
    """Check whether fn_name is a syscall entry point."""
    return is_syscall_root(fn_name, None)


def _query_async_callee_rows(
    cur: sqlite3.Cursor, clean_file: str, span: Tuple[int, int]
) -> List[Tuple[int, str, str, str, str, str]]:
    """Fetch raw async_edges rows registered within (clean_file, span)."""
    if not table_exists(cur, "async_edges"):
        return []
    try:
        if column_exists(cur, "async_edges", "callee_file"):
            cur.execute(
                "SELECT DISTINCT line, callee, mechanism, form, context,"
                " callee_file FROM async_edges"
                " WHERE (file = ? OR file = ?) AND line BETWEEN ? AND ?"
                " ORDER BY line, callee",
                (clean_file, f"linux/{clean_file}", span[0], span[1]),
            )
            return [
                (r[0], r[1], r[2], r[3], r[4], r[5] or "")
                for r in cur.fetchall()
            ]
        cur.execute(
            "SELECT DISTINCT line, callee, mechanism, form, context"
            " FROM async_edges"
            " WHERE (file = ? OR file = ?) AND line BETWEEN ? AND ?"
            " ORDER BY line, callee",
            (clean_file, f"linux/{clean_file}", span[0], span[1]),
        )
        return [(r[0], r[1], r[2], r[3], r[4], "") for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def query_async_callees(
    cur: sqlite3.Cursor,
    clean_file: str,
    span: Tuple[int, int],
) -> List[Tuple[int, str, str, int, str]]:
    """Return (reg_line, callee, callee_file, callee_line, dispatch) in span."""
    results: List[Tuple[int, str, str, int, str]] = []
    for reg_l, callee, mech, form, ctx, callee_f in _query_async_callee_rows(
        cur, clean_file, span
    ):
        pref_file = clean_file_path(callee_f or clean_file)
        fn_row = find_preferred_function_location(cur, callee, pref_file)
        res_file = (
            fn_row[0]
            if fn_row
            else (clean_file_path(callee_f) if callee_f else "unknown")
        )
        res_line = fn_row[1] if fn_row else 0
        results.append(
            (reg_l, callee, res_file, res_line, f"{mech}/{form} ({ctx})")
        )
    return results


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
    results: List[Dict[str, Any]] = []
    for row in query_direct_edge_rows(
        cur, function_name, options.get("target_file")
    ):
        resolved = resolve_edge_caller(
            cur, function_name, (row[0], row[1], row[2], row[3], row[5])
        )
        if not resolved:
            continue
        caller_fn, raw_file, caller_line, site_line = resolved
        clean_file = clean_file_path(raw_file)
        key = (caller_fn, clean_file, site_line, "direct")
        if key in seen:
            continue
        seen.add(key)
        gates, syzk_covered = _site_annotations(
            caller_fn, clean_file, site_line, options
        )
        results.append({
            "caller": caller_fn,
            "file": clean_file,
            "line": caller_line,
            "call_site_line": site_line,
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
        " AND ? BETWEEN start_line AND end_line"
        " ORDER BY (end_line - start_line) ASC, start_line DESC LIMIT 1",
        (clean_expr, f"%/{clean_expr}", expr_line),
    )
    fn_row = cur.fetchone()
    if fn_row:
        return fn_row[0], clean_file_path(fn_row[1]), fn_row[2]
    return "unknown", clean_expr, expr_line


def _lookup_acq_gates(
    function_name: str,
    clean_tfile: str,
    dispatch: str,
    options: Dict[str, Any],
) -> GateList:
    """Lookup .open / .proc_open acquisition gates for an indirect caller."""
    ops_acq_gates = options.get("ops_acq_gates") or {}
    return list(
        ops_acq_gates.get(
            (function_name, clean_tfile, dispatch),
            ops_acq_gates.get((function_name, "", dispatch), []),
        )
    )


def _query_indirect_callers(
    cur: sqlite3.Cursor,
    function_name: str,
    seen: Set[Tuple[str, str, int, str]],
    options: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Query indirect function-pointer callers from ops_targets table."""
    clean_tgt = clean_file_path(options.get("target_file") or "")
    cur.execute(
        "SELECT DISTINCT o.parent, o.field, o.target_file, o.exprcall_file,"
        " o.exprcall_line FROM ops_targets o WHERE o.target = ?",
        (function_name,),
    )
    results: List[Dict[str, Any]] = []
    for row in cur.fetchall():
        clean_tfile = clean_file_path(row[2] or "")
        if clean_tgt and clean_tfile and clean_tfile != clean_tgt:
            continue
        if not row[3] or row[4] is None:
            continue
        caller_fn, caller_file, caller_line = _resolve_indirect_caller_loc(
            cur, row[3], row[4]
        )
        dispatch = f"{row[0]}->{row[1]}"
        if (caller_fn, caller_file, row[4], dispatch) in seen:
            continue
        seen.add((caller_fn, caller_file, row[4], dispatch))
        gates, syzk_covered = _site_annotations(
            caller_fn, caller_file, row[4], options
        )
        results.append({
            "caller": caller_fn,
            "file": caller_file,
            "line": caller_line,
            "call_site_line": row[4],
            "call_type": "indirect",
            "dispatch": dispatch,
            "is_syscall": check_is_syscall_root(caller_fn),
            "gates": deduplicate_gates(
                gates
                + _lookup_acq_gates(
                    function_name, clean_tfile, dispatch, options
                )
            ),
            "syzk_covered": syzk_covered,
        })
    return results


def _query_async_callers(
    cur: sqlite3.Cursor,
    function_name: str,
    seen: Set[Tuple[str, str, int, str]],
    options: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Query asynchronous handler callers from async_edges table."""
    rows = query_async_callers(cur, function_name, options.get("target_file"))
    results: List[Dict[str, Any]] = []
    for caller_fn, caller_file, caller_line, reg_line, dispatch in rows:
        key = (caller_fn, caller_file, reg_line, dispatch)
        if key in seen:
            continue
        seen.add(key)
        gates, syzk_covered = _site_annotations(
            caller_fn, caller_file, reg_line, options
        )
        results.append({
            "caller": caller_fn,
            "file": caller_file,
            "line": caller_line,
            "call_site_line": reg_line,
            "call_type": "async",
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
    """Find direct, indirect ops, and async callers targeting function."""
    cur = conn.cursor()
    seen: Set[Tuple[str, str, int, str]] = set()
    results = _query_direct_callers(cur, function_name, seen, options)
    results.extend(_query_indirect_callers(cur, function_name, seen, options))
    results.extend(_query_async_callers(cur, function_name, seen, options))
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
    target_file: Optional[str] = options.get("target_file")
    visited: Set[Any] = (
        set(options["visited"]) if options.get("visited") else set()
    )
    if (
        is_node_visited(visited, target_fn, target_file)
        or current_depth > max_depth
    ):
        return []

    mark_node_visited(visited, target_fn, target_file)
    sub_opts = {
        k: v
        for k, v in options.items()
        if k in ("call_gates", "func_gates", "ops_acq_gates", "syzk_conn")
    }
    callers = get_callers_for_function(
        conn,
        target_fn,
        target_file=target_file,
        **sub_opts,
    )

    for c in callers:
        c["depth"] = current_depth
        if current_depth < max_depth:
            c["callers"] = build_caller_tree(
                conn,
                c["caller"],
                target_file=c.get("file"),
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
    calls_by_line: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    seen_direct: Set[Tuple[int, str, str]] = set()
    for cs_line, callee_fn, callee_f, callee_l in query_span_outgoing_calls(
        cur, clean_file, span
    ):
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


def _query_async_callees(
    cur: sqlite3.Cursor,
    function_name: str,
    clean_file: str,
    span: Tuple[int, int],
    options: Dict[str, Any],
) -> Dict[int, List[Dict[str, Any]]]:
    """Query outgoing async handler registrations inside function_name."""
    by_line: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    seen_async: Set[Tuple[int, str, str, str]] = set()
    for (
        reg_line,
        callee_fn,
        callee_f,
        callee_l,
        dispatch,
    ) in query_async_callees(cur, clean_file, span):
        key = (reg_line, callee_fn, callee_f, dispatch)
        if key in seen_async:
            continue
        seen_async.add(key)
        gates, syzk_covered = _site_annotations(
            function_name, clean_file, reg_line, options
        )
        by_line[reg_line].append({
            "call_site_line": reg_line,
            "call_type": "async",
            "callee": callee_fn,
            "file": callee_f,
            "line": callee_l,
            "dispatch": dispatch,
            "candidates": [],
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
    """Find direct calls, indirect dispatch, and async registrations."""
    cur = conn.cursor()
    clean_file = clean_file_path(file_path)
    span = (start_line, end_line)
    calls_by_line = _query_direct_callees(
        cur, function_name, clean_file, span, options
    )
    indirect_by_line = _query_indirect_callees(
        cur, function_name, clean_file, span, options
    )
    async_by_line = _query_async_callees(
        cur, function_name, clean_file, span, options
    )
    for line, items in indirect_by_line.items():
        calls_by_line[line].extend(items)
    for line, items in async_by_line.items():
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
    visited: Set[Any] = (
        set(options["visited"]) if options.get("visited") else set()
    )
    if (
        is_node_visited(visited, function_name, file_path)
        or current_depth > max_depth
    ):
        return []

    mark_node_visited(visited, function_name, file_path)
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
        if current_depth < max_depth and c["call_type"] in ("direct", "async"):
            target_fn = c.get("callee")
            cand_file = (
                c.get("file") if c.get("file") != "unknown" else file_path
            )
            if target_fn and not is_node_visited(visited, target_fn, cand_file):
                fn_info = get_function_by_name(conn, target_fn, cand_file)
                if fn_info and not is_node_visited(
                    visited, fn_info[0], fn_info[1]
                ):
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
    allow_ambiguous: bool = False,
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
        matches = get_functions_by_name(conn, function_name, file_path)
        if len(matches) > 1 and not file_path and not allow_ambiguous:
            raise ValueError(
                format_ambiguous_symbol_error(function_name, matches)
            )
        if matches:
            fn_row = matches[0]
            return {
                "function": fn_row[0],
                "file": clean_file_path(fn_row[1]),
                "start_line": fn_row[2],
                "end_line": fn_row[3],
                "query_line": fn_row[2],
            }
    return None


def _build_inspect_tree_opts(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    target_info: Dict[str, Any],
    options: Dict[str, Any],
) -> Dict[str, Any]:
    """Load gates and build tree options for inspect_function_calls."""
    call_gates, func_gates, _ = load_condition_gates(
        conn, verbose=bool(options.get("verbose", False))
    )
    ops_acq_gates = (
        load_ops_acquisition_gates(conn, func_gates) if func_gates else {}
    )
    if options.get("show_callers", True):
        ops_res = inspect_function_ops_with_conn(
            conn,
            target_info["function"],
            file_path=target_info["file"],
            syzk_conn=syzk_conn,
            ops_acq_gates=ops_acq_gates,
            allow_ambiguous=True,
        )
        if ops_res.get("registrations"):
            target_info["ops_registrations"] = ops_res["registrations"]
    return {
        "max_depth": options.get("depth", 1),
        "call_gates": call_gates,
        "func_gates": func_gates,
        "ops_acq_gates": ops_acq_gates,
        "syzk_conn": syzk_conn,
        "target_file": target_info["file"],
    }


def inspect_function_calls(
    db_path: str,
    function_name: Optional[str] = None,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    **options: Any,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Main programmatic interface for function caller and callee inspection."""
    conn, syzk_conn = open_databases(
        db_path,
        syzkaller_db=options.get("syzkaller_db"),
        verbose=bool(options.get("verbose", False)),
    )
    try:
        target_info = _resolve_inspect_target(
            conn,
            function_name,
            file_path,
            line_number,
            allow_ambiguous=bool(options.get("allow_ambiguous", False)),
        )
    except ValueError:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        raise

    if not target_info:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        target_repr = function_name or f"{file_path}:{line_number}"
        raise ValueError(
            f"Target function '{target_repr}' not found in database."
        )

    tree_opts = _build_inspect_tree_opts(conn, syzk_conn, target_info, options)
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
