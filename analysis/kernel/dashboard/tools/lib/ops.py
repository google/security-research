#!/usr/bin/env python3
"""Forward and inverse indirect-dispatch (ops_targets) exploration library."""

from collections import defaultdict
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    LOCATION_RE,
    clean_file_path,
    file_matches_filter,
    get_enclosing_function,
    get_functions_by_name,
    is_non_runtime_path,
    open_databases,
    table_exists,
)
from tools.lib.metadata import format_ambiguous_symbol_error
from tools.lib.privilege import (
    OpsAcqGateMap,
    load_condition_gates,
    load_ops_acquisition_gates,
)

__all__ = [
    "inspect_ops_slot_with_conn",
    "inspect_ops_slot",
    "inspect_function_ops_with_conn",
    "inspect_function_ops",
    "format_ops_text",
]


def _clean_def_loc(def_loc: Optional[str]) -> str:
    """Normalize the file-path prefix of a 5-part location string."""
    if not def_loc:
        return "unknown"
    m = LOCATION_RE.match(def_loc)
    if not m:
        return clean_file_path(def_loc)
    return (
        f"{clean_file_path(m.group(1))}:"
        f"{m.group(2)}:{m.group(3)}:{m.group(4)}:{m.group(5)}"
    )


def _resolve_caller_cached(
    conn: sqlite3.Connection,
    expr_file: Optional[str],
    expr_line: Optional[int],
    cache: Dict[Tuple[str, int], str],
) -> Optional[Dict[str, Any]]:
    """Resolve and cache enclosing caller function for expr_file:expr_line."""
    if not expr_file or expr_line is None or expr_file == "unknown":
        return None
    clean_expr = clean_file_path(expr_file)
    if not clean_expr or is_non_runtime_path(clean_expr):
        return None
    key = (clean_expr, int(expr_line))
    if key not in cache:
        fn_row = get_enclosing_function(conn, clean_expr, int(expr_line))
        cache[key] = fn_row[0] if fn_row else "unknown"
    return {
        "caller": cache[key],
        "file": clean_expr,
        "line": int(expr_line),
    }


def _get_ops_acq_gates(
    conn: sqlite3.Connection, options: Dict[str, Any]
) -> OpsAcqGateMap:
    """Return preloaded or freshly computed ops acquisition gates."""
    if options.get("ops_acq_gates") is not None:
        return options["ops_acq_gates"]
    if not options.get("include_gates", True):
        return {}
    _, func_gates, _ = load_condition_gates(conn, verbose=False)
    return load_ops_acquisition_gates(conn, func_gates) if func_gates else {}


def _query_slot_rows(
    cur: sqlite3.Cursor,
    struct_name: str,
    field_name: Optional[str],
    file_path: Optional[str],
) -> List[Tuple[Any, ...]]:
    """Query ops_targets rows for struct_name and optional field_name."""
    if not table_exists(cur, "ops_targets"):
        return []
    if field_name:
        cur.execute(
            "SELECT definition, parent, field, target, target_file,"
            " target_start, target_end, exprcall_file, exprcall_line"
            " FROM ops_targets WHERE parent = ? AND field = ?",
            (struct_name, field_name),
        )
    else:
        cur.execute(
            "SELECT definition, parent, field, target, target_file,"
            " target_start, target_end, exprcall_file, exprcall_line"
            " FROM ops_targets WHERE parent = ?",
            (struct_name,),
        )
    rows = []
    for r in cur.fetchall():
        clean_tf = clean_file_path(r[4] or "")
        if clean_tf and is_non_runtime_path(clean_tf) and not file_path:
            continue
        if file_path and not file_matches_filter(clean_tf, file_path):
            continue
        rows.append(r)
    return rows


def _collect_slot_defs_and_sites(
    conn: sqlite3.Connection,
    rows: List[Tuple[Any, ...]],
    caller_cache: Dict[Tuple[str, int], str],
) -> Tuple[Dict[Tuple[str, str, int, int], Set[str]], List[Dict[str, Any]]]:
    """Collect deduplicated callback definitions and dispatch call sites."""
    cb_defs: Dict[Tuple[str, str, int, int], Set[str]] = defaultdict(set)
    dispatch_seen: Set[Tuple[str, str, int]] = set()
    dispatch_sites: List[Dict[str, Any]] = []

    for row in rows:
        clean_tf = clean_file_path(row[4] or "")
        if row[3]:
            cb_key = (row[3], clean_tf, int(row[5] or 0), int(row[6] or 0))
            clean_def = _clean_def_loc(row[0])
            if clean_def != "unknown":
                cb_defs[cb_key].add(clean_def)
            else:
                cb_defs.setdefault(cb_key, set())
        site = _resolve_caller_cached(conn, row[7], row[8], caller_cache)
        if site:
            s_key = (site["caller"], site["file"], site["line"])
            if s_key not in dispatch_seen:
                dispatch_seen.add(s_key)
                dispatch_sites.append(site)

    dispatch_sites.sort(key=lambda s: (s["file"], s["line"], s["caller"]))
    return cb_defs, dispatch_sites


def _build_slot_summary(
    conn: sqlite3.Connection,
    parent: str,
    field: str,
    rows: List[Tuple[Any, ...]],
    ctx: Tuple[OpsAcqGateMap, Dict[Tuple[str, int], str]],
) -> Dict[str, Any]:
    """Build callback and dispatch-site summary for a (parent, field) slot."""
    cb_defs, dispatch_sites = _collect_slot_defs_and_sites(conn, rows, ctx[1])
    callbacks: List[Dict[str, Any]] = []
    for cb_key, defs in sorted(cb_defs.items()):
        acq = ctx[0].get((cb_key[0], cb_key[1], f"{parent}->{field}"), [])
        callbacks.append({
            "target": cb_key[0],
            "file": cb_key[1],
            "start_line": cb_key[2],
            "end_line": cb_key[3],
            "definitions": sorted(defs),
            "acquisition_gates": [
                {"cap_str": g["cap_str"], "via": g.get("call")} for g in acq
            ],
        })
    return {
        "struct": parent,
        "field": field,
        "callback_count": len(callbacks),
        "dispatch_site_count": len(dispatch_sites),
        "callbacks": callbacks,
        "dispatch_sites": dispatch_sites,
    }


def inspect_ops_slot_with_conn(
    conn: sqlite3.Connection,
    struct_name: str,
    field_name: Optional[str] = None,
    file_path: Optional[str] = None,
    **options: Any,
) -> Dict[str, Any]:
    """Inspect registered callbacks and dispatch sites for struct_name.field."""
    cur = conn.cursor()
    rows = _query_slot_rows(cur, struct_name, field_name, file_path)
    grouped: Dict[str, List[Tuple[Any, ...]]] = defaultdict(list)
    for r in rows:
        grouped[r[2]].append(r)

    ops_acq_gates = _get_ops_acq_gates(conn, options) if rows else {}
    caller_cache: Dict[Tuple[str, int], str] = {}
    slots = [
        _build_slot_summary(
            conn,
            struct_name,
            fname,
            grouped[fname],
            (ops_acq_gates, caller_cache),
        )
        for fname in sorted(grouped.keys())
    ]
    return {
        "mode": "slot",
        "query": {
            "struct": struct_name,
            "field": field_name,
            "file": clean_file_path(file_path) if file_path else None,
        },
        "slot_count": len(slots),
        "slots": slots,
    }


def inspect_ops_slot(
    db_path: str,
    struct_name: str,
    field_name: Optional[str] = None,
    file_path: Optional[str] = None,
    **options: Any,
) -> Dict[str, Any]:
    """Open db_path and inspect ops_targets slots for struct_name."""
    conn, _ = open_databases(db_path, verbose=options.get("verbose", False))
    try:
        return inspect_ops_slot_with_conn(
            conn,
            struct_name,
            field_name=field_name,
            file_path=file_path,
            **options,
        )
    finally:
        conn.close()


def _disambiguate_ops_function(
    conn: sqlite3.Connection,
    function_name: str,
    file_path: Optional[str],
    allow_ambiguous: bool,
) -> Optional[str]:
    """Resolve and disambiguate function_name to a single file if needed."""
    matches = get_functions_by_name(conn, function_name, file_path)
    if len(matches) > 1 and not file_path and not allow_ambiguous:
        raise ValueError(format_ambiguous_symbol_error(function_name, matches))
    if len(matches) == 1:
        return matches[0][1]
    return clean_file_path(file_path) if file_path else None


def _query_instance_siblings(
    cur: sqlite3.Cursor, parent: str, raw_def: str
) -> List[Dict[str, Any]]:
    """Query all sibling callbacks registered on the same ops instance."""
    if not raw_def or raw_def == "unknown":
        return []
    cur.execute(
        "SELECT DISTINCT field, target, target_file, target_start, target_end"
        " FROM ops_targets WHERE parent = ? AND definition = ?"
        " ORDER BY field ASC, target ASC",
        (parent, raw_def),
    )
    siblings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()
    for field, target, tfile, tstart, tend in cur.fetchall():
        clean_tf = clean_file_path(tfile or "")
        key = (field, target, clean_tf)
        if key in seen:
            continue
        seen.add(key)
        siblings.append({
            "field": field,
            "target": target,
            "file": clean_tf,
            "start_line": int(tstart or 0),
            "end_line": int(tend or 0),
        })
    return siblings


def _group_function_registrations(
    cur: sqlite3.Cursor, function_name: str, resolved_file: Optional[str]
) -> Dict[Tuple[str, str, str, str, int, int], List[Tuple[str, int]]]:
    """Group ops_targets rows for function_name by registration key."""
    cur.execute(
        "SELECT definition, parent, field, target_file, target_start,"
        " target_end, exprcall_file, exprcall_line"
        " FROM ops_targets WHERE target = ?",
        (function_name,),
    )
    grouped: Dict[
        Tuple[str, str, str, str, int, int], List[Tuple[str, int]]
    ] = defaultdict(list)
    for row in cur.fetchall():
        raw_def, parent, field, tfile, tstart, tend, efile, eline = row
        clean_tf = clean_file_path(tfile or "")
        if resolved_file and not file_matches_filter(clean_tf, resolved_file):
            continue
        reg_key = (
            parent,
            field,
            raw_def or "unknown",
            clean_tf,
            int(tstart or 0),
            int(tend or 0),
        )
        grouped.setdefault(reg_key, [])
        if efile and eline is not None:
            grouped[reg_key].append((efile, int(eline)))
    return grouped


def _resolve_unique_dispatch_sites(
    conn: sqlite3.Connection,
    expr_sites: List[Tuple[str, int]],
    caller_cache: Dict[Tuple[str, int], str],
) -> List[Dict[str, Any]]:
    """Resolve and deduplicate (exprcall_file, exprcall_line) call sites."""
    sites: List[Dict[str, Any]] = []
    seen_s: Set[Tuple[str, str, int]] = set()
    for ef, el in expr_sites:
        s = _resolve_caller_cached(conn, ef, el, caller_cache)
        if s:
            sk = (s["caller"], s["file"], s["line"])
            if sk not in seen_s:
                seen_s.add(sk)
                sites.append(s)
    sites.sort(key=lambda x: (x["file"], x["line"], x["caller"]))
    return sites


def inspect_function_ops_with_conn(
    conn: sqlite3.Connection,
    function_name: str,
    file_path: Optional[str] = None,
    **options: Any,
) -> Dict[str, Any]:
    """Inspect all ops_targets registrations and siblings for function_name."""
    resolved_file = _disambiguate_ops_function(
        conn,
        function_name,
        file_path,
        bool(options.get("allow_ambiguous", False)),
    )
    cur = conn.cursor()
    if not table_exists(cur, "ops_targets"):
        return {
            "mode": "function",
            "query": {"function": function_name, "file": resolved_file},
            "registration_count": 0,
            "registrations": [],
        }

    grouped = _group_function_registrations(cur, function_name, resolved_file)
    ops_acq_gates = _get_ops_acq_gates(conn, options) if grouped else {}
    caller_cache: Dict[Tuple[str, int], str] = {}
    registrations: List[Dict[str, Any]] = []
    for reg_k, expr_sites in sorted(grouped.items()):
        acq = ops_acq_gates.get(
            (function_name, reg_k[3], f"{reg_k[0]}->{reg_k[1]}"), []
        )
        registrations.append({
            "struct": reg_k[0],
            "field": reg_k[1],
            "definition": _clean_def_loc(reg_k[2]),
            "target": function_name,
            "file": reg_k[3],
            "start_line": reg_k[4],
            "end_line": reg_k[5],
            "acquisition_gates": [
                {"cap_str": g["cap_str"], "via": g.get("call")} for g in acq
            ],
            "siblings": _query_instance_siblings(cur, reg_k[0], reg_k[2]),
            "dispatch_sites": _resolve_unique_dispatch_sites(
                conn, expr_sites, caller_cache
            ),
        })
    return {
        "mode": "function",
        "query": {"function": function_name, "file": resolved_file},
        "registration_count": len(registrations),
        "registrations": registrations,
    }


def inspect_function_ops(
    db_path: str,
    function_name: str,
    file_path: Optional[str] = None,
    **options: Any,
) -> Dict[str, Any]:
    """Open db_path and inspect ops_targets registrations for function_name."""
    conn, _ = open_databases(db_path, verbose=options.get("verbose", False))
    try:
        return inspect_function_ops_with_conn(
            conn, function_name, file_path=file_path, **options
        )
    finally:
        conn.close()


def _format_slot_section(
    slot: Dict[str, Any], out: List[str], limit: int, show_all: bool
) -> None:
    """Append human-readable lines for a single (struct, field) slot."""
    out.extend([
        "-" * 72,
        (
            f"SLOT: {slot['struct']}.{slot['field']}"
            f" (Callbacks: {slot['callback_count']} |"
            f" Dispatch Sites: {slot['dispatch_site_count']})"
        ),
        "-" * 72,
    ])
    cbs = slot.get("callbacks", [])
    display_cbs = cbs if show_all else cbs[:limit]
    if display_cbs:
        out.append("  Registered Callbacks:")
        for cb in display_cbs:
            gates = cb.get("acquisition_gates", [])
            g_str = (
                " [ACQ GATED: "
                + ", ".join(
                    f"{g['cap_str']} via {g['via']}"
                    if g.get("via")
                    else g["cap_str"]
                    for g in gates
                )
                + "]"
                if gates
                else ""
            )
            defs = cb.get("definitions", [])
            d_str = f" (defined at {', '.join(defs[:2])})" if defs else ""
            out.append(
                f"    * {cb['target']}"
                f" ({cb['file']}:{cb['start_line']}-{cb['end_line']})"
                f"{d_str}{g_str}"
            )
        if not show_all and len(cbs) > limit:
            out.append(
                f"    ... and {len(cbs) - limit} more callback(s)"
                " (use --all to show all)"
            )

    sites = slot.get("dispatch_sites", [])
    display_sites = sites if show_all else sites[:limit]
    if display_sites:
        out.append("  Indirect Dispatch Callsites:")
        for s in display_sites:
            out.append(f"    * {s['caller']} ({s['file']}:{s['line']})")
        if not show_all and len(sites) > limit:
            out.append(
                f"    ... and {len(sites) - limit} more dispatch site(s)"
            )


def _format_function_reg(reg: Dict[str, Any], out: List[str]) -> None:
    """Append human-readable lines for a single function ops registration."""
    out.extend([
        "-" * 72,
        (
            f"REGISTRATION: {reg['struct']}.{reg['field']} = {reg['target']}"
            f" ({reg['file']}:{reg['start_line']}-{reg['end_line']})"
        ),
        f"  Ops Instance Definition: {reg['definition']}",
    ])
    gates = reg.get("acquisition_gates", [])
    if gates:
        g_list = ", ".join(
            f"{g['cap_str']} via {g['via']}" if g.get("via") else g["cap_str"]
            for g in gates
        )
        out.append(f"  Acquisition Gates:       {g_list}")

    siblings = reg.get("siblings", [])
    if siblings:
        out.append(f"  Sibling Callbacks on Instance ({len(siblings)}):")
        for sib in siblings:
            marker = " <-- [TARGET]" if sib["field"] == reg["field"] else ""
            out.append(
                f"    .{sib['field']:<20} = {sib['target']}"
                f" ({sib['file']}:{sib['start_line']}){marker}"
            )

    sites = reg.get("dispatch_sites", [])
    if sites:
        out.append(f"  Indirect Dispatch Callsites ({len(sites)}):")
        for s in sites:
            out.append(f"    * {s['caller']} ({s['file']}:{s['line']})")


def format_ops_text(
    result: Dict[str, Any], limit: int = 25, show_all: bool = False
) -> str:
    """Format inspect_ops_slot or inspect_function_ops output as text."""
    mode = result.get("mode", "slot")
    q = result.get("query", {})
    if mode == "slot":
        title = (
            f"{q.get('struct')}.{q.get('field')}"
            if q.get("field")
            else str(q.get("struct"))
        )
        out = [
            "=" * 72,
            f"INDIRECT DISPATCH (OPS) INSPECTOR: {title}",
            "=" * 72,
        ]
        slots = result.get("slots", [])
        if not slots:
            out.append("  (No matching ops_targets slots found in database)")
        for slot in slots:
            _format_slot_section(slot, out, limit, show_all)
        out.append("=" * 72)
        return "\n".join(out)

    out = [
        "=" * 72,
        f"FUNCTION OPS REGISTRATIONS: {q.get('function')}",
        "=" * 72,
    ]
    regs = result.get("registrations", [])
    if not regs:
        out.append("  (Function is not registered in any ops_targets table)")
    for reg in regs:
        _format_function_reg(reg, out)
    out.append("=" * 72)
    return "\n".join(out)
