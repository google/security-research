#!/usr/bin/env python3
"""Struct layout, BTF parity, heap allocation, and field access library."""

from collections import defaultdict
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    clean_file_path,
    file_matches_filter,
    get_enclosing_function,
    is_non_runtime_path,
    open_databases,
    table_exists,
)
from tools.lib.metadata import (
    infer_repo_dir,
    load_reachable_fn_sets,
    name_matches_pattern,
    parse_loc_file_line,
)
from tools.lib.privilege import (
    format_gate_summary,
    get_call_site_gates,
    load_condition_gates,
)
from tools.lib.source import read_disk_lines, slice_disk_span

__all__ = [
    "format_struct_text",
    "get_struct_allocations",
    "get_struct_field_accesses",
    "get_struct_fields_layout",
    "get_struct_ops_summary",
    "inspect_struct",
    "inspect_struct_with_conn",
    "locate_struct_definitions",
    "normalize_struct_name",
]


def normalize_struct_name(raw_name: str) -> str:
    """Strip optional leading 'struct ' or 'union ' prefix from a type name."""
    cleaned = raw_name.strip()
    for prefix in ("struct ", "union ", "const struct ", "const union "):
        if cleaned.startswith(prefix):
            return cleaned[len(prefix) :].strip()
    return cleaned


def _query_struct_locations(
    cur: sqlite3.Cursor,
    pattern: str,
    file_filter: Optional[str],
    match_mode: str,
) -> List[Dict[str, Any]]:
    """Query struct_locations table for matching compiled struct definitions."""
    if not table_exists(cur, "struct_locations"):
        return []
    if match_mode == "exact":
        cur.execute(
            "SELECT struct_name, file_path, start_line, end_line, byte_size,"
            " member_count, is_anonymous, is_typedef, has_flex_member"
            " FROM struct_locations WHERE struct_name = ?"
            " ORDER BY file_path, start_line",
            (pattern,),
        )
    else:
        cur.execute(
            "SELECT struct_name, file_path, start_line, end_line, byte_size,"
            " member_count, is_anonymous, is_typedef, has_flex_member"
            " FROM struct_locations ORDER BY struct_name, file_path, start_line"
        )
    results: List[Dict[str, Any]] = []
    for row in cur.fetchall():
        s_name = row[0]
        clean_f = clean_file_path(row[1])
        if is_non_runtime_path(clean_f):
            continue
        if not name_matches_pattern(s_name, pattern, match_mode):
            continue
        if not file_matches_filter(clean_f, file_filter):
            continue
        results.append({
            "struct_name": s_name,
            "file": clean_f,
            "start_line": int(row[2]),
            "end_line": int(row[3]),
            "byte_size": int(row[4]),
            "member_count": int(row[5]),
            "is_anonymous": bool(row[6]),
            "is_typedef": bool(row[7]),
            "has_flex_member": bool(row[8]),
            "source": "struct_locations",
        })
    return results


def _query_btf_fallback_defs(
    btf_cur: sqlite3.Cursor,
    pattern: str,
    match_mode: str,
) -> List[Dict[str, Any]]:
    """Synthesize struct definitions from BTF types table when needed."""
    if not table_exists(btf_cur, "types"):
        return []
    if match_mode == "exact":
        btf_cur.execute(
            "SELECT struct_name, MAX(struct_size), COUNT(DISTINCT name),"
            " MAX(is_flex) FROM types WHERE struct_name = ?"
            " GROUP BY struct_name",
            (pattern,),
        )
    else:
        btf_cur.execute(
            "SELECT struct_name, MAX(struct_size), COUNT(DISTINCT name),"
            " MAX(is_flex) FROM types GROUP BY struct_name"
            " ORDER BY struct_name"
        )
    results: List[Dict[str, Any]] = []
    for row in btf_cur.fetchall():
        s_name = row[0] or ""
        if not s_name or not name_matches_pattern(s_name, pattern, match_mode):
            continue
        results.append({
            "struct_name": s_name,
            "file": "<btf:vmlinux>",
            "start_line": 0,
            "end_line": 0,
            "byte_size": int(row[1] or 0),
            "member_count": int(row[2] or 0),
            "is_anonymous": False,
            "is_typedef": False,
            "has_flex_member": bool(row[3]),
            "source": "btf_types",
        })
    return results


def locate_struct_definitions(
    conn: sqlite3.Connection,
    struct_name: str,
    file_filter: Optional[str] = None,
    match_mode: str = "exact",
    btf_conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """Find compiled struct definitions in struct_locations or BTF types."""
    norm_name = normalize_struct_name(struct_name)
    defs = _query_struct_locations(
        conn.cursor(), norm_name, file_filter, match_mode
    )
    if defs or file_filter:
        return defs
    eff_btf = btf_conn or conn
    return _query_btf_fallback_defs(eff_btf.cursor(), norm_name, match_mode)


_BTF_COMMENT_RE = re.compile(r"/\*.*?\*/")
_BTF_SUBSCRIPT_RE = re.compile(r"\[\d+\]")


def _normalize_btf_field_path(raw_name: str) -> str:
    """Strip /*...*/ comments, (anon) segments, and array subscripts."""
    cleaned = _BTF_COMMENT_RE.sub("", str(raw_name or ""))
    cleaned = _BTF_SUBSCRIPT_RE.sub("", cleaned)
    parts = [p.strip() for p in cleaned.split(".") if p.strip()]
    return ".".join(p for p in parts if p != "(anon)")


def _load_btf_field_offsets(
    btf_cur: sqlite3.Cursor, struct_name: str
) -> Tuple[Optional[int], Dict[str, int]]:
    """Load BTF struct_size and minimum bits_offset per field path."""
    if not table_exists(btf_cur, "types"):
        return None, {}
    btf_cur.execute(
        "SELECT struct_size, name, bits_offset FROM types"
        " WHERE struct_name = ?",
        (struct_name,),
    )
    rows = btf_cur.fetchall()
    if not rows:
        return None, {}
    struct_size = int(rows[0][0]) if rows[0][0] is not None else None
    offsets: Dict[str, int] = {}
    for _, raw_name, bits_off in rows:
        norm_path = _normalize_btf_field_path(raw_name)
        if not norm_path or bits_off is None:
            continue
        b_val = int(bits_off)
        parts = norm_path.split(".")
        for idx in range(1, len(parts) + 1):
            prefix = ".".join(parts[:idx])
            if prefix not in offsets or b_val < offsets[prefix]:
                offsets[prefix] = b_val
    return struct_size, offsets


def _field_matches_filter(
    field_name: str, field_path: str, field_filter: Optional[str]
) -> bool:
    """Check whether a struct field matches an optional field name/path."""
    if not field_filter:
        return True
    flt = field_filter.strip().lstrip(".")
    return (
        field_name == flt
        or field_path == flt
        or field_path.startswith(f"{flt}.")
        or field_path.endswith(f".{flt}")
    )


def _build_field_record(
    row: Tuple[Any, ...], btf_offsets: Dict[str, int]
) -> Dict[str, Any]:
    """Convert a struct_fields SQLite row into a field layout dictionary."""
    b_off = int(row[3])
    bt_off = int(row[4]) if row[4] is not None else None
    codeql_bits = b_off * 8 + (bt_off if bt_off is not None else 0)
    btf_bits = btf_offsets.get(row[1], btf_offsets.get(row[0]))
    return {
        "field_name": row[0],
        "field_path": row[1],
        "field_type": row[2],
        "byte_offset": b_off,
        "bit_offset": bt_off,
        "bit_size": int(row[5]) if row[5] is not None else None,
        "is_funcptr": bool(row[6]),
        "is_flex": bool(row[7]),
        "array_len": int(row[8]) if row[8] is not None else None,
        "btf_bits_offset": btf_bits,
        "btf_offset_match": (
            (btf_bits == codeql_bits) if btf_bits is not None else None
        ),
    }


def _query_btf_only_fields(
    btf_cur: sqlite3.Cursor,
    struct_name: str,
    field_filter: Optional[str],
) -> List[Dict[str, Any]]:
    """Fallback field layout builder from BTF when struct_fields is absent."""
    if not table_exists(btf_cur, "types"):
        return []
    btf_cur.execute(
        "SELECT name, type, kind, bits_offset, nr_bits, is_flex"
        " FROM types WHERE struct_name = ? ORDER BY bits_offset, name",
        (struct_name,),
    )
    fields: List[Dict[str, Any]] = []
    seen_paths: Set[str] = set()
    for row in btf_cur.fetchall():
        f_path = _normalize_btf_field_path(row[0])
        if not f_path or f_path in seen_paths:
            continue
        f_name = f_path.rsplit(".", maxsplit=1)[-1]
        if not _field_matches_filter(f_name, f_path, field_filter):
            continue
        seen_paths.add(f_path)
        b_bits = int(row[3] or 0)
        byte_off, rem_bits = divmod(b_bits, 8)
        f_type = str(row[1] or "")
        fields.append({
            "field_name": f_name,
            "field_path": f_path,
            "field_type": f"{row[2]}: {f_type}" if row[2] else f_type,
            "byte_offset": byte_off,
            "bit_offset": rem_bits if rem_bits else None,
            "bit_size": int(row[4]) if rem_bits and row[4] else None,
            "is_funcptr": "func_proto" in f_type,
            "is_flex": bool(row[5]),
            "array_len": None,
            "btf_bits_offset": b_bits,
            "btf_offset_match": True,
        })
    return fields


def get_struct_fields_layout(
    conn: sqlite3.Connection,
    struct_def: Dict[str, Any],
    field_filter: Optional[str] = None,
    btf_conn: Optional[sqlite3.Connection] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Fetch ordered field layout and BTF offset comparison for struct_def."""
    s_name = struct_def["struct_name"]
    eff_btf = btf_conn or conn
    btf_size, btf_offsets = _load_btf_field_offsets(eff_btf.cursor(), s_name)

    cur = conn.cursor()
    fields: List[Dict[str, Any]] = []
    if (
        table_exists(cur, "struct_fields")
        and struct_def["source"] == "struct_locations"
    ):
        clean_f = struct_def["file"]
        cur.execute(
            "SELECT field_name, field_path, field_type, byte_offset,"
            " bit_offset, bit_size, is_funcptr, is_flex, array_len"
            " FROM struct_fields"
            " WHERE struct_name = ? AND (file_path = ? OR file_path = ?)"
            " AND start_line = ?"
            " ORDER BY byte_offset ASC, COALESCE(bit_offset, -1) ASC,"
            " field_path ASC",
            (s_name, clean_f, f"linux/{clean_f}", struct_def["start_line"]),
        )
        fields = [
            _build_field_record(row, btf_offsets)
            for row in cur.fetchall()
            if _field_matches_filter(row[0], row[1], field_filter)
        ]
    else:
        fields = _query_btf_only_fields(eff_btf.cursor(), s_name, field_filter)

    checked = [f for f in fields if f["btf_offset_match"] is not None]
    btf_summary = {
        "btf_present": btf_size is not None,
        "btf_struct_size": btf_size,
        "size_match": (
            btf_size == struct_def["byte_size"]
            if btf_size is not None
            else None
        ),
        "checked_fields": len(checked),
        "matched_fields": sum(1 for f in checked if f["btf_offset_match"]),
    }
    return fields, btf_summary


def _collect_kmalloc_sites(
    cur: sqlite3.Cursor, struct_name: str
) -> List[Dict[str, Any]]:
    """Query kmalloc_calls table for struct_name allocation sites."""
    if not table_exists(cur, "kmalloc_calls"):
        return []
    cur.execute(
        "SELECT call_site, call_expr, struct_size, flags, alloc_size,"
        " sizeof_expr, is_flexible FROM kmalloc_calls"
        " WHERE struct_type = ? ORDER BY call_site",
        (struct_name,),
    )
    sites: List[Dict[str, Any]] = []
    for row in cur.fetchall():
        c_file, c_line = parse_loc_file_line(row[0] or "")
        if is_non_runtime_path(c_file):
            continue
        sites.append({
            "file": c_file,
            "line": c_line,
            "allocator": str(row[1] or ""),
            "object_size": int(row[2]) if row[2] is not None else None,
            "alloc_size": str(row[4]) if row[4] is not None else "variable",
            "size_min": int(row[4]) if row[4] is not None else None,
            "size_max": int(row[4]) if row[4] is not None else None,
            "flags": str(row[3] or ""),
            "sizeof_expr": str(row[5] or ""),
            "is_flexible": str(row[6] or "").lower() in ("true", "1"),
            "source_table": "kmalloc_calls",
        })
    return sites


def _collect_allocs_sites(
    cur: sqlite3.Cursor, struct_name: str
) -> List[Dict[str, Any]]:
    """Query allocs table for struct_name allocation sites."""
    if not table_exists(cur, "allocs"):
        return []
    cur.execute(
        "SELECT call_value, objectSize_value, allocSizeMin_value,"
        " allocSizeMax_value, allocSize_value, flags_value, call_uri,"
        " call_startLine, is_flexible FROM allocs"
        " WHERE type_value = ? ORDER BY call_uri, call_startLine",
        (struct_name,),
    )
    sites: List[Dict[str, Any]] = []
    for row in cur.fetchall():
        c_file = clean_file_path(row[6] or "")
        c_line = int(row[7] or 0)
        if is_non_runtime_path(c_file):
            continue
        obj_sz = int(row[1]) if str(row[1] or "").isdigit() else None
        sz_min = int(row[2]) if str(row[2] or "").isdigit() else None
        sz_max = int(row[3]) if str(row[3] or "").isdigit() else None
        sites.append({
            "file": c_file,
            "line": c_line,
            "allocator": str(row[0] or ""),
            "object_size": obj_sz,
            "alloc_size": str(row[4] or ""),
            "size_min": sz_min,
            "size_max": sz_max,
            "flags": str(row[5] or ""),
            "sizeof_expr": "",
            "is_flexible": str(row[8] or "").lower() in ("true", "1"),
            "source_table": "allocs",
        })
    return sites


def get_struct_allocations(
    conn: sqlite3.Connection,
    struct_name: str,
    allocs_conn: Optional[sqlite3.Connection] = None,
) -> List[Dict[str, Any]]:
    """Return deduplicated heap allocation sites for struct_name."""
    norm_name = normalize_struct_name(struct_name)
    acur = (allocs_conn or conn).cursor()

    merged: Dict[Tuple[str, int, str], Dict[str, Any]] = {
        (s["file"], s["line"], s["allocator"]): s
        for s in _collect_kmalloc_sites(acur, norm_name)
    }
    for site in _collect_allocs_sites(acur, norm_name):
        key = (site["file"], site["line"], site["allocator"])
        prev = merged.get(key)
        if prev is None:
            merged[key] = site
        elif prev["size_min"] is None and site["size_min"] is not None:
            prev.update({
                "size_min": site["size_min"],
                "size_max": site["size_max"],
                "alloc_size": site["alloc_size"],
            })

    results = [merged[k] for k in sorted(merged.keys())]
    for item in results:
        enc = get_enclosing_function(conn, item["file"], item["line"])
        item["function"] = enc[0] if enc else "unknown"

    sys_fns, ent_fns = load_reachable_fn_sets(
        conn, {item["function"] for item in results}
    )
    for item in results:
        item["is_syscall_reachable"] = item["function"] in sys_fns
        item["is_entry_reachable"] = item["function"] in ent_fns
    return results


def _normalize_access_tuple(
    row: Tuple[Any, ...],
) -> Optional[Tuple[str, str, str, str, int]]:
    """Normalize a field_access row without running SQL queries."""
    acc_type = str(row[0] or "")
    field_name = str(row[1] or "")
    loc_str = str(row[2] or "")
    fn_name = str(row[3] or "")
    raw_file = str(row[4] or "")
    line_no = int(row[5] or 0)

    clean_f = clean_file_path(raw_file) if raw_file else ""
    if not clean_f or line_no <= 0:
        clean_f, line_no = parse_loc_file_line(loc_str)
    if is_non_runtime_path(clean_f):
        return None
    return acc_type, field_name, fn_name, clean_f, line_no


def _query_raw_field_accesses(
    cur: sqlite3.Cursor,
    struct_name: str,
    field_filter: Optional[str],
    access_type: Optional[str],
) -> List[Tuple[Any, ...]]:
    """Execute SQL query against field_access table with optional filters."""
    if not table_exists(cur, "field_access"):
        return []
    clauses = ["parent = ?"]
    params: List[Any] = [struct_name]
    if field_filter:
        leaf_field = field_filter.strip().split(".")[-1]
        clauses.append("field = ?")
        params.append(leaf_field)
    if access_type and access_type != "all":
        clauses.append("type = ?")
        params.append(access_type)
    sql = (
        "SELECT type, field, location, function_name, file_path, line"
        f" FROM field_access WHERE {' AND '.join(clauses)}"
        " ORDER BY field, type, file_path, line"
    )
    cur.execute(sql, tuple(params))
    return cur.fetchall()


def _resolve_sliced_access_fns(
    conn: sqlite3.Connection,
    sliced: Dict[str, List[Tuple[str, str, str, str, int]]],
) -> Tuple[Dict[str, List[Tuple[str, str, str, str, int]]], Set[str]]:
    """Resolve enclosing function names for sliced field access tuples."""
    resolved_by_type: Dict[str, List[Tuple[str, str, str, str, int]]] = {}
    cand_fns: Set[str] = set()
    for acc_t, items in sliced.items():
        res_list: List[Tuple[str, str, str, str, int]] = []
        for _, fld, fn_name, clean_f, line_no in items:
            if not fn_name and clean_f and line_no > 0:
                enc = get_enclosing_function(conn, clean_f, line_no)
                fn_name = enc[0] if enc else ""
            eff_fn = fn_name or "unknown"
            cand_fns.add(eff_fn)
            res_list.append((acc_t, fld, eff_fn, clean_f, line_no))
        resolved_by_type[acc_t] = res_list
    return resolved_by_type, cand_fns


def _annotate_sliced_accesses(
    conn: sqlite3.Connection,
    sliced: Dict[str, List[Tuple[str, str, str, str, int]]],
    call_gates: Any,
    func_gates: Any,
) -> Dict[str, List[Dict[str, Any]]]:
    """Resolve enclosing functions, reachability, and gates for accesses."""
    resolved_by_type, cand_fns = _resolve_sliced_access_fns(conn, sliced)
    sys_fns, ent_fns = load_reachable_fn_sets(conn, cand_fns)
    has_gates = call_gates is not None and func_gates is not None
    return {
        acc_t: [
            {
                "access_type": acc_t,
                "field": fld,
                "function": eff_fn,
                "file": clean_f,
                "line": line_no,
                "is_syscall_reachable": eff_fn in sys_fns,
                "is_entry_reachable": eff_fn in ent_fns,
                "gates": (
                    get_call_site_gates(
                        call_gates, func_gates, clean_f, line_no, eff_fn
                    )
                    if has_gates
                    else []
                ),
            }
            for acc_t, fld, eff_fn, clean_f, line_no in res_list
        ]
        for acc_t, res_list in resolved_by_type.items()
    }


def get_struct_field_accesses(
    conn: sqlite3.Connection,
    struct_name: str,
    **options: Any,
) -> Dict[str, Any]:
    """Query and annotate read, write, and exec field accesses on a struct."""
    raw_rows = _query_raw_field_accesses(
        conn.cursor(),
        normalize_struct_name(struct_name),
        options.get("field_filter"),
        options.get("access_type"),
    )
    grouped: Dict[str, List[Tuple[str, str, str, str, int]]] = {
        "write": [],
        "read": [],
        "exec": [],
    }
    seen: Set[Tuple[str, str, str, str, int]] = set()
    for row in raw_rows:
        norm = _normalize_access_tuple(row)
        if norm and norm[0] in grouped and norm not in seen:
            seen.add(norm)
            grouped[norm[0]].append(norm)

    counts = {k: len(v) for k, v in grouped.items()}
    counts["total"] = sum(counts.values())
    limit = int(options.get("limit", 50))
    show_all = bool(options.get("show_all", False))
    sliced = {
        k: (v if show_all else v[: max(0, limit)]) for k, v in grouped.items()
    }

    call_gates = options.get("call_gates")
    func_gates = options.get("func_gates")
    if (call_gates is None or func_gates is None) and any(sliced.values()):
        call_gates, func_gates, _ = load_condition_gates(conn)

    out_by_type = _annotate_sliced_accesses(
        conn, sliced, call_gates, func_gates
    )
    return {"counts": counts, **out_by_type}


def get_struct_ops_summary(
    conn: sqlite3.Connection,
    struct_name: str,
) -> List[Dict[str, Any]]:
    """Summarize ops_targets function-pointer slots registered on struct."""
    cur = conn.cursor()
    if not table_exists(cur, "ops_targets"):
        return []
    norm_name = normalize_struct_name(struct_name)
    cur.execute(
        "SELECT field, target, target_file, target_start, definition"
        " FROM ops_targets WHERE parent = ? ORDER BY field, target",
        (norm_name,),
    )
    by_field: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    seen: Set[Tuple[str, str, str]] = set()
    for fld, tgt, tgt_file, tgt_start, def_loc in cur.fetchall():
        if not tgt:
            continue
        clean_tf = clean_file_path(tgt_file or "")
        if is_non_runtime_path(clean_tf):
            continue
        key = (str(fld), str(tgt), clean_tf)
        if key not in seen:
            seen.add(key)
            by_field[str(fld)].append({
                "target": str(tgt),
                "file": clean_tf,
                "start_line": int(tgt_start or 0),
                "definition": clean_file_path(def_loc or ""),
            })
    return [
        {
            "field": fld,
            "callback_count": len(cbs),
            "callbacks": cbs[:10],
        }
        for fld, cbs in sorted(by_field.items())
    ]


def _load_struct_source_lines(
    struct_def: Dict[str, Any], repo_dir: Optional[str]
) -> List[Dict[str, Any]]:
    """Read numbered C source lines for struct_def when repo_dir is present."""
    if (
        not repo_dir
        or struct_def["source"] != "struct_locations"
        or struct_def["start_line"] <= 0
    ):
        return []
    disk_lines = read_disk_lines(repo_dir, struct_def["file"])
    if not disk_lines:
        return []
    _, _, numbered = slice_disk_span(
        disk_lines,
        struct_def["start_line"],
        struct_def["end_line"],
        context=0,
    )
    return [{"line": ln, "code": text} for ln, text in numbered]


def _enrich_struct_definitions(
    conn: sqlite3.Connection,
    defs: List[Dict[str, Any]],
    field_filter: Optional[str],
    options: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Attach field layouts, BTF parity summaries, and source lines to defs."""
    if str(options.get("section", "all")) not in ("all", "layout"):
        return [dict(d) for d in defs]
    btf_conn = options.get("btf_conn")
    repo_dir = options.get("repo_dir")
    enriched: List[Dict[str, Any]] = []
    for d in defs:
        d_copy = dict(d)
        fields, btf_info = get_struct_fields_layout(
            conn, d, field_filter=field_filter, btf_conn=btf_conn
        )
        d_copy["fields"] = fields
        d_copy["btf_validation"] = btf_info
        d_copy["btf_summary"] = btf_info
        if options.get("include_source"):
            d_copy["source_lines"] = _load_struct_source_lines(d, repo_dir)
        enriched.append(d_copy)
    return enriched


def inspect_struct_with_conn(
    conn: sqlite3.Connection,
    struct_name: str,
    **options: Any,
) -> Dict[str, Any]:
    """Inspect struct layout, BTF parity, allocations, and field accesses."""
    norm_name = normalize_struct_name(struct_name)
    file_filter = options.get("file_filter") or options.get("file_path")
    field_filter = options.get("field_filter") or options.get("field")
    match_mode = str(options.get("match_mode", "exact"))
    if not field_filter and "." in norm_name and match_mode != "regex":
        norm_name, field_filter = norm_name.split(".", 1)
    section = str(options.get("section", "all"))

    defs = locate_struct_definitions(
        conn,
        norm_name,
        file_filter=file_filter,
        match_mode=match_mode,
        btf_conn=options.get("btf_conn"),
    )
    enriched_defs = _enrich_struct_definitions(
        conn, defs, field_filter, options
    )
    primary_name = defs[0]["struct_name"] if defs else norm_name
    allocations = (
        get_struct_allocations(
            conn, primary_name, allocs_conn=options.get("allocs_conn")
        )
        if section in ("all", "allocs")
        else []
    )
    field_accesses = (
        get_struct_field_accesses(
            conn, primary_name, **{**options, "field_filter": field_filter}
        )
        if section in ("all", "accesses")
        else {
            "counts": {"write": 0, "read": 0, "exec": 0, "total": 0},
            "write": [],
            "read": [],
            "exec": [],
        }
    )
    ops_summary = (
        get_struct_ops_summary(conn, primary_name)
        if section in ("all", "ops")
        else []
    )
    return {
        "query": {
            "struct": norm_name,
            "file": file_filter,
            "field": field_filter,
            "match_mode": match_mode,
            "section": section,
        },
        "field_filter": field_filter,
        "count": len(enriched_defs),
        "is_ambiguous": len(enriched_defs) > 1 and not file_filter,
        "definitions": enriched_defs,
        "allocations": allocations,
        "field_accesses": field_accesses,
        "ops_slots": ops_summary,
        "ops_summary": ops_summary,
    }


def inspect_struct(
    db_path: str,
    struct_name: str,
    **options: Any,
) -> Dict[str, Any]:
    """Open SQLite database(s) and run inspect_struct_with_conn."""
    conn, _ = open_databases(
        db_path, verbose=bool(options.get("verbose", False))
    )
    btf_db = options.get("btf_db")
    allocs_db = options.get("allocs_db")
    btf_conn = sqlite3.connect(btf_db) if btf_db else None
    allocs_conn = sqlite3.connect(allocs_db) if allocs_db else None
    if not options.get("repo_dir"):
        options["repo_dir"] = infer_repo_dir(db_path)
    try:
        return inspect_struct_with_conn(
            conn,
            struct_name,
            btf_conn=btf_conn,
            allocs_conn=allocs_conn,
            **options,
        )
    finally:
        conn.close()
        if btf_conn:
            btf_conn.close()
        if allocs_conn:
            allocs_conn.close()


def _format_field_line(f: Dict[str, Any]) -> str:
    """Format a single struct field layout line for text output."""
    off_str = f"+0x{f['byte_offset']:04x} ({f['byte_offset']:4d})"
    if f.get("bit_offset") is not None and f.get("bit_size") is not None:
        end_b = f["bit_offset"] + f["bit_size"] - 1
        off_str += f" [bits {f['bit_offset']}..{end_b}]"
    flags: List[str] = []
    if f.get("is_funcptr"):
        flags.append("FUNCPTR")
    if f.get("is_flex"):
        flags.append("FLEX_ARRAY")
    if f.get("array_len") is not None and f["array_len"] > 0:
        flags.append(f"len={f['array_len']}")
    if f.get("btf_offset_match") is False:
        flags.append(f"BTF_MISMATCH(btf_bits={f.get('btf_bits_offset')})")
    flag_str = f" [{' | '.join(flags)}]" if flags else ""
    return (
        f"    {off_str}  {f['field_path']:<28} : {f['field_type']}{flag_str}"
    )


def _format_definition_section(
    d: Dict[str, Any], out: List[str], idx: int, total: int
) -> None:
    """Append formatted struct definition and field layout to out."""
    hdr = f"[{idx}/{total}] struct {d['struct_name']}"
    if d.get("is_typedef"):
        hdr = f"[{idx}/{total}] typedef struct {d['struct_name']}"
    out.append(
        f"\n{hdr} ({d['file']}:{d['start_line']}-{d['end_line']})"
        f" | size={d['byte_size']}B | members={d['member_count']}"
        f" | flex={'yes' if d['has_flex_member'] else 'no'}"
    )
    btf = d.get("btf_validation")
    if btf and btf.get("btf_present"):
        sz_ok = "MATCH" if btf.get("size_match") else "DIFF"
        out.append(
            f"  BTF Parity: struct_size={btf['btf_struct_size']}B ({sz_ok}),"
            f" fields_matched={btf['matched_fields']}/{btf['checked_fields']}"
        )
    fields = d.get("fields")
    if fields is not None:
        out.append(f"  Layout Fields ({len(fields)}):")
        for f in fields:
            out.append(_format_field_line(f))
    src_lines = d.get("source_lines") or []
    if src_lines:
        out.append("  Source Definition:")
        for srec in src_lines:
            out.append(f"    {srec['line']:6d} | {srec['code']}")


def _format_allocations_section(
    allocs: List[Dict[str, Any]], out: List[str]
) -> None:
    """Append heap allocation sites section to out."""
    out.append(f"\nHEAP ALLOCATIONS ({len(allocs)}):")
    if not allocs:
        out.append("  (No direct struct heap allocations recorded)")
        return
    for a in allocs:
        reach = []
        if a.get("is_syscall_reachable"):
            reach.append("syscall")
        if a.get("is_entry_reachable"):
            reach.append("entry")
        r_tag = f" [reachable: {','.join(reach)}]" if reach else ""
        flx = " [FLEXIBLE]" if a.get("is_flexible") else ""
        out.append(
            f"  * {a['function']} ({a['file']}:{a['line']}) -> {a['allocator']}"
            f" | size={a['alloc_size']} (obj={a['object_size']}B)"
            f" | flags={a['flags']}{flx}{r_tag}"
        )


def _format_access_section(
    fa: Dict[str, Any], out: List[str], limit: int, show_all: bool
) -> None:
    """Append field_access write/read/exec summary and sites to out."""
    counts = fa.get("counts", {})
    out.append(
        f"\nFIELD ACCESSES (total={counts.get('total', 0)}:"
        f" write={counts.get('write', 0)}, read={counts.get('read', 0)},"
        f" exec={counts.get('exec', 0)}):"
    )
    for kind in ("exec", "write", "read"):
        items = fa.get(kind, [])
        total_k = counts.get(kind, 0)
        if not items:
            continue
        out.append(f"  [{kind.upper()}] ({len(items)}/{total_k} shown):")
        for item in items:
            reach = [
                k
                for k, v in (
                    ("syscall", item.get("is_syscall_reachable")),
                    ("entry", item.get("is_entry_reachable")),
                )
                if v
            ]
            r_tag = f" [reachable: {','.join(reach)}]" if reach else ""
            g_str = format_gate_summary(item.get("gates", []))
            g_tag = f" [Gated: {g_str}]" if g_str else ""
            out.append(
                f"    .{item['field']:<20} in {item['function']}"
                f" ({item['file']}:{item['line']}){r_tag}{g_tag}"
            )
        if not show_all and total_k > limit:
            out.append(
                f"    ... ({total_k - limit} more {kind} accesses;"
                " use --show-all)"
            )


def format_struct_text(
    result: Dict[str, Any], limit: int = 50, show_all: bool = False
) -> str:
    """Format inspect_struct result dictionary as a human-readable report."""
    q = result.get("query", {})
    sec = q.get("section", "all")
    title = (
        f"struct {q.get('struct')}.{q.get('field')}"
        if q.get("field")
        else f"struct {q.get('struct')}"
    )
    out = ["=" * 72, f"STRUCT & OBJECT LIFECYCLE INSPECTOR: {title}", "=" * 72]
    defs = result.get("definitions", [])
    if not defs:
        out.append("  (No matching struct definitions found in database)")
    if result.get("is_ambiguous"):
        out.append(
            f"  [Note: {len(defs)} compiled definitions found; pass --file"
            " to disambiguate]"
        )
    for idx, d in enumerate(defs, start=1):
        _format_definition_section(d, out, idx, len(defs))

    if sec in ("all", "allocs"):
        _format_allocations_section(result.get("allocations", []), out)

    if sec in ("all", "accesses"):
        _format_access_section(
            result.get("field_accesses", {}), out, limit, show_all
        )

    ops_slots = result.get("ops_slots", [])
    if sec in ("all", "ops") and ops_slots:
        out.append(f"\nOPS FUNCTION-POINTER SLOTS ({len(ops_slots)}):")
        for slot in ops_slots:
            sample = ", ".join(c["target"] for c in slot["callbacks"][:5])
            more = "..." if slot["callback_count"] > 5 else ""
            out.append(
                f"  .{slot['field']:<22} : {slot['callback_count']}"
                f" callback(s) ({sample}{more})"
            )

    out.append("=" * 72)
    return "\n".join(out)
