#!/usr/bin/env python3
"""Database, function-resolution, and reverse call-graph traversal utilities."""

from collections import deque
import os
import re
import sqlite3
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

LOCATION_RE = re.compile(r"^(.+):(\d+):(\d+):(\d+):(\d+)$")

CallerRow = Tuple[str, str, int, int, str, str]
SpanFuncList = List[Tuple[str, int, int]]

_INDEX_SPECS = [
    (
        "idx_fl_file_lines",
        "function_locations(file_path, start_line, end_line)",
    ),
    ("idx_fl_name", "function_locations(function_name)"),
    ("idx_sn_fn", "syscall_node(function)"),
    ("idx_sn_sys", "syscall_node(syscall)"),
    ("idx_loc_msg", "locations(message)"),
    ("idx_loc_uri_line", "locations(uri, startLine)"),
    ("idx_edges_target", "edges(target_location_id)"),
    ("idx_edges_source", "edges(source_location_id)"),
    ("idx_ops_target", "ops_targets(target)"),
    ("idx_ops_exprcall", "ops_targets(exprcall_file, exprcall_line)"),
    ("idx_configs_path", "configs(path, ifdef, endif)"),
    ("idx_kconfig_sym", "kconfig_symbols(config)"),
    ("idx_async_callee", "async_edges(callee)"),
    ("idx_async_caller", "async_edges(caller)"),
    ("idx_en_fn", "entry_node(function)"),
    ("idx_en_entry", "entry_node(entry)"),
    ("idx_en_kind", "entry_node(entry_kind)"),
]
INDEXES = [
    (name, f"CREATE INDEX IF NOT EXISTS {name} ON {spec}")
    for name, spec in _INDEX_SPECS
]

_CALL_TYPE_PRIORITY = {"direct": 0, "indirect": 1, "async": 2}


def clean_file_path(path: str) -> str:
    """Normalize file path by stripping leading slashes and linux/ prefixes."""
    return path.lstrip("/").replace("linux/", "")


def table_exists(cur: sqlite3.Cursor, table_name: str) -> bool:
    """Check whether a table exists in the SQLite database."""
    cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return cur.fetchone() is not None


def ensure_indexes(conn: sqlite3.Connection, verbose: bool = False) -> None:
    """Create essential SQLite indexes for fast callgraph traversal."""
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
    existing = {r[0] for r in cur.fetchall()}
    missing = [(name, sql) for name, sql in INDEXES if name not in existing]
    if not missing:
        return

    if verbose:
        print(
            f"Creating {len(missing)} missing SQLite indexes for fast traversal"
            " (one-time setup)...",
            file=sys.stderr,
        )
    for name, sql in missing:
        try:
            cur.execute(sql)
            conn.commit()
            if verbose:
                print(f"  Created index {name}", file=sys.stderr)
        except sqlite3.Error as e:
            if verbose:
                print(
                    f"  Warning: could not create index {name}: {e}",
                    file=sys.stderr,
                )


def open_databases(
    db_file: str,
    syzkaller_db: Optional[str] = None,
    verbose: bool = False,
) -> Tuple[sqlite3.Connection, Optional[sqlite3.Connection]]:
    """Open main CodeQL database (with indexes) and optional Syzkaller DB."""
    if not os.path.isfile(db_file):
        raise FileNotFoundError(f"Database file not found: {db_file}")
    conn = sqlite3.connect(db_file)
    ensure_indexes(conn, verbose=verbose)
    syzk_conn = (
        sqlite3.connect(syzkaller_db)
        if syzkaller_db and os.path.isfile(syzkaller_db)
        else None
    )
    return conn, syzk_conn


def get_enclosing_function(
    conn: sqlite3.Connection, file_path: str, line_number: int
) -> Optional[Tuple[str, str, int, int]]:
    """Find the enclosing function for a given file and line number."""
    clean_path = clean_file_path(file_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT function_name, file_path, start_line, end_line"
        " FROM function_locations"
        " WHERE (file_path = ? OR file_path LIKE ?)"
        " AND ? BETWEEN start_line AND end_line"
        " ORDER BY (end_line - start_line) ASC",
        (clean_path, f"%/{clean_path}", line_number),
    )
    rows = cur.fetchall()
    return rows[0] if rows else None


def get_function_by_name(
    conn: sqlite3.Connection, function_name: str
) -> Optional[Tuple[str, str, int, int]]:
    """Look up canonical file and line span for a function name."""
    cur = conn.cursor()
    cur.execute(
        "SELECT function_name, file_path, start_line, end_line"
        " FROM function_locations WHERE function_name = ? LIMIT 1",
        (function_name,),
    )
    row = cur.fetchone()
    return (row[0], clean_file_path(row[1]), row[2], row[3]) if row else None


def load_functions_for_files(
    conn: sqlite3.Connection,
    file_paths: Iterable[str],
    batch_size: int = 500,
) -> Dict[str, SpanFuncList]:
    """Batch-load (function_name, start_line, end_line) grouped by file."""
    file_list = list(file_paths)
    file_funcs: Dict[str, SpanFuncList] = {}
    cur = conn.cursor()
    for i in range(0, len(file_list), batch_size):
        batch = file_list[i : i + batch_size]
        placeholders = ",".join("?" for _ in batch)
        cur.execute(
            "SELECT file_path, function_name, start_line, end_line"
            f" FROM function_locations WHERE file_path IN ({placeholders})",
            batch,
        )
        for f, fn, s, e in cur.fetchall():
            file_funcs.setdefault(clean_file_path(f), []).append((fn, s, e))
    return file_funcs


def _record_caller_site(
    results: List[CallerRow],
    seen_sites: Dict[Tuple[str, int], int],
    site_key: Tuple[str, int],
    entry: CallerRow,
) -> None:
    """Append caller entry or upgrade an existing site with a richer label."""
    if site_key in seen_sites:
        idx = seen_sites[site_key]
        if _CALL_TYPE_PRIORITY[entry[4]] > _CALL_TYPE_PRIORITY[results[idx][4]]:
            results[idx] = entry
        return
    seen_sites[site_key] = len(results)
    results.append(entry)


def _resolve_edge_caller(
    cur: sqlite3.Cursor,
    function_name: str,
    edge_row: Tuple[str, str, int, str, int],
) -> Optional[Tuple[str, str, int, int]]:
    """Resolve an edges row to (caller_fn, caller_file, caller_line, site)."""
    src_msg, src_file, src_line, dst_msg, dst_line = edge_row
    if dst_msg == f"call to {function_name}":
        if src_msg.startswith("call to "):
            return None
        return src_msg, src_file, src_line, dst_line
    if src_msg == f"call to {function_name}":
        return None
    cur.execute(
        "SELECT function_name, file_path, start_line FROM function_locations"
        " WHERE file_path = ? AND ? BETWEEN start_line AND end_line LIMIT 1",
        (src_file, src_line),
    )
    fn_row = cur.fetchone()
    if fn_row and (src_msg.startswith("call to ") or src_msg != fn_row[0]):
        return fn_row[0], fn_row[1], fn_row[2], src_line
    if not src_msg.startswith("call to "):
        return src_msg, src_file, src_line, dst_line
    return None


def _add_direct_callers(
    cur: sqlite3.Cursor,
    function_name: str,
    results: List[CallerRow],
    seen_sites: Dict[Tuple[str, int], int],
) -> None:
    """Populate direct and points-to callers from edges and locations."""
    cur.execute(
        "SELECT DISTINCT s.message, s.uri, s.startLine, t.message, t.startLine"
        " FROM edges e JOIN locations s ON e.source_location_id = s.id"
        " JOIN locations t ON e.target_location_id = t.id"
        " WHERE t.message = ? OR t.message = ?",
        (function_name, f"call to {function_name}"),
    )
    for edge_row in cur.fetchall():
        resolved = _resolve_edge_caller(cur, function_name, edge_row)
        if resolved:
            c_fn, c_file, c_line, cs_line = resolved
            _record_caller_site(
                results,
                seen_sites,
                (c_fn, cs_line),
                (c_fn, c_file, c_line, cs_line, "direct", ""),
            )


def _add_indirect_callers(
    cur: sqlite3.Cursor,
    function_name: str,
    results: List[CallerRow],
    seen_sites: Dict[Tuple[str, int], int],
) -> None:
    """Populate indirect function-pointer callers from ops_targets."""
    cur.execute(
        "SELECT DISTINCT parent, field, exprcall_file, exprcall_line"
        " FROM ops_targets WHERE target = ?",
        (function_name,),
    )
    for parent, field, expr_file, expr_line in cur.fetchall():
        cur.execute(
            "SELECT function_name, file_path, start_line"
            " FROM function_locations"
            " WHERE file_path = ? AND ? BETWEEN start_line AND end_line"
            " LIMIT 1",
            (expr_file, expr_line),
        )
        fn_row = cur.fetchone()
        if fn_row:
            c_fn, c_file, c_line = fn_row
            detail = f"{parent}->{field}"
            _record_caller_site(
                results,
                seen_sites,
                (c_fn, expr_line),
                (c_fn, c_file, c_line, expr_line, "indirect", detail),
            )


def _add_async_callers(
    cur: sqlite3.Cursor,
    function_name: str,
    results: List[CallerRow],
    seen_sites: Dict[Tuple[str, int], int],
) -> None:
    """Populate asynchronous handler callers from async_edges."""
    try:
        cur.execute(
            "SELECT DISTINCT caller, mechanism, form, file, line, context"
            " FROM async_edges WHERE callee = ?",
            (function_name,),
        )
        async_rows = cur.fetchall()
    except sqlite3.Error:
        return

    for caller_fn, mechanism, form, reg_file, reg_line, context in async_rows:
        if caller_fn.startswith("<file-scope:"):
            continue
        cur.execute(
            "SELECT file_path, start_line FROM function_locations"
            " WHERE function_name = ?"
            " ORDER BY CASE WHEN file_path = ? THEN 0 ELSE 1 END LIMIT 1",
            (caller_fn, reg_file),
        )
        fn_row = cur.fetchone()
        c_file = fn_row[0] if fn_row else reg_file
        c_line = fn_row[1] if fn_row else reg_line
        detail = f"{mechanism}/{form} ({context})"
        _record_caller_site(
            results,
            seen_sites,
            (caller_fn, reg_line),
            (caller_fn, c_file, c_line, reg_line, "async", detail),
        )


def get_callers(
    conn: sqlite3.Connection, function_name: str
) -> List[CallerRow]:
    """Find callers invoking function_name directly, indirectly, or async."""
    cur = conn.cursor()
    results: List[CallerRow] = []
    seen_sites: Dict[Tuple[str, int], int] = {}
    _add_direct_callers(cur, function_name, results, seen_sites)
    _add_indirect_callers(cur, function_name, results, seen_sites)
    _add_async_callers(cur, function_name, results, seen_sites)
    return results


def iter_pruned_callers(
    conn: sqlite3.Connection,
    curr_fn: str,
    reachable_set: Optional[Set[str]],
    allow_prune: bool = True,
    exclude: Optional[Set[str]] = None,
) -> List[CallerRow]:
    """Return callers of curr_fn, pruning unreachable direct branches."""
    callers = get_callers(conn, curr_fn)
    can_prune = (
        allow_prune
        and reachable_set is not None
        and curr_fn in reachable_set
        and any(
            c[0] in reachable_set and (not exclude or c[0] not in exclude)
            for c in callers
        )
    )
    if not can_prune or reachable_set is None:
        return callers
    return [
        c
        for c in callers
        if c[0] in reachable_set or c[4] in ("indirect", "async")
    ]


def is_syscall_root(fn_name: str, target_syscall: Optional[str] = None) -> bool:
    """Check if fn_name corresponds to target_syscall or a syscall root."""
    if target_syscall:
        if fn_name == target_syscall:
            return True
        clean_target = target_syscall.replace("__do_sys_", "").replace(
            "__se_sys_", ""
        )
        clean_fn = (
            fn_name.replace("__do_sys_", "")
            .replace("__se_sys_", "")
            .replace("__x64_sys_", "")
            .replace("__ia32_sys_", "")
        )
        return clean_fn == clean_target
    return fn_name.startswith(("__do_sys_", "__se_sys_", "__x64_sys_"))


def load_entry_roots(conn: sqlite3.Connection) -> Dict[str, str]:
    """Load non-syscall entry roots (entry -> entry_kind) from entry_node."""
    cur = conn.cursor()
    try:
        cur.execute("SELECT DISTINCT entry, entry_kind FROM entry_node")
        return {r[0]: r[1] for r in cur.fetchall()}
    except sqlite3.Error:
        return {}


def is_entry_root(
    fn_name: str,
    target_entry: Optional[str],
    entry_roots: Dict[str, str],
) -> Optional[str]:
    """Return entry_kind if fn_name is a matching non-syscall entry root."""
    kind = entry_roots.get(fn_name)
    if not kind:
        return None
    if target_entry and fn_name != target_entry and kind != target_entry:
        return None
    return kind


def load_target_reachable_set(
    conn: sqlite3.Connection, target_syscall: Optional[str]
) -> Optional[Set[str]]:
    """Build direct reachability set for target_syscall or non-syscall entry."""
    if not target_syscall:
        return None
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT function FROM syscall_node WHERE syscall = ?",
        (target_syscall,),
    )
    reachable_set = {r[0] for r in cur.fetchall()}
    try:
        cur.execute(
            "SELECT DISTINCT function FROM entry_node"
            " WHERE entry = ? OR entry_kind = ?",
            (target_syscall, target_syscall),
        )
        reachable_set.update(r[0] for r in cur.fetchall())
    except sqlite3.Error:
        pass
    reachable_set.add(target_syscall)
    base_name = target_syscall.replace("__do_sys_", "").replace("__se_sys_", "")
    for prefix in ("__do_sys_", "__se_sys_", "__x64_sys_", "__ia32_sys_"):
        reachable_set.add(f"{prefix}{base_name}")
    return reachable_set


def _collect_backward_roots(
    conn: sqlite3.Connection,
    function_name: str,
    lookup_fn: Callable[[str], List[Any]],
    limits: Tuple[int, int] = (6, 20),
    check_syscall_root: bool = False,
) -> Set[Any]:
    """Traverse backward callgraph bridges to collect reaching roots."""
    collected: Set[Any] = set(lookup_fn(function_name))
    queue = deque([(function_name, 0, 0)])
    visited: Set[str] = {function_name}

    while queue:
        curr_fn, direct_depth, bridge_depth = queue.popleft()
        if check_syscall_root and is_syscall_root(curr_fn, None):
            collected.add(curr_fn)
            continue
        if bridge_depth >= limits[0] or direct_depth >= limits[1]:
            continue
        for caller in get_callers(conn, curr_fn):
            caller_fn = caller[0]
            if caller_fn.startswith("<file-scope:") or caller_fn in visited:
                continue
            visited.add(caller_fn)
            hits = lookup_fn(caller_fn)
            if hits:
                collected.update(hits)
            elif caller[4] in ("indirect", "async"):
                queue.append((caller_fn, 0, bridge_depth + 1))
            else:
                queue.append((caller_fn, direct_depth + 1, bridge_depth))
    return collected


def get_reachable_syscalls(
    conn: sqlite3.Connection,
    function_name: str,
    max_bridge_depth: int = 6,
    max_direct_depth: int = 20,
) -> List[str]:
    """Return all system calls capable of reaching function_name."""
    cur = conn.cursor()

    def _lookup(fn: str) -> List[str]:
        cur.execute(
            "SELECT DISTINCT syscall FROM syscall_node WHERE function = ?",
            (fn,),
        )
        return [r[0] for r in cur.fetchall()]

    syscalls = _collect_backward_roots(
        conn,
        function_name,
        _lookup,
        limits=(max_bridge_depth, max_direct_depth),
        check_syscall_root=True,
    )
    return sorted(syscalls)


def get_reachable_entries(
    conn: sqlite3.Connection,
    function_name: str,
    max_bridge_depth: int = 6,
    max_direct_depth: int = 20,
) -> List[Dict[str, str]]:
    """Return all categorized non-syscall entry roots reaching function_name."""
    cur = conn.cursor()
    if not table_exists(cur, "entry_node"):
        return []

    def _lookup(fn: str) -> List[Tuple[str, str]]:
        cur.execute(
            "SELECT DISTINCT entry_kind, entry FROM entry_node"
            " WHERE function = ? OR entry = ?",
            (fn, fn),
        )
        return [(r[0], r[1]) for r in cur.fetchall()]

    entries = _collect_backward_roots(
        conn,
        function_name,
        _lookup,
        limits=(max_bridge_depth, max_direct_depth),
        check_syscall_root=False,
    )
    return [{"entry_kind": kind, "entry": ent} for kind, ent in sorted(entries)]


def select_eval_roots(
    target_info: Dict[str, Any], **options: Any
) -> Optional[List[str]]:
    """Select candidate root entry names to evaluate, or None for global."""
    target_syscall: Optional[str] = options.get("target_syscall")
    reachable_syscalls = target_info.get("all_syscalls", [])
    reachable_entries = target_info.get("all_entries", [])
    if target_syscall:
        if not target_syscall.startswith(("__do_sys_", "__se_sys_")):
            matched = [
                s
                for s in reachable_syscalls
                if s.endswith(f"_{target_syscall}") or s == target_syscall
            ]
            matched_entries = [
                e["entry"]
                for e in reachable_entries
                if target_syscall in {e["entry"], e["entry_kind"]}
            ]
            return (
                matched + matched_entries
                if (matched or matched_entries)
                else [f"__do_sys_{target_syscall}"]
            )
        return [target_syscall]

    if options.get("all_syscalls", False):
        candidates = list(reachable_syscalls) + [
            e["entry"] for e in reachable_entries
        ]
        return candidates[: options.get("limit_syscalls", 5)]
    return None


def format_root_label(step: Dict[str, Any]) -> str:
    """Return formatted tree root prefix for a syscall or non-syscall entry."""
    ekind = step.get("entry_kind", "syscall")
    return "[Syscall Entry]" if ekind == "syscall" else f"[Entry: {ekind}]"


def format_target_banner(target_info: Dict[str, Any]) -> List[str]:
    """Format target file:line, function name, and function span lines."""
    lines = [
        f"Target: {target_info['file']}:{target_info['line']} in function"
        f" '{target_info['function']}'"
    ]
    if target_info.get("span"):
        s, e = target_info["span"]
        lines.append(f"Function Span: lines {s} - {e}")
    return lines
