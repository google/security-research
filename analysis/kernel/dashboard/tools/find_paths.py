#!/usr/bin/env python3
# pylint: disable=duplicate-code,too-many-lines
"""Find call graph paths from userspace syscall entry points to kernel lines.

Uses CodeQL callgraph data in SQLite and optional Syzkaller coverage data.
"""

import argparse
from collections import deque
import json
import os
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

CONFIG_TOKEN_RE = re.compile(r"\b(CONFIG_[A-Za-z0-9_]+)\b")

INDEXES = [
    (
        "idx_fl_file_lines",
        "CREATE INDEX IF NOT EXISTS idx_fl_file_lines ON"
        " function_locations(file_path, start_line, end_line)",
    ),
    (
        "idx_fl_name",
        "CREATE INDEX IF NOT EXISTS idx_fl_name ON"
        " function_locations(function_name)",
    ),
    (
        "idx_sn_fn",
        "CREATE INDEX IF NOT EXISTS idx_sn_fn ON syscall_node(function)",
    ),
    (
        "idx_sn_sys",
        "CREATE INDEX IF NOT EXISTS idx_sn_sys ON syscall_node(syscall)",
    ),
    (
        "idx_loc_msg",
        "CREATE INDEX IF NOT EXISTS idx_loc_msg ON locations(message)",
    ),
    (
        "idx_loc_uri_line",
        "CREATE INDEX IF NOT EXISTS idx_loc_uri_line ON locations(uri,"
        " startLine)",
    ),
    (
        "idx_edges_target",
        "CREATE INDEX IF NOT EXISTS idx_edges_target ON"
        " edges(target_location_id)",
    ),
    (
        "idx_edges_source",
        "CREATE INDEX IF NOT EXISTS idx_edges_source ON"
        " edges(source_location_id)",
    ),
    (
        "idx_ops_target",
        "CREATE INDEX IF NOT EXISTS idx_ops_target ON ops_targets(target)",
    ),
    (
        "idx_ops_exprcall",
        "CREATE INDEX IF NOT EXISTS idx_ops_exprcall ON"
        " ops_targets(exprcall_file, exprcall_line)",
    ),
    (
        "idx_configs_path",
        "CREATE INDEX IF NOT EXISTS idx_configs_path ON"
        " configs(path, ifdef, endif)",
    ),
    (
        "idx_kconfig_sym",
        "CREATE INDEX IF NOT EXISTS idx_kconfig_sym ON"
        " kconfig_symbols(config)",
    ),
    (
        "idx_async_callee",
        "CREATE INDEX IF NOT EXISTS idx_async_callee ON async_edges(callee)",
    ),
    (
        "idx_async_caller",
        "CREATE INDEX IF NOT EXISTS idx_async_caller ON async_edges(caller)",
    ),
    (
        "idx_en_fn",
        "CREATE INDEX IF NOT EXISTS idx_en_fn ON entry_node(function)",
    ),
    (
        "idx_en_entry",
        "CREATE INDEX IF NOT EXISTS idx_en_entry ON entry_node(entry)",
    ),
    (
        "idx_en_kind",
        "CREATE INDEX IF NOT EXISTS idx_en_kind ON entry_node(entry_kind)",
    ),
]


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


def get_syzkaller_coverage(  # pylint: disable=too-many-locals
    syzk_conn: Optional[sqlite3.Connection],
    file_path: str,
    line_number: int,
    fn_span: Optional[Tuple[int, int]] = None,
) -> Dict[str, Any]:
    """Query dynamic Syzkaller coverage for a kernel line and function span."""
    if not syzk_conn:
        return {"configured": False}

    cur = syzk_conn.cursor()
    clean_path = file_path.lstrip("/").replace("linux/", "")

    cur.execute(
        "SELECT file_id FROM file_path WHERE file_path = ? OR file_path LIKE ?",
        (clean_path, f"%/{clean_path}"),
    )
    row = cur.fetchone()
    if not row:
        return {
            "configured": True,
            "file_tracked": False,
            "line_covered": False,
            "fn_covered": False,
            "syscalls": [],
            "progs": [],
        }

    file_id = row[0]

    # Query exact line coverage
    cur.execute(
        """
        SELECT DISTINCT s.syscall, c.prog_id, p.prog_code
        FROM syzk_cov c
        LEFT JOIN syscalls s ON c.prog_id = s.prog_id
        LEFT JOIN syzk_prog p ON c.prog_id = p.prog_id
        WHERE c.file_id = ? AND c.code_line_no = ?
    """,
        (file_id, line_number),
    )
    exact_hits = cur.fetchall()

    fn_covered_lines = 0
    fn_covered_progs = 0
    if fn_span:
        s_line, e_line = fn_span
        cur.execute(
            """
            SELECT count(DISTINCT c.code_line_no), count(DISTINCT c.prog_id)
            FROM syzk_cov c
            WHERE c.file_id = ? AND c.code_line_no BETWEEN ? AND ?
        """,
            (file_id, s_line, e_line),
        )
        r = cur.fetchone()
        if r:
            fn_covered_lines, fn_covered_progs = r

    syscalls = sorted(list({r[0] for r in exact_hits if r[0]}))
    progs = [
        {"prog_id": r[1], "syscall": r[0], "prog_code": r[2]}
        for r in exact_hits
        if r[1]
    ]

    return {
        "configured": True,
        "file_tracked": True,
        "line_covered": len(exact_hits) > 0,
        "exact_hits_count": len(exact_hits),
        "syscalls": syscalls,
        "progs": progs[:5],
        "fn_covered": fn_covered_lines > 0,
        "fn_covered_lines": fn_covered_lines,
        "fn_covered_progs": fn_covered_progs,
    }


def is_line_covered_by_syzkaller(
    syzk_conn: Optional[sqlite3.Connection], file_path: str, line_number: int
) -> bool:
    """Quick boolean check if a line has been executed in Syzkaller."""
    if not syzk_conn:
        return False
    clean_path = file_path.lstrip("/").replace("linux/", "")
    cur = syzk_conn.cursor()
    cur.execute(
        """
        SELECT 1
        FROM syzk_cov c
        JOIN file_path f ON c.file_id = f.file_id
        WHERE (f.file_path = ? OR f.file_path LIKE ?)
          AND c.code_line_no = ?
        LIMIT 1
    """,
        (clean_path, f"%/{clean_path}", line_number),
    )
    return cur.fetchone() is not None


def get_enclosing_function(
    conn: sqlite3.Connection, file_path: str, line_number: int
) -> Optional[Tuple[str, str, int, int]]:
    """Find the enclosing function for a given file and line number.

    Returns (function_name, canonical_file_path, start_line, end_line) or None.
    """
    clean_path = file_path.lstrip("/").replace("linux/", "")
    cur = conn.cursor()

    # Try exact match, then suffix match
    query = """
        SELECT function_name, file_path, start_line, end_line
        FROM function_locations
        WHERE (file_path = ? OR file_path LIKE ?)
          AND ? BETWEEN start_line AND end_line
        ORDER BY (end_line - start_line) ASC
    """
    cur.execute(query, (clean_path, f"%/{clean_path}", line_number))
    rows = cur.fetchall()
    if rows:
        return rows[0]
    return None


def get_reachable_syscalls(  # pylint: disable=too-many-locals
    conn: sqlite3.Connection,
    function_name: str,
    max_bridge_depth: int = 6,
    max_direct_depth: int = 20,
) -> List[str]:
    """Return all system calls capable of reaching function_name.

    Unions direct syscall_node hits with backward traversal across indirect
    (ops_targets) and asynchronous (async_edges) bridges, separating
    direct_depth from bridge_depth so deep Socket/Inode subtrees reach their
    ops/async bridge without premature depth cutoff.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT syscall FROM syscall_node WHERE function = ? ORDER BY"
        " syscall",
        (function_name,),
    )
    syscalls: Set[str] = {r[0] for r in cur.fetchall()}

    queue = deque([(function_name, 0, 0)])
    visited: Set[str] = {function_name}

    while queue:
        curr_fn, direct_depth, bridge_depth = queue.popleft()
        if is_syscall_root(curr_fn, None):
            syscalls.add(curr_fn)
            continue
        if bridge_depth >= max_bridge_depth or direct_depth >= max_direct_depth:
            continue

        for caller_fn, _file, _line, _cs, call_type, _det in get_callers(
            conn, curr_fn
        ):
            if caller_fn.startswith("<file-scope:") or caller_fn in visited:
                continue
            visited.add(caller_fn)
            cur.execute(
                "SELECT DISTINCT syscall FROM syscall_node WHERE function = ?",
                (caller_fn,),
            )
            caller_syscalls = [r[0] for r in cur.fetchall()]
            if caller_syscalls:
                syscalls.update(caller_syscalls)
            if call_type in ("indirect", "async"):
                if not caller_syscalls:
                    queue.append((caller_fn, 0, bridge_depth + 1))
            elif not caller_syscalls:
                queue.append((caller_fn, direct_depth + 1, bridge_depth))

    return sorted(syscalls)


def get_reachable_entries(  # pylint: disable=too-many-locals
    conn: sqlite3.Connection,
    function_name: str,
    max_bridge_depth: int = 6,
    max_direct_depth: int = 20,
) -> List[Dict[str, str]]:
    """Return all categorized non-syscall entry roots reaching function_name.

    Unions direct entry_node hits with backward traversal across ops_targets
    and async_edges bridges, mirroring get_reachable_syscalls().
    """
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT DISTINCT entry_kind, entry FROM entry_node"
            " WHERE function = ?",
            (function_name,),
        )
        entries: Set[Tuple[str, str]] = {(r[0], r[1]) for r in cur.fetchall()}
        cur.execute(
            "SELECT DISTINCT entry_kind, entry FROM entry_node"
            " WHERE entry = ?",
            (function_name,),
        )
        entries.update((r[0], r[1]) for r in cur.fetchall())
    except sqlite3.Error:
        return []

    queue = deque([(function_name, 0, 0)])
    visited: Set[str] = {function_name}

    while queue:
        curr_fn, direct_depth, bridge_depth = queue.popleft()
        if bridge_depth >= max_bridge_depth or direct_depth >= max_direct_depth:
            continue

        for caller_fn, _file, _line, _cs, call_type, _det in get_callers(
            conn, curr_fn
        ):
            if caller_fn.startswith("<file-scope:") or caller_fn in visited:
                continue
            visited.add(caller_fn)
            cur.execute(
                "SELECT DISTINCT entry_kind, entry FROM entry_node"
                " WHERE function = ? OR entry = ?",
                (caller_fn, caller_fn),
            )
            caller_entries = [(r[0], r[1]) for r in cur.fetchall()]
            if caller_entries:
                entries.update(caller_entries)
            if call_type in ("indirect", "async"):
                if not caller_entries:
                    queue.append((caller_fn, 0, bridge_depth + 1))
            elif not caller_entries:
                queue.append((caller_fn, direct_depth + 1, bridge_depth))

    return [
        {"entry_kind": kind, "entry": ent} for kind, ent in sorted(entries)
    ]


_CALL_TYPE_PRIORITY = {"direct": 0, "indirect": 1, "async": 2}


def _record_caller_site(
    results: List[Tuple[str, str, int, int, str, str]],
    seen_sites: Dict[Tuple[str, int], int],
    site_key: Tuple[str, int],
    entry: Tuple[str, str, int, int, str, str],
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
        """
        SELECT function_name, file_path, start_line
        FROM function_locations
        WHERE file_path = ? AND ? BETWEEN start_line AND end_line
        LIMIT 1
    """,
        (src_file, src_line),
    )
    fn_row = cur.fetchone()
    if fn_row and (src_msg.startswith("call to ") or src_msg != fn_row[0]):
        return fn_row[0], fn_row[1], fn_row[2], src_line
    if not src_msg.startswith("call to "):
        return src_msg, src_file, src_line, dst_line
    return None


def get_callers(  # pylint: disable=too-many-locals
    conn: sqlite3.Connection, function_name: str
) -> List[Tuple[str, str, int, int, str, str]]:
    """Find all callers invoking function_name directly, indirectly, or async.

    Returns list of tuples:
      (caller_fn, caller_file, caller_line, call_site_line, call_type, details)
    """
    cur = conn.cursor()
    results: List[Tuple[str, str, int, int, str, str]] = []
    seen_sites: Dict[Tuple[str, int], int] = {}

    # 1. Direct and points-to callers from edges + locations
    cur.execute(
        """
        SELECT DISTINCT s.message AS src_msg,
                        s.uri AS src_file,
                        s.startLine AS src_line,
                        t.message AS dst_msg,
                        t.startLine AS dst_line
        FROM edges e
        JOIN locations s ON e.source_location_id = s.id
        JOIN locations t ON e.target_location_id = t.id
        WHERE t.message = ? OR t.message = ?
    """,
        (function_name, f"call to {function_name}"),
    )

    for edge_row in cur.fetchall():
        resolved = _resolve_edge_caller(cur, function_name, edge_row)
        if not resolved:
            continue
        caller_fn, caller_file, caller_line, call_site_line = resolved
        _record_caller_site(
            results,
            seen_sites,
            (caller_fn, call_site_line),
            (caller_fn, caller_file, caller_line, call_site_line, "direct", ""),
        )

    # 2. Indirect callers from ops_targets
    cur.execute(
        """
        SELECT DISTINCT o.parent, o.field, o.exprcall_file, o.exprcall_line
        FROM ops_targets o
        WHERE o.target = ?
    """,
        (function_name,),
    )

    for parent, field, expr_file, expr_line in cur.fetchall():
        # Find enclosing function of the exprcall call site
        cur.execute(
            """
            SELECT function_name, file_path, start_line
            FROM function_locations
            WHERE file_path = ? AND ? BETWEEN start_line AND end_line
            LIMIT 1
        """,
            (expr_file, expr_line),
        )
        fn_row = cur.fetchone()
        if fn_row:
            caller_fn, caller_file, caller_line = fn_row
            _record_caller_site(
                results,
                seen_sites,
                (caller_fn, expr_line),
                (
                    caller_fn,
                    caller_file,
                    caller_line,
                    expr_line,
                    "indirect",
                    f"{parent}->{field}",
                ),
            )

    # 3. Asynchronous callers from async_edges
    try:
        cur.execute(
            """
            SELECT DISTINCT a.caller, a.mechanism, a.form, a.file, a.line,
                            a.context
            FROM async_edges a
            WHERE a.callee = ?
        """,
            (function_name,),
        )
        async_rows = cur.fetchall()
    except sqlite3.Error:
        async_rows = []

    for (
        caller_fn,
        mechanism,
        form,
        reg_file,
        reg_line,
        context,
    ) in async_rows:
        if caller_fn.startswith("<file-scope:"):
            continue
        cur.execute(
            """
            SELECT file_path, start_line
            FROM function_locations
            WHERE function_name = ? AND file_path = ?
            LIMIT 1
        """,
            (caller_fn, reg_file),
        )
        fn_row = cur.fetchone()
        if not fn_row:
            cur.execute(
                """
                SELECT file_path, start_line
                FROM function_locations
                WHERE function_name = ?
                LIMIT 1
            """,
                (caller_fn,),
            )
            fn_row = cur.fetchone()
        caller_file = fn_row[0] if fn_row else reg_file
        caller_line = fn_row[1] if fn_row else reg_line
        _record_caller_site(
            results,
            seen_sites,
            (caller_fn, reg_line),
            (
                caller_fn,
                caller_file,
                caller_line,
                reg_line,
                "async",
                f"{mechanism}/{form} ({context})",
            ),
        )

    return results


def _invert_config_expr(config: str) -> str:
    """Inverts a CONFIG_* expression for the #else branch of a guard."""
    if config.startswith("!") and " " not in config:
        return config[1:]
    if " " in config:
        return f"!({config})"
    return f"!{config}"


def get_line_configs(
    conn: sqlite3.Connection, file_path: str, line_number: Optional[int]
) -> List[str]:
    """Return all active CONFIG_* guards covering (file_path, line_number)."""
    if line_number is None:
        return []
    clean_path = file_path.lstrip("/").replace("linux/", "")
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT config, ifdef, endif, else_
            FROM configs
            WHERE (path = ? OR path LIKE ?)
              AND ? BETWEEN ifdef AND endif
            ORDER BY ifdef ASC, config ASC
        """,
            (clean_path, f"%/{clean_path}", line_number),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        return []

    seen: Set[str] = set()
    active: List[str] = []
    for cfg, _ifdef_l, _endif_l, else_l in rows:
        if else_l and else_l > 0:
            if line_number == else_l:
                continue
            eff = _invert_config_expr(cfg) if line_number > else_l else cfg
        else:
            eff = cfg
        if eff not in seen:
            seen.add(eff)
            active.append(eff)
    return active


def get_kconfig_metadata(
    conn: sqlite3.Connection, config_exprs: List[str]
) -> Dict[str, Dict[str, Any]]:
    """Lookup Kconfig symbol metadata for CONFIG_* tokens in config_exprs."""
    tokens: Set[str] = set()
    for expr in config_exprs:
        tokens.update(CONFIG_TOKEN_RE.findall(expr))
    if not tokens:
        return {}

    cur = conn.cursor()
    placeholders = ",".join("?" for _ in tokens)
    try:
        cur.execute(
            f"""
            SELECT config, type, prompt, depends_on, select_list,
                   default_val, build_val, kconfig_file, line_no
            FROM kconfig_symbols
            WHERE config IN ({placeholders})
        """,
            sorted(tokens),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        return {}

    meta: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        meta[row[0]] = {
            "type": row[1],
            "prompt": row[2],
            "depends_on": row[3],
            "select_list": row[4],
            "default_val": row[5],
            "build_val": row[6],
            "kconfig_file": row[7],
            "line_no": row[8],
        }
    return meta


def is_syscall_root(fn_name: str, target_syscall: Optional[str]) -> bool:
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


def _load_target_reachable_set(
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
    base_name = target_syscall.replace("__do_sys_", "").replace(
        "__se_sys_", ""
    )
    for prefix in ["__do_sys_", "__se_sys_", "__x64_sys_", "__ia32_sys_"]:
        reachable_set.add(f"{prefix}{base_name}")
    return reachable_set


def find_shortest_path(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    conn: sqlite3.Connection,
    target_fn: str,
    target_file: str,
    target_line: int,
    target_syscall: Optional[str] = None,
    syzk_conn: Optional[sqlite3.Connection] = None,
    max_depth: int = 25,
) -> Optional[List[Dict[str, Any]]]:
    """Perform a backward BFS from target_fn to target_syscall or any root.

    Guided by target_syscall/entry reachability in syscall_node and entry_node.
    """
    reachable_set = _load_target_reachable_set(conn, target_syscall)
    entry_roots = load_entry_roots(conn)

    target_syzk_cov = is_line_covered_by_syzkaller(
        syzk_conn, target_file, target_line
    )

    start_step = {
        "function": target_fn,
        "file": target_file,
        "line": target_line,
        "call_site_line": None,
        "call_type": "target",
        "details": "",
        "configs": get_line_configs(conn, target_file, target_line),
        "syzk_covered": target_syzk_cov,
    }

    queue = deque([(target_fn, target_file, target_line, [start_step])])
    visited: Set[str] = {target_fn}

    while queue:
        curr_fn, _curr_file, _curr_line, path = queue.popleft()

        if is_syscall_root(curr_fn, target_syscall):
            path[0]["entry_kind"] = "syscall"
            return path
        entry_kind = is_entry_root(curr_fn, target_syscall, entry_roots)
        if entry_kind:
            path[0]["entry_kind"] = entry_kind
            return path

        if len(path) > max_depth:
            continue

        callers = get_callers(conn, curr_fn)
        has_reachable_caller = reachable_set is not None and any(
            c[0] in reachable_set and c[0] not in visited for c in callers
        )
        for (
            caller_fn,
            caller_file,
            caller_line,
            call_site_line,
            call_type,
            details,
        ) in callers:
            is_allowed = (
                reachable_set is None
                or curr_fn not in reachable_set
                or not has_reachable_caller
                or caller_fn in reachable_set
                or call_type in ("indirect", "async")
            )
            if is_allowed and caller_fn not in visited:
                visited.add(caller_fn)
                check_line = call_site_line or caller_line
                step_cov = is_line_covered_by_syzkaller(
                    syzk_conn, caller_file, check_line
                )
                step = {
                    "function": caller_fn,
                    "file": caller_file,
                    "line": caller_line,
                    "call_site_line": call_site_line,
                    "call_type": call_type,
                    "details": details,
                    "configs": get_line_configs(conn, caller_file, check_line),
                    "syzk_covered": step_cov,
                }
                new_path = [step] + path
                queue.append((caller_fn, caller_file, caller_line, new_path))

    return None


def format_tree(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    paths_by_syscall: Dict[str, List[Dict[str, Any]]],
    target_info: Dict[str, Any],
    show_repro: bool = False,
) -> str:
    """Format call paths as an indented ASCII tree with annotations."""
    out = []
    out.append("=" * 70)
    out.append(
        f"Target: {target_info['file']}:{target_info['line']} in function"
        f" '{target_info['function']}'"
    )
    if target_info.get("span"):
        s, e = target_info["span"]
        out.append(f"Function Span: lines {s} - {e}")

    all_sys = target_info.get("all_syscalls", list(paths_by_syscall.keys()))
    out.append(
        f"Static Reachability (CodeQL): Reachable from {len(all_sys)}"
        f" syscall(s) ({', '.join(all_sys[:5])}"
        f"{'...' if len(all_sys) > 5 else ''})"
    )
    all_entries = target_info.get("all_entries", [])
    if all_entries:
        ent_strs = [f"{e['entry_kind']}:{e['entry']}" for e in all_entries[:5]]
        out.append(
            f"Non-Syscall Entries (CodeQL): Reachable from {len(all_entries)}"
            f" entry root(s) ({', '.join(ent_strs)}"
            f"{'...' if len(all_entries) > 5 else ''})"
        )

    if target_info.get("configs"):
        out.append(
            f"Kernel Configs (Target): {', '.join(target_info['configs'])}"
        )

    syzk = target_info.get("syzkaller", {})
    if syzk.get("configured"):
        if syzk.get("line_covered"):
            hit_sys = ", ".join(syzk.get("syscalls", [])) or "unknown"
            out.append(
                "Dynamic Coverage (Syzkaller): COVERED (executed via syscalls:"
                f" {hit_sys})"
            )
            out.append(
                "Classification: FULLY PROVEN (Static Call Path + Live Fuzzer"
                " Execution)"
            )
        elif syzk.get("fn_covered"):
            fn_lines = syzk.get("fn_covered_lines")
            tgt_line = target_info["line"]
            out.append(
                f"Dynamic Coverage (Syzkaller): PARTIALLY COVERED ({fn_lines}"
                f" lines in function executed, but line {tgt_line} unfuzzed)"
            )
            out.append(
                "Classification: FUZZING GAP (Function hit, but target"
                " branch/line unfuzzed)"
            )
        else:
            out.append(
                "Dynamic Coverage (Syzkaller): UNCOVERED (0 live executions"
                " recorded)"
            )
            out.append(
                "Classification: ATTACK SURFACE BLIND SPOT (Statically"
                " reachable, but unfuzzed!)"
            )
    else:
        out.append("Dynamic Coverage (Syzkaller): (Database not configured)")
    out.append("=" * 70)

    for syscall, path in paths_by_syscall.items():
        out.append(f"\n[Call Path from {syscall}]")
        if not path:
            out.append("  (No direct callgraph path found within depth limit)")
            continue

        for i, step in enumerate(path):
            indent = "  " * i
            fn = step["function"]
            f = step["file"]
            l = step["line"]
            cs = step.get("call_site_line")
            ctype = step.get("call_type")
            details = step.get("details", "")
            syzk_tag = ""
            if syzk.get("configured"):
                syzk_tag = (
                    " [Syzkaller: Covered]"
                    if step.get("syzk_covered")
                    else " [Static Only]"
                )
            cfg_list = step.get("configs", [])
            cfg_tag = f" [Kconfig: {', '.join(cfg_list)}]" if cfg_list else ""

            type_info = f" [{ctype}]" if ctype and ctype != "target" else ""
            if details:
                type_info += f" ({details})"
            call_info = f" [calls at line {cs}]" if cs else ""

            if i == 0:
                ekind = step.get("entry_kind", "syscall")
                root_lbl = (
                    "[Syscall Entry]"
                    if ekind == "syscall"
                    else f"[Entry: {ekind}]"
                )
                out.append(
                    f"{indent}└── {root_lbl} {fn}"
                    f" ({f}:{l}){syzk_tag}{cfg_tag}"
                )
            elif i == len(path) - 1:
                out.append(
                    f"{indent}└── [Target Line] {fn}"
                    f" ({f}:{l}){type_info}{syzk_tag}{cfg_tag}"
                )
            else:
                out.append(
                    f"{indent}└── {fn}"
                    f" ({f}:{l}){call_info}{type_info}{syzk_tag}{cfg_tag}"
                )

    if show_repro and syzk.get("progs"):
        out.append("\n" + "-" * 70)
        out.append("Syzkaller Reproduction Program:")
        out.append("-" * 70)
        p = syzk["progs"][0]
        out.append(f"// Prog ID: {p.get('prog_id')}")
        if p.get("prog_code"):
            out.append(p["prog_code"].strip())
        out.append("-" * 70)

    return "\n".join(out)


def format_list(paths_by_syscall: Dict[str, List[Dict[str, Any]]]) -> str:
    """Format call paths as arrow-separated chains."""
    out = []
    for _syscall, path in paths_by_syscall.items():
        if not path:
            continue
        chain = " -> ".join([
            f"{s['function']}"
            f" ({s['file']}:{s.get('call_site_line') or s['line']})"
            for s in path
        ])
        out.append(chain)
    return "\n\n".join(out)


def format_mermaid(  # pylint: disable=too-many-locals
    paths_by_syscall: Dict[str, List[Dict[str, Any]]],
) -> str:
    """Format call paths as a styled Mermaid diagram with coverage coloring."""
    lines = [
        "```mermaid",
        "graph TD",
        (
            "    classDef covered"
            " fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724;"
        ),
        (
            "    classDef uncovered"
            " fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#856404;"
        ),
    ]
    seen_edges = set()
    node_classes = {}

    for _syscall, path in paths_by_syscall.items():
        if not path:
            continue
        for i in range(len(path) - 1):
            s_curr = path[i]
            s_next = path[i + 1]
            src_label = (
                f"{s_curr['function']}\\n({s_curr['file']}:{s_curr['line']})"
            )
            dst_label = (
                f"{s_next['function']}\\n({s_next['file']}:{s_next['line']})"
            )
            edge_lbl = (
                f"calls at L{s_curr.get('call_site_line')}"
                if s_curr.get("call_site_line")
                else "calls"
            )
            if s_next.get("details"):
                edge_lbl += f" ({s_next['details']})"

            src_id = f"node_{abs(hash(src_label)) % 100000}"
            dst_id = f"node_{abs(hash(dst_label)) % 100000}"

            node_classes[src_id] = (
                "covered" if s_curr.get("syzk_covered") else "uncovered"
            )
            node_classes[dst_id] = (
                "covered" if s_next.get("syzk_covered") else "uncovered"
            )

            edge_key = (src_label, dst_label, edge_lbl)
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                lines.append(f'    {src_id}["{src_label}"]')
                lines.append(f'    {dst_id}["{dst_label}"]')
                lines.append(f'    {src_id} -->|"{edge_lbl}"| {dst_id}')

    for nid, cls in node_classes.items():
        lines.append(f"    class {nid} {cls};")

    lines.append("```")
    return "\n".join(lines)


def find_paths_to_line(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,too-many-branches
    db_file: str,
    file_path: str,
    line_number: int,
    target_syscall: Optional[str] = None,
    syzkaller_db: Optional[str] = None,
    all_syscalls: bool = False,
    limit_syscalls: int = 5,
    max_depth: int = 25,
    verbose: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]]]:
    """Main programmatic interface to find callgraph paths to a kernel line.

    Returns (target_info, paths_by_syscall).
    """
    if not os.path.isfile(db_file):
        raise FileNotFoundError(f"Database file not found: {db_file}")

    conn = sqlite3.connect(db_file)
    ensure_indexes(conn, verbose=verbose)

    syzk_conn = (
        sqlite3.connect(syzkaller_db)
        if syzkaller_db and os.path.isfile(syzkaller_db)
        else None
    )

    fn_info = get_enclosing_function(conn, file_path, line_number)
    if not fn_info:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        raise ValueError(
            f"No enclosing function found for {file_path}:{line_number}"
        )

    fn_name, canonical_file, start_line, end_line = fn_info
    reachable_syscalls = get_reachable_syscalls(conn, fn_name)
    reachable_entries = get_reachable_entries(conn, fn_name)
    syzk_info = get_syzkaller_coverage(
        syzk_conn, canonical_file, line_number, fn_span=(start_line, end_line)
    )
    target_configs = get_line_configs(conn, canonical_file, line_number)

    target_info = {
        "function": fn_name,
        "file": canonical_file,
        "line": line_number,
        "span": (start_line, end_line),
        "all_syscalls": reachable_syscalls,
        "all_entries": reachable_entries,
        "configs": target_configs,
        "kconfig_metadata": get_kconfig_metadata(conn, target_configs),
        "syzkaller": syzk_info,
    }

    if not reachable_syscalls and not reachable_entries:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        return target_info, {}

    paths_by_syscall = {}
    if target_syscall:
        if not target_syscall.startswith(
            "__do_sys_"
        ) and not target_syscall.startswith("__se_sys_"):
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
            eval_syscalls = (
                matched + matched_entries
                if (matched or matched_entries)
                else [f"__do_sys_{target_syscall}"]
            )
        else:
            eval_syscalls = [target_syscall]

        for sc in eval_syscalls:
            path = find_shortest_path(
                conn,
                fn_name,
                canonical_file,
                line_number,
                sc,
                syzk_conn=syzk_conn,
                max_depth=max_depth,
            )
            if path:
                paths_by_syscall[sc] = path
    elif all_syscalls:
        candidates = list(reachable_syscalls) + [
            e["entry"] for e in reachable_entries
        ]
        for sc in candidates[:limit_syscalls]:
            path = find_shortest_path(
                conn,
                fn_name,
                canonical_file,
                line_number,
                sc,
                syzk_conn=syzk_conn,
                max_depth=max_depth,
            )
            if path:
                paths_by_syscall[sc] = path
    else:
        # Find globally shortest path to ANY syscall or non-syscall entry
        path = find_shortest_path(
            conn,
            fn_name,
            canonical_file,
            line_number,
            target_syscall=None,
            syzk_conn=syzk_conn,
            max_depth=max_depth,
        )
        if path:
            root_sc = path[0]["function"]
            paths_by_syscall[root_sc] = path

    all_cfg_exprs = list(target_configs)
    for path in paths_by_syscall.values():
        for step in path:
            all_cfg_exprs.extend(step.get("configs", []))
    target_info["kconfig_metadata"] = get_kconfig_metadata(conn, all_cfg_exprs)

    conn.close()
    if syzk_conn:
        syzk_conn.close()
    return target_info, paths_by_syscall


def find_paths_to_function_recursive(
    db_file: str, function: str, max_depth: int = 25
) -> List[List[Tuple[str, str, int]]]:
    """Backwards compatibility interface with original find_paths.py.

    Finds paths to function and returns list of paths formatted as tuples.
    """
    conn = sqlite3.connect(db_file)
    ensure_indexes(conn)

    cur = conn.cursor()
    cur.execute(
        "SELECT file_path, start_line, end_line FROM function_locations WHERE"
        " function_name = ? LIMIT 1",
        (function,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return []

    file_path, start_line, _end_line = row
    syscalls = get_reachable_syscalls(conn, function)

    results = []
    for sc in syscalls[:10]:
        path = find_shortest_path(
            conn, function, file_path, start_line, sc, max_depth=max_depth
        )
        if path:
            formatted_path = [
                (node["function"], node["file"], node["line"]) for node in path
            ]
            results.append(formatted_path)

    conn.close()
    return results


def main() -> None:  # pylint: disable=too-many-statements
    """CLI entry point for find_paths."""
    ap = argparse.ArgumentParser(
        description=(
            "Find call graph reachability paths from syscall entry points to"
            " kernel source lines or functions, correlated with Syzkaller"
            " dynamic coverage."
        )
    )
    ap.add_argument(
        "--db",
        required=True,
        help="Path to CodeQL SQLite database",
    )
    ap.add_argument(
        "--syzkaller-db",
        default=None,
        help="Path to Syzkaller coverage SQLite database (optional)",
    )
    ap.add_argument(
        "--file", "-f", help="Kernel source file (e.g. net/socket.c)"
    )
    ap.add_argument(
        "--line",
        "-l",
        type=int,
        help="Line number within the kernel source file",
    )
    ap.add_argument(
        "--function", "-fn", help="Direct function name to find paths to"
    )
    ap.add_argument(
        "--syscall",
        "-s",
        help="Target a specific syscall (e.g. __do_sys_recvmsg or recvmsg)",
    )
    ap.add_argument(
        "--max-depth",
        type=int,
        default=25,
        help="Maximum call graph traversal depth (default: 25)",
    )
    ap.add_argument(
        "--all-syscalls",
        "-a",
        action="store_true",
        help=(
            "Find paths for all reachable syscalls (default: find shortest path"
            " to closest syscall)"
        ),
    )
    ap.add_argument(
        "--limit-syscalls",
        type=int,
        default=5,
        help=(
            "Maximum number of syscall paths to compute when --all-syscalls is"
            " set (default: 5)"
        ),
    )
    ap.add_argument(
        "--show-repro",
        action="store_true",
        help="Display Syzkaller reproduction program code if covered",
    )
    ap.add_argument(
        "--format",
        choices=["tree", "list", "json", "mermaid"],
        default="tree",
        help="Output format (default: tree)",
    )
    ap.add_argument(
        "--ensure-indexes",
        action="store_true",
        help="Ensure fast SQLite indexes exist on the database and exit",
    )
    ap.add_argument(
        "--verbose", "-v", action="store_true", help="Print debug information"
    )

    args = ap.parse_args()

    if not os.path.isfile(args.db):
        sys.exit(f"Error: Database file not found: {args.db}")

    if args.syzkaller_db and not os.path.isfile(args.syzkaller_db):
        sys.exit(
            f"Error: Syzkaller database file not found: {args.syzkaller_db}"
        )

    if args.ensure_indexes:
        conn = sqlite3.connect(args.db)
        ensure_indexes(conn, verbose=True)
        conn.close()
        print("Indexes verified successfully.")
        return

    if args.function and not args.file:
        conn = sqlite3.connect(args.db)
        cur = conn.cursor()
        cur.execute(
            "SELECT file_path, start_line FROM function_locations WHERE"
            " function_name = ? LIMIT 1",
            (args.function,),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            sys.exit(
                f"Error: Function '{args.function}' not found in"
                " function_locations table."
            )
        args.file = row[0]
        args.line = row[1]

    if not args.file or args.line is None:
        ap.print_help()
        sys.exit(
            "\nError: Please provide either (--file AND --line) or --function."
        )

    try:
        target_info, paths = find_paths_to_line(
            args.db,
            args.file,
            args.line,
            target_syscall=args.syscall,
            syzkaller_db=args.syzkaller_db,
            all_syscalls=args.all_syscalls,
            limit_syscalls=args.limit_syscalls,
            max_depth=args.max_depth,
            verbose=args.verbose,
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        sys.exit(f"Error: {e}")

    if not paths:
        print(
            f"No reachability path found for {args.file}:{args.line} (Function:"
            f" {target_info.get('function')}).",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.format == "tree":
        print(format_tree(paths, target_info, show_repro=args.show_repro))
    elif args.format == "list":
        print(format_list(paths))
    elif args.format == "json":
        print(json.dumps({"target": target_info, "paths": paths}, indent=2))
    elif args.format == "mermaid":
        print(format_mermaid(paths))


if __name__ == "__main__":
    main()
