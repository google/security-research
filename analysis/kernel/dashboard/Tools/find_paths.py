#!/usr/bin/env python3
"""
Find call graph paths from userspace syscall entry points to any kernel source file
and line number (or function name) using CodeQL callgraph data in SQLite.
"""

import argparse
from collections import deque
import glob
import json
import os
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

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
]


def ensure_indexes(conn: sqlite3.Connection, verbose: bool = False) -> None:
    """Create essential SQLite indexes for sub-millisecond callgraph traversal if missing."""
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


def find_default_db() -> Optional[str]:
    """Search standard locations for the CodeQL SQLite database."""
    # 1. Environment variable
    env_db = os.environ.get("CODEQL_DB")
    if env_db and os.path.isfile(env_db):
        return env_db

    # 2. Current working directory
    for name in ("codeql_data.db", "codeql_data-6.1.db"):
        if os.path.isfile(name):
            return os.path.abspath(name)
    cwd_matches = sorted(glob.glob("codeql_data*.db"))
    if cwd_matches and os.path.isfile(cwd_matches[0]):
        return os.path.abspath(cwd_matches[0])

    # 3. Repository root and Data/ directories relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_1 = os.path.abspath(os.path.join(script_dir, ".."))
    parent_2 = os.path.abspath(os.path.join(script_dir, "..", ".."))
    search_dirs = [
        parent_1,
        os.path.join(parent_1, "Data"),
        os.path.join(parent_1, "Data", "CodeQL"),
        parent_2,
        os.path.join(parent_2, "Data"),
        os.path.join(parent_2, "Data", "CodeQL"),
        script_dir,
    ]
    for d in search_dirs:
        for name in ("codeql_data.db", "codeql_data-6.1.db"):
            target = os.path.join(d, name)
            if os.path.isfile(target):
                return target
        matches = sorted(glob.glob(os.path.join(d, "codeql_data*.db")))
        if matches and os.path.isfile(matches[0]):
            return matches[0]

    return None


def find_default_syzkaller_db(
    codeql_db_path: Optional[str] = None,
) -> Optional[str]:
    """Search standard locations for the Syzkaller coverage SQLite database."""
    # 1. Environment variable
    env_db = os.environ.get("SYZKALLER_DB")
    if env_db and os.path.isfile(env_db):
        return env_db

    # 2. Check the directory containing the CodeQL database
    if codeql_db_path and os.path.isfile(codeql_db_path):
        db_dir = os.path.dirname(os.path.abspath(codeql_db_path))
        for name in ("syzkaller.db",):
            target = os.path.join(db_dir, name)
            if os.path.isfile(target):
                return target
        matches = sorted(glob.glob(os.path.join(db_dir, "syzkaller*.db")))
        if matches and os.path.isfile(matches[0]):
            return matches[0]

    # 3. Current working directory
    for name in ("syzkaller.db",):
        if os.path.isfile(name):
            return os.path.abspath(name)
    cwd_matches = sorted(glob.glob("syzkaller*.db"))
    if cwd_matches and os.path.isfile(cwd_matches[0]):
        return os.path.abspath(cwd_matches[0])

    # 4. Repository root and Data/ directories relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_1 = os.path.abspath(os.path.join(script_dir, ".."))
    parent_2 = os.path.abspath(os.path.join(script_dir, "..", ".."))
    search_dirs = [
        parent_1,
        os.path.join(parent_1, "Data"),
        os.path.join(parent_1, "Data", "Syzkaller_Coverage"),
        parent_2,
        os.path.join(parent_2, "Data"),
        os.path.join(parent_2, "Data", "Syzkaller_Coverage"),
        script_dir,
    ]
    for d in search_dirs:
        for name in ("syzkaller.db",):
            target = os.path.join(d, name)
            if os.path.isfile(target):
                return target
        matches = sorted(glob.glob(os.path.join(d, "syzkaller*.db")))
        if matches and os.path.isfile(matches[0]):
            return matches[0]

    return None


def get_syzkaller_coverage(
    syzk_conn: Optional[sqlite3.Connection],
    file_path: str,
    line_number: int,
    fn_span: Optional[Tuple[int, int]] = None,
) -> Dict[str, Any]:
    """
    Query dynamic Syzkaller coverage for a kernel source line and function span.
    """
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
    """
    Find the enclosing function for a given file and line number.
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


def get_reachable_syscalls(
    conn: sqlite3.Connection, function_name: str
) -> List[str]:
    """Return all system calls capable of reaching function_name."""
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT syscall FROM syscall_node WHERE function = ? ORDER BY"
        " syscall",
        (function_name,),
    )
    return [r[0] for r in cur.fetchall()]


def get_callers(
    conn: sqlite3.Connection, function_name: str
) -> List[Tuple[str, str, int, int, str, str]]:
    """
    Find all callers invoking function_name directly or indirectly.
    Returns list of tuples:
      (caller_fn, caller_file, caller_line, call_site_line, call_type, details)
    """
    cur = conn.cursor()
    results = []

    # 1. Direct callers from edges + locations
    cur.execute(
        """
        SELECT DISTINCT s.message AS caller_fn,
                        s.uri AS caller_file,
                        s.startLine AS caller_line,
                        t.startLine AS call_site_line
        FROM edges e
        JOIN locations s ON e.source_location_id = s.id
        JOIN locations t ON e.target_location_id = t.id
        WHERE (t.message = ? OR t.message = ?)
          AND s.message NOT LIKE "call to %"
    """,
        (function_name, f"call to {function_name}"),
    )

    for caller_fn, caller_file, caller_line, call_site_line in cur.fetchall():
        results.append(
            (caller_fn, caller_file, caller_line, call_site_line, "direct", "")
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
            results.append((
                caller_fn,
                caller_file,
                caller_line,
                expr_line,
                "indirect",
                f"{parent}->{field}",
            ))

    return results


def is_syscall_root(fn_name: str, target_syscall: Optional[str]) -> bool:
    """Check if fn_name corresponds to the target syscall or a syscall entry point."""
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
        if clean_fn == clean_target:
            return True
    return fn_name.startswith(("__do_sys_", "__se_sys_", "__x64_sys_"))


def find_shortest_path(
    conn: sqlite3.Connection,
    target_fn: str,
    target_file: str,
    target_line: int,
    target_syscall: Optional[str] = None,
    syzk_conn: Optional[sqlite3.Connection] = None,
    max_depth: int = 25,
) -> Optional[List[Dict[str, Any]]]:
    """
    Perform a backward breadth-first search from target_fn to target_syscall (or ANY syscall if None),
    guided and pruned at every step by target_syscall reachability in syscall_node.
    """
    cur = conn.cursor()

    reachable_set = None
    if target_syscall:
        cur.execute(
            "SELECT DISTINCT function FROM syscall_node WHERE syscall = ?",
            (target_syscall,),
        )
        reachable_set = {r[0] for r in cur.fetchall()}
        reachable_set.add(target_syscall)

        base_name = target_syscall.replace("__do_sys_", "")
        for prefix in ["__do_sys_", "__se_sys_", "__x64_sys_", "__ia32_sys_"]:
            reachable_set.add(f"{prefix}{base_name}")

        if target_fn not in reachable_set:
            return None

    target_syzk_cov = is_line_covered_by_syzkaller(syzk_conn, target_file, target_line)

    start_step = {
        "function": target_fn,
        "file": target_file,
        "line": target_line,
        "call_site_line": None,
        "call_type": "target",
        "details": "",
        "syzk_covered": target_syzk_cov,
    }

    queue = deque([(target_fn, target_file, target_line, [start_step])])
    visited: Set[str] = {target_fn}

    while queue:
        curr_fn, curr_file, curr_line, path = queue.popleft()

        if is_syscall_root(curr_fn, target_syscall):
            return path

        if len(path) > max_depth:
            continue

        callers = get_callers(conn, curr_fn)
        for (
            caller_fn,
            caller_file,
            caller_line,
            call_site_line,
            call_type,
            details,
        ) in callers:
            if (reachable_set is None or caller_fn in reachable_set) and caller_fn not in visited:
                visited.add(caller_fn)
                step_cov = is_line_covered_by_syzkaller(
                    syzk_conn, caller_file, call_site_line or caller_line
                )
                step = {
                    "function": caller_fn,
                    "file": caller_file,
                    "line": caller_line,
                    "call_site_line": call_site_line,
                    "call_type": call_type,
                    "details": details,
                    "syzk_covered": step_cov,
                }
                new_path = [step] + path
                queue.append((caller_fn, caller_file, caller_line, new_path))

    return None


def format_tree(
    paths_by_syscall: Dict[str, List[Dict[str, Any]]],
    target_info: Dict[str, Any],
    show_repro: bool = False,
) -> str:
    """Format call paths as an indented ASCII tree with static and dynamic annotations."""
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
        f"Static Reachability (CodeQL): Reachable from {len(all_sys)} syscall(s)"
        f" ({', '.join(all_sys[:5])}{'...' if len(all_sys) > 5 else ''})"
    )

    syzk = target_info.get("syzkaller", {})
    if syzk.get("configured"):
        if syzk.get("line_covered"):
            hit_sys = ", ".join(syzk.get("syscalls", [])) or "unknown"
            out.append(
                f"Dynamic Coverage (Syzkaller): COVERED (executed via syscalls: {hit_sys})"
            )
            out.append(
                "Classification: FULLY PROVEN (Static Call Path + Live Fuzzer Execution)"
            )
        elif syzk.get("fn_covered"):
            out.append(
                f"Dynamic Coverage (Syzkaller): PARTIALLY COVERED ({syzk.get('fn_covered_lines')} lines in function executed, but line {target_info['line']} unfuzzed)"
            )
            out.append(
                "Classification: FUZZING GAP (Function hit, but target branch/line unfuzzed)"
            )
        else:
            out.append(
                "Dynamic Coverage (Syzkaller): UNCOVERED (0 live executions recorded)"
            )
            out.append(
                "Classification: ATTACK SURFACE BLIND SPOT (Statically reachable, but unfuzzed!)"
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
                syzk_tag = " [Syzkaller: Covered]" if step.get("syzk_covered") else " [Static Only]"

            type_info = f" [{ctype}]" if ctype and ctype != "target" else ""
            if details:
                type_info += f" ({details})"
            call_info = f" [calls at line {cs}]" if cs else ""

            if i == 0:
                out.append(f"{indent}└── [Syscall Entry] {fn} ({f}:{l}){syzk_tag}")
            elif i == len(path) - 1:
                out.append(
                    f"{indent}└── [Target Line] {fn} ({f}:{l}){type_info}{syzk_tag}"
                )
            else:
                out.append(
                    f"{indent}└── {fn} ({f}:{l}){call_info}{type_info}{syzk_tag}"
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
    for syscall, path in paths_by_syscall.items():
        if not path:
            continue
        chain = " -> ".join([
            f"{s['function']} ({s['file']}:{s.get('call_site_line') or s['line']})"
            for s in path
        ])
        out.append(chain)
    return "\n\n".join(out)


def format_mermaid(paths_by_syscall: Dict[str, List[Dict[str, Any]]]) -> str:
    """Format call paths as a styled Mermaid diagram with coverage coloring."""
    lines = [
        "```mermaid",
        "graph TD",
        "    classDef covered fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724;",
        "    classDef uncovered fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#856404;",
    ]
    seen_edges = set()
    node_classes = {}

    for syscall, path in paths_by_syscall.items():
        if not path:
            continue
        for i in range(len(path) - 1):
            s_curr = path[i]
            s_next = path[i + 1]
            src_label = f"{s_curr['function']}\\n({s_curr['file']}:{s_curr['line']})"
            dst_label = f"{s_next['function']}\\n({s_next['file']}:{s_next['line']})"
            edge_lbl = (
                f"calls at L{s_curr.get('call_site_line')}"
                if s_curr.get("call_site_line")
                else "calls"
            )
            if s_next.get("details"):
                edge_lbl += f" ({s_next['details']})"

            src_id = f"node_{abs(hash(src_label)) % 100000}"
            dst_id = f"node_{abs(hash(dst_label)) % 100000}"

            node_classes[src_id] = "covered" if s_curr.get("syzk_covered") else "uncovered"
            node_classes[dst_id] = "covered" if s_next.get("syzk_covered") else "uncovered"

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


def find_paths_to_line(
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
    """
    Main programmatic interface to find callgraph paths to a kernel line.
    Returns (target_info, paths_by_syscall).
    """
    if not os.path.isfile(db_file):
        raise FileNotFoundError(f"Database file not found: {db_file}")

    conn = sqlite3.connect(db_file)
    ensure_indexes(conn, verbose=verbose)

    syzk_path = syzkaller_db or find_default_syzkaller_db(codeql_db_path=db_file)
    syzk_conn = sqlite3.connect(syzk_path) if syzk_path and os.path.isfile(syzk_path) else None

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
    syzk_info = get_syzkaller_coverage(syzk_conn, canonical_file, line_number, fn_span=(start_line, end_line))

    target_info = {
        "function": fn_name,
        "file": canonical_file,
        "line": line_number,
        "span": (start_line, end_line),
        "all_syscalls": reachable_syscalls,
        "syzkaller": syzk_info,
    }

    if not reachable_syscalls:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        return target_info, {}

    paths_by_syscall = {}
    if target_syscall:
        if not target_syscall.startswith("__do_sys_") and not target_syscall.startswith("__se_sys_"):
            matched = [
                s
                for s in reachable_syscalls
                if s.endswith(f"_{target_syscall}") or s == target_syscall
            ]
            eval_syscalls = matched if matched else [f"__do_sys_{target_syscall}"]
        else:
            eval_syscalls = [target_syscall]

        for sc in eval_syscalls:
            path = find_shortest_path(
                conn, fn_name, canonical_file, line_number, sc, syzk_conn=syzk_conn, max_depth=max_depth
            )
            if path:
                paths_by_syscall[sc] = path
    elif all_syscalls:
        for sc in reachable_syscalls[:limit_syscalls]:
            path = find_shortest_path(
                conn, fn_name, canonical_file, line_number, sc, syzk_conn=syzk_conn, max_depth=max_depth
            )
            if path:
                paths_by_syscall[sc] = path
    else:
        # Find globally shortest path to ANY syscall in a single pass (< 50ms)
        path = find_shortest_path(
            conn, fn_name, canonical_file, line_number, target_syscall=None, syzk_conn=syzk_conn, max_depth=max_depth
        )
        if path:
            root_sc = path[0]["function"]
            paths_by_syscall[root_sc] = path

    conn.close()
    if syzk_conn:
        syzk_conn.close()
    return target_info, paths_by_syscall


def find_paths_to_function_recursive(
    db_file: str, function: str, max_depth: int = 25
) -> List[List[Tuple[str, str, int]]]:
    """
    Backwards compatibility interface with original find_paths.py.
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

    file_path, start_line, end_line = row
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


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Find call graph reachability paths from syscall entry points to"
            " kernel source lines or functions, correlated with Syzkaller dynamic coverage."
        )
    )
    ap.add_argument(
        "--db",
        default=find_default_db(),
        help="Path to CodeQL SQLite database (default: $CODEQL_DB or codeql_data.db in current directory)",
    )
    ap.add_argument(
        "--syzkaller-db",
        default=None,
        help="Path to Syzkaller coverage SQLite database (default: $SYZKALLER_DB or discovered beside CodeQL DB)",
    )
    ap.add_argument("--file", "-f", help="Kernel source file (e.g. net/socket.c)")
    ap.add_argument(
        "--line", "-l", type=int, help="Line number within the kernel source file"
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
        help="Find paths for all reachable syscalls (default: find shortest path to closest syscall)",
    )
    ap.add_argument(
        "--limit-syscalls",
        type=int,
        default=5,
        help="Maximum number of syscall paths to compute when --all-syscalls is set (default: 5)",
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

    if not args.db or not os.path.isfile(args.db):
        sys.exit(
            "Error: CodeQL database file not found.\n"
            "Please specify via --db /path/to/codeql_data.db or set the CODEQL_DB environment variable."
        )

    if not args.syzkaller_db:
        args.syzkaller_db = find_default_syzkaller_db(codeql_db_path=args.db)

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
        sys.exit("\nError: Please provide either (--file AND --line) or --function.")

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
    except Exception as e:
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


