#!/usr/bin/env python3
"""Kconfig preconditions, Syzkaller coverage, and shared CLI utilities."""

import argparse
import os
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    CallerRow,
    clean_file_path,
    ensure_indexes,
    get_enclosing_function,
    get_function_by_name,
    get_reachable_entries,
    get_reachable_syscalls,
)

CONFIG_TOKEN_RE = re.compile(r"\b(CONFIG_[A-Za-z0-9_]+)\b")
_KCONFIG_KEYS = (
    "type prompt depends_on select_list default_val build_val"
    " kconfig_file line_no"
).split()


def _query_fn_span_coverage(
    cur: sqlite3.Cursor, file_id: int, fn_span: Optional[Tuple[int, int]]
) -> Tuple[int, int]:
    """Return (covered_lines, covered_progs) within fn_span for file_id."""
    if not fn_span:
        return 0, 0
    cur.execute(
        "SELECT count(DISTINCT code_line_no), count(DISTINCT prog_id)"
        " FROM syzk_cov WHERE file_id = ? AND code_line_no BETWEEN ? AND ?",
        (file_id, fn_span[0], fn_span[1]),
    )
    row = cur.fetchone()
    return (row[0], row[1]) if row else (0, 0)


def get_syzkaller_coverage(
    syzk_conn: Optional[sqlite3.Connection],
    file_path: str,
    line_number: int,
    fn_span: Optional[Tuple[int, int]] = None,
) -> Dict[str, Any]:
    """Query dynamic Syzkaller coverage for a kernel line and function span."""
    if not syzk_conn:
        return {"configured": False}

    cur = syzk_conn.cursor()
    clean_path = clean_file_path(file_path)
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
    cur.execute(
        "SELECT DISTINCT s.syscall, c.prog_id, p.prog_code FROM syzk_cov c"
        " LEFT JOIN syscalls s ON c.prog_id = s.prog_id"
        " LEFT JOIN syzk_prog p ON c.prog_id = p.prog_id"
        " WHERE c.file_id = ? AND c.code_line_no = ?",
        (file_id, line_number),
    )
    hits = cur.fetchall()
    fn_lines, fn_progs = _query_fn_span_coverage(cur, file_id, fn_span)
    progs = [
        {"prog_id": r[1], "syscall": r[0], "prog_code": r[2]}
        for r in hits
        if r[1]
    ]
    return {
        "configured": True,
        "file_tracked": True,
        "line_covered": bool(hits),
        "exact_hits_count": len(hits),
        "syscalls": sorted({r[0] for r in hits if r[0]}),
        "progs": progs[:5],
        "fn_covered": fn_lines > 0,
        "fn_covered_lines": fn_lines,
        "fn_covered_progs": fn_progs,
    }


def is_line_covered_by_syzkaller(
    syzk_conn: Optional[sqlite3.Connection], file_path: str, line_number: int
) -> bool:
    """Quick boolean check if a line has been executed in Syzkaller."""
    if not syzk_conn:
        return False
    clean_path = clean_file_path(file_path)
    cur = syzk_conn.cursor()
    cur.execute(
        "SELECT 1 FROM syzk_cov c JOIN file_path f ON c.file_id = f.file_id"
        " WHERE (f.file_path = ? OR f.file_path LIKE ?)"
        " AND c.code_line_no = ? LIMIT 1",
        (clean_path, f"%/{clean_path}", line_number),
    )
    return cur.fetchone() is not None


def _invert_config_expr(config: str) -> str:
    """Invert a CONFIG_* expression for the #else branch of a guard."""
    if config.startswith("!") and " " not in config:
        return config[1:]
    return f"!({config})" if " " in config else f"!{config}"


def get_line_configs(
    conn: sqlite3.Connection, file_path: str, line_number: Optional[int]
) -> List[str]:
    """Return all active CONFIG_* guards covering (file_path, line_number)."""
    if line_number is None:
        return []
    clean_path = clean_file_path(file_path)
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT config, ifdef, endif, else_ FROM configs"
            " WHERE (path = ? OR path LIKE ?) AND ? BETWEEN ifdef AND endif"
            " ORDER BY ifdef ASC, config ASC",
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
            "SELECT config, type, prompt, depends_on, select_list,"
            " default_val, build_val, kconfig_file, line_no"
            f" FROM kconfig_symbols WHERE config IN ({placeholders})",
            sorted(tokens),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        return {}
    return {row[0]: dict(zip(_KCONFIG_KEYS, row[1:])) for row in rows}


def build_target_info(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    file_path: str,
    line_number: int,
    is_function_entry: Optional[bool] = None,
) -> Dict[str, Any]:
    """Resolve target file:line to enclosing function and reachability info."""
    fn_info = get_enclosing_function(conn, file_path, line_number)
    if not fn_info:
        conn.close()
        if syzk_conn:
            syzk_conn.close()
        raise ValueError(
            f"No enclosing function found for {file_path}:{line_number}"
        )

    fn_name, canonical_file, start_line, end_line = fn_info
    target_configs = get_line_configs(conn, canonical_file, line_number)
    info: Dict[str, Any] = {
        "function": fn_name,
        "file": canonical_file,
        "line": line_number,
        "span": (start_line, end_line),
    }
    if is_function_entry is not None:
        info["is_function_entry"] = is_function_entry
    info.update({
        "all_syscalls": get_reachable_syscalls(conn, fn_name),
        "all_entries": get_reachable_entries(conn, fn_name),
        "configs": target_configs,
        "kconfig_metadata": get_kconfig_metadata(conn, target_configs),
        "syzkaller": get_syzkaller_coverage(
            syzk_conn,
            canonical_file,
            line_number,
            fn_span=(start_line, end_line),
        ),
    })
    return info


def make_path_step(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    function: str,
    file_path: str,
    line: int,
    **extra: Any,
) -> Dict[str, Any]:
    """Construct a call-path step record with Kconfig and Syzkaller status."""
    call_site_line = extra.pop("call_site_line", None)
    call_type = extra.pop("call_type", "target")
    details = extra.pop("details", "")
    check_line = call_site_line or line
    step: Dict[str, Any] = {
        "function": function,
        "file": file_path,
        "line": line,
        "call_site_line": call_site_line,
        "call_type": call_type,
        "details": details,
        "configs": get_line_configs(conn, file_path, check_line),
        "syzk_covered": is_line_covered_by_syzkaller(
            syzk_conn, file_path, check_line
        ),
    }
    step.update(extra)
    return step


def make_caller_step(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    caller: CallerRow,
    **extra: Any,
) -> Dict[str, Any]:
    """Construct a call-path step record from a 6-tuple caller row."""
    return make_path_step(
        conn,
        syzk_conn,
        caller[0],
        caller[1],
        caller[2],
        call_site_line=caller[3],
        call_type=caller[4],
        details=caller[5],
        **extra,
    )


def add_common_cli_args(
    parser: argparse.ArgumentParser,
    include_reachability_flags: bool = True,
) -> None:
    """Register standard CLI arguments shared by the analysis tools."""
    parser.add_argument(
        "--db", required=True, help="Path to CodeQL SQLite database"
    )
    parser.add_argument(
        "--syzkaller-db",
        default=None,
        help="Path to Syzkaller coverage SQLite database (optional)",
    )
    parser.add_argument(
        "--file", "-f", help="Kernel source file (e.g. mm/shmem.c)"
    )
    parser.add_argument(
        "--line", "-l", type=int, help="Line number within kernel source file"
    )
    parser.add_argument(
        "--function", "-fn", help="Direct function name to analyze"
    )
    if include_reachability_flags:
        parser.add_argument(
            "--syscall",
            "-s",
            help="Target a specific syscall (e.g. recvmsg or __do_sys_recvmsg)",
        )
        parser.add_argument(
            "--max-depth",
            type=int,
            default=25,
            help="Maximum call graph traversal depth (default: 25)",
        )
        parser.add_argument(
            "--all-syscalls",
            "-a",
            action="store_true",
            help="Evaluate all reachable syscalls up to --limit-syscalls",
        )
        parser.add_argument(
            "--limit-syscalls",
            type=int,
            default=5,
            help="Maximum syscall paths when --all-syscalls is set",
        )
    parser.add_argument(
        "--ensure-indexes",
        action="store_true",
        help="Ensure fast SQLite indexes exist on the database and exit",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print debug information"
    )


def handle_common_cli_setup(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    resolve_function_to_line: bool = True,
) -> Optional[bool]:
    """Validate DB files, handle --ensure-indexes, and resolve --function."""
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
        return None

    is_function_entry = False
    if resolve_function_to_line and args.function and not args.file:
        conn = sqlite3.connect(args.db)
        fn_row = get_function_by_name(conn, args.function)
        conn.close()
        if not fn_row:
            sys.exit(
                f"Error: Function '{args.function}' not found in"
                " function_locations table."
            )
        args.file = fn_row[1]
        if args.line is None:
            args.line = fn_row[2]
            is_function_entry = True

    if resolve_function_to_line and (not args.file or args.line is None):
        parser.print_help()
        sys.exit(
            "\nError: Please provide either (--file AND --line) or --function."
        )
    return is_function_entry


def extract_reachability_cli_kwargs(
    args: argparse.Namespace, is_function_entry: Optional[bool] = None
) -> Dict[str, Any]:
    """Build standard keyword arguments dict for reachability analysis calls."""
    kwargs: Dict[str, Any] = {
        "target_syscall": args.syscall,
        "syzkaller_db": args.syzkaller_db,
        "all_syscalls": args.all_syscalls,
        "limit_syscalls": args.limit_syscalls,
        "max_depth": args.max_depth,
        "verbose": args.verbose,
    }
    if is_function_entry is not None:
        kwargs["is_function_entry"] = is_function_entry
    return kwargs
