#!/usr/bin/env python3
"""Kconfig preconditions, Syzkaller coverage, and shared CLI utilities."""

import argparse
import fnmatch
import json
import os
import re
import sqlite3
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    CallerRow,
    LOCATION_RE,
    clean_file_path,
    column_exists,
    ensure_indexes,
    get_enclosing_function,
    get_function_by_name,
    get_functions_by_name,
    get_reachable_entries,
    get_reachable_syscalls,
    table_exists,
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


def is_span_covered_by_syzkaller(
    syzk_conn: Optional[sqlite3.Connection],
    file_path: str,
    fn_span: Tuple[int, int],
) -> bool:
    """Quick boolean check if any line in fn_span was executed in Syzkaller."""
    if not syzk_conn:
        return False
    clean_path = clean_file_path(file_path)
    cur = syzk_conn.cursor()
    cur.execute(
        "SELECT file_id FROM file_path WHERE file_path = ? OR file_path LIKE ?",
        (clean_path, f"%/{clean_path}"),
    )
    row = cur.fetchone()
    if not row:
        return False
    cur.execute(
        "SELECT 1 FROM syzk_cov"
        " WHERE file_id = ? AND code_line_no BETWEEN ? AND ? LIMIT 1",
        (row[0], fn_span[0], fn_span[1]),
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


_DB_VERSION_RE = re.compile(
    r"(?:kernel_dashboard-|run_)v?([0-9]+\.[0-9]+[^\s/]*?)(?:\.db|/|$)"
)


def infer_repo_dir(
    db_path: Optional[str], repo_dir: Optional[str] = None
) -> Optional[str]:
    """Resolve kernel source checkout dir from --repo-dir or WORKSPACE_DIR."""
    if repo_dir:
        return repo_dir if os.path.isdir(repo_dir) else None
    if not db_path:
        return None
    m = _DB_VERSION_RE.search(db_path)
    if not m:
        return None
    ver = m.group(1)
    repo_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..")
    )
    ws_candidates = [
        os.environ.get("WORKSPACE_DIR", ""),
        os.path.expanduser("~/kernel_codeql_workspace"),
        os.path.join(repo_root, "kernel_codeql_workspace"),
    ]
    for ws in ws_candidates:
        if not ws:
            continue
        candidate = os.path.join(ws, f"linux_v{ver}")
        if os.path.isdir(candidate):
            return candidate
    return None


def resolve_syzk_conn(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection] = None,
) -> Optional[sqlite3.Connection]:
    """Return explicit syzk_conn or conn if syzk_cov table is embedded."""
    if syzk_conn is not None:
        return syzk_conn
    cur = conn.cursor()
    if table_exists(cur, "syzk_cov") and table_exists(cur, "file_path"):
        return conn
    return None


def get_file_kconfig_guards(
    conn: sqlite3.Connection,
    file_path: str,
    line_number: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return enriched Kconfig guard records for a file and optional line."""
    clean_p = clean_file_path(file_path)
    exprs = get_line_configs(conn, clean_p, line_number or 1)
    if not exprs:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT DISTINCT config FROM configs"
                " WHERE (path = ? OR path LIKE ?) AND ifdef <= 1"
                " ORDER BY config ASC",
                (clean_p, f"%/{clean_p}"),
            )
            exprs = [r[0] for r in cur.fetchall() if r[0]]
        except sqlite3.Error:
            exprs = []

    kmeta = get_kconfig_metadata(conn, exprs)
    guards: List[Dict[str, Any]] = []
    seen_tokens: Set[str] = set()
    for expr in exprs:
        tokens = CONFIG_TOKEN_RE.findall(expr)
        if not tokens:
            guards.append({"config": expr, "build_val": None})
            continue
        for tok in tokens:
            if tok in seen_tokens:
                continue
            seen_tokens.add(tok)
            info = kmeta.get(tok, {})
            guards.append({
                "config": tok,
                "expr": expr,
                "build_val": info.get("build_val"),
                "type": info.get("type"),
                "depends_on": info.get("depends_on"),
                "kconfig_file": info.get("kconfig_file"),
            })
    return guards


def _query_git_log_row(
    cur: sqlite3.Cursor,
    function_name: str,
    clean_p: str,
    span: Tuple[int, int],
    include_data: bool,
) -> Optional[Tuple[Any, ...]]:
    """Query git_log by (function_name, file_path) or span fallback."""
    cols = (
        "start_line, end_line, author_date, `commit`, data"
        if include_data
        else "start_line, end_line, author_date, `commit`"
    )
    if column_exists(cur, "git_log", "function_name") and function_name:
        cur.execute(
            f"SELECT {cols} FROM git_log"
            " WHERE function_name = ? AND (file_path = ? OR file_path LIKE ?)"
            " ORDER BY CASE WHEN start_line = ? THEN 0 ELSE 1 END LIMIT 1",
            (function_name, clean_p, f"%/{clean_p}", span[0]),
        )
        row = cur.fetchone()
        if row:
            return row

    cur.execute(
        f"SELECT {cols} FROM git_log"
        " WHERE (file_path = ? OR file_path LIKE ?)"
        " AND start_line = ? AND end_line = ? LIMIT 1",
        (clean_p, f"%/{clean_p}", span[0], span[1]),
    )
    return cur.fetchone()


def get_git_log_metadata(
    conn: sqlite3.Connection,
    function_name: str,
    file_path: str,
    span: Tuple[int, int],
    include_data: bool = False,
) -> Optional[Dict[str, Any]]:
    """Return git_log commit, author_date, and optional body for a function."""
    cur = conn.cursor()
    if not table_exists(cur, "git_log"):
        return None
    clean_p = clean_file_path(file_path)
    try:
        row = _query_git_log_row(
            cur, function_name, clean_p, span, include_data
        )
    except sqlite3.Error:
        return None
    if not row:
        return None
    meta: Dict[str, Any] = {
        "start_line": int(row[0]),
        "end_line": int(row[1]),
        "author_date": int(row[2]) if row[2] is not None else None,
        "commit": row[3],
    }
    if include_data:
        meta["data"] = row[4]
    return meta


def format_ambiguous_symbol_error(
    function_name: str, candidates: List[Tuple[str, str, int, int]]
) -> str:
    """Format an actionable AMBIGUOUS_SYMBOL error listing all candidates."""
    lines = [
        (
            f"Error: AMBIGUOUS_SYMBOL: Function '{function_name}' has"
            f" {len(candidates)} definitions across files:"
        ),
    ]
    for fn, fpath, s_line, e_line in candidates:
        lines.append(f"  - {fn} in {fpath}:{s_line}-{e_line}")
    lines.append(
        "Please disambiguate with --file <path> (or pass --allow-ambiguous)."
    )
    return "\n".join(lines)


def build_target_info(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    file_path: str,
    line_number: int,
    **options: Any,
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
    truncated: List[bool] = []
    max_bridge = options.get("max_bridge_depth", 6)
    info: Dict[str, Any] = {
        "function": fn_name,
        "file": canonical_file,
        "line": line_number,
        "span": (start_line, end_line),
    }
    if options.get("is_function_entry") is not None:
        info["is_function_entry"] = options["is_function_entry"]
    info.update({
        "all_syscalls": get_reachable_syscalls(
            conn,
            fn_name,
            max_bridge_depth=max_bridge,
            target_file=canonical_file,
            truncated_out=truncated,
        ),
        "all_entries": get_reachable_entries(
            conn,
            fn_name,
            max_bridge_depth=max_bridge,
            target_file=canonical_file,
            truncated_out=truncated,
        ),
        "depth_truncated": bool(truncated),
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
    parser.add_argument(
        "--allow-ambiguous",
        action="store_true",
        help="Pick first candidate if --function matches multiple files",
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
            "--max-bridge-depth",
            type=int,
            default=6,
            help="Maximum indirect/async bridge depth (default: 6)",
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


def add_standard_tool_cli_args(
    parser: argparse.ArgumentParser,
    *,
    include_syzkaller: bool = True,
    include_repo_dir: bool = False,
) -> None:
    """Register common --db, --syzkaller-db, --repo-dir, --format, and flags."""
    parser.add_argument(
        "--db", required=True, help="Path to CodeQL SQLite database"
    )
    if include_syzkaller:
        parser.add_argument(
            "--syzkaller-db",
            default=None,
            help="Path to Syzkaller coverage SQLite database (optional)",
        )
    if include_repo_dir:
        parser.add_argument(
            "--repo-dir",
            default=None,
            help=(
                "Optional kernel source tree path (auto-detected from"
                " WORKSPACE_DIR)"
            ),
        )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--ensure-indexes",
        action="store_true",
        help="Ensure fast SQLite indexes exist on the database and exit",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print debug information"
    )


def verify_db_and_indexes(args: argparse.Namespace) -> bool:
    """Validate --db/--syzkaller-db and return True if --ensure-indexes ran."""
    if not os.path.isfile(args.db):
        sys.exit(f"Error: Database file not found: {args.db}")
    syzk_db = getattr(args, "syzkaller_db", None)
    if syzk_db and not os.path.isfile(syzk_db):
        sys.exit(f"Error: Syzkaller database file not found: {syzk_db}")
    if getattr(args, "ensure_indexes", False):
        conn = sqlite3.connect(args.db)
        ensure_indexes(conn, verbose=True)
        conn.close()
        print("Indexes verified successfully.")
        return True
    return False


def handle_common_cli_setup(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    resolve_function_to_line: bool = True,
) -> Optional[bool]:
    """Validate DB files, handle --ensure-indexes, and resolve --function."""
    if verify_db_and_indexes(args):
        return None

    is_function_entry = False
    if resolve_function_to_line and args.function and args.line is None:
        conn = sqlite3.connect(args.db)
        candidates = get_functions_by_name(conn, args.function, args.file)
        if not candidates and args.file:
            fn_fallback = get_function_by_name(conn, args.function, args.file)
            candidates = [fn_fallback] if fn_fallback else []
        conn.close()
        if not candidates:
            sys.exit(
                f"Error: Function '{args.function}' not found in"
                " function_locations table."
            )
        if (
            len(candidates) > 1
            and not args.file
            and not getattr(args, "allow_ambiguous", False)
        ):
            sys.exit(format_ambiguous_symbol_error(args.function, candidates))
        fn_row = candidates[0]
        args.file = fn_row[1]
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
        "max_bridge_depth": getattr(args, "max_bridge_depth", 6),
        "verbose": args.verbose,
    }
    if is_function_entry is not None:
        kwargs["is_function_entry"] = is_function_entry
    return kwargs


def clean_def_location(def_loc: Optional[str]) -> str:
    """Normalize the file-path prefix of a 5-part CodeQL location string."""
    if not def_loc:
        return "unknown"
    m = LOCATION_RE.match(def_loc)
    if not m:
        return clean_file_path(def_loc)
    return (
        f"{clean_file_path(m.group(1))}:"
        f"{m.group(2)}:{m.group(3)}:{m.group(4)}:{m.group(5)}"
    )


def parse_loc_file_line(loc_str: str) -> Tuple[str, int]:
    """Extract (clean_file_path, start_line) from a CodeQL location string."""
    m = LOCATION_RE.match(loc_str or "")
    if m:
        return clean_file_path(m.group(1)), int(m.group(2))
    parts = (loc_str or "").split(":")
    if len(parts) >= 2 and parts[1].isdigit():
        return clean_file_path(parts[0]), int(parts[1])
    return clean_file_path(loc_str or ""), 0


def name_matches_pattern(name: str, pattern: str, match_mode: str) -> bool:
    """Check whether symbol or struct name matches pattern under match_mode."""
    if match_mode == "exact":
        return name == pattern
    if match_mode in ("wildcard", "substring"):
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatchcase(name, pattern)
        return pattern in name
    if match_mode == "regex":
        return bool(re.search(pattern, name))
    return name == pattern


def load_reachable_fn_sets(
    conn: sqlite3.Connection,
    fn_names: Optional[Set[str]] = None,
) -> Tuple[Set[str], Set[str]]:
    """Load sets of function names present in syscall_node and entry_node."""
    if fn_names is not None:
        valid = [f for f in fn_names if f and f != "unknown"]
        if not valid:
            return set(), set()
    else:
        valid = []

    cur = conn.cursor()
    sys_fns: Set[str] = set()
    ent_fns: Set[str] = set()
    has_sys = table_exists(cur, "syscall_node")
    has_ent = table_exists(cur, "entry_node")
    if fn_names is None:
        if has_sys:
            cur.execute("SELECT DISTINCT function FROM syscall_node")
            sys_fns = {r[0] for r in cur.fetchall() if r[0]}
        if has_ent:
            cur.execute("SELECT DISTINCT function FROM entry_node")
            ent_fns = {r[0] for r in cur.fetchall() if r[0]}
        return sys_fns, ent_fns

    for idx in range(0, len(valid), 500):
        batch = valid[idx : idx + 500]
        ph = ",".join("?" for _ in batch)
        if has_sys:
            cur.execute(
                f"SELECT DISTINCT function FROM syscall_node"
                f" WHERE function IN ({ph})",
                batch,
            )
            sys_fns.update(r[0] for r in cur.fetchall() if r[0])
        if has_ent:
            cur.execute(
                f"SELECT DISTINCT function FROM entry_node"
                f" WHERE function IN ({ph})",
                batch,
            )
            ent_fns.update(r[0] for r in cur.fetchall() if r[0])
    return sys_fns, ent_fns


def run_json_or_text_cli(
    args: argparse.Namespace,
    action_fn: Callable[[], Any],
    text_formatter: Callable[[Any], str],
) -> None:
    """Validate DB, run action_fn with error handling, and emit JSON or text."""
    if verify_db_and_indexes(args):
        return
    try:
        res = action_fn()
    except (
        FileNotFoundError,
        ValueError,
        sqlite3.Error,
        OSError,
        re.error,
    ) as exc:
        sys.exit(f"Error: {exc}")
    if getattr(args, "format", "text") == "json":
        print(json.dumps(res, indent=2))
    else:
        print(text_formatter(res))
