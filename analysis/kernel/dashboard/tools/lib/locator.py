#!/usr/bin/env python3
"""Atomic function-resolution, disambiguation, and Kconfig diagnosis helpers."""

import os
import re
import sqlite3
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    _filter_node_rows_by_file,
    clean_file_path,
    file_matches_filter,
    get_callers,
    get_enclosing_function,
    get_functions_by_name,
    is_non_runtime_path,
    is_syscall_root,
    open_databases,
    table_exists,
)
from tools.lib.metadata import (
    get_file_kconfig_guards,
    get_git_log_metadata,
    infer_repo_dir,
    is_span_covered_by_syzkaller,
    resolve_syzk_conn,
)

_STOP_SCAN_RE = re.compile(r"[;{}]\s*$|^#")


def _lookup_entry_root_kind(
    conn: sqlite3.Connection, function_name: str
) -> Optional[str]:
    """Return entry_kind if function_name is an entry root in entry_node."""
    cur = conn.cursor()
    if not table_exists(cur, "entry_node"):
        return None
    try:
        cur.execute(
            "SELECT entry_kind FROM entry_node WHERE entry = ? LIMIT 1",
            (function_name,),
        )
        row = cur.fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def classify_function_kind(
    conn: sqlite3.Connection, function_name: str, file_path: str
) -> str:
    """Classify a (function_name, file_path) definition into a semantic kind."""
    clean_f = clean_file_path(file_path)
    if is_non_runtime_path(clean_f):
        return "non_runtime_boot_or_tool"
    if is_syscall_root(function_name):
        return "entry_root:syscall"
    entry_kind = _lookup_entry_root_kind(conn, function_name)
    if entry_kind:
        return f"entry_root:{entry_kind}"
    if clean_f.endswith(".h"):
        return "header_inline"
    if clean_f.startswith("arch/"):
        return "arch_specific"
    return "tu_definition"


def find_brace_line_in_text(text: str, start_line: int) -> int:
    """Find 1-based line number of the opening '{' in function source text."""
    for offset, line in enumerate(text.splitlines()):
        if "{" in line:
            return start_line + offset
    return start_line


def _scan_upward_sig_start(
    file_lines: List[str], function_name: str, start_line: int
) -> int:
    """Scan up to 6 lines above start_line for signature on legacy DBs."""
    idx = start_line - 1
    if idx < 0 or idx >= len(file_lines):
        return start_line
    if not file_lines[idx].lstrip().startswith("{"):
        return start_line
    sig_start = start_line
    for lookback in range(1, 7):
        pos = idx - lookback
        if pos < 0:
            break
        prev = file_lines[pos].strip()
        if not prev or _STOP_SCAN_RE.search(prev) or prev.endswith("*/"):
            break
        sig_start = pos + 1
        if function_name in prev:
            break
    return sig_start


def detect_span_lines(
    conn: sqlite3.Connection,
    fn_row: Tuple[str, str, int, int],
    repo_dir: Optional[str] = None,
) -> Dict[str, int]:
    """Return sig_start_line, body_start_line, and end_line for fn_row."""
    fn_name, fpath, s_line, e_line = fn_row
    clean_f = clean_file_path(fpath)
    if repo_dir:
        full_p = os.path.join(repo_dir, clean_f)
        if os.path.isfile(full_p):
            try:
                with open(full_p, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
                sig_start = _scan_upward_sig_start(lines, fn_name, s_line)
                snippet = "\n".join(
                    lines[sig_start - 1 : min(e_line, sig_start + 12)]
                )
                body_start = find_brace_line_in_text(snippet, sig_start)
                return {
                    "sig_start_line": sig_start,
                    "body_start_line": body_start,
                    "end_line": e_line,
                }
            except OSError:
                pass

    gmeta = get_git_log_metadata(
        conn, fn_name, clean_f, (s_line, e_line), include_data=True
    )
    if gmeta and gmeta.get("data"):
        body_start = find_brace_line_in_text(gmeta["data"], s_line)
        return {
            "sig_start_line": s_line,
            "body_start_line": body_start,
            "end_line": e_line,
        }
    return {
        "sig_start_line": s_line,
        "body_start_line": s_line,
        "end_line": e_line,
    }


def _count_direct_syscall_reach(
    cur: sqlite3.Cursor, function_name: str, clean_f: str
) -> int:
    """Count distinct syscalls in syscall_node reaching (function, file)."""
    if not table_exists(cur, "syscall_node"):
        return 0
    cur.execute(
        "SELECT DISTINCT syscall, function_location"
        " FROM syscall_node WHERE function = ?",
        (function_name,),
    )
    rows = _filter_node_rows_by_file(
        cur, function_name, clean_f, cur.fetchall(), loc_idx=1
    )
    return len({r[0] for r in rows})


def _count_direct_entry_reach(
    cur: sqlite3.Cursor, function_name: str, clean_f: str
) -> int:
    """Count distinct non-syscall entries in entry_node reaching function."""
    if not table_exists(cur, "entry_node"):
        return 0
    cur.execute(
        "SELECT DISTINCT entry_kind, entry, function_location"
        " FROM entry_node WHERE function = ?",
        (function_name,),
    )
    rows = _filter_node_rows_by_file(
        cur, function_name, clean_f, cur.fetchall(), loc_idx=2
    )
    entries = {(r[0], r[1]) for r in rows}
    cur.execute(
        "SELECT DISTINCT entry_kind, entry, entry_location"
        " FROM entry_node WHERE entry = ? LIMIT 5",
        (function_name,),
    )
    root_rows = _filter_node_rows_by_file(
        cur, function_name, clean_f, cur.fetchall(), loc_idx=2
    )
    entries.update((r[0], r[1]) for r in root_rows)
    return len(entries)


def compute_candidate_degree(
    conn: sqlite3.Connection, function_name: str, file_path: str
) -> Dict[str, int]:
    """Compute caller counts and reachability root counts for a candidate."""
    clean_f = clean_file_path(file_path)
    callers = get_callers(conn, function_name, target_file=clean_f)
    direct = sum(1 for c in callers if c[4] == "direct")
    indirect = sum(1 for c in callers if c[4] == "indirect")
    async_c = sum(1 for c in callers if c[4] == "async")
    cur = conn.cursor()
    return {
        "direct_callers": direct,
        "indirect_ops_callers": indirect,
        "async_callers": async_c,
        "reachable_syscalls": _count_direct_syscall_reach(
            cur, function_name, clean_f
        ),
        "reachable_entries": _count_direct_entry_reach(
            cur, function_name, clean_f
        ),
    }


def _fetch_raw_function_rows(
    cur: sqlite3.Cursor, name: str, match_mode: str
) -> List[Tuple[str, str, int, int]]:
    """Fetch raw function_locations rows for substring or regex match_mode."""
    if match_mode == "substring":
        cur.execute(
            "SELECT DISTINCT function_name, file_path, start_line, end_line"
            " FROM function_locations WHERE function_name LIKE ?"
            " ORDER BY function_name ASC, file_path ASC, start_line ASC",
            (f"%{name}%",),
        )
        return list(cur.fetchall())
    if match_mode == "regex":
        pattern = re.compile(name)
        cur.execute(
            "SELECT DISTINCT function_name, file_path, start_line, end_line"
            " FROM function_locations"
            " ORDER BY function_name ASC, file_path ASC, start_line ASC"
        )
        return [r for r in cur.fetchall() if pattern.search(r[0] or "")]
    raise ValueError(f"Unsupported match_mode: {match_mode}")


def query_function_candidates(
    conn: sqlite3.Connection,
    name: str,
    file_filter: Optional[str] = None,
    match_mode: str = "exact",
    include_non_runtime: bool = False,
) -> List[Tuple[str, str, int, int]]:
    """Query function_locations using exact, substring, or regex matching."""
    if match_mode == "exact":
        return get_functions_by_name(
            conn, name, file_filter, include_non_runtime=include_non_runtime
        )

    raw_rows = _fetch_raw_function_rows(conn.cursor(), name, match_mode)
    results: List[Tuple[str, str, int, int]] = []
    seen: Set[Tuple[str, str, int, int]] = set()
    for fn, fpath, s_line, e_line in raw_rows:
        clean_f = clean_file_path(fpath)
        if not include_non_runtime and not file_filter:
            if is_non_runtime_path(clean_f):
                continue
        if file_filter and not file_matches_filter(clean_f, file_filter):
            continue
        item = (fn, clean_f, s_line, e_line)
        if item not in seen:
            seen.add(item)
            results.append(item)
    return results


def find_fallback_suggestions(
    conn: sqlite3.Connection,
    name: str,
    file_filter: Optional[str] = None,
    limit: int = 10,
) -> List[str]:
    """Suggest syscall wrappers, compiler clones, or substring matches."""
    cur = conn.cursor()
    suggestions: List[str] = []
    seen: Set[str] = set()
    variants = [
        f"__do_sys_{name}",
        f"__se_sys_{name}",
        f"__x64_sys_{name}",
        f"ksys_{name}",
        f"vfs_{name}",
        f"do_{name}",
        f"__{name}",
        f"____{name}",
    ]
    placeholders = ",".join("?" for _ in variants)
    cur.execute(
        "SELECT DISTINCT function_name, file_path FROM function_locations"
        f" WHERE function_name IN ({placeholders})"
        " OR function_name LIKE ?"
        " ORDER BY length(function_name) ASC, function_name ASC",
        (*variants, f"{name}.%"),
    )
    rows = list(cur.fetchall())
    if len(rows) < limit:
        cur.execute(
            "SELECT DISTINCT function_name, file_path FROM function_locations"
            " WHERE function_name LIKE ?"
            " ORDER BY length(function_name) ASC, function_name ASC LIMIT 50",
            (f"%{name}%",),
        )
        rows.extend(cur.fetchall())

    for fn, fpath in rows:
        clean_f = clean_file_path(fpath)
        if is_non_runtime_path(clean_f):
            continue
        if file_filter and not file_matches_filter(clean_f, file_filter):
            continue
        if fn not in seen and fn != name:
            seen.add(fn)
            suggestions.append(fn)
            if len(suggestions) >= limit:
                break
    return suggestions


def _run_repo_grep(repo_dir: str, name: str) -> str:
    """Run git grep or rg in repo_dir for function name definition lines."""
    cmds = [
        [
            "git",
            "-C",
            repo_dir,
            "grep",
            "-n",
            f"{name}(",
            "--",
            "*.[ch]",
        ],
        [
            "rg",
            "-n",
            "--no-heading",
            "-g",
            "*.[ch]",
            rf"\b{re.escape(name)}\s*\(",
            repo_dir,
        ],
    ]
    for cmd in cmds:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout
        except (OSError, subprocess.SubprocessError):
            continue
    return ""


def scan_repo_for_uncompiled_definition(
    repo_dir: str, name: str, file_filter: Optional[str] = None
) -> List[Tuple[str, int]]:
    """Locate uncompiled C definitions of name in repo_dir."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return []
    fn_re = re.compile(
        rf"^\s*(?:[A-Za-z_][\w\s\*]*\s+)?\b{re.escape(name)}\s*\("
    )
    if file_filter:
        clean_f = clean_file_path(file_filter)
        full_p = os.path.join(repo_dir, clean_f)
        if os.path.isfile(full_p):
            hits: List[Tuple[str, int]] = []
            try:
                with open(full_p, "r", encoding="utf-8", errors="replace") as f:
                    for idx, line in enumerate(f, start=1):
                        if fn_re.search(line) and not line.strip().endswith(
                            ";"
                        ):
                            hits.append((clean_f, idx))
            except OSError:
                pass
            return hits

    stdout = _run_repo_grep(repo_dir, name)
    hits = []
    for line in stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3 or parts[2].strip().endswith(";"):
            continue
        raw_p = parts[0]
        rel_p = clean_file_path(
            os.path.relpath(raw_p, repo_dir) if os.path.isabs(raw_p) else raw_p
        )
        if file_filter and not file_matches_filter(rel_p, file_filter):
            continue
        if fn_re.search(parts[2]):
            hits.append((rel_p, int(parts[1])))
    return hits[:10]


def diagnose_uncompiled_symbol(
    conn: sqlite3.Connection,
    name: Optional[str],
    file_filter: Optional[str] = None,
    line_number: Optional[int] = None,
    repo_dir: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Diagnose why a function or file:line is absent from compiled tables."""
    target_locs: List[Tuple[str, Optional[int]]] = []
    if name and repo_dir:
        for rel_p, ln in scan_repo_for_uncompiled_definition(
            repo_dir, name, file_filter
        ):
            target_locs.append((rel_p, ln))
    if not target_locs and file_filter:
        target_locs.append((clean_file_path(file_filter), line_number))

    if not target_locs:
        return None

    rel_p, ln = target_locs[0]
    guards = get_file_kconfig_guards(conn, rel_p, ln)
    blocking = [g for g in guards if g.get("build_val") in ("n", None, "")]
    return {
        "compiled": False,
        "file_path": rel_p,
        "line": ln,
        "kconfig_guards": guards,
        "blocking_kconfigs": blocking,
    }


def build_candidate_record(
    conn: sqlite3.Connection,
    fn_row: Tuple[str, str, int, int],
    syzk_conn: Optional[sqlite3.Connection] = None,
    repo_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble candidate metadata dict for a function_locations row."""
    fn_name, fpath, s_line, e_line = fn_row
    clean_f = clean_file_path(fpath)
    span_info = detect_span_lines(conn, fn_row, repo_dir=repo_dir)
    gmeta = get_git_log_metadata(
        conn, fn_name, clean_f, (s_line, e_line), include_data=False
    )
    eff_syzk = resolve_syzk_conn(conn, syzk_conn)
    return {
        "key": {"function_name": fn_name, "file_path": clean_f},
        "compiled": True,
        "kind": classify_function_kind(conn, fn_name, clean_f),
        "span": span_info,
        "degree": compute_candidate_degree(conn, fn_name, clean_f),
        "kconfig_guards": get_file_kconfig_guards(conn, clean_f, s_line),
        "git_meta": (
            {
                "commit": gmeta["commit"],
                "author_date": gmeta["author_date"],
            }
            if gmeta
            else None
        ),
        "syzkaller_covered": is_span_covered_by_syzkaller(
            eff_syzk, clean_f, (s_line, e_line)
        ),
    }


def locate_functions_with_conn(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection] = None,
    **query_opts: Any,
) -> Dict[str, Any]:
    """Resolve function candidates over an open SQLite connection."""
    name: Optional[str] = query_opts.get("name")
    file_path: Optional[str] = query_opts.get("file_path")
    line_number: Optional[int] = query_opts.get("line_number")
    match_mode: str = query_opts.get("match_mode", "exact")
    repo_dir: Optional[str] = query_opts.get("repo_dir")
    include_non_runtime: bool = bool(query_opts.get("include_non_runtime"))
    limit: int = query_opts.get("limit", 50)

    if file_path and line_number is not None and not name:
        enc = get_enclosing_function(conn, file_path, line_number)
        rows = [enc] if enc else []
    elif name:
        rows = query_function_candidates(
            conn,
            name,
            file_filter=file_path,
            match_mode=match_mode,
            include_non_runtime=include_non_runtime,
        )
    else:
        raise ValueError("Provide either --name or (--file and --line).")

    candidates = [
        build_candidate_record(conn, r, syzk_conn=syzk_conn, repo_dir=repo_dir)
        for r in rows[:limit]
    ]
    suggestions: List[str] = []
    uncompiled: Optional[Dict[str, Any]] = None
    if not candidates:
        if name and match_mode == "exact":
            suggestions = find_fallback_suggestions(conn, name, file_path)
        uncompiled = diagnose_uncompiled_symbol(
            conn, name, file_path, line_number, repo_dir=repo_dir
        )

    return {
        "query": {
            "name": name,
            "file": clean_file_path(file_path) if file_path else None,
            "line": line_number,
            "match": match_mode,
        },
        "count": len(rows),
        "is_ambiguous": len(rows) > 1,
        "candidates": candidates,
        "suggestions": suggestions,
        "uncompiled_diagnosis": uncompiled,
    }


def locate_functions(db_path: str, **query_opts: Any) -> Dict[str, Any]:
    """Open database and resolve function candidates with full metadata."""
    conn, syzk_conn = open_databases(
        db_path,
        syzkaller_db=query_opts.get("syzkaller_db"),
        verbose=bool(query_opts.get("verbose")),
    )
    if not query_opts.get("repo_dir"):
        query_opts["repo_dir"] = infer_repo_dir(db_path)
    try:
        return locate_functions_with_conn(conn, syzk_conn, **query_opts)
    finally:
        conn.close()
        if syzk_conn:
            syzk_conn.close()


def _format_candidate_line(idx: int, cand: Dict[str, Any]) -> List[str]:
    """Format a single candidate record for human-readable CLI output."""
    key = cand["key"]
    span = cand["span"]
    deg = cand["degree"]
    kcfgs = [g["config"] for g in cand.get("kconfig_guards", [])]
    cfg_str = f" | Kconfig: {', '.join(kcfgs)}" if kcfgs else ""
    syzk_str = " | Syzkaller: COVERED" if cand.get("syzkaller_covered") else ""
    git_m = cand.get("git_meta")
    git_str = (
        f" | commit: {git_m['commit'][:12]}"
        if git_m and git_m.get("commit")
        else ""
    )
    return [
        (
            f"  [{idx}] {key['function_name']} ({key['file_path']}:"
            f"{span['sig_start_line']}-{span['end_line']}) [{cand['kind']}]"
        ),
        (
            f"      Callers: {deg['direct_callers']} direct,"
            f" {deg['indirect_ops_callers']} indirect_ops,"
            f" {deg['async_callers']} async |"
            f" Reachable: {deg['reachable_syscalls']} syscall(s),"
            f" {deg['reachable_entries']} entry root(s)"
            f"{cfg_str}{syzk_str}{git_str}"
        ),
    ]


def format_locator_text(result: Dict[str, Any]) -> str:
    """Format locate_functions result dict into a human-readable report."""
    q = result["query"]
    q_desc = q.get("name") or f"{q.get('file')}:{q.get('line')}"
    status = (
        "AMBIGUOUS"
        if result["is_ambiguous"]
        else ("FOUND" if result["count"] == 1 else "NOT FOUND")
    )
    lines = [
        "=" * 72,
        (
            f"FUNCTION LOCATOR: '{q_desc}' (match={q['match']}) -> {status}"
            f" ({result['count']} candidate(s))"
        ),
        "=" * 72,
    ]
    for idx, cand in enumerate(result["candidates"], start=1):
        lines.extend(_format_candidate_line(idx, cand))

    if result.get("uncompiled_diagnosis"):
        diag = result["uncompiled_diagnosis"]
        lines.append(
            f"  Uncompiled Source Match: {diag['file_path']}"
            + (f":{diag['line']}" if diag.get("line") else "")
        )
        if diag.get("blocking_kconfigs"):
            b_strs = [
                f"{g['config']} (build_val={g.get('build_val') or 'n'})"
                for g in diag["blocking_kconfigs"]
            ]
            lines.append(f"  Blocking Kconfigs: {', '.join(b_strs)}")

    if result.get("suggestions"):
        lines.append(f"  Suggestions: {', '.join(result['suggestions'])}")
    lines.append("=" * 72)
    return "\n".join(lines)
