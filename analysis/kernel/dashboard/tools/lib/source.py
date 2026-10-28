#!/usr/bin/env python3
"""Atomic function-body and source-window fetching and annotation utilities."""

from collections import defaultdict
import os
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.lib.callgraph import (
    LOCATION_RE,
    clean_file_path,
    get_enclosing_function,
    get_function_by_name,
    get_functions_by_name,
    open_databases,
    query_span_outgoing_calls,
    table_exists,
)
from tools.lib.locator import _scan_upward_sig_start
from tools.lib.metadata import (
    format_ambiguous_symbol_error,
    get_git_log_metadata,
    infer_repo_dir,
    resolve_syzk_conn,
)
from tools.lib.privilege import LINUX_UAPI_CAPABILITIES, format_capability


def read_disk_lines(repo_dir: str, file_path: str) -> Optional[List[str]]:
    """Read source file lines from repo_dir if the file exists on disk."""
    if not repo_dir or not os.path.isdir(repo_dir):
        return None
    full_p = os.path.join(repo_dir, clean_file_path(file_path))
    if not os.path.isfile(full_p):
        return None
    try:
        with open(full_p, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return None


def slice_disk_span(
    file_lines: List[str],
    start_line: int,
    end_line: int,
    context: int = 0,
    function_name: Optional[str] = None,
) -> Tuple[int, int, List[Tuple[int, str]]]:
    """Slice 1-based line range with upward signature scan and context."""
    sig_start = (
        _scan_upward_sig_start(file_lines, function_name, start_line)
        if function_name
        else start_line
    )
    win_start = max(1, sig_start - max(0, context))
    win_end = min(len(file_lines), end_line + max(0, context))
    numbered = [
        (ln, file_lines[ln - 1]) for ln in range(win_start, win_end + 1)
    ]
    return sig_start, end_line, numbered


def slice_git_log_span(
    conn: sqlite3.Connection,
    function_name: Optional[str],
    file_path: str,
    start_line: int,
    end_line: int,
) -> Optional[Dict[str, Any]]:
    """Fetch numbered function body lines from git_log table as fallback."""
    gmeta = get_git_log_metadata(
        conn,
        function_name or "",
        file_path,
        (start_line, end_line),
        include_data=True,
    )
    if not gmeta or not gmeta.get("data"):
        return None
    s_line = gmeta["start_line"]
    raw_lines = str(gmeta["data"]).splitlines()
    numbered = [(s_line + idx, text) for idx, text in enumerate(raw_lines)]
    return {
        "source": "git_log",
        "sig_start_line": s_line,
        "end_line": gmeta["end_line"],
        "commit": gmeta.get("commit"),
        "author_date": gmeta.get("author_date"),
        "lines": numbered,
    }


def _resolve_line_cap_arg(
    cur: sqlite3.Cursor, clean_f: str, line_no: int, arg: str
) -> str:
    """Resolve a numeric capability argument at (clean_f, line_no) to CAP_*."""
    s_arg = str(arg)
    if s_arg in LINUX_UAPI_CAPABILITIES:
        return LINUX_UAPI_CAPABILITIES[s_arg]
    if not s_arg.isdigit() or not table_exists(
        cur, "macroinvocation_locations"
    ):
        return s_arg
    cur.execute(
        "SELECT macroinvocation_name FROM macroinvocation_locations"
        " WHERE (file_path = ? OR file_path = ?)"
        " AND start_line = ? AND macroinvocation_name LIKE 'CAP_%' LIMIT 1",
        (clean_f, f"linux/{clean_f}", line_no),
    )
    row = cur.fetchone()
    return row[0] if row else s_arg


def _collect_condition_tags(
    conn: sqlite3.Connection,
    clean_f: str,
    win: Tuple[int, int],
    tags: Dict[int, List[str]],
) -> None:
    """Attach capability and tunable check annotations from conditions table."""
    cur = conn.cursor()
    if not table_exists(cur, "conditions"):
        return
    cur.execute(
        "SELECT DISTINCT type, argument, definition, condition"
        " FROM conditions WHERE definition LIKE ? OR condition LIKE ?"
        " OR definition LIKE ? OR condition LIKE ?",
        (
            f"{clean_f}:%",
            f"{clean_f}:%",
            f"%/{clean_f}:%",
            f"%/{clean_f}:%",
        ),
    )
    seen: Set[Tuple[int, str]] = set()
    for c_type, arg, def_loc, cond_loc in cur.fetchall():
        m = LOCATION_RE.match(
            (def_loc if (def_loc and clean_f in def_loc) else cond_loc) or ""
        )
        if not m or clean_file_path(m.group(1)) != clean_f:
            continue
        ln = int(m.group(2))
        if ln < win[0] or ln > win[1]:
            continue
        resolved_arg = _resolve_line_cap_arg(cur, clean_f, ln, str(arg))
        label = (
            f"GATE: {format_capability(c_type, resolved_arg)}"
            if c_type in ("capable", "ns_capable")
            else f"TUNABLE: {c_type}({arg})"
        )
        if (ln, label) not in seen:
            seen.add((ln, label))
            tags[ln].append(label)


def _collect_callee_tags(
    cur: sqlite3.Cursor,
    clean_f: str,
    win: Tuple[int, int],
    tags: Dict[int, List[str]],
) -> None:
    """Attach direct, indirect ops, and async callee annotations within span."""
    if table_exists(cur, "locations") and table_exists(cur, "edges"):
        for ln, callee, _, _ in query_span_outgoing_calls(cur, clean_f, win):
            lbl = f"CALLEE: {callee}"
            if lbl not in tags[ln]:
                tags[ln].append(lbl)

    if table_exists(cur, "ops_targets"):
        cur.execute(
            "SELECT exprcall_line, parent, field, COUNT(DISTINCT target)"
            " FROM ops_targets"
            " WHERE (exprcall_file = ? OR exprcall_file = ?)"
            " AND exprcall_line BETWEEN ? AND ?"
            " GROUP BY exprcall_line, parent, field",
            (clean_f, f"linux/{clean_f}", win[0], win[1]),
        )
        for ln, parent, field, cnt in cur.fetchall():
            tags[ln].append(f"INDIRECT: {parent}->{field} ({cnt} target(s))")

    if table_exists(cur, "async_edges"):
        cur.execute(
            "SELECT DISTINCT line, mechanism, callee FROM async_edges"
            " WHERE (file = ? OR file LIKE ?) AND line BETWEEN ? AND ?",
            (clean_f, f"%/{clean_f}", win[0], win[1]),
        )
        for ln, mech, callee in cur.fetchall():
            tags[ln].append(f"ASYNC: {mech} -> {callee}")


def _collect_kconfig_and_syzk_tags(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    clean_f: str,
    win: Tuple[int, int],
    tags: Dict[int, List[str]],
) -> None:
    """Attach #ifdef CONFIG_* and Syzkaller line coverage tags within span."""
    cur = conn.cursor()
    if table_exists(cur, "configs"):
        cur.execute(
            "SELECT DISTINCT config, ifdef, else_ FROM configs"
            " WHERE (path = ? OR path LIKE ?)"
            " AND (ifdef BETWEEN ? AND ? OR else_ BETWEEN ? AND ?)",
            (clean_f, f"%/{clean_f}", win[0], win[1], win[0], win[1]),
        )
        for cfg, ifdef_l, else_l in cur.fetchall():
            if win[0] <= ifdef_l <= win[1] and ifdef_l > 1:
                tags[ifdef_l].append(f"KCONFIG: {cfg}")
            if else_l and win[0] <= else_l <= win[1]:
                tags[else_l].append(f"KCONFIG: !({cfg})")

    eff_syzk = resolve_syzk_conn(conn, syzk_conn)
    if eff_syzk is not None:
        scur = eff_syzk.cursor()
        scur.execute(
            "SELECT file_id FROM file_path"
            " WHERE file_path = ? OR file_path LIKE ?",
            (clean_f, f"%/{clean_f}"),
        )
        frow = scur.fetchone()
        if frow:
            scur.execute(
                "SELECT DISTINCT code_line_no FROM syzk_cov"
                " WHERE file_id = ? AND code_line_no BETWEEN ? AND ?",
                (frow[0], win[0], win[1]),
            )
            for (ln,) in scur.fetchall():
                tags[int(ln)].append("SYZKALLER: COVERED")


def collect_span_annotations(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection],
    file_path: str,
    win_start: int,
    win_end: int,
) -> Dict[int, List[str]]:
    """Collect inline annotations for lines in [win_start, win_end]."""
    clean_f = clean_file_path(file_path)
    win = (win_start, win_end)
    tags: Dict[int, List[str]] = defaultdict(list)
    _collect_condition_tags(conn, clean_f, win, tags)
    _collect_callee_tags(conn.cursor(), clean_f, win, tags)
    _collect_kconfig_and_syzk_tags(conn, syzk_conn, clean_f, win, tags)
    return dict(tags)


def resolve_fetch_target(
    conn: sqlite3.Connection,
    function_name: Optional[str] = None,
    file_path: Optional[str] = None,
    span: Optional[Tuple[Optional[int], Optional[int]]] = None,
    allow_ambiguous: bool = False,
) -> Tuple[Optional[str], str, int, int]:
    """Resolve function_name or explicit file span to (fn, file, start, end)."""
    start_line = span[0] if span else None
    end_line = span[1] if span else None
    if file_path and start_line is not None and end_line is not None:
        clean_f = clean_file_path(file_path)
        fn_name = function_name
        if not fn_name:
            enc = get_enclosing_function(conn, clean_f, start_line)
            fn_name = enc[0] if enc else None
        return fn_name, clean_f, start_line, end_line

    if not function_name:
        raise ValueError(
            "Provide either --function or (--file, --start-line, --end-line)."
        )

    candidates = get_functions_by_name(conn, function_name, file_path)
    if not candidates and file_path:
        fb = get_function_by_name(conn, function_name, file_path)
        candidates = [fb] if fb else []
    if not candidates:
        raise ValueError(
            f"Function '{function_name}' not found in function_locations."
        )
    if len(candidates) > 1 and not file_path and not allow_ambiguous:
        raise ValueError(
            format_ambiguous_symbol_error(function_name, candidates)
        )
    fn, clean_f, s_line, e_line = candidates[0]
    return fn, clean_f, s_line, e_line


def _load_raw_body_slice(
    conn: sqlite3.Connection,
    target: Tuple[Optional[str], str, int, int],
    repo_dir: Optional[str],
    context: int,
) -> Dict[str, Any]:
    """Load raw numbered lines and git metadata from repo_dir or git_log."""
    fn_name, clean_f, s_line, e_line = target
    disk_lines = read_disk_lines(repo_dir, clean_f) if repo_dir else None
    if disk_lines is not None:
        sig_start, span_end, numbered = slice_disk_span(
            disk_lines, s_line, e_line, context=context, function_name=fn_name
        )
        gmeta = get_git_log_metadata(
            conn, fn_name or "", clean_f, (s_line, e_line), include_data=False
        )
        return {
            "source": "repo_dir",
            "sig_start_line": sig_start,
            "end_line": span_end,
            "commit": gmeta.get("commit") if gmeta else None,
            "author_date": gmeta.get("author_date") if gmeta else None,
            "lines": numbered,
        }

    gl_slice = slice_git_log_span(conn, fn_name, clean_f, s_line, e_line)
    if not gl_slice:
        raise ValueError(
            f"Source unavailable for {clean_f}:{s_line}-{e_line}"
            " (neither --repo-dir file nor git_log.data row found)."
        )
    return gl_slice


def _apply_up_to_line_cutoff(
    numbered: List[Tuple[int, str]],
    sig_start: int,
    span_end: int,
    up_to_line: Optional[int],
    context: int,
) -> List[Tuple[int, str]]:
    """Truncate numbered lines after up_to_line + context when requested."""
    if up_to_line is None or up_to_line < sig_start:
        return numbered
    cutoff = min(span_end, up_to_line) + max(0, context)
    return [(ln, text) for ln, text in numbered if ln <= cutoff]


def fetch_function_body_with_conn(
    conn: sqlite3.Connection,
    syzk_conn: Optional[sqlite3.Connection] = None,
    **opts: Any,
) -> Dict[str, Any]:
    """Fetch line-numbered function or window source over an open connection."""
    target = resolve_fetch_target(
        conn,
        function_name=opts.get("function_name"),
        file_path=opts.get("file_path"),
        span=(opts.get("start_line"), opts.get("end_line")),
        allow_ambiguous=bool(opts.get("allow_ambiguous")),
    )
    context = int(opts.get("context", 5))
    raw = _load_raw_body_slice(conn, target, opts.get("repo_dir"), context)
    sig_start, span_end = raw["sig_start_line"], raw["end_line"]
    numbered = _apply_up_to_line_cutoff(
        raw["lines"], sig_start, span_end, opts.get("up_to_line"), context
    )
    win_start = numbered[0][0] if numbered else sig_start
    win_end = numbered[-1][0] if numbered else span_end
    annotations = (
        collect_span_annotations(conn, syzk_conn, target[1], win_start, win_end)
        if opts.get("annotate")
        else {}
    )
    res = {
        "function": target[0],
        "file": target[1],
        "sig_start_line": sig_start,
        "end_line": span_end,
        "window_start": win_start,
        "window_end": win_end,
        "source": raw["source"],
        "commit": raw["commit"],
        "author_date": raw["author_date"],
        "lines": [
            {
                "line": ln,
                "code": text,
                "in_span": sig_start <= ln <= span_end,
                "annotations": annotations.get(ln, []),
            }
            for ln, text in numbered
        ],
    }
    if opts.get("up_to_line") is not None:
        res["up_to_line"] = int(opts["up_to_line"])
    return res


def fetch_callsite_snippet(
    conn: sqlite3.Connection,
    file_path: str,
    focus_line: int,
    context: int = 2,
    repo_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch a compact ±context snippet around focus_line from disk or DB."""
    if not file_path or focus_line <= 0:
        return []
    clean_f = clean_file_path(file_path)
    win_s = max(1, focus_line - max(0, context))
    win_e = focus_line + max(0, context)

    disk_lines = read_disk_lines(repo_dir, clean_f) if repo_dir else None
    if disk_lines is not None:
        _, _, numbered = slice_disk_span(disk_lines, win_s, win_e, context=0)
        return [
            {"line": ln, "code": text, "is_focus_line": ln == focus_line}
            for ln, text in numbered
        ]

    enc = get_enclosing_function(conn, clean_f, focus_line)
    if not enc:
        return []
    gl = slice_git_log_span(conn, enc[0], clean_f, enc[2], enc[3])
    if not gl:
        return []
    return [
        {"line": ln, "code": text, "is_focus_line": ln == focus_line}
        for ln, text in gl["lines"]
        if win_s <= ln <= win_e
    ]


def fetch_function_body(db_path: str, **opts: Any) -> Dict[str, Any]:
    """Open database and fetch line-numbered function or window source."""
    conn, syzk_conn = open_databases(
        db_path,
        syzkaller_db=opts.get("syzkaller_db"),
        verbose=bool(opts.get("verbose")),
    )
    if not opts.get("repo_dir") and not opts.get("force_git_log"):
        opts["repo_dir"] = infer_repo_dir(db_path)
    try:
        return fetch_function_body_with_conn(conn, syzk_conn, **opts)
    finally:
        conn.close()
        if syzk_conn:
            syzk_conn.close()


def format_body_text(result: Dict[str, Any]) -> str:
    """Format fetched function body result into numbered source lines."""
    fn_lbl = result.get("function") or "<span_window>"
    commit_str = (
        f" | commit: {result['commit'][:12]}" if result.get("commit") else ""
    )
    lines = [
        "=" * 72,
        (
            f"SOURCE BODY: {fn_lbl} ({result['file']}:"
            f"{result['sig_start_line']}-{result['end_line']})"
            f" [source={result['source']}{commit_str}]"
        ),
        "=" * 72,
    ]
    for rec in result["lines"]:
        marker = " " if rec["in_span"] else "|"
        ann = (
            f"  /* {' | '.join(rec['annotations'])} */"
            if rec.get("annotations")
            else ""
        )
        lines.append(f"{rec['line']:6d}{marker} {rec['code']}{ann}")
    lines.append("=" * 72)
    return "\n".join(lines)
