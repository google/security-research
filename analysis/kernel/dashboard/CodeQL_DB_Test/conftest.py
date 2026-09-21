"""pytest configuration and session fixtures for CodeQL_DB_Test.

Evaluates a Linux kernel CodeQL database (`linux_codeql_db_v*`) across 6 domains
(25 intrinsic quality checks) using a single shared session-scoped CodeQL query run.

Usage:
    pytest CodeQL_DB_Test -v --codeql-db /path/to/linux_codeql_db_v6.1.111
    pytest CodeQL_DB_Test -v --codeql-db /path/to/db --btf-db /path/to/btf.db
    pytest CodeQL_DB_Test -v --codeql-db /path/to/db --vmlinux /path/to/vmlinux
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest


@dataclass
class CheckRecord:
    domain: str
    name: str
    status: str  # "PASS", "WARN", "FAIL"
    metric_str: str
    expected_str: str
    detail: str


# Global registry for terminal summary reporting
_CHECK_RECORDS: List[CheckRecord] = []


def record_check(
    domain: str,
    name: str,
    status: str,
    metric_str: str,
    expected_str: str,
    detail: str,
) -> None:
    _CHECK_RECORDS.append(
        CheckRecord(
            domain=domain,
            name=name,
            status=status,
            metric_str=metric_str,
            expected_str=expected_str,
            detail=detail,
        )
    )


def pytest_addoption(parser: pytest.Parser) -> None:
    default_codeql = shutil.which("codeql") or str(
        Path.home() / "kernel_codeql_workspace" / "codeql-home" / "codeql" / "codeql"
    )
    group = parser.getgroup("codeql_db_test", "CodeQL Kernel Database Quality Test Options")
    group.addoption(
        "--codeql-db",
        action="store",
        default=None,
        help="Path to the raw CodeQL database directory (required)",
    )
    group.addoption(
        "--codeql-bin",
        action="store",
        default=default_codeql,
        help="Path to codeql CLI executable",
    )
    group.addoption(
        "--btf-db",
        action="store",
        default=None,
        help="Optional path to BTF SQLite database (from extract-btf.py) for ground-truth struct size verification",
    )
    group.addoption(
        "--vmlinux",
        action="store",
        default=None,
        help="Optional path to vmlinux image with .BTF section (extract-btf.py will be invoked to create a BTF DB)",
    )
    group.addoption(
        "--ram",
        action="store",
        type=int,
        default=16000,
        help="RAM limit in MB for CodeQL query evaluation (default: 16000)",
    )
    group.addoption(
        "--threads",
        action="store",
        type=int,
        default=8,
        help="Thread count for CodeQL query evaluation (default: 8)",
    )


@pytest.fixture(scope="session")
def codeql_db(request: pytest.FixtureRequest) -> Path:
    db_opt = request.config.getoption("--codeql-db")
    if not db_opt:
        pytest.UsageError("Missing required argument: --codeql-db <path/to/linux_codeql_db>")
    db_path = Path(db_opt).resolve()
    if not db_path.exists():
        pytest.fail(f"CodeQL database directory not found: {db_path}")
    return db_path


@pytest.fixture(scope="session")
def log_stats(codeql_db: Path) -> Dict[str, Any]:
    """Parses <db>/log/build-tracer*.log once per test session."""
    log_dir = codeql_db / "log"
    log_files = sorted(log_dir.glob("build-tracer*.log")) if log_dir.exists() else []

    stats: Dict[str, Any] = {
        "has_log": bool(log_files),
        "log_size_mb": 0.0,
        "intercepted_compiles": 0,
        "edg_errors": 0,
        "tu_aborts": 0,
        "typeof_unqual_errors": 0,
        "seg_gs_errors": 0,
    }

    if not log_files:
        return stats

    total_size_mb = sum(lf.stat().st_size for lf in log_files) / (1024 * 1024)
    stats["log_size_mb"] = round(total_size_mb, 2)

    re_intercept = re.compile(r"Intercepted call to compiler")
    re_error = re.compile(r"error: |catastrophic error:", re.IGNORECASE)
    re_abort = re.compile(r"Error limit reached\.", re.IGNORECASE)
    re_typeof = re.compile(r'identifier "(pto_tmp__|pao_tmp__|pscr_ret__)"|error:[^-\n]*\b__typeof_unqual__\b')
    re_seg_gs = re.compile(r"error:[^-\n]*\b__seg_(gs|fs)\b")

    for lf in log_files:
        with open(lf, "r", errors="replace") as f:
            for line in f:
                if "Intercepted call" in line and re_intercept.search(line):
                    stats["intercepted_compiles"] += 1
                if "error:" in line or "Error limit" in line or "catastrophic" in line:
                    if re_abort.search(line):
                        stats["tu_aborts"] += 1
                    if re_error.search(line):
                        stats["edg_errors"] += 1
                        if re_typeof.search(line):
                            stats["typeof_unqual_errors"] += 1
                        if re_seg_gs.search(line):
                            stats["seg_gs_errors"] += 1

    return stats


@pytest.fixture(scope="session")
def codeql_query_results(
    codeql_db: Path, request: pytest.FixtureRequest
) -> Dict[str, List[Dict[str, str]]]:
    """Executes all 5 modular .ql quality queries in one shared CodeQL session."""
    codeql_bin = request.config.getoption("--codeql-bin")
    ram_mb = request.config.getoption("--ram")
    threads = request.config.getoption("--threads")
    script_dir = Path(__file__).resolve().parent

    queries = [
        "extraction_coverage.ql",
        "ast_corruption.ql",
        "callgraph_completeness.ql",
        "kernel_invariants.ql",
        "btf_struct_sizes.ql",
    ]
    query_paths = [str(script_dir / q) for q in queries]

    cmd = [
        codeql_bin,
        "database",
        "run-queries",
        f"--ram={ram_mb}",
        f"--threads={threads}",
        str(codeql_db),
    ] + query_paths

    print(f"\n[*] Evaluating {len(queries)} standalone CodeQL quality queries on {codeql_db.name}...")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        pytest.fail(f"Error running CodeQL test queries:\n{res.stderr}")

    parsed_outputs: Dict[str, List[Dict[str, str]]] = {}
    results_dir = codeql_db / "results" / "codeql-db-test-queries"

    try:
        for q in queries:
            q_stem = q.replace(".ql", "")
            bqrs_path = results_dir / f"{q_stem}.bqrs"
            if not bqrs_path.exists():
                matches = list((codeql_db / "results").rglob(f"{q_stem}.bqrs"))
                if matches:
                    bqrs_path = matches[0]

            decode_cmd = [
                codeql_bin,
                "bqrs",
                "decode",
                str(bqrs_path),
                "--format=csv",
            ]
            dec = subprocess.run(
                decode_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            reader = csv.DictReader(io.StringIO(dec.stdout))
            parsed_outputs[q_stem] = list(reader)
    finally:
        if results_dir.exists():
            shutil.rmtree(results_dir, ignore_errors=True)

    return parsed_outputs


def _load_sizes_from_btf_sqlite(db_path: Path) -> Dict[str, int]:
    """Reads distinct (struct_name, struct_size) from a BTF SQLite DB generated by extract-btf.py."""
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT struct_name, struct_size FROM types "
        "WHERE struct_name != '(anon)' AND struct_size > 0"
    )
    btf_sizes: Dict[str, int] = {}
    for name, size in cur.fetchall():
        if name and size:
            btf_sizes[name] = max(btf_sizes.get(name, 0), int(size))
    conn.close()
    return btf_sizes


@pytest.fixture(scope="session")
def btf_ground_truth(
    codeql_db: Path, request: pytest.FixtureRequest
) -> Tuple[Optional[Dict[str, int]], str]:
    """Loads ground-truth struct sizes from --btf-db SQLite or extracts via Data/Field_Information/extract-btf.py."""
    btf_db_opt = request.config.getoption("--btf-db")
    vmlinux_opt = request.config.getoption("--vmlinux")

    # 1. Explicit --btf-db SQLite database
    if btf_db_opt:
        btf_db_path = Path(btf_db_opt).resolve()
        if btf_db_path.exists():
            try:
                btf_sizes = _load_sizes_from_btf_sqlite(btf_db_path)
                if btf_sizes:
                    return btf_sizes, f"SQLite BTF DB ({btf_db_path.name})"
            except Exception as e:
                print(f"[!] Warning: Could not load BTF SQLite DB {btf_db_path}: {e}", file=sys.stderr)

    # 2. Check for existing sibling BTF SQLite DB (e.g. btf.db or btf_v*.db)
    m = re.search(r"v\d+\.\d+(?:\.\d+)?", codeql_db.name)
    ver = m.group(0) if m else None
    db_candidates = []
    if ver:
        db_candidates.append(codeql_db.parent / f"btf_{ver}.db")
    db_candidates.append(codeql_db.parent / "btf.db")
    db_candidates.append(codeql_db / "btf.db")
    for cand in db_candidates:
        if cand.exists():
            try:
                btf_sizes = _load_sizes_from_btf_sqlite(cand)
                if btf_sizes:
                    return btf_sizes, f"SQLite BTF DB ({cand.name})"
            except Exception:
                pass

    # 3. Resolve vmlinux and extract SQLite BTF DB via Data/Field_Information/extract-btf.py
    vmlinux_path: Optional[Path] = Path(vmlinux_opt).resolve() if vmlinux_opt else None
    if not vmlinux_path or not vmlinux_path.exists():
        vmlinux_candidates = []
        if ver:
            vmlinux_candidates.append(codeql_db.parent / f"linux_{ver}" / "vmlinux")
        vmlinux_candidates.append(codeql_db / "vmlinux")
        vmlinux_candidates.append(codeql_db.parent / "vmlinux")
        for cand in vmlinux_candidates:
            if cand.exists():
                vmlinux_path = cand
                break

    extract_btf_script = (
        Path(__file__).resolve().parent.parent / "Data" / "Field_Information" / "extract-btf.py"
    )
    if vmlinux_path and vmlinux_path.exists() and extract_btf_script.exists():
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_btf_db = Path(tmpdir) / "btf.db"
                print(f"[*] Extracting BTF SQLite DB via {extract_btf_script.name} from {vmlinux_path.name}...")
                subprocess.run(
                    [sys.executable, str(extract_btf_script), str(vmlinux_path), "--db_file", str(tmp_btf_db)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                btf_sizes = _load_sizes_from_btf_sqlite(tmp_btf_db)
                if btf_sizes:
                    return btf_sizes, f"extract-btf.py SQLite DB ({vmlinux_path.name})"
        except Exception as e:
            print(f"[!] Warning: extract-btf.py failed on {vmlinux_path}: {e}", file=sys.stderr)

    return None, "No BTF ground truth provided or auto-discovered"


def pytest_terminal_summary(terminalreporter: Any, exitstatus: int, config: pytest.Config) -> None:
    """Renders the structured 6-domain diagnostic table at the end of the pytest run."""
    if not _CHECK_RECORDS:
        return

    tw = terminalreporter
    db_opt = config.getoption("--codeql-db") or "Unknown"

    tw.write_sep("=", "STANDALONE CODEQL KERNEL DATABASE QUALITY REPORT")
    tw.write_line(f"  Target Database : {db_opt}")
    tw.write_sep("-")

    current_domain = ""
    pass_cnt = sum(1 for c in _CHECK_RECORDS if c.status == "PASS")
    warn_cnt = sum(1 for c in _CHECK_RECORDS if c.status == "WARN")
    fail_cnt = sum(1 for c in _CHECK_RECORDS if c.status == "FAIL")

    for c in _CHECK_RECORDS:
        if c.domain != current_domain:
            current_domain = c.domain
            tw.write_line(f"\n[{current_domain}]")
        tag = f"[{c.status}]"
        tw.write_line(f"  {tag:6s} {c.name}")
        tw.write_line(f"         Metric  : {c.metric_str}")
        tw.write_line(f"         Target  : {c.expected_str}")
        if c.status != "PASS":
            tw.write_line(f"         Detail  : {c.detail}")

    tw.write_line("")
    verdict = (
        "HEALTHY (100% READY FOR DASHBOARD QUERIES)"
        if fail_cnt == 0
        else f"DEGRADED ({fail_cnt} CRITICAL FAILURES DETECTED)"
    )
    tw.write_sep(
        "=",
        f"VERDICT: {len(_CHECK_RECORDS)} checks | {pass_cnt} PASS | {warn_cnt} WARN | {fail_cnt} FAIL --> {verdict}",
    )
