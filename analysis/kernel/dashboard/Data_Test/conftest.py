"""pytest wiring for the dashboard data-quality tests.

Supports three invocation modes:
1. Per-query validation mode:
   pytest Data_Test --query allocs --results-dir /path/to/results [--btf-db /path/to/btf.db]

   - Automatically resolves CSV/SARIF files from --results-dir.
   - Reads BTF struct sizes directly from SQLite --btf-db (types table) or --btf CSV.
   - Maps all 13 dashboard queries to their dedicated quality test modules.
   - If --query specifies an experimental query without a test module yet,
     prints a skip message and exits with status code 0.

2. SQLite database validation mode:
   pytest Data_Test -v --sqlite-db /path/to/codeql_data-6.1.db [--allocs-db /path/to/allocs.db] [--btf-db /path/to/btf.db]

   - Loads tables directly from an imported SQLite database (such as the reference DBs in
     /usr/local/google/home/ametla/Documents or newly imported DBs) and validates both
     per-table quality checks and cross-table SQLite/tool invariants.

3. Standalone explicit CSV mode:
   pytest Data_Test -v \
       --kernel 6.18.45 \
       --allocs allocs.csv \
       --db btf.db \
       --syscall-node syscall_node.csv \
       --function-locations functions.csv \
       --ops-targets ops_edges.csv \
       --baseline Data_Test/6.1.111.json
"""
from __future__ import annotations

from collections import defaultdict
import json
import os
import sqlite3
import sys
from pathlib import Path
import pytest

from common import canonical_path, clean, load_rows, sniff_delimiter

# --------------------------------------------------------------------------- #
# CLI Options
# --------------------------------------------------------------------------- #

_OPTIONS = [
    ("--query", "Name or stem of the single CodeQL query under test (e.g. allocs, ops_edges)"),
    ("--results-dir", "Directory containing decoded CSV/SARIF query outputs"),
    ("--sqlite-db", "Path to unified CodeQL SQLite database file (e.g. codeql_data-6.1.db)"),
    ("--allocs-db", "Optional path to separate allocs SQLite database file (e.g. allocs.db)"),
    ("--btf-db", "Path to BTF SQLite database file (e.g. btf.db or unified DB) containing 'types' table"),
    ("--db", "Alias for --btf-db (path to SQLite database file)"),
    ("--kernel", "Kernel version under test, for reporting"),
    ("--allocs", "allocs.ql output CSV"),
    ("--allocations", "allocations.ql / kmalloc_calls output CSV"),
    ("--field-access", "field-acces-type.ql / field_access output CSV"),
    ("--macro-locations", "macro-locations.ql / macro_locations output CSV"),
    ("--macro-invocations", "macro-invocations.ql / macroinvocation_locations output CSV"),
    ("--conditions", "condition-graph-direct.ql / conditions output CSV"),
    ("--conditions-node", "condition-graph-all.ql / conditions_node output CSV"),
    ("--all-calls", "all-calls.ql output SARIF"),
    ("--btf", "BTF SQLite database (btf.db) or CSV (struct_name,struct_size)"),
    ("--allocs-oracle", "Reference allocs dump (6.1.111 only)"),
    ("--syscall-node", "4-column syscall_node CSV"),
    ("--syscall-node-pairs", "2- or 3-column syscall-node-pairs.csv (syscall, function[, file])"),
    ("--syscall-node-locs", "6-column syscall-node-locs.csv (name, file, sl, sc, el, ec)"),
    ("--syscall-node-oracle", "Reference syscall_node dump (6.1.111 only)"),
    ("--function-locations", "functions.ql / function_locations CSV"),
    ("--ops-targets", "ops_edges.ql / ops_targets CSV"),
    ("--configs", "kernel-configs-needed.ql / configs CSV"),
    ("--baseline", "baselines/<kernel>.json recorded from a validated run"),
]

# Maps all 13 CodeQL query stems (and table aliases) to their 1-to-1 test_<query_stem>.py module
QUERY_TO_TEST_MODULE = {
    "functions": "test_functions.py",
    "function_locations": "test_functions.py",
    "kernel-configs-needed": "test_kernel_configs_needed.py",
    "configs": "test_kernel_configs_needed.py",
    "ops_edges": "test_ops_edges.py",
    "ops_targets": "test_ops_edges.py",
    "allocs": "test_allocs.py",
    "allocations": "test_allocations.py",
    "kmalloc_calls": "test_allocations.py",
    "field-acces-type": "test_field_acces_type.py",
    "field_access": "test_field_acces_type.py",
    "macro-locations": "test_macro_locations.py",
    "macro_locations": "test_macro_locations.py",
    "macro-invocations": "test_macro_invocations.py",
    "macroinvocation_locations": "test_macro_invocations.py",
    "syscall-node-pairs": "test_syscall_node_pairs.py",
    "syscall-node-locs": "test_syscall_node_locs.py",
    "syscall_node": "test_syscall_node_pairs.py",
    "condition-graph-direct": "test_condition_graph_direct.py",
    "conditions": "test_condition_graph_direct.py",
    "condition-graph-all": "test_condition_graph_all.py",
    "conditions_node": "test_condition_graph_all.py",
    "all-calls": "test_all_calls.py",
    "all_calls": "test_all_calls.py",
}


def pytest_addoption(parser):
    for name, help_text in _OPTIONS:
        parser.addoption(name, action="store", default=None, help=help_text)


def _normalize_query_stem(q: str) -> str:
    """Strip directory path and .ql/.bqrs/.csv extensions from query argument."""
    base = os.path.basename(q.strip())
    for ext in (".ql", ".bqrs", ".csv", ".sarif"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def pytest_collection_modifyitems(config, items):
    query_arg = config.getoption("--query")
    if not query_arg:
        return

    stem = _normalize_query_stem(query_arg)
    target_module = QUERY_TO_TEST_MODULE.get(stem)
    if not target_module:
        config._unimplemented_query = stem
        items.clear()
        return

    filtered = [
        item for item in items if os.path.basename(str(item.fspath)) == target_module
    ]
    if not filtered:
        config._unimplemented_query = stem
        items.clear()
    else:
        items[:] = filtered


def pytest_sessionfinish(session, exitstatus):
    unimpl = getattr(session.config, "_unimplemented_query", None)
    if unimpl is not None:
        print(
            f"\n[Data_Test] No quality test implemented for query '{unimpl}' — skipping validation (OK).",
            file=sys.stderr,
        )
        session.exitstatus = 0
    elif exitstatus == 5 and session.config.getoption("--query"):
        q = session.config.getoption("--query")
        print(
            f"\n[Data_Test] No tests collected for query '{q}' — skipping validation (OK).",
            file=sys.stderr,
        )
        session.exitstatus = 0


# --------------------------------------------------------------------------- #
# Column contracts (positional, matching queries & importers)
# --------------------------------------------------------------------------- #

ALLOCS_COLS_17 = [
    "call_value", "type_value", "objectSize", "sizeMin", "sizeMax", "sizeVal",
    "flagsMin", "flagsMax", "flagsVal", "file", "line", "col",
    "isFlexible", "depth", "typeUri", "typeLine", "typeCol",
]
ALLOCS_COLS_12 = ALLOCS_COLS_17[:12]

ALLOCATIONS_COLS_10 = [
    "call_site", "call_expr", "struct_type", "struct_def", "struct_size",
    "flags", "alloc_size", "sizeof_expr", "is_flexible", "target_name",
]
ALLOCATIONS_COLS_9 = ALLOCATIONS_COLS_10[:9]

FIELD_ACCESS_COLS = ["type", "field", "parent", "location"]
MACRO_LOCATION_COLS = ["macro_name", "file_path", "start_line", "end_line"]
MACRO_INVOCATION_COLS = ["macroinvocation_name", "file_path", "start_line", "end_line"]
CONDITIONS_COLS = ["type", "definition", "condition", "argument", "call", "call_location"]
CONDITIONS_NODE_COLS = ["conditions", "function", "conditions_location", "function_location"]

SYSCALL_NODE_COLS = ["syscall", "function", "syscall_location", "function_location"]
FUNCTION_LOCATION_COLS = ["function_name", "file_path", "start_line", "end_line"]
OPS_TARGETS_COLS = [
    "definition", "parent", "field", "target", "target_file", "target_start",
    "target_end", "exprcall_file", "exprcall_line", "exprcall_parent_start",
    "exprcall_parent_end",
]
CONFIGS_COLS = ["config", "path", "ifdef", "endif", "else_"]


def _resolve_file(config, explicit_opt: str, candidates: list[str], description: str) -> Path | None:
    explicit = config.getoption(explicit_opt)
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p
        pytest.skip(f"{description} file not found at explicit path: {explicit}")

    results_dir = config.getoption("--results-dir")
    if results_dir:
        rdir = Path(results_dir)
        for cand in candidates:
            p = rdir / cand
            if p.exists():
                return p
    return None


def _query_sqlite_table(db_path: str | Path, query: str, cols: list[str]) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute(query)
    rows = [
        {c: clean(str(v)) if v is not None else "" for c, v in zip(cols, raw)}
        for raw in cur.fetchall()
    ]
    conn.close()
    return rows


def _has_sqlite_table(db_path: str | Path | None, table_name: str) -> bool:
    if not db_path or not os.path.exists(db_path):
        return False
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        found = cur.fetchone() is not None
        conn.close()
        return found
    except sqlite3.Error:
        return False


# --------------------------------------------------------------------------- #
# Fixtures -- session scoped
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="session")
def kernel(pytestconfig):
    return pytestconfig.getoption("--kernel") or "unknown"


@pytest.fixture(scope="session")
def baseline_path(pytestconfig):
    explicit = pytestconfig.getoption("--baseline")
    if explicit:
        return explicit
    base_dir = Path(__file__).resolve().parent
    kernel = pytestconfig.getoption("--kernel")
    if kernel:
        kernel_bl = base_dir / f"{kernel}.json"
        if kernel_bl.exists():
            return str(kernel_bl)
    default_bl = base_dir / "6.1.111.json"
    return str(default_bl) if default_bl.exists() else None


@pytest.fixture(scope="session")
def sqlite_db(pytestconfig):
    return pytestconfig.getoption("--sqlite-db")


@pytest.fixture(scope="session")
def allocs_db(pytestconfig):
    return pytestconfig.getoption("--allocs-db") or pytestconfig.getoption("--sqlite-db")


@pytest.fixture(scope="session")
def allocs(pytestconfig, allocs_db):
    path = _resolve_file(pytestconfig, "--allocs", ["allocs.csv"], "allocs output")
    if path and _has_sqlite_table(path, "allocs"):
        allocs_db = path
        path = None
    if path:
        delim = sniff_delimiter(path)
        with open(path, encoding="utf-8", errors="ignore") as fh:
            first_line = fh.readline()
        ncols = len(first_line.split(delim))
        cols = ALLOCS_COLS_17 if ncols >= 17 else ALLOCS_COLS_12
        return load_rows(path, cols)

    if _has_sqlite_table(allocs_db, "allocs"):
        conn = sqlite3.connect(str(allocs_db))
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(allocs)")
        db_cols = {r[1] for r in cur.fetchall()}
        conn.close()
        has_flex = "is_flexible" in db_cols
        flex_expr = "is_flexible" if has_flex else "CASE WHEN allocSizeMin_value != allocSizeMax_value THEN 'true' ELSE 'false' END"
        return _query_sqlite_table(
            allocs_db,
            f"""
            SELECT call_value, type_value, objectSize_value, allocSizeMin_value,
                   allocSizeMax_value, allocSize_value, flagsMin_value, flagsMax_value,
                   flags_value, call_uri, call_startLine, call_startColumn,
                   {flex_expr}, depth_value, type_uri, type_startLine, type_startColumn
            FROM allocs
            """,
            ALLOCS_COLS_17,
        )

    pytest.skip("allocs not supplied (pass --allocs, --results-dir with allocs.csv, or --allocs-db)")


@pytest.fixture(scope="session")
def allocations(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--allocations",
        ["allocations.csv", "kmalloc_calls.csv"],
        "allocations output",
    )
    if path:
        delim = sniff_delimiter(path)
        with open(path, encoding="utf-8", errors="ignore") as fh:
            first_line = fh.readline()
        ncols = len(first_line.split(delim))
        cols = ALLOCATIONS_COLS_10 if ncols >= 10 else ALLOCATIONS_COLS_9
        return load_rows(path, cols)

    if _has_sqlite_table(sqlite_db, "kmalloc_calls"):
        return _query_sqlite_table(
            sqlite_db,
            """
            SELECT call_site, call_expr, struct_type, struct_def, struct_size,
                   flags, alloc_size, sizeof_expr, is_flexible
            FROM kmalloc_calls
            """,
            ALLOCATIONS_COLS_9,
        )

    pytest.skip("allocations not supplied (pass --allocations, --results-dir, or --sqlite-db)")


@pytest.fixture(scope="session")
def field_access(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--field-access",
        ["field-acces-type.csv", "field_access.csv"],
        "field_access output",
    )
    if path:
        return load_rows(path, FIELD_ACCESS_COLS)

    if _has_sqlite_table(sqlite_db, "field_access"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT type, field, parent, location FROM field_access",
            FIELD_ACCESS_COLS,
        )

    pytest.skip("field_access not supplied (pass --field-access, --results-dir, or --sqlite-db)")


@pytest.fixture(scope="session")
def macro_locations(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--macro-locations",
        ["macro-locations.csv", "macro_locations.csv"],
        "macro_locations output",
    )
    if path:
        return load_rows(path, MACRO_LOCATION_COLS)

    if _has_sqlite_table(sqlite_db, "macro_locations"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT macro_name, file_path, start_line, end_line FROM macro_locations",
            MACRO_LOCATION_COLS,
        )

    return None


@pytest.fixture(scope="session")
def macro_invocations(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--macro-invocations",
        ["macro-invocations.csv", "macroinvocation_locations.csv"],
        "macroinvocation_locations output",
    )
    if path:
        return load_rows(path, MACRO_INVOCATION_COLS)

    if _has_sqlite_table(sqlite_db, "macroinvocation_locations"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT macroinvocation_name, file_path, start_line, end_line FROM macroinvocation_locations",
            MACRO_INVOCATION_COLS,
        )

    return None


@pytest.fixture(scope="session")
def conditions(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--conditions",
        ["condition-graph-direct.csv", "conditions.csv"],
        "conditions output",
    )
    if path:
        return load_rows(path, CONDITIONS_COLS)

    if _has_sqlite_table(sqlite_db, "conditions"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT type, definition, condition, argument, call, call_location FROM conditions",
            CONDITIONS_COLS,
        )

    pytest.skip("conditions not supplied (pass --conditions, --results-dir, or --sqlite-db)")


@pytest.fixture(scope="session")
def conditions_node(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--conditions-node",
        ["condition-graph-all.csv", "conditions_node.csv"],
        "conditions_node output",
    )
    if path:
        return load_rows(path, CONDITIONS_NODE_COLS)

    if _has_sqlite_table(sqlite_db, "conditions_node"):
        # Note: conditions_node can have 27.7M+ rows; fetch aggregated summary + sample if from SQLite
        return _query_sqlite_table(
            sqlite_db,
            "SELECT conditions, function, conditions_location, function_location FROM conditions_node LIMIT 250000",
            CONDITIONS_NODE_COLS,
        )

    pytest.skip("conditions_node not supplied (pass --conditions-node, --results-dir, or --sqlite-db)")


@pytest.fixture(scope="session")
def all_calls_stats(pytestconfig, sqlite_db):
    """Returns summary dict for all-calls SARIF file or imported SQLite edges/locations tables."""
    path = _resolve_file(
        pytestconfig,
        "--all-calls",
        ["all-calls.sarif", "all_calls.sarif"],
        "all-calls SARIF output",
    )
    if path:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            sarif = json.load(f)
        runs = sarif.get("runs", [])
        total_results = 0
        total_locations = 0
        total_edges = 0
        sample_uris = []
        sample_messages = []
        for run in runs:
            results = run.get("results", [])
            total_results += len(results)
            for res in results:
                for cf in res.get("codeFlows", []):
                    for tf in cf.get("threadFlows", []):
                        locs = tf.get("locations", [])
                        total_locations += len(locs)
                        if len(locs) >= 2:
                            total_edges += len(locs) - 1
                        for loc_entry in locs[:2]:
                            loc = loc_entry.get("location", {})
                            msg = loc.get("message", {}).get("text", "")
                            uri = (
                                loc.get("physicalLocation", {})
                                .get("artifactLocation", {})
                                .get("uri", "")
                            )
                            if uri and len(sample_uris) < 200:
                                sample_uris.append(uri)
                            if msg and len(sample_messages) < 200:
                                sample_messages.append(msg)
        return {
            "source": f"SARIF ({path.name})",
            "runs": len(runs),
            "results": total_results,
            "locations": total_locations,
            "edges": total_edges,
            "sample_uris": sample_uris,
            "sample_messages": sample_messages,
        }

    if _has_sqlite_table(sqlite_db, "edges") and _has_sqlite_table(sqlite_db, "locations"):
        conn = sqlite3.connect(str(sqlite_db))
        cur = conn.cursor()
        runs_cnt = cur.execute("SELECT count(*) FROM runs").fetchone()[0] if _has_sqlite_table(sqlite_db, "runs") else 1
        res_cnt = cur.execute("SELECT count(*) FROM results").fetchone()[0] if _has_sqlite_table(sqlite_db, "results") else 0
        loc_cnt = cur.execute("SELECT count(*) FROM locations").fetchone()[0]
        edge_cnt = cur.execute("SELECT count(*) FROM edges").fetchone()[0]
        sample_rows = cur.execute("SELECT uri, message FROM locations LIMIT 200").fetchall()
        conn.close()
        return {
            "source": f"SQLite ({Path(sqlite_db).name})",
            "runs": runs_cnt,
            "results": res_cnt,
            "locations": loc_cnt,
            "edges": edge_cnt,
            "sample_uris": [r[0] for r in sample_rows if r[0]],
            "sample_messages": [r[1] for r in sample_rows if r[1]],
        }

    pytest.skip("all-calls data not supplied (pass --all-calls, --results-dir with all-calls.sarif, or --sqlite-db)")


@pytest.fixture(scope="session")
def allocs_oracle(pytestconfig):
    path = pytestconfig.getoption("--allocs-oracle")
    if not path:
        pytest.skip("no allocs oracle for this kernel (--allocs-oracle)")
    if _has_sqlite_table(path, "allocs"):
        return _query_sqlite_table(
            path,
            """
            SELECT call_value, type_value, objectSize_value,
                   allocSizeMin_value, allocSizeMax_value, allocSize_value,
                   flagsMin_value, flagsMax_value, flags_value,
                   call_uri, call_startLine, call_startColumn
            FROM allocs
            """,
            ALLOCS_COLS_12,
        )
    return load_rows(path, ALLOCS_COLS_12)


@pytest.fixture(scope="session")
def btf_sizes(pytestconfig):
    """struct_name -> struct_size (selecting max size per struct name to avoid 32-bit VDSO shadowing)."""
    btf_db_opt = pytestconfig.getoption("--btf-db")
    btf_opt = pytestconfig.getoption("--btf")
    db_opt = pytestconfig.getoption("--db")
    sqlite_db_opt = pytestconfig.getoption("--sqlite-db")
    results_dir = pytestconfig.getoption("--results-dir")

    target_path = None
    for cand in [
        btf_db_opt,
        btf_opt,
        db_opt,
        sqlite_db_opt,
        os.path.join(results_dir, "btf.db") if results_dir else None,
        os.path.join(results_dir, "btf.csv") if results_dir else None,
    ]:
        if cand and os.path.exists(cand):
            target_path = cand
            break

    if not target_path:
        pytest.skip("BTF ground truth not supplied (pass --btf-db <btf.db> or --btf <path>)")

    sizes_int: dict[str, int] = {}
    is_sqlite = False
    try:
        with open(target_path, "rb") as fh:
            if fh.read(16).startswith(b"SQLite format 3"):
                is_sqlite = True
    except Exception:
        pass

    if is_sqlite:
        try:
            conn = sqlite3.connect(target_path)
            cursor = conn.cursor()
            cursor.execute("SELECT struct_name, struct_size FROM types WHERE struct_size > 0;")
            for sname, ssize in cursor.fetchall():
                if sname and ssize is not None:
                    sizes_int[str(sname)] = max(sizes_int.get(str(sname), 0), int(ssize))
            conn.close()
        except sqlite3.Error as e:
            pytest.skip(f"SQLite database at {target_path} does not contain a valid BTF 'types' table: {e}")
    else:
        for row in load_rows(target_path, ["struct_name", "struct_size"]):
            if row["struct_name"] and row["struct_size"].isdigit():
                s = row["struct_name"]
                sizes_int[s] = max(sizes_int.get(s, 0), int(row["struct_size"]))

    if not sizes_int:
        pytest.skip(f"No BTF struct sizes found in {target_path}")
    return {k: str(v) for k, v in sizes_int.items()}


@pytest.fixture(scope="session")
def syscall_node(pytestconfig, sqlite_db):
    """Loads 4-column syscall_node data from combined CSV, split pairs+locs CSVs
    (using exact (function, file) 5-part location joining), or SQLite DB."""
    explicit_combined = pytestconfig.getoption("--syscall-node")
    if explicit_combined and os.path.exists(explicit_combined):
        return load_rows(explicit_combined, SYSCALL_NODE_COLS)

    results_dir = pytestconfig.getoption("--results-dir")
    pairs_path = pytestconfig.getoption("--syscall-node-pairs") or (
        os.path.join(results_dir, "syscall-node-pairs.csv") if results_dir else None
    )
    locs_path = pytestconfig.getoption("--syscall-node-locs") or (
        os.path.join(results_dir, "syscall-node-locs.csv") if results_dir else None
    )

    if pairs_path and locs_path and os.path.exists(pairs_path) and os.path.exists(locs_path):
        # Use exact (function, file) 5-part location joining matching import_syscall_node.py
        loc_rows_6 = load_rows(locs_path, ["func", "file", "sl", "sc", "el", "ec"])
        by_fn_file: dict[tuple[str, str], list[str]] = defaultdict(list)
        by_name: dict[str, list[tuple[str, str]]] = defaultdict(list)
        if loc_rows_6:
            for r in loc_rows_6:
                cfile = canonical_path(r["file"])
                loc_str = f"{cfile}:{r['sl']}:{r['sc']}:{r['el']}:{r['ec']}"
                by_fn_file[(r["func"], cfile)].append(loc_str)
                by_name[r["func"]].append((cfile, loc_str))
        else:
            # Fallback for 3-column locs
            for r in load_rows(locs_path, ["func", "file", "line"]):
                cfile = canonical_path(r["file"])
                loc_str = f"{cfile}:{r['line']}"
                by_fn_file[(r["func"], cfile)].append(loc_str)
                by_name[r["func"]].append((cfile, loc_str))

        sysloc = {}
        for name, file_loc_pairs in by_name.items():
            if name.startswith("__do_sys_"):
                c_locs = [loc for f, loc in file_loc_pairs if f.endswith(".c")]
                sysloc[name] = c_locs[0] if c_locs else file_loc_pairs[0][1]

        pair_rows_3 = load_rows(pairs_path, ["syscall", "function", "file"])
        pair_rows = pair_rows_3 if pair_rows_3 else load_rows(pairs_path, ["syscall", "function"])
        assembled = []
        seen = set()
        for r in pair_rows:
            sc = r["syscall"]
            fn = r["function"]
            sloc = sysloc.get(sc, "")
            if "file" in r and r["file"]:
                cfile = canonical_path(r["file"])
                flocs = by_fn_file.get((fn, cfile)) or [loc for _, loc in by_name.get(fn, [])]
            else:
                flocs = [loc for _, loc in by_name.get(fn, [])]
            if not flocs:
                flocs = [""]
            for floc in flocs:
                key = (sc, fn, sloc, floc)
                if key not in seen:
                    seen.add(key)
                    assembled.append(
                        {
                            "syscall": sc,
                            "function": fn,
                            "syscall_location": sloc,
                            "function_location": floc,
                        }
                    )
        return assembled

    # Single-query mode when only syscall-node-pairs.csv has been generated so far
    if pairs_path and os.path.exists(pairs_path):
        pair_rows_3 = load_rows(pairs_path, ["syscall", "function", "file"])
        pair_rows = pair_rows_3 if pair_rows_3 else load_rows(pairs_path, ["syscall", "function"])
        return [
            {
                "syscall": r["syscall"],
                "function": r["function"],
                "syscall_location": "",
                "function_location": f"{canonical_path(r['file'])}:1" if r.get("file") else "",
            }
            for r in pair_rows
        ]

    if results_dir:
        comb = os.path.join(results_dir, "syscall_node.csv")
        if os.path.exists(comb):
            return load_rows(comb, SYSCALL_NODE_COLS)

    if _has_sqlite_table(sqlite_db, "syscall_node"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT syscall, function, syscall_location, function_location FROM syscall_node",
            SYSCALL_NODE_COLS,
        )

    pytest.skip("syscall_node data not supplied (pass --syscall-node, --results-dir, or --sqlite-db)")


@pytest.fixture(scope="session")
def syscall_node_pairs(pytestconfig, syscall_node):
    """Loads syscall-node-pairs.ql rows (or falls back to syscall_node)."""
    results_dir = pytestconfig.getoption("--results-dir")
    pairs_path = pytestconfig.getoption("--syscall-node-pairs") or (
        os.path.join(results_dir, "syscall-node-pairs.csv") if results_dir else None
    )
    if pairs_path and os.path.exists(pairs_path):
        rows_3 = load_rows(pairs_path, ["syscall", "function", "file"])
        return rows_3 if rows_3 else load_rows(pairs_path, ["syscall", "function"])
    return syscall_node


@pytest.fixture(scope="session")
def syscall_node_locs(pytestconfig, sqlite_db):
    """Loads syscall-node-locs.ql rows (or reconstructs from SQLite function_locations / syscall_node)."""
    results_dir = pytestconfig.getoption("--results-dir")
    locs_path = pytestconfig.getoption("--syscall-node-locs") or (
        os.path.join(results_dir, "syscall-node-locs.csv") if results_dir else None
    )
    if locs_path and os.path.exists(locs_path):
        rows_6 = load_rows(locs_path, ["func", "file", "sl", "sc", "el", "ec"])
        return rows_6 if rows_6 else load_rows(locs_path, ["func", "file", "sl"])

    if _has_sqlite_table(sqlite_db, "function_locations"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT function_name, file_path, start_line, 1, end_line, 1 FROM function_locations",
            ["func", "file", "sl", "sc", "el", "ec"],
        )

    pytest.skip("syscall-node-locs not supplied (pass --syscall-node-locs, --results-dir, or --sqlite-db)")



@pytest.fixture(scope="session")
def syscall_node_oracle(pytestconfig):
    path = pytestconfig.getoption("--syscall-node-oracle")
    if not path:
        pytest.skip("no syscall_node oracle for this kernel (--syscall-node-oracle)")
    if _has_sqlite_table(path, "syscall_node"):
        return _query_sqlite_table(
            path,
            "SELECT syscall, function, syscall_location, function_location FROM syscall_node",
            SYSCALL_NODE_COLS,
        )
    return load_rows(path, SYSCALL_NODE_COLS)


@pytest.fixture(scope="session")
def function_locations(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--function-locations",
        ["functions.csv", "function_locations.csv"],
        "function_locations output",
    )
    if path:
        return load_rows(path, FUNCTION_LOCATION_COLS)

    if _has_sqlite_table(sqlite_db, "function_locations"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT function_name, file_path, start_line, end_line FROM function_locations",
            FUNCTION_LOCATION_COLS,
        )

    pytest.skip("function_locations not supplied (pass --function-locations, --results-dir, or --sqlite-db)")


@pytest.fixture(scope="session")
def ops_targets(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--ops-targets",
        ["ops_edges.csv", "ops_targets.csv"],
        "ops_targets output",
    )
    if path:
        return load_rows(path, OPS_TARGETS_COLS)

    if _has_sqlite_table(sqlite_db, "ops_targets"):
        return _query_sqlite_table(
            sqlite_db,
            """
            SELECT definition, parent, field, target, target_file, target_start,
                   target_end, exprcall_file, exprcall_line, exprcall_parent_start,
                   exprcall_parent_end
            FROM ops_targets
            """,
            OPS_TARGETS_COLS,
        )

    pytest.skip("ops_targets not supplied (pass --ops-targets, --results-dir, or --sqlite-db)")


@pytest.fixture(scope="session")
def configs(pytestconfig, sqlite_db):
    path = _resolve_file(
        pytestconfig,
        "--configs",
        ["kernel-configs-needed.csv", "configs.csv"],
        "configs output",
    )
    if path:
        return load_rows(path, CONFIGS_COLS)

    if _has_sqlite_table(sqlite_db, "configs"):
        return _query_sqlite_table(
            sqlite_db,
            "SELECT config, path, ifdef, endif, else_ FROM configs",
            CONFIGS_COLS,
        )

    pytest.skip("configs not supplied (pass --configs, --results-dir, or --sqlite-db)")
