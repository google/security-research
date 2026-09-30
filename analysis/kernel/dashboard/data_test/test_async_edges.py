"""Data-quality checks for the `async_edges` table (async-edges.ql output).

Validates asynchronous callback edges across Form A (registrar argument),
Form B (struct field assignment), and Form C (designated struct initializer),
including per-mechanism coverage, canonical kernel spot-checks, cross-table
function resolution, and source-code matching heuristics across kernel versions.
"""

from __future__ import annotations

import collections
import os
import re

from common import load_baseline, pct, report, top_counts
import pytest

VALID_FORMS = {"arg", "assign", "init"}
VALID_CONTEXTS = {"kthread", "softirq", "hard_irq", "ipi", "process"}
INTERNAL_TRAMPOLINES = {
    "delayed_work_timer_fn",
    "kthread_delayed_work_timer_fn",
    "rcu_work_rcufn",
}

# Minimum expected edges per active mechanism across 6.1 - 6.18 x86_64 builds
EXPECTED_MECHANISM_MIN_COUNTS = {
    "async": 8,
    "block_io": 250,
    "cpuhp": 80,
    "crypto": 30,
    "hrtimer": 30,
    "io_uring": 10,
    "ipi": 100,
    "irq": 100,
    "kref": 120,
    "kthread": 40,
    "kthread_worker": 5,
    "napi": 15,
    "netfilter": 120,
    "notifier": 150,
    "poll": 8,
    "rcu": 150,
    "skb": 15,
    "socket": 40,
    "softirq": 10,
    "task_work": 25,
    "tasklet": 5,
    "teardown": 180,
    "timer": 100,
    "waitqueue": 100,
    "workqueue": 400,
}

# Canonical kernel async registrations present across 6.1, 6.6, 6.12, and 6.18
CANONICAL_EDGES = [
    ("mntput_no_expire", "__cleanup_mnt", "task_work", "arg"),
    ("softirq_init", "tasklet_action", "softirq", "arg"),
    ("softirq_init", "tasklet_hi_action", "softirq", "arg"),
    ("hrtimers_init", "hrtimer_run_softirq", "softirq", "arg"),
    ("net_dev_init", "process_backlog", "napi", "assign"),
    ("in6_dev_finish_destroy", "in6_dev_finish_destroy_rcu", "rcu", "arg"),
    ("xfrm_policy_destroy", "xfrm_policy_destroy_rcu", "rcu", "arg"),
    ("kernfs_notify", "kernfs_notify_workfn", "workqueue", "init"),
    ("poll_initwait", "__pollwait", "poll", "arg"),
    ("bio_chain", "bio_chain_endio", "block_io", "assign"),
    ("__clk_put", "__clk_release", "kref", "arg"),
    ("__cpu_device_create", "device_create_release", "teardown", "assign"),
    ("acpi_processor_driver_init", "acpi_soft_cpu_online", "cpuhp", "arg"),
]

_MACRO_KEYWORDS = (
    "DEFINE_WAIT",
    "init_wait",
    "DECLARE_",
    "INIT_",
    "_INIT",
    "##",
)


def _locate_kernel_source_file(raw_file: str, kernel: str) -> str | None:
    """Resolve `raw_file` to an on-disk kernel source file if available."""
    if os.path.isfile(raw_file):
        return raw_file

    workspace = os.environ.get(
        "WORKSPACE_DIR",
        os.path.expanduser("~/kernel_codeql_workspace"),
    )
    candidates = []
    if kernel and kernel != "unknown":
        clean_ver = kernel.lstrip("v")
        candidates.append(os.path.join(workspace, f"linux_v{clean_ver}"))
    entries = (
        sorted(os.listdir(workspace)) if os.path.isdir(workspace) else []
    )
    for entry in entries:
        if entry.startswith("linux_v"):
            candidates.append(os.path.join(workspace, entry))

    for repo_dir in candidates:
        candidate = os.path.join(repo_dir, raw_file)
        if os.path.isfile(candidate):
            return candidate
    return None


def _verify_edge_in_source(row: dict, src_path: str) -> bool:
    """Heuristic verifying an async_edges row against its C source file."""
    try:
        line_no = int(row["line"])
        with open(src_path, encoding="utf-8", errors="replace") as src_file:
            lines = src_file.readlines()
    except (OSError, ValueError):
        return False

    if not 1 <= line_no <= len(lines):
        return False

    callee = row["callee"]
    start = max(0, line_no - 20)
    end = min(len(lines), line_no + 25)
    window = "".join(lines[start:end])

    # 1. Direct appearance of callback identifier in local source window
    if callee in window:
        return True

    # 2. Standard kernel initializer macro that embeds a default callback
    if any(kw in window for kw in _MACRO_KEYWORDS):
        return True

    # 3. File-local helper macro (e.g., `#define node_free(n) call_rcu(...)`)
    # defined earlier in the same source file and invoked in the local window.
    full_source = "".join(lines[: line_no + 5])
    if callee in full_source:
        for match in re.finditer(
            r"#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", full_source
        ):
            macro_name = match.group(1)
            if macro_name in window:
                return True

    return False


def test_async_edges_not_empty(async_edges, kernel):
    """Verify async_edges contains a substantial set of callback edges."""
    report(f"async_edges rows [{kernel}]", {"rows": len(async_edges)})
    assert len(async_edges) >= 1500, (
        f"expected >= 1500 async edges, got {len(async_edges)}"
    )


def test_async_edges_fields_and_forms_valid(async_edges):
    """Verify all columns, registration forms, and contexts are valid."""
    blank_caller = sum(1 for r in async_edges if not r["caller"])
    blank_callee = sum(1 for r in async_edges if not r["callee"])
    blank_mech = sum(1 for r in async_edges if not r["mechanism"])
    bad_forms = [r["form"] for r in async_edges if r["form"] not in VALID_FORMS]
    bad_lines = [
        r["line"]
        for r in async_edges
        if not r["line"].isdigit() or int(r["line"]) <= 0
    ]
    trampoline_hits = [
        r for r in async_edges if r["callee"] in INTERNAL_TRAMPOLINES
    ]
    bad_contexts = [
        r.get("context")
        for r in async_edges
        if "context" in r and r["context"] not in VALID_CONTEXTS
    ]

    report(
        "field & form validity",
        {
            "blank caller": blank_caller,
            "blank callee": blank_callee,
            "blank mechanism": blank_mech,
            "invalid forms": len(bad_forms),
            "invalid lines": len(bad_lines),
            "invalid contexts": len(bad_contexts),
            "trampoline leaks": len(trampoline_hits),
        },
    )
    assert blank_caller == 0
    assert blank_callee == 0
    assert blank_mech == 0
    assert not bad_forms, f"unexpected form values: {set(bad_forms)}"
    assert not bad_lines, f"invalid line numbers: {bad_lines[:5]}"
    assert not bad_contexts, f"invalid context values: {set(bad_contexts)}"
    assert not trampoline_hits, (
        f"internal work trampolines leaked into async_edges: "
        f"{trampoline_hits[:5]}"
    )


def test_async_edges_no_self_or_degenerate_edges(async_edges):
    """Verify caller != callee and <file-scope:...> callers are well-formed."""
    self_edges = [r for r in async_edges if r["caller"] == r["callee"]]
    file_scope_rows = [
        r for r in async_edges if r["caller"].startswith("<file-scope:")
    ]
    bad_file_scope = [
        r
        for r in file_scope_rows
        if not r["caller"].endswith(">")
        or len(r["caller"]) <= len("<file-scope:>")
    ]
    report(
        "self & file-scope edges",
        {
            "self edges": len(self_edges),
            "file-scope rows": len(file_scope_rows),
            "malformed file-scope": len(bad_file_scope),
        },
    )
    assert not self_edges, f"found degenerate self-edges: {self_edges[:5]}"
    assert file_scope_rows, "expected Form C static initializers at file scope"
    assert not bad_file_scope, (
        f"malformed <file-scope:...> callers: {bad_file_scope[:5]}"
    )


def test_async_edges_all_core_mechanisms_populated(async_edges):
    """Verify every catalog mechanism meets its minimum expected edge count."""
    counts = collections.Counter(r["mechanism"] for r in async_edges)
    report("top async mechanisms", top_counts(async_edges, "mechanism", 25))
    report("registration forms", top_counts(async_edges, "form", 5))

    below_min = {
        mech: (counts.get(mech, 0), min_cnt)
        for mech, min_cnt in EXPECTED_MECHANISM_MIN_COUNTS.items()
        if counts.get(mech, 0) < min_cnt
    }
    assert not below_min, (
        f"mechanisms below minimum threshold (actual, min): {below_min}"
    )


def test_async_edges_canonical_kernel_callbacks_present(async_edges):
    """Spot-check canonical kernel async registrations across subsystems."""
    edge_set = {
        (r["caller"], r["callee"], r["mechanism"], r["form"])
        for r in async_edges
    }
    missing = [edge for edge in CANONICAL_EDGES if edge not in edge_set]

    # Verify fput -> ____fput (fput in 6.1..6.12, __fput_deferred in 6.18)
    has_fput_task_work = any(
        r["callee"] == "____fput"
        and r["caller"] in ("fput", "__fput_deferred")
        and r["mechanism"] == "task_work"
        and r["form"] == "arg"
        for r in async_edges
    )
    # Also verify socket default callbacks (sock_init_data / sock_init_data_uid)
    has_sock_def_readable = any(
        r["callee"] == "sock_def_readable"
        and r["mechanism"] == "socket"
        and r["form"] == "assign"
        for r in async_edges
    )
    has_skb_sock_wfree = any(
        r["callee"] == "sock_wfree"
        and r["mechanism"] == "skb"
        and r["form"] == "assign"
        for r in async_edges
    )

    report(
        "canonical spot-checks",
        {
            "checked": len(CANONICAL_EDGES) + 3,
            "missing": len(missing)
            + (0 if has_fput_task_work else 1)
            + (0 if has_sock_def_readable else 1)
            + (0 if has_skb_sock_wfree else 1),
        },
    )
    assert not missing, f"missing canonical async edges: {missing}"
    assert has_fput_task_work, "missing fput/__fput_deferred -> ____fput"
    assert has_sock_def_readable, "missing socket assign -> sock_def_readable"
    assert has_skb_sock_wfree, "missing skb assign -> sock_wfree"


def test_async_edges_callees_resolve_to_known_functions(
    async_edges, function_locations
):
    """Verify callees and function callers exist in function_locations."""
    known = {r["function_name"] for r in function_locations}
    callees = {r["callee"] for r in async_edges if r["callee"]}
    callers = {
        r["caller"]
        for r in async_edges
        if r["caller"] and not r["caller"].startswith("<file-scope:")
    }

    callee_rate = pct(len(callees & known), len(callees))
    caller_rate = pct(len(callers & known), len(callers))
    report(
        "async_edges vs function_locations",
        {
            "distinct callees": len(callees),
            "callee present %": f"{callee_rate:.1f}%",
            "distinct fn callers": len(callers),
            "caller present %": f"{caller_rate:.1f}%",
        },
    )
    assert callee_rate >= 95.0, (
        f"only {callee_rate:.1f}% of async callees found in function_locations"
    )
    assert caller_rate >= 95.0, (
        f"only {caller_rate:.1f}% of async callers found in function_locations"
    )


def test_async_edges_source_code_verification_heuristic(async_edges, kernel):
    """Verify stratified sample of async edges against kernel C source files."""
    by_pair = collections.defaultdict(list)
    for row in async_edges:
        by_pair[(row["mechanism"], row["form"])].append(row)

    # Stratified sample: up to 10 rows per (mechanism, form) bucket
    sampled = []
    for key in sorted(by_pair):
        sampled.extend(by_pair[key][:10])

    verified = 0
    checked = 0
    unmatched_samples = []
    for row in sampled:
        src_path = _locate_kernel_source_file(row["file"], kernel)
        if not src_path:
            continue
        checked += 1
        if _verify_edge_in_source(row, src_path):
            verified += 1
        else:
            unmatched_samples.append(row)

    if checked == 0:
        pytest.skip("kernel source files not available on disk")

    match_rate = pct(verified, checked)
    report(
        "source-code heuristic verification",
        {
            "sampled edges": checked,
            "verified in C source": verified,
            "match rate %": f"{match_rate:.1f}%",
        },
    )
    assert match_rate >= 99.0, (
        f"source verification rate {match_rate:.1f}% < 99.0%; "
        f"unmatched samples: {unmatched_samples[:5]}"
    )


def test_async_edges_distribution(async_edges, baseline_path):
    """Verify async_edges row count does not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "async_edges")
    if not base:
        pytest.skip("no baseline recorded for async_edges (--baseline)")
    report(
        "distribution",
        {"rows": len(async_edges), "baseline rows": base.get("rows")},
    )
    if base.get("rows"):
        ratio = len(async_edges) / base["rows"]
        assert ratio >= 0.75, (
            f"async_edges row count dropped below 75% of baseline "
            f"({len(async_edges)} vs {base['rows']})"
        )
