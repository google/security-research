"""Data-quality checks for the `async_edges` table (async-edges.ql output).

Validates asynchronous callback edges across Form A (registrar argument),
Form B (struct field assignment), and Form C (designated struct initializer),
including per-mechanism coverage, inline vs. deferred context taxonomy (A2),
USB subsystem gating (C1), tightened source-code verification (C2),
CVE ground-truth callback recall (B2), and cross-table function resolution.
"""

from __future__ import annotations

import collections
import os
import re

from common import (
    load_baseline,
    locate_kernel_source_file as _locate_kernel_source_file,
    pct,
    report,
    scan_compiled_c_targets,
    top_counts,
)
import pytest

VALID_FORMS = {"arg", "assign", "init"}
VALID_CONTEXTS = {"kthread", "softirq", "hard_irq", "ipi", "process", "inline"}
INLINE_MECHANISMS = {"kref", "nf_hook_inline", "rhashtable_destroy"}
INTERNAL_TRAMPOLINES = {
    "delayed_work_timer_fn",
    "kthread_delayed_work_timer_fn",
    "rcu_work_rcufn",
}

USB_MIN_COUNT_WHEN_ENABLED = 20

# Minimum expected edges for core mechanisms present in all x86_64 builds;
# subsystem-optional mechanisms (io_uring, block_io, netfilter, nf_hook_inline)
# are gated/verified against compiled C source below.
EXPECTED_MECHANISM_MIN_COUNTS = {
    "async": 8,
    "block_io": 100,
    "cpuhp": 80,
    "crypto": 30,
    "hrtimer": 30,
    "ipi": 100,
    "irq": 100,
    "kref": 120,
    "kthread": 40,
    "kthread_worker": 5,
    "napi": 15,
    "netfilter": 80,
    "nf_hook_inline": 25,
    "notifier": 150,
    "poll": 8,
    "rcu": 150,
    "rhashtable_destroy": 5,
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

# Compiled C source patterns for measuring extraction recall % across
# the .c files actually compiled in this kernel build.
_ASYNC_SOURCE_PATTERNS = {
    "workqueue (INIT_WORK)": (
        "workqueue",
        re.compile(r"\bINIT_WORK\s*\([^,]+,\s*&?([A-Za-z_][A-Za-z0-9_]*)\s*\)"),
    ),
    "timer (timer_setup)": (
        "timer",
        re.compile(
            r"\btimer_setup\s*\([^,]+,\s*&?([A-Za-z_][A-Za-z0-9_]*)\s*,"
        ),
    ),
    "rcu (call_rcu)": (
        "rcu",
        re.compile(r"\bcall_rcu\s*\([^,]+,\s*&?([A-Za-z_][A-Za-z0-9_]*)\s*\)"),
    ),
    "block_io (bi_end_io)": (
        "block_io",
        re.compile(
            r"(?:->|\.)bi_end_io\s*=\s*&?([A-Za-z_][A-Za-z0-9_]*)\b"
        ),
    ),
    "task_work (init_task_work)": (
        "task_work",
        re.compile(
            r"\binit_task_work\s*\([^,]+,\s*&?([A-Za-z_][A-Za-z0-9_]*)\s*\)"
        ),
    ),
    "softirq (open_softirq)": (
        "softirq",
        re.compile(
            r"\bopen_softirq\s*\([^,]+,\s*&?([A-Za-z_][A-Za-z0-9_]*)\s*\)"
        ),
    ),
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

# Ground-truth async callbacks from historical Linux kernel UAF / race CVEs
# (Recommendation B2: CVE recall check across net, io_uring, fs, keys, crypto)
CVE_CALLBACK_GROUND_TRUTH = [
    ("io_ring_exit_work", "workqueue"),
    ("io_tctx_exit_cb", "task_work"),
    ("____fput", "task_work"),
    ("delayed_fput", "workqueue"),
    ("gc_worker", "workqueue"),
    ("neigh_timer_handler", "timer"),
    ("neigh_periodic_work", "workqueue"),
    ("tcp_write_timer", "timer"),
    ("tcp_delack_timer", "timer"),
    ("tcp_keepalive_timer", "timer"),
    ("xfrm_state_gc_task", "workqueue"),
    ("xfrm_policy_timer", "timer"),
    ("in6_dev_finish_destroy_rcu", "rcu"),
    ("ip_expire", "timer"),
    ("ip6_frag_expire", "timer"),
    ("key_garbage_collector", "workqueue"),
    ("key_gc_timer_func", "timer"),
    ("cryptd_queue_worker", "workqueue"),
    ("call_usermodehelper_exec_work", "workqueue"),
    ("rht_deferred_worker", "workqueue"),
    ("bdev_free_inode", "rcu"),
    ("ext4_free_in_core_inode", "rcu"),
]

# Narrowed default-callback macros that expand a standard kernel callback
# without spelling the callback identifier at the invocation site (C2).
_DEFAULT_CB_MACROS = {
    "autoremove_wake_function": ("DEFINE_WAIT", "init_wait"),
    "default_wake_function": ("DEFINE_WAIT", "DECLARE_WAIT"),
    "woken_wake_function": ("DEFINE_WAIT_FUNC",),
    "wake_bit_function": ("DEFINE_WAIT_BIT", "__init_waitqueue_func_entry"),
    "__pollwait": ("poll_initwait", "init_poll_funcptr"),
}


def _verify_edge_in_source(row: dict, src_path: str) -> str | None:
    """Verify an async_edges row against its C source file (Recommendation C2).

    Returns:
      - "direct" if `row["callee"]` appears literally in the local window
      - "macro" if matched via a known default-callback macro or a file-local
        `#define` whose body references `callee` or token-pasting `##`
      - None if unverified
    """
    try:
        line_no = int(row["line"])
        with open(src_path, encoding="utf-8", errors="replace") as src_file:
            lines = src_file.readlines()
    except (OSError, ValueError):
        return None

    if not 1 <= line_no <= len(lines):
        return None

    callee = row["callee"]
    start = max(0, line_no - 20)
    end = min(len(lines), line_no + 25)
    window = "".join(lines[start:end])

    # 1. Direct appearance of callback identifier in local source window
    if callee in window:
        return "direct"

    # 2. Narrowed default-callback macros (e.g., DEFINE_WAIT -> autoremove)
    allowed_macros = _DEFAULT_CB_MACROS.get(callee, ())
    if any(macro_kw in window for macro_kw in allowed_macros):
        return "macro"

    # 3. File-local helper macro defined earlier in the same file whose body
    # references `callee` or token-pastes `##`
    prefix_source = "".join(lines[: line_no + 5])
    macro_def_re = re.compile(
        r"#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b([^\n]*(?:\\\n[^\n]*)*)"
    )
    for match in macro_def_re.finditer(prefix_source):
        macro_name, macro_body = match.group(1), match.group(2)
        if macro_name in window and (
            callee in macro_body or "##" in macro_body
        ):
            return "macro"

    return None


def test_async_edges_not_empty(async_edges, kernel):
    """Verify async_edges contains a substantial set of callback edges."""
    report(f"async_edges rows [{kernel}]", {"rows": len(async_edges)})
    assert len(async_edges) >= 1500, (
        f"expected >= 1500 async edges, got {len(async_edges)}"
    )


def test_async_edges_fields_and_forms_valid(async_edges):
    """Verify columns, forms, and inline vs. deferred contexts (A2)."""
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
    bad_inline_taxonomy = [
        (r["mechanism"], r["context"])
        for r in async_edges
        if "context" in r
        and (
            (r["mechanism"] in INLINE_MECHANISMS) != (r["context"] == "inline")
        )
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
            "inline taxonomy mismatches": len(bad_inline_taxonomy),
            "trampoline leaks": len(trampoline_hits),
        },
    )
    assert blank_caller == 0
    assert blank_callee == 0
    assert blank_mech == 0
    assert not bad_forms, f"unexpected form values: {set(bad_forms)}"
    assert not bad_lines, f"invalid line numbers: {bad_lines[:5]}"
    assert not bad_contexts, f"invalid context values: {set(bad_contexts)}"
    assert not bad_inline_taxonomy, (
        f"inline vs deferred context mismatch: {bad_inline_taxonomy[:5]}"
    )
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
    init_fn_rows = [
        r
        for r in async_edges
        if r["form"] == "init" and not r["caller"].startswith("<file-scope:")
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
            "Form C function-bridged rows": len(init_fn_rows),
            "file-scope rows": len(file_scope_rows),
            "malformed file-scope": len(bad_file_scope),
        },
    )
    assert not self_edges, f"found degenerate self-edges: {self_edges[:5]}"
    assert init_fn_rows, (
        "expected Form C static initializers bridged to functions"
    )
    assert file_scope_rows, "expected unreferenced Form C tables at file scope"
    assert not bad_file_scope, (
        f"malformed <file-scope:...> callers: {bad_file_scope[:5]}"
    )


def test_async_edges_all_core_mechanisms_populated(
    async_edges, function_locations, kernel
):
    """Verify compiled mechanisms are populated and source callback recall >= 90%."""
    counts = collections.Counter(r["mechanism"] for r in async_edges)
    usb_compiled = any(
        "drivers/usb/core/" in r["file_path"] for r in function_locations
    )
    io_uring_compiled = any(
        r["file_path"].endswith(".c")
        and (
            "/io_uring/" in r["file_path"]
            or r["file_path"].startswith("io_uring/")
        )
        for r in function_locations
    )

    below_min = {
        mech: (counts.get(mech, 0), min_cnt)
        for mech, min_cnt in EXPECTED_MECHANISM_MIN_COUNTS.items()
        if counts.get(mech, 0) < min_cnt
    }
    if io_uring_compiled and counts.get("io_uring", 0) < 10:
        below_min["io_uring"] = (counts.get("io_uring", 0), 10)
    if usb_compiled and counts.get("usb", 0) < USB_MIN_COUNT_WHEN_ENABLED:
        below_min["usb"] = (counts.get("usb", 0), USB_MIN_COUNT_WHEN_ENABLED)

    by_mech_callees: dict[str, set[str]] = collections.defaultdict(set)
    for row in async_edges:
        by_mech_callees[row["mechanism"]].add(row["callee"])

    source_patterns = {
        label: rx for label, (_, rx) in _ASYNC_SOURCE_PATTERNS.items()
    }
    compiled_source_targets = scan_compiled_c_targets(
        function_locations, kernel, source_patterns
    )
    recall_metrics: dict[str, str] = {}
    low_recall: dict[str, str] = {}
    for label, (mech, _) in _ASYNC_SOURCE_PATTERNS.items():
        expected = compiled_source_targets.get(label, set())
        if not expected:
            continue
        recalled = expected & by_mech_callees.get(mech, set())
        rate = pct(len(recalled), len(expected))
        recall_metrics[label] = (
            f"{len(recalled)} / {len(expected)} ({rate:.1f}%)"
        )
        if rate < 90.0:
            missing_sample = sorted(expected - recalled)[:5]
            low_recall[label] = (
                f"{rate:.1f}% ({len(recalled)}/{len(expected)}), "
                f"missing sample: {missing_sample}"
            )

    report("top async mechanisms", top_counts(async_edges, "mechanism", 30))
    report("registration forms", top_counts(async_edges, "form", 5))
    report(
        "subsystem gates & compiled-source recall",
        {
            "drivers/usb/core/ compiled": usb_compiled,
            "io_uring/ compiled": io_uring_compiled,
            **recall_metrics,
        },
    )

    assert not below_min, (
        f"mechanisms below minimum threshold (actual, min): {below_min}"
    )
    assert not low_recall, (
        f"compiled-source async callback recall below 90%: {low_recall}"
    )


def test_async_edges_canonical_kernel_callbacks_present(
    async_edges, function_locations
):
    """Spot-check canonical kernel async registrations compiled in the DB."""
    known_funcs = {r["function_name"] for r in function_locations}
    edge_set = {
        (r["caller"], r["callee"], r["mechanism"], r["form"])
        for r in async_edges
    }
    compiled_canonical = [
        edge
        for edge in CANONICAL_EDGES
        if edge[0] in known_funcs and edge[1] in known_funcs
    ]
    missing = [edge for edge in compiled_canonical if edge not in edge_set]

    # Verify fput -> ____fput (fput in 6.1..6.12, __fput_deferred in 6.18)
    has_fput_task_work = any(
        r["callee"] == "____fput"
        and r["caller"] in ("fput", "__fput_deferred")
        and r["mechanism"] == "task_work"
        and r["form"] == "arg"
        for r in async_edges
    )
    # Verify socket default callbacks (sock_init_data / sock_init_data_uid)
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
    usb_compiled = any(
        "drivers/usb/core/" in r["file_path"] for r in function_locations
    )
    has_usb_canonical = (not usb_compiled) or any(
        r["callee"] in ("sg_complete", "usb_api_blocking_completion")
        and r["mechanism"] == "usb"
        for r in async_edges
    )

    report(
        "canonical spot-checks (compiled in DB)",
        {
            "compiled canonical edges": (
                f"{len(compiled_canonical)} / {len(CANONICAL_EDGES)}"
            ),
            "recalled": len(compiled_canonical) - len(missing),
            "recall %": (
                f"{pct(len(compiled_canonical) - len(missing), len(compiled_canonical)):.1f}%"
            ),
        },
    )
    assert compiled_canonical, "no canonical async edges found in function_locations"
    assert not missing, f"missing compiled canonical async edges: {missing}"
    assert has_fput_task_work, "missing fput/__fput_deferred -> ____fput"
    assert has_sock_def_readable, "missing socket assign -> sock_def_readable"
    assert has_skb_sock_wfree, "missing skb assign -> sock_wfree"
    assert has_usb_canonical, (
        "missing canonical usb core callback (sg_complete / "
        "usb_api_blocking_completion)"
    )


def test_async_edges_cve_callback_recall(async_edges, function_locations):
    """Verify 100% recall against ground-truth CVE callbacks compiled in DB (B2)."""
    known_funcs = {r["function_name"] for r in function_locations}
    compiled_ground_truth = [
        item for item in CVE_CALLBACK_GROUND_TRUTH if item[0] in known_funcs
    ]
    by_callee_mech = {
        (r["callee"], r["mechanism"]) for r in async_edges
    }
    recalled = [
        item for item in compiled_ground_truth if item in by_callee_mech
    ]
    missing = [
        item
        for item in compiled_ground_truth
        if item not in by_callee_mech
    ]
    recall_pct = pct(len(recalled), len(compiled_ground_truth))

    report(
        "CVE async callback recall (B2, normalized to compiled functions)",
        {
            "compiled ground-truth CVE callbacks": (
                f"{len(compiled_ground_truth)} / {len(CVE_CALLBACK_GROUND_TRUTH)}"
            ),
            "recalled": len(recalled),
            "recall %": f"{recall_pct:.1f}%",
        },
    )
    assert compiled_ground_truth, (
        "no CVE ground-truth callbacks found in function_locations"
    )
    assert not missing, (
        f"missed compiled ground-truth CVE async callbacks: {missing}"
    )


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
    """Verify stratified sample of async edges against kernel C source (C2)."""
    by_pair = collections.defaultdict(list)
    for row in async_edges:
        by_pair[(row["mechanism"], row["form"])].append(row)

    # Stratified sample: up to 10 rows per (mechanism, form) bucket
    sampled = []
    for key in sorted(by_pair):
        sampled.extend(by_pair[key][:10])

    direct_matches = 0
    macro_matches = 0
    checked = 0
    unmatched_samples = []
    for row in sampled:
        src_path = _locate_kernel_source_file(row["file"], kernel)
        if not src_path:
            continue
        checked += 1
        kind = _verify_edge_in_source(row, src_path)
        if kind == "direct":
            direct_matches += 1
        elif kind == "macro":
            macro_matches += 1
        else:
            unmatched_samples.append(row)

    if checked == 0:
        pytest.skip("kernel source files not available on disk")

    verified = direct_matches + macro_matches
    direct_rate = pct(direct_matches, checked)
    total_rate = pct(verified, checked)
    report(
        "source-code heuristic verification (C2)",
        {
            "sampled edges": checked,
            "direct symbol matches": f"{direct_matches} ({direct_rate:.1f}%)",
            "macro-expanded matches": macro_matches,
            "total verified": f"{verified} ({total_rate:.1f}%)",
        },
    )
    assert direct_rate >= 90.0, (
        f"direct symbol match rate {direct_rate:.1f}% < 90.0%"
    )
    assert total_rate >= 98.0, (
        f"total source verification rate {total_rate:.1f}% < 98.0%; "
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
