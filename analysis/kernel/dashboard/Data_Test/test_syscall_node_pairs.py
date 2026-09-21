"""Data-quality checks for `syscall-node-pairs.ql` (syscall-to-function reachability pairs)."""
from __future__ import annotations

import statistics

import pytest

from common import group_sets, load_baseline, pct, report

SYSCALL_PREFIX = "__do_sys_"


def test_syscall_node_pairs_not_empty(syscall_node_pairs, kernel):
    report(f"syscall_node_pairs rows [{kernel}]", {"rows": len(syscall_node_pairs)})
    assert syscall_node_pairs, "no reachability rows -- the closure produced nothing"


def test_syscall_seeds_are_do_sys(syscall_node_pairs):
    bad = {
        r["syscall"] for r in syscall_node_pairs
        if not r["syscall"].startswith(SYSCALL_PREFIX)
    }
    distinct = len({r["syscall"] for r in syscall_node_pairs})
    report("syscall seeds", {"distinct syscalls": distinct, "non __do_sys_ seeds": len(bad)})
    assert not bad, f"unexpected seed names: {sorted(bad)[:5]}"
    assert distinct > 300, f"only {distinct} syscalls -- seeding looks broken"


def test_reachability_is_irreflexive(syscall_node_pairs):
    """The closure is edges+ with the root excluded; a syscall must not reach itself."""
    self_rows = [r for r in syscall_node_pairs if r["syscall"] == r["function"]]
    report("self-reachability", {"rows where syscall == function": len(self_rows)})
    assert not self_rows


def test_reach_per_syscall_is_plausible(syscall_node_pairs):
    """A deep call graph gives thousands of reachable functions per syscall; a
    collapse to double digits means the indirect-call edges were lost."""
    reach = group_sets(syscall_node_pairs, "syscall", "function")
    counts = sorted(len(v) for v in reach.values())
    median = statistics.median(counts)
    report(
        "per-syscall reach",
        {"min": counts[0], "median": median, "max": counts[-1], "syscalls": len(counts)},
    )
    assert median > 500, f"median reach is only {median} -- indirect edges likely missing"


def test_reached_functions_exist_in_function_locations(syscall_node_pairs, function_locations):
    """Every reached function should be a function the extractor also recorded."""
    known = {r["function_name"] for r in function_locations}
    reached = {r["function"] for r in syscall_node_pairs}
    missing = reached - known
    rate = pct(len(reached & known), len(reached))
    report(
        "reached vs function_locations",
        {
            "reached functions": len(reached),
            "known functions": len(known),
            "present %": f"{rate:.1f}",
            "missing": len(missing),
        },
    )
    assert rate >= 95.0, f"only {rate:.1f}% of reached functions appear in function_locations"


def test_syscall_node_distribution(syscall_node_pairs, baseline_path):
    base = load_baseline(baseline_path, "syscall_node")
    if not base:
        pytest.skip("no baseline recorded for syscall_node (--baseline)")
    reach = group_sets(syscall_node_pairs, "syscall", "function")
    mean_reach = statistics.mean(len(v) for v in reach.values())
    report(
        "distribution",
        {
            "rows": len(syscall_node_pairs),
            "baseline rows": base.get("rows"),
            "mean reach": f"{mean_reach:.0f}",
            "baseline mean reach": base.get("mean_reach"),
        },
    )
    if base.get("rows"):
        ratio = len(syscall_node_pairs) / base["rows"]
        assert ratio >= 0.75, f"row count dropped to {ratio:.1%} of baseline ({len(syscall_node_pairs)} vs {base['rows']})"


def test_syscall_node_is_superset_of_oracle(syscall_node_pairs, syscall_node_oracle):
    """Reachability should never LOSE an edge the reference found."""
    ours = group_sets(syscall_node_pairs, "syscall", "function")
    theirs = group_sets(syscall_node_oracle, "syscall", "function")
    common_funcs = {f for v in ours.values() for f in v} & {f for v in theirs.values() for f in v}
    shared_syscalls = set(ours) & set(theirs)

    ours_only = oracle_only = 0
    worst = []
    for syscall in shared_syscalls:
        a = ours[syscall] & common_funcs
        b = theirs[syscall] & common_funcs
        ours_only += len(a - b)
        missing = len(b - a)
        oracle_only += missing
        if missing:
            worst.append((syscall, missing))
    report(
        "vs oracle (shared function universe)",
        {
            "shared syscalls": len(shared_syscalls),
            "ours-only reachability": ours_only,
            "oracle-only (we MISS)": oracle_only,
        },
    )
    if worst:
        report("syscalls where we miss reachability", sorted(worst, key=lambda x: -x[1])[:10])
    assert oracle_only == 0, f"we lose {oracle_only} reachability edges the reference found"
