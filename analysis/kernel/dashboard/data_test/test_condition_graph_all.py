"""Data-quality checks for `conditions_node` (`condition-graph-all.ql`)."""
from __future__ import annotations

from common import load_baseline, pct, report
import pytest


def test_conditions_node_not_empty(conditions_node, kernel):
    """Verify conditions_node table has at least 10,000 reachability rows.

    Reference 6.1.111 DB contains 27,791,381 rows (with exprCallEdge);
    resolveCall produces ~10.6M rows. Catches accidental target-function
    filtering (like the 7-function debug filter).
    """
    report(
        f"conditions_node sample/table rows [{kernel}]",
        {"rows loaded": len(conditions_node)},
    )
    assert len(conditions_node) >= 10000, (
        f"only {len(conditions_node)} conditions_node rows -- "
        "reachability closure truncated or filtered"
    )


def test_conditions_node_diversity(conditions_node):
    """Verify reachability spans >100 distinct kernel functions."""
    distinct_conds = {r["conditions"] for r in conditions_node}
    distinct_funcs = {r["function"] for r in conditions_node}
    report(
        "conditions_node reachability diversity",
        {
            "distinct condition seeds": len(distinct_conds),
            "distinct reached functions": len(distinct_funcs),
        },
    )
    assert len(distinct_funcs) > 100, (
        f"only {len(distinct_funcs)} distinct reached functions in "
        "conditions_node (expected > 100)"
    )


def test_conditions_node_locations_well_formed(conditions_node):
    """Verify conditions_location and function_location have 5-part format."""
    bad_cloc = sum(
        1 for r in conditions_node if r["conditions_location"].count(":") < 4
    )
    bad_floc = sum(
        1 for r in conditions_node if r["function_location"].count(":") < 4
    )
    report(
        "conditions_node 5-part location formatting",
        {
            "bad conditions_location": bad_cloc,
            "bad function_location": bad_floc,
        },
    )
    assert bad_cloc == 0 and bad_floc == 0


def test_conditions_node_functions_exist_in_function_locations(
    conditions_node, function_locations
):
    """Verify >=90% of reached functions appear in function_locations."""
    known = {r["function_name"] for r in function_locations}
    reached = {r["function"] for r in conditions_node}
    rate = pct(len(reached & known), len(reached))
    report(
        "conditions_node reached functions vs function_locations",
        {"reached functions": len(reached), "present %": f"{rate:.1f}"},
    )
    assert rate >= 90.0, (
        f"only {rate:.1f}% of conditions_node functions appear in "
        "function_locations"
    )


def test_conditions_node_distribution(conditions_node, baseline_path):
    """Verify conditions_node row count against baseline when un-sampled."""
    base = load_baseline(baseline_path, "conditions_node")
    if not base or len(conditions_node) == 250000:
        pytest.skip("no baseline recorded or SQLite sample limit active")
    ratio = len(conditions_node) / base["rows"]
    report(
        "conditions_node distribution",
        {
            "rows": len(conditions_node),
            "baseline rows": base["rows"],
            "ratio": f"{ratio:.2f}x",
        },
    )
    assert ratio >= 0.35, (
        f"conditions_node row count dropped below 35% of baseline "
        f"({len(conditions_node)} vs {base['rows']})"
    )
