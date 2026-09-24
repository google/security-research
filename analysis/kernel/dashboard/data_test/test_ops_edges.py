"""Data-quality checks for the `ops_targets` table (ops_edges.ql output).

This table resolves indirect calls through kernel operations structs
(file_operations, inode_operations, ...) to concrete target functions. It has
never been validated against anything, so these checks are intrinsic and
cross-table only -- there is no reference dump.
"""
from __future__ import annotations

from common import load_baseline, pct, report, top_counts
import pytest


def test_ops_targets_not_empty(ops_targets, kernel):
    """Verify ops_targets contains resolved indirect call edges."""
    report(f"ops_targets rows [{kernel}]", {"rows": len(ops_targets)})
    assert (
        ops_targets
    ), "no ops-table edges -- indirect call resolution produced nothing"


def test_ops_targets_fields_are_populated(ops_targets):
    """Every edge needs a parent struct, a field, and a target to be useful."""
    blank_parent = sum(1 for r in ops_targets if not r["parent"])
    blank_field = sum(1 for r in ops_targets if not r["field"])
    blank_target = sum(1 for r in ops_targets if not r["target"])
    report(
        "field population",
        {
            "blank parent": blank_parent,
            "blank field": blank_field,
            "blank target": blank_target,
        },
    )
    assert blank_target == 0, "edges without a resolved target are useless"
    assert pct(blank_parent, len(ops_targets)) < 5.0
    assert pct(blank_field, len(ops_targets)) < 5.0


def test_ops_targets_cover_known_ops_structs(ops_targets):
    """Verify well-known dispatch tables appear in ops_targets."""
    parents = {r["parent"] for r in ops_targets}
    expected = {"file_operations", "inode_operations"}
    present = expected & parents
    report(
        "ops struct coverage",
        {
            "distinct parent structs": len(parents),
            "expected present": f"{sorted(present)}",
        },
    )
    report("top parent structs", top_counts(ops_targets, "parent"))
    assert (
        present
    ), f"none of {sorted(expected)} appear among {len(parents)} parent structs"


def test_ops_target_line_ranges_are_ordered(ops_targets):
    """Verify target_start <= target_end for >=99.5% of ops target callbacks."""
    bad = [
        r
        for r in ops_targets
        if r["target_start"].isdigit()
        and r["target_end"].isdigit()
        and int(r["target_start"]) > int(r["target_end"])
    ]
    report(
        "target line ranges",
        {
            "start > end": len(bad),
            "pct": f"{pct(len(bad), len(ops_targets)):.2f}%",
        },
    )
    # Up to ~0.15% of kernel ops callbacks (e.g. SHOW_CPU_ATTR macros in
    # drivers/base/cpu.c) span header/macro boundaries.
    assert pct(len(bad), len(ops_targets)) < 0.5


def test_ops_targets_resolve_to_known_functions(
    ops_targets, function_locations
):
    """Verify resolved targets exist in extracted function_locations."""
    known = {r["function_name"] for r in function_locations}
    targets = {r["target"] for r in ops_targets if r["target"]}
    rate = pct(len(targets & known), len(targets))
    report(
        "targets vs function_locations",
        {
            "distinct targets": len(targets),
            "present %": f"{rate:.1f}",
            "missing": len(targets - known),
        },
    )
    assert (
        rate >= 90.0
    ), f"only {rate:.1f}% of ops targets are known functions"


def test_ops_targets_distribution(ops_targets, baseline_path):
    """Verify ops_targets row count does not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "ops_targets")
    if not base:
        pytest.skip("no baseline recorded for ops_targets (--baseline)")
    report(
        "distribution",
        {"rows": len(ops_targets), "baseline rows": base.get("rows")},
    )
    if base.get("rows"):
        ratio = len(ops_targets) / base["rows"]
        assert ratio >= 0.75, (
            f"ops_targets row count dropped below 75% of baseline "
            f"({len(ops_targets)} vs {base['rows']})"
        )
