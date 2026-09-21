"""Data-quality checks for the `conditions` table (`condition-graph-direct.ql` output).

Consumed by `Tools/check_privilege.py` to determine whether call sites are gated by
`capable(...)`, `ns_capable(...)`, `sysctl`, or `module_param`.
"""
from __future__ import annotations

from collections import Counter
import pytest

from common import load_baseline, report


def test_conditions_not_empty(conditions, kernel):
    """Reference 6.1.111 DB contains 9,719 condition-dominated call rows."""
    report(f"conditions rows [{kernel}]", {"total": len(conditions)})
    assert len(conditions) >= 2500, f"only {len(conditions)} condition-dominated calls extracted"


def test_conditions_covers_all_four_gate_types(conditions):
    """Must include all 4 gate classes: capable, ns_capable, sysctl, module_param."""
    counts = Counter(r["type"] for r in conditions)
    expected = {"capable", "ns_capable", "sysctl", "module_param"}
    missing = {k for k in expected if counts.get(k, 0) == 0}
    report("condition gate type distribution", dict(counts))
    assert not missing, f"missing condition gate categories: {sorted(missing)}"
    assert counts["capable"] >= 500, f"too few capable() gates: {counts['capable']}"
    assert counts["ns_capable"] >= 500, f"too few ns_capable() gates: {counts['ns_capable']}"


def test_conditions_locations_well_formed(conditions):
    """Tools/check_privilege.py parses definition, condition, and call_location as file:sl:sc:el:ec."""
    bad_def = sum(1 for r in conditions if r["definition"].count(":") < 4)
    bad_cond = sum(1 for r in conditions if r["condition"].count(":") < 4)
    bad_call = sum(1 for r in conditions if r["call_location"].count(":") < 4)
    report(
        "condition 5-part location formatting",
        {"bad definition": bad_def, "bad condition": bad_cond, "bad call_location": bad_call},
    )
    assert bad_def == 0 and bad_cond == 0 and bad_call == 0


def test_conditions_distribution(conditions, baseline_path):
    base = load_baseline(baseline_path, "conditions")
    if not base or not base.get("rows"):
        pytest.skip("no baseline recorded for conditions")
    ratio = len(conditions) / base["rows"]
    report(
        "conditions distribution",
        {"rows": len(conditions), "baseline rows": base["rows"], "ratio vs baseline": f"{ratio:.2f}x"},
    )
    assert ratio >= 0.75, f"conditions row count dropped to {ratio:.1%} of baseline"
