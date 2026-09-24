"""Data-quality checks for `field_access` (`field-acces-type.ql` output)."""
from __future__ import annotations

from collections import Counter

from common import load_baseline, pct, report
import pytest


def test_field_access_not_empty(field_access, kernel):
    """Reference 6.1.111 DB contains 1,493,089 field access rows."""
    report(f"field_access rows [{kernel}]", {"total": len(field_access)})
    assert (
        len(field_access) >= 200000
    ), f"only {len(field_access)} field access rows extracted"


def test_field_access_types_complete(field_access):
    """Verify all three access categories ('read', 'write', 'exec') exist."""
    counts = Counter(r["type"] for r in field_access)
    report(
        "field access type breakdown",
        {
            "read": counts.get("read", 0),
            "write": counts.get("write", 0),
            "exec": counts.get("exec", 0),
        },
    )
    assert counts.get("read", 0) > 100000, "insufficient 'read' field accesses"
    assert counts.get("write", 0) > 10000, "insufficient 'write' field accesses"
    assert (
        counts.get("exec", 0) > 1000
    ), "insufficient 'exec' (indirect call) field accesses"


def test_field_access_fields_and_locations_valid(field_access):
    """Verify field, parent struct, and location columns are non-empty."""
    blank_field = sum(1 for r in field_access if not r["field"])
    blank_parent = sum(1 for r in field_access if not r["parent"])
    blank_loc = sum(
        1 for r in field_access if not r["location"] or ":" not in r["location"]
    )
    report(
        "field_access completeness",
        {
            "blank field": blank_field,
            "blank parent": blank_parent,
            "invalid location": blank_loc,
        },
    )
    assert blank_loc == 0
    assert pct(blank_field, len(field_access)) < 1.0
    assert pct(blank_parent, len(field_access)) < 1.0


def test_field_access_distribution(field_access, baseline_path):
    """Verify field_access row count does not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "field_access")
    if not base or not base.get("rows"):
        pytest.skip("no baseline recorded for field_access")
    ratio = len(field_access) / base["rows"]
    report(
        "field_access distribution",
        {
            "rows": len(field_access),
            "baseline rows": base["rows"],
            "ratio": f"{ratio:.2f}x",
        },
    )
    assert ratio >= 0.75, (
        f"field_access row count dropped below 75% of baseline "
        f"({len(field_access)} vs {base['rows']})"
    )
