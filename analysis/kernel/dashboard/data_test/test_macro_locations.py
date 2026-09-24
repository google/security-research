"""Data-quality checks for `macro-locations.ql` (`macro_locations` table)."""
from __future__ import annotations

from common import is_int, load_baseline, report
import pytest


def test_macro_locations_not_empty(macro_locations, kernel):
    """Verify at least 30,000 macro definitions are extracted."""
    if macro_locations is None:
        pytest.skip("macro_locations not supplied")
    report(f"macro_locations rows [{kernel}]", {"total": len(macro_locations)})
    assert (
        len(macro_locations) >= 30000
    ), f"only {len(macro_locations)} macro definitions extracted"


def test_macro_locations_line_ranges_ordered(macro_locations):
    """Verify start_line <= end_line for all extracted macro definitions."""
    if macro_locations is None:
        pytest.skip("macro_locations not supplied")
    bad_lines = [
        r
        for r in macro_locations
        if is_int(r["start_line"])
        and is_int(r["end_line"])
        and int(r["start_line"]) > int(r["end_line"])
    ]
    report(
        "macro_locations line ordering",
        {"start_line > end_line": len(bad_lines)},
    )
    assert not bad_lines, f"{len(bad_lines)} macros have start_line > end_line"


def test_macro_locations_distribution(macro_locations, baseline_path):
    """Verify macro_locations row count does not drop below 75% of baseline."""
    if macro_locations is None:
        pytest.skip("macro_locations not supplied")
    base = load_baseline(baseline_path, "macro_locations")
    if not base or not base.get("rows"):
        pytest.skip("no baseline recorded for macro_locations")
    ratio = len(macro_locations) / base["rows"]
    report(
        "macro_locations distribution",
        {
            "rows": len(macro_locations),
            "baseline rows": base["rows"],
            "ratio": f"{ratio:.2f}x",
        },
    )
    assert ratio >= 0.75, (
        f"macro_locations count dropped below 75% of baseline "
        f"({len(macro_locations)} vs {base['rows']})"
    )
