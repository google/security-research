"""Data-quality checks for `macro-invocations.ql` output."""
from __future__ import annotations

from common import is_int, load_baseline, report
import pytest


def test_macro_invocations_not_empty(macro_invocations, kernel):
    """Verify at least 100,000 macro invocations are extracted."""
    if macro_invocations is None:
        pytest.skip("macro_invocations not supplied")
    report(
        f"macroinvocation_locations rows [{kernel}]",
        {"total": len(macro_invocations)},
    )
    assert (
        len(macro_invocations) >= 100000
    ), f"only {len(macro_invocations)} macro invocations extracted"


def test_macro_invocations_line_ranges_and_capabilities(macro_invocations):
    """Verify line ordering and CAP_* capability macro invocation coverage.

    tools/check_privilege.py relies on CAP_* macro invocations in
    macroinvocation_locations to map numeric capability constants back to
    human-readable CAP_SYS_ADMIN / CAP_NET_ADMIN.
    """
    if macro_invocations is None:
        pytest.skip("macro_invocations not supplied")

    bad_lines = [
        r
        for r in macro_invocations
        if is_int(r["start_line"])
        and is_int(r["end_line"])
        and int(r["start_line"]) > int(r["end_line"])
    ]
    assert (
        not bad_lines
    ), f"{len(bad_lines)} macro invocations have start_line > end_line"

    cap_macros = {
        r["macroinvocation_name"]
        for r in macro_invocations
        if r["macroinvocation_name"].startswith("CAP_")
    }
    expected_caps = {"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_DAC_OVERRIDE"}
    missing_caps = expected_caps - cap_macros
    report(
        "CAP_* macro invocation coverage",
        {
            "distinct CAP_* macros": len(cap_macros),
            "missing core CAPs": sorted(missing_caps),
        },
    )
    assert (
        not missing_caps
    ), f"missing essential CAP_* macro invocations: {sorted(missing_caps)}"


def test_macro_invocations_distribution(macro_invocations, baseline_path):
    """Verify macroinvocation_locations count does not drop below 75%."""
    if macro_invocations is None:
        pytest.skip("macro_invocations not supplied")
    base = load_baseline(baseline_path, "macroinvocation_locations")
    if not base or not base.get("rows"):
        pytest.skip("no baseline recorded for macroinvocation_locations")
    ratio = len(macro_invocations) / base["rows"]
    report(
        "macroinvocation_locations vs 6.1.111 baseline",
        {
            "rows": len(macro_invocations),
            "baseline rows": base["rows"],
            "ratio vs baseline": f"{ratio:.2f}x",
        },
    )
    assert ratio >= 0.75, (
        f"macroinvocation_locations dropped to {ratio:.1%} of baseline "
        f"({len(macro_invocations)} vs {base['rows']})"
    )
