"""Data-quality checks for the `function_locations` table (`functions.ql` output).

Runs as the very first query gate in the pipeline because cross-table checks in
subsequent tests (`ops_targets`, `syscall_node`) rely on `function_locations`.
"""
from __future__ import annotations

from common import is_int, pct, report


def test_function_locations_not_empty(function_locations, kernel):
    """A full Linux kernel build contains 40,000+ functions."""
    report(f"function_locations rows [{kernel}]", {"total": len(function_locations)})
    assert len(function_locations) > 10000, (
        f"only {len(function_locations)} functions extracted -- database or query severely truncated"
    )


def test_function_locations_line_ranges_are_ordered(function_locations):
    bad = [
        r for r in function_locations
        if is_int(r["start_line"]) and is_int(r["end_line"])
        and int(r["start_line"]) > int(r["end_line"])
    ]
    report("function line ordering", {"start_line > end_line": len(bad)})
    assert not bad, f"{len(bad)} functions have start_line > end_line"


def test_function_locations_core_kernel_anchors_exist(function_locations):
    """Universal built-in kernel entry points must always be present."""
    names = {r["function_name"] for r in function_locations}
    expected = {"vfs_read", "vfs_write", "__sys_setsockopt", "schedule"}
    missing = expected - names
    report(
        "core kernel anchors",
        {"distinct function names": len(names), "missing anchors": sorted(missing)},
    )
    assert not missing, f"core kernel functions missing from function_locations: {sorted(missing)}"
