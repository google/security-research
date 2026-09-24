"""Data-quality checks for the `kmalloc_calls` table (`allocations.ql` output)."""
from __future__ import annotations

import pytest

from common import agreement, is_int, load_baseline, pct, report, top_counts


def test_allocations_not_empty(allocations, kernel):
    """Reference 6.1.111 DB contains 2,051 struct allocation rows in kmalloc_calls."""
    report(f"kmalloc_calls rows [{kernel}]", {"total": len(allocations)})
    assert len(allocations) >= 1000, f"only {len(allocations)} struct allocations extracted"


def test_allocations_is_flexible_total_and_valid(allocations):
    """is_flexible must be populated ('true' or 'false') for 100% of rows, with >0 'true' rows,
    and must not falsely mark fixed-size array element structs (iovec, bio_vec, input_event)
    referenced inside struct_size(p, member, count) as flexible."""
    valid_vals = {"true", "false"}
    invalid = [r for r in allocations if r.get("is_flexible", "").lower() not in valid_vals]
    flex_rows = [r for r in allocations if r.get("is_flexible", "").lower() == "true"]
    false_flex_element_structs = {"iovec", "bio_vec", "input_event"}
    falsely_marked_flex = [
        r for r in flex_rows if r.get("struct_type") in false_flex_element_structs
    ]
    report(
        "is_flexible completeness",
        {
            "total": len(allocations),
            "flexible ('true')": len(flex_rows),
            "invalid is_flexible": len(invalid),
            "falsely marked fixed element structs": len(falsely_marked_flex),
        },
    )
    assert not invalid, f"{len(invalid)} rows have invalid is_flexible values"
    assert not falsely_marked_flex, (
        f"{len(falsely_marked_flex)} non-flexible element structs marked is_flexible='true': "
        f"{falsely_marked_flex[:5]}"
    )
    assert len(flex_rows) >= 50, f"only {len(flex_rows)} flexible struct allocations detected"


def test_allocations_struct_sizes_positive(allocations):
    """Allocated struct_size must be a positive integer."""
    bad_size = [
        r for r in allocations
        if not is_int(r.get("struct_size", "")) or int(r["struct_size"]) <= 0
    ]
    report("struct_size validity", {"non-positive or non-int": len(bad_size)})
    assert len(bad_size) == 0


def test_allocations_struct_fits_in_alloc_size(allocations):
    """Ensure struct_size <= alloc_size when alloc_size is a known constant
    (catches pointer-array struct** unwrapping and bit-layout struct/8 false positives)."""
    oversized = [
        r for r in allocations
        if is_int(r.get("struct_size", ""))
        and is_int(r.get("alloc_size", ""))
        and int(r["alloc_size"]) > 0
        and int(r["struct_size"]) > int(r["alloc_size"])
    ]
    report("struct_size <= alloc_size", {"oversized struct rows": len(oversized)})
    assert len(oversized) == 0, f"{len(oversized)} rows have struct_size > alloc_size: {oversized[:5]}"



def test_allocations_struct_size_matches_btf(allocations, btf_sizes):
    """Cross-check kmalloc_calls.struct_size against ground-truth BTF struct sizes."""
    named = [
        r for r in allocations
        if r.get("struct_type") and is_int(r.get("struct_size", ""))
    ]
    checked, matched, mismatches = agreement(named, "struct_type", "struct_size", btf_sizes)
    rate = pct(matched, checked)
    report(
        "kmalloc_calls.struct_size vs BTF",
        {"checked": checked, "matched": matched, "match %": f"{rate:.2f}"},
    )
    assert checked > 0
    assert rate >= 95.0, f"struct_size agrees with BTF for only {rate:.2f}% of rows"


def test_allocations_distribution(allocations, baseline_path):
    base = load_baseline(baseline_path, "kmalloc_calls")
    if not base or not base.get("rows"):
        pytest.skip("no baseline recorded for kmalloc_calls")
    ratio = len(allocations) / base["rows"]
    report(
        "kmalloc_calls distribution",
        {"rows": len(allocations), "baseline rows": base["rows"], "ratio": f"{ratio:.2f}x", "top structs": top_counts(allocations, "struct_type", 5)},
    )
    assert ratio >= 0.75, f"allocations row count dropped below 75% of baseline ({len(allocations)} vs {base['rows']})"
