"""Data-quality checks for the `allocs` table (allocs.ql output).

Ported from the harnesses that validated allocs on 6.1.111 (differential vs the
reference dump) and 6.18 (BTF cross-check). Assertions are deliberately loose --
they catch catastrophe, not noise -- while every measurement is reported so a
regression is visible even on a passing run.
"""
from __future__ import annotations

import pytest

from common import (agreement, canonical_path, drift, is_int, load_baseline,
                    pct, report, top_counts)

PRIMITIVES = {
    "void", "", "char", "unsigned char", "int", "unsigned int", "long",
    "unsigned long", "unsigned long long", "short", "unsigned short", "size_t",
}


def _site(row):
    return (canonical_path(row["file"]), row["line"], row["type_value"])


def _dynamic(row):
    return row["sizeMin"] != row["sizeMax"]


# --------------------------------------------------------------------------- #
# structural invariants -- must hold by construction, no oracle needed
# --------------------------------------------------------------------------- #

def test_allocs_not_empty(allocs, kernel):
    """Zero rows means allocator matching failed outright (e.g. the 6.10 _noprof
    refactor defeating name-based matching)."""
    report(f"allocs rows [{kernel}]", {"total": len(allocs)})
    assert allocs, "no allocation rows -- allocator matching failed on this kernel"


def test_allocs_bounds_are_ordered(allocs):
    bad_size = [r for r in allocs
                if is_int(r["sizeMin"]) and is_int(r["sizeMax"])
                and int(r["sizeMin"]) > int(r["sizeMax"])]
    bad_flags = [r for r in allocs
                 if is_int(r["flagsMin"]) and is_int(r["flagsMax"])
                 and int(r["flagsMin"]) > int(r["flagsMax"])]
    report("bound ordering", {"sizeMin>sizeMax": len(bad_size),
                              "flagsMin>flagsMax": len(bad_flags)})
    assert not bad_size and not bad_flags


def test_allocs_object_size_fits_in_alloc_size(allocs):
    """For direct allocations (depth <= 1), the allocated object's size (objectSize)
    cannot exceed the maximum allocation size (sizeMax) when sizeMax > 0
    (catches bit-layout struct/8 false positives like MLX5_ST_SZ_BYTES).
    For pointer-array allocations (depth >= 2, e.g. struct request **), objectSize
    is the base pointee struct size while sizeMax is sizeof(void*) = 8."""
    oversized = [
        r for r in allocs
        if is_int(r.get("depth", "1")) and int(r.get("depth", "1")) <= 1
        and is_int(r["objectSize"]) and is_int(r["sizeMax"])
        and int(r["sizeMax"]) > 0
        and int(r["objectSize"]) > int(r["sizeMax"])
    ]
    report("objectSize <= sizeMax", {"oversized object rows": len(oversized)})
    assert len(oversized) == 0, f"{len(oversized)} rows have objectSize > sizeMax: {oversized[:5]}"



def test_allocs_sentinel_is_consistent(allocs):
    """sizeVal should read 'variable' exactly when the range is non-trivial."""
    dynamic = sum(1 for r in allocs if _dynamic(r))
    variable = sum(1 for r in allocs if r["sizeVal"] == "variable")
    report("dynamic / variable sentinel",
           {"min!=max": dynamic, "sizeVal=='variable'": variable})
    # a small divergence is legitimate (constant base, variable total, or flex-array sentinel in reference allocs.db)
    assert abs(dynamic - variable) <= max(50, 0.15 * max(dynamic, 1))


def test_allocs_untyped_rows_are_bounded(allocs):
    """Raw byte buffers legitimately resolve to void, but a large void share means
    type resolution has degraded (e.g. alloc_hooks StmtExpr blinding the context)."""
    void_rows = [r for r in allocs if r["type_value"] in ("void", "")]
    share = pct(len(void_rows), len(allocs))
    report("untyped (void) rows", {"count": len(void_rows), "share %": f"{share:.1f}"})
    assert share < 10.0, f"{share:.1f}% of allocations resolve to void"


def test_allocs_flexible_array_detection(allocs):
    """Verify isFlexible column is populated and detects elastic/flexible-array structs."""
    if "isFlexible" not in allocs[0]:
        pytest.skip("isFlexible column not present in legacy 12-column allocs dump")
    flex_rows = [r for r in allocs if r.get("isFlexible", "").lower() == "true"]
    flex_types = {r["type_value"] for r in flex_rows}
    report(
        "flexible array (elastic) allocations",
        {
            "flex rows": len(flex_rows),
            "distinct flex struct types": len(flex_types),
            "sample flex types": sorted(flex_types)[:8],
        },
    )
    assert len(flex_rows) > 0, "0 flexible-array allocations detected (isFlexible == 'true')"


# --------------------------------------------------------------------------- #
# cross-table agreement -- independent ground truth, no oracle needed
# --------------------------------------------------------------------------- #

def test_allocs_objectsize_matches_btf(allocs, btf_sizes):
    """objectSize is CodeQL's sizeof; BTF carries the built kernel's struct sizes.
    Agreement validates type resolution without needing an allocs oracle."""
    named = [r for r in allocs
             if r["type_value"] not in PRIMITIVES and is_int(r["objectSize"])]
    checked, matched, mismatches = agreement(named, "type_value", "objectSize", btf_sizes)
    rate = pct(matched, checked)
    report("objectSize vs BTF", {"btf structs": len(btf_sizes), "checked": checked,
                                 "matched": matched, "match %": f"{rate:.2f}"})
    if mismatches:
        report("objectSize mismatches (type | ours | btf)", mismatches)
    assert checked > 0, "no named structs overlap BTF -- check the BTF dump columns"
    assert rate >= 98.0, f"objectSize agrees with BTF for only {rate:.2f}% of rows"


# --------------------------------------------------------------------------- #
# distribution drift vs a recorded, validated run
# --------------------------------------------------------------------------- #

def test_allocs_distribution_has_not_drifted(allocs, baseline_path):
    base = load_baseline(baseline_path, "allocs")
    if not base:
        pytest.skip("no baseline recorded for allocs (--baseline)")
    dynamic_ratio = sum(1 for r in allocs if _dynamic(r)) / len(allocs)
    ok_ratio, detail = drift(dynamic_ratio, base.get("dynamic_ratio"), 0.15)
    report("distribution", {"dynamic ratio": detail,
                            "rows": len(allocs),
                            "baseline rows": base.get("rows")})
    report("allocator families", top_counts(allocs, "call_value"))
    assert ok_ratio, f"dynamic/fixed ratio drifted: {detail}"
    if base.get("rows"):
        ratio = len(allocs) / base["rows"]
        assert ratio >= 0.75, f"allocs row count dropped below 75% of baseline ({len(allocs)} vs {base['rows']})"



# --------------------------------------------------------------------------- #
# differential vs the reference dump -- only where an oracle exists
# --------------------------------------------------------------------------- #

def test_allocs_classification_matches_oracle(allocs, allocs_oracle):
    """kmalloc_dyn (sizeMin != sizeMax) is what the dashboard consumes; it must
    agree with the reference on the sites both produce."""
    ours = {_site(r): r for r in allocs}
    theirs = {_site(r): r for r in allocs_oracle}
    shared = set(ours) & set(theirs)
    agree = sum(1 for k in shared if _dynamic(ours[k]) == _dynamic(theirs[k]))
    rate = pct(agree, len(shared))
    disagreements = [(k[2], f"ours[{ours[k]['sizeMin']},{ours[k]['sizeMax']}]",
                      f"oracle[{theirs[k]['sizeMin']},{theirs[k]['sizeMax']}]")
                     for k in shared if _dynamic(ours[k]) != _dynamic(theirs[k])][:15]
    report("classification vs oracle",
           {"shared sites": len(shared), "agree": agree, "agree %": f"{rate:.1f}",
            "ours-only": len(set(ours) - set(theirs)),
            "oracle-only": len(set(theirs) - set(ours))})
    if disagreements:
        report("classification disagreements", disagreements)
    assert len(shared) > 0, "no overlapping sites with the oracle"
    assert rate >= 95.0, f"elastic classification agrees on only {rate:.1f}% of shared sites"


def test_allocs_bounds_match_oracle(allocs, allocs_oracle):
    ours = {_site(r): r for r in allocs}
    theirs = {_site(r): r for r in allocs_oracle}
    shared = set(ours) & set(theirs)
    size_exact = sum(1 for k in shared
                     if (ours[k]["sizeMin"], ours[k]["sizeMax"])
                     == (theirs[k]["sizeMin"], theirs[k]["sizeMax"]))
    flags_exact = sum(1 for k in shared
                      if (ours[k]["flagsMin"], ours[k]["flagsMax"])
                      == (theirs[k]["flagsMin"], theirs[k]["flagsMax"]))
    report("bounds vs oracle",
           {"size exact %": f"{pct(size_exact, len(shared)):.1f}",
            "flags exact %": f"{pct(flags_exact, len(shared)):.1f}"})
    assert pct(size_exact, len(shared)) >= 95.0
    assert pct(flags_exact, len(shared)) >= 98.0
