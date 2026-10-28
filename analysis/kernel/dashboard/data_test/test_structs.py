"""Data-quality checks for `structs.ql` (`struct_locations`/`struct_fields`)."""
from __future__ import annotations

from common import canonical_path, is_int, load_baseline, pct, report
import pytest

_NON_RUNTIME_SUBSTRINGS = (
    "/boot/",
    "drivers/firmware/efi/libstub/",
    "/vdso/",
    "/purgatory/",
)
_NON_RUNTIME_PREFIXES = (
    "scripts/", "tools/", "samples/", "usr/", "Documentation/",
)


def _is_non_runtime_path(raw_path: str) -> bool:
    """Return True if `raw_path` belongs to a non-runtime kernel directory."""
    rel = canonical_path(raw_path)
    if any(rel.startswith(p) for p in _NON_RUNTIME_PREFIXES):
        return True
    if rel.startswith("arch/") and "/boot/" in rel:
        return True
    return any(sub in rel for sub in _NON_RUNTIME_SUBSTRINGS)


def test_structs_not_empty(structs, kernel):
    """Verify compiled structs and flattened fields meet volume bounds."""
    distinct_structs = {
        (r["struct_name"], canonical_path(r["file_path"]), r["start_line"])
        for r in structs
    }
    report(
        f"structs & fields [{kernel}]",
        {
            "distinct struct definitions": len(distinct_structs),
            "flattened struct_fields rows": len(structs),
        },
    )
    assert len(distinct_structs) >= 10000, (
        f"expected >= 10,000 struct definitions, got {len(distinct_structs)}"
    )
    assert len(structs) >= 80000, (
        f"expected >= 80,000 flattened struct fields, got {len(structs)}"
    )


def test_structs_line_ranges_and_non_runtime_denylist(structs):
    """Verify start_line <= end_line and 0 non-runtime files in structs."""
    bad_spans = [
        r
        for r in structs
        if not is_int(r["start_line"])
        or not is_int(r["end_line"])
        or int(r["start_line"]) <= 0
        or int(r["start_line"]) > int(r["end_line"])
    ]
    non_runtime = [
        r["file_path"] for r in structs if _is_non_runtime_path(r["file_path"])
    ]
    unnamed_paths = [
        r["field_path"]
        for r in structs
        if "(unnamed" in r["field_path"] or "(unknown" in r["field_path"]
    ]
    report(
        "structs span & scope hygiene",
        {
            "start_line > end_line": len(bad_spans),
            "non-runtime kernel rows": len(non_runtime),
            "uncleaned (unnamed/unknown) field_paths": len(unnamed_paths),
        },
    )
    assert not bad_spans, f"invalid struct line spans: {bad_spans[:5]}"
    assert not non_runtime, (
        f"non-runtime kernel files leaked into structs: {non_runtime[:5]}"
    )
    assert not unnamed_paths, (
        f"uncleaned anonymous container names in field_path: "
        f"{unnamed_paths[:5]}"
    )


def test_structs_anonymous_union_flattening(structs):
    """Verify fields nested inside anonymous unions/structs are flattened."""
    by_struct_field: dict[tuple[str, str], list[dict]] = {}
    for row in structs:
        by_struct_field.setdefault(
            (row["struct_name"], row["field_name"]), []
        ).append(row)

    canonical_anon_fields = [
        ("sk_buff", "dev"),
        ("sk_buff", "sk"),
        ("sk_buff", "cb"),
        ("page", "lru"),
        ("folio", "lru"),
        ("inode", "i_rdev"),
    ]
    missing = [
        pair for pair in canonical_anon_fields if pair not in by_struct_field
    ]
    bad_offsets = [
        (pair, by_struct_field[pair][0]["byte_offset"])
        for pair in canonical_anon_fields
        if pair in by_struct_field
        and (
            not is_int(by_struct_field[pair][0]["byte_offset"])
            or int(by_struct_field[pair][0]["byte_offset"]) <= 0
        )
    ]
    report(
        "anonymous union/struct flattening spot-checks",
        {
            f"{st}.{fl}": (
                f"offset={by_struct_field[(st, fl)][0]['byte_offset']} "
                f"path={by_struct_field[(st, fl)][0]['field_path']}"
                if (st, fl) in by_struct_field
                else "MISSING"
            )
            for st, fl in canonical_anon_fields
        },
    )
    assert not missing, (
        f"missing canonical anonymous-union fields: {missing}"
    )
    assert not bad_offsets, (
        f"anonymous-union fields had non-positive byte offsets: {bad_offsets}"
    )


def test_structs_btf_size_agreement(structs, btf_sizes):
    """Verify struct byte_size agrees with BTF on unambiguous types."""
    by_name_sizes: dict[str, set[int]] = {}
    for row in structs:
        if is_int(row["byte_size"]) and int(row["byte_size"]) > 0:
            by_name_sizes.setdefault(row["struct_name"], set()).add(
                int(row["byte_size"])
            )

    checked = 0
    matched = 0
    for s_name, sizes in by_name_sizes.items():
        if len(sizes) != 1 or s_name not in btf_sizes:
            continue
        checked += 1
        if next(iter(sizes)) == int(btf_sizes[s_name]):
            matched += 1

    rate = pct(matched, checked)
    report(
        "structs vs BTF byte_size agreement",
        {
            "unambiguous structs in both": checked,
            "exact byte_size match": f"{matched} ({rate:.1f}%)",
        },
    )
    assert checked >= 2000, f"only {checked} structs matched against BTF"
    assert rate >= 95.0, (
        f"struct byte_size agreement with BTF is {rate:.1f}% (< 95.0%)"
    )


def test_structs_distribution(structs, baseline_path):
    """Verify structs field count does not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "structs")
    if not base or not base.get("struct_fields"):
        pytest.skip("no baseline recorded for structs")
    ratio = len(structs) / base["struct_fields"]
    report(
        "structs distribution",
        {
            "struct_fields": len(structs),
            "baseline struct_fields": base["struct_fields"],
            "ratio": f"{ratio:.2f}x",
        },
    )
    assert ratio >= 0.75, (
        f"struct_fields row count dropped below 75% of baseline "
        f"({len(structs)} vs {base['struct_fields']})"
    )
