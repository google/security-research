"""Data-quality checks for `syscall-node-locs.ql` and `syscall_node`."""
from __future__ import annotations

from common import canonical_path, is_int, pct, report


def _file_of(location: str) -> str:
    """Return canonical file path prefix of a `file:sl:sc:el:ec` location."""
    return canonical_path(location.split(":", 1)[0]) if location else ""


def test_syscall_node_locs_not_empty(syscall_node_locs, kernel):
    """Verify at least 50,000 function locations are extracted."""
    report(
        f"syscall_node_locs rows [{kernel}]",
        {"rows": len(syscall_node_locs)},
    )
    assert (
        len(syscall_node_locs) >= 50000
    ), f"only {len(syscall_node_locs)} function locations extracted"


def test_syscall_node_locs_ranges_and_files(syscall_node_locs):
    """Verify start line <= end line and non-empty file path for all rows."""
    bad_ranges = [
        r
        for r in syscall_node_locs
        if is_int(r.get("sl", ""))
        and is_int(r.get("el", ""))
        and int(r["sl"]) > int(r["el"])
    ]
    empty_files = [r for r in syscall_node_locs if not r.get("file")]
    report(
        "syscall_node_locs span validity",
        {"sl > el": len(bad_ranges), "empty file": len(empty_files)},
    )
    assert not bad_ranges, f"{len(bad_ranges)} rows have startLine > endLine"
    assert not empty_files, f"{len(empty_files)} rows have empty file path"


def test_function_location_files_agree(syscall_node, function_locations):
    """Verify function_location file prefixes match function_locations."""
    by_name = {}
    for row in function_locations:
        by_name.setdefault(row["function_name"], set()).add(
            canonical_path(row["file_path"])
        )

    unique_pairs = {
        (row["function"], row["function_location"])
        for row in syscall_node
        if row.get("function_location")
    }
    checked = agree = 0
    for func, loc in unique_pairs:
        files = by_name.get(func)
        if not files:
            continue
        checked += 1
        if _file_of(loc) in files:
            agree += 1
    report(
        "function_location file agreement",
        {
            "checked unique functions": checked,
            "agree %": f"{pct(agree, checked):.1f}",
        },
    )
    assert checked > 0
    assert pct(agree, checked) >= 90.0
