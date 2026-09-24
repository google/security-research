"""Data-quality checks for `all-calls.ql` SARIF output."""
from __future__ import annotations

from common import load_baseline, report
import pytest


def test_all_calls_edges_and_locations_populated(all_calls_stats, kernel):
    """Verify call edges and locations meet minimum volume thresholds."""
    edges = all_calls_stats["edges"]
    locations = all_calls_stats["locations"]
    results = all_calls_stats["results"]
    report(
        f"all-calls graph [{kernel}] ({all_calls_stats['source']})",
        {"results": results, "locations": locations, "edges": edges},
    )
    assert edges >= 300000, (
        f"only {edges:,} callgraph edges in all-calls (expected >= 300,000)"
    )
    assert locations >= 600000, (
        f"only {locations:,} locations in all-calls (expected >= 600,000)"
    )


def test_all_calls_messages_and_uris_valid(all_calls_stats):
    """Verify sample location URIs and 'call to <func>' messages exist."""
    uris = all_calls_stats.get("sample_uris", [])
    msgs = all_calls_stats.get("sample_messages", [])
    call_msgs = [m for m in msgs if m.startswith("call to ")]
    report(
        "all-calls sample locations",
        {
            "sample URIs checked": len(uris),
            "call target messages ('call to ...')": len(call_msgs),
        },
    )
    assert len(uris) > 0, "no location URIs found in all-calls"
    assert (
        len(call_msgs) > 0
    ), "no 'call to <func>' target location messages found in all-calls"


def test_all_calls_distribution(all_calls_stats, baseline_path):
    """Verify all_calls edge count does not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "all_calls")
    if not base or not base.get("edges"):
        pytest.skip("no baseline recorded for all_calls")
    edges = all_calls_stats["edges"]
    ratio = edges / base["edges"]
    report(
        "all_calls distribution",
        {
            "edges": edges,
            "baseline edges": base["edges"],
            "ratio": f"{ratio:.2f}x",
        },
    )
    assert ratio >= 0.75, (
        f"all_calls edge count dropped below 75% of baseline "
        f"({edges} vs {base['edges']})"
    )
