"""Data-quality checks for `configs` (`kernel-configs-needed.ql` output).

Validates 5-column preprocessor branch tracking
(`config, path, ifdef, endif, else_`).
"""
from __future__ import annotations

from common import is_int, report, top_counts


def test_configs_not_empty(configs, kernel):
    """Verify at least 1,000 preprocessor config blocks are extracted."""
    report(f"configs rows [{kernel}]", {"total": len(configs)})
    assert (
        len(configs) > 1000
    ), f"only {len(configs)} config preprocessor blocks extracted"


def test_configs_bounds_are_ordered(configs):
    """Verify ifdef < endif, and if else_ != 0, then ifdef < else_ < endif."""
    bad_endif = [
        r
        for r in configs
        if is_int(r["ifdef"])
        and is_int(r["endif"])
        and int(r["ifdef"]) >= int(r["endif"])
    ]
    bad_else = [
        r
        for r in configs
        if is_int(r["ifdef"])
        and is_int(r["endif"])
        and is_int(r["else_"])
        and int(r["else_"]) != 0
        and not int(r["ifdef"]) < int(r["else_"]) < int(r["endif"])
    ]
    report(
        "preprocessor block line ordering",
        {"ifdef >= endif": len(bad_endif), "invalid else_ line": len(bad_else)},
    )
    assert not bad_endif, f"{len(bad_endif)} config blocks have ifdef >= endif"
    assert (
        not bad_else
    ), f"{len(bad_else)} config blocks have else_ outside (ifdef, endif)"


def test_configs_core_symbols_present(configs):
    """Verify universal CONFIG_NET, CONFIG_SMP, and CONFIG_SECURITY exist."""
    distinct_configs = {r["config"] for r in configs}
    expected = {"CONFIG_NET", "CONFIG_SMP", "CONFIG_SECURITY"}
    missing = expected - distinct_configs
    report(
        "core config coverage",
        {
            "distinct CONFIG_* symbols": len(distinct_configs),
            "top configs": top_counts(configs, "config", 5),
        },
    )
    assert (
        not missing
    ), f"expected core kernel configs missing: {sorted(missing)}"
