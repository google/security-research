"""Data-quality checks for `configs` (`kernel-configs-needed.ql` output).

Validates 5-column preprocessor and IS_ENABLED branch tracking
(`config, path, ifdef, endif, else_`).
"""
from __future__ import annotations

import re

from common import is_int, report, top_counts

CONFIG_TOKEN_RE = re.compile(r"\bCONFIG_[A-Za-z0-9_]+\b")


def test_configs_not_empty(configs, kernel):
    """Verify at least 10,000 config guard blocks are extracted."""
    report(f"configs rows [{kernel}]", {"total": len(configs)})
    assert (
        len(configs) > 10000
    ), f"only {len(configs)} config blocks extracted (expected > 10,000)"


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
            "distinct CONFIG_* expressions": len(distinct_configs),
            "top configs": top_counts(configs, "config", 5),
        },
    )
    assert (
        not missing
    ), f"expected core kernel configs missing: {sorted(missing)}"


def test_configs_every_row_contains_valid_config_token(configs):
    """Verify every row contains a valid CONFIG_* symbol and no newlines."""
    missing_token = [
        r for r in configs if not CONFIG_TOKEN_RE.search(r.get("config", ""))
    ]
    has_newline = [
        r
        for r in configs
        if "\n" in r.get("config", "") or "\r" in r.get("config", "")
    ]
    blank_path = [r for r in configs if not r.get("path", "").strip()]
    report(
        "config token & single-line integrity",
        {
            "missing CONFIG_* token": len(missing_token),
            "contains newline": len(has_newline),
            "blank path": len(blank_path),
        },
    )
    assert not missing_token, (
        f"{len(missing_token)} rows lack a valid CONFIG_* symbol: "
        f"{missing_token[:3]}"
    )
    assert not has_newline, (
        f"{len(has_newline)} rows contain unstripped newlines: "
        f"{has_newline[:3]}"
    )
    assert not blank_path, f"{len(blank_path)} rows have blank file path"


def test_configs_captures_negations_and_expressions(configs):
    """Verify #ifndef (!CONFIG_*), defined(...), and IS_ENABLED(...)."""
    negated = [r for r in configs if r["config"].startswith("!")]
    defined_exprs = [r for r in configs if "defined(" in r["config"]]
    is_enabled_exprs = [
        r
        for r in configs
        if any(
            m in r["config"]
            for m in ("IS_ENABLED(", "IS_BUILTIN(", "IS_MODULE(")
        )
    ]
    report(
        "extended config guard coverage",
        {
            "negated (!CONFIG_* / !IS_ENABLED)": len(negated),
            "#if defined(...CONFIG_*)": len(defined_exprs),
            "IS_ENABLED / IS_BUILTIN / IS_MODULE": len(is_enabled_exprs),
        },
    )
    assert negated, "no negated (#ifndef / !CONFIG_*) guards extracted"
    assert (
        defined_exprs
    ), "no #if defined(CONFIG_*) compound expressions extracted"
    assert (
        is_enabled_exprs
    ), "no IS_ENABLED(CONFIG_*) / IS_BUILTIN / IS_MODULE guards extracted"

