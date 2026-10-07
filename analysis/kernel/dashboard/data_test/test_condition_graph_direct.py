"""Data-quality checks for `conditions` (`condition-graph-direct.ql`).

Consumed by `tools/check_privilege.py` to determine whether call sites and
controlled line spans are gated by `capable(...)`, `ns_capable(...)`,
declarative Generic Netlink flags, `sysctl`, or `module_param`.
"""
from __future__ import annotations

from collections import Counter
import os
import random

from common import canonical_path, load_baseline, pct, report
import pytest

CAP_SOURCE_TOKENS = (
    "capable",
    "CAP_",
    "GENL_ADMIN_PERM",
    "GENL_UNS_ADMIN_PERM",
    "may_mount",
    "ptrace_has_cap",
    "has_capability",
    "has_ns_capability",
    "privileged_wrt_inode_uidgid",
    "netlink_allowed",
)

ALLOWED_NS_SCOPES = {
    "init_user_ns",
    "net_ns",
    "s_user_ns",
    "mnt_ns",
    "f_cred",
    "user_ns",
}


def _locate_kernel_source_file(raw_file: str, kernel: str) -> str | None:
    """Resolve `raw_file` to an on-disk kernel source file if available."""
    if not raw_file:
        return None
    clean_rel = canonical_path(raw_file)
    if os.path.isfile(clean_rel):
        return clean_rel

    workspace = os.environ.get(
        "WORKSPACE_DIR",
        os.path.expanduser("~/kernel_codeql_workspace"),
    )
    candidates = []
    if kernel and kernel != "unknown":
        clean_ver = kernel.lstrip("v")
        candidates.append(os.path.join(workspace, f"linux_v{clean_ver}"))
    entries = (
        sorted(os.listdir(workspace)) if os.path.isdir(workspace) else []
    )
    for entry in entries:
        if entry.startswith("linux_v"):
            candidates.append(os.path.join(workspace, entry))

    for repo_dir in candidates:
        candidate = os.path.join(repo_dir, clean_rel)
        if os.path.isfile(candidate):
            return candidate
    return None


def _parse_loc(loc_str: str) -> tuple[str, int, int]:
    """Parse `file:sl:sc:el:ec` into `(clean_file, start_line, end_line)`."""
    parts = loc_str.rsplit(":", 4)
    rel = canonical_path(parts[0])
    sl = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
    el = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else sl
    return rel, sl, el


def test_conditions_not_empty(conditions, kernel):
    """Verify condition-graph-direct.ql extracts a full set of rows."""
    report(f"conditions rows [{kernel}]", {"total": len(conditions)})
    assert (
        len(conditions) >= 2500
    ), f"only {len(conditions)} condition-dominated calls extracted"


def test_conditions_covers_all_four_gate_types(conditions):
    """Must include all 4 gate classes: capable, ns_capable, sysctl, param."""
    counts = Counter(r["type"] for r in conditions)
    expected = {"capable", "ns_capable", "sysctl", "module_param"}
    missing = {k for k in expected if counts.get(k, 0) == 0}
    cap_defs = {
        r["definition"]
        for r in conditions
        if r["type"] in ("capable", "ns_capable")
    }
    report(
        "condition gate type distribution",
        {**dict(counts), "distinct_cap_definitions": len(cap_defs)},
    )
    assert (
        not missing
    ), f"missing condition gate categories: {sorted(missing)}"
    assert (
        counts["capable"] >= 1500
    ), f"too few capable() gates: {counts['capable']}"
    assert (
        counts["ns_capable"] >= 800
    ), f"too few ns_capable() gates: {counts['ns_capable']}"
    assert (
        len(cap_defs) >= 500
    ), f"too few distinct capability check sites: {len(cap_defs)}"


def test_conditions_locations_well_formed(conditions):
    """Verify definition, condition, and call_location use file:sl:sc:el:ec."""
    bad_def = sum(1 for r in conditions if r["definition"].count(":") < 4)
    bad_cond = sum(1 for r in conditions if r["condition"].count(":") < 4)
    bad_call = sum(1 for r in conditions if r["call_location"].count(":") < 4)
    report(
        "condition 5-part location formatting",
        {
            "bad definition": bad_def,
            "bad condition": bad_cond,
            "bad call_location": bad_call,
        },
    )
    assert bad_def == 0 and bad_cond == 0 and bad_call == 0


def test_conditions_no_internal_capability_c_leakage(conditions):
    """Verify capable(cap) -> ns_capable(&init_user_ns, cap) does not leak."""
    leaked = [
        r
        for r in conditions
        if "kernel/capability.c:" in r["definition"] and r["argument"] == "cap"
    ]
    report("kernel/capability.c 'cap' leakage rows", {"leaked": len(leaked)})
    assert (
        not leaked
    ), f"found {len(leaked)} bogus kernel/capability.c 'cap' rows"


def test_conditions_guarded_spans_and_ns_scopes(conditions):
    """Verify __guarded_span__ rows carry valid line bounds and ns_scope."""
    span_rows = [
        r for r in conditions if r["call"].startswith("__guarded_span__:")
    ]
    scopes = Counter(r["call"].split(":", 1)[1] for r in span_rows)
    bad_scopes = set(scopes) - ALLOWED_NS_SCOPES
    bad_polarity = [
        r
        for r in span_rows
        if (
            r["call"] == "__guarded_span__:init_user_ns"
            and r["type"] != "capable"
        )
        or (
            r["call"] != "__guarded_span__:init_user_ns"
            and r["type"] != "ns_capable"
        )
    ]
    bad_bounds = 0
    for r in span_rows:
        cond_file, _, _ = _parse_loc(r["condition"])
        span_file, sl, el = _parse_loc(r["call_location"])
        if cond_file != span_file or sl > el or sl <= 0:
            bad_bounds += 1

    report(
        "guarded span rows & namespace scopes",
        {
            "total_guarded_spans": len(span_rows),
            "scopes": dict(scopes),
            "bad_polarity": len(bad_polarity),
            "bad_bounds": bad_bounds,
        },
    )
    assert len(span_rows) >= 450, f"too few guarded spans: {len(span_rows)}"
    assert not bad_scopes, f"unexpected ns_scope tags: {sorted(bad_scopes)}"
    assert not bad_polarity, "ns_scope vs type mismatch in __guarded_span__"
    assert bad_bounds == 0, f"{bad_bounds} guarded spans have invalid bounds"
    for req_scope in ("init_user_ns", "net_ns", "s_user_ns", "user_ns"):
        assert (
            scopes[req_scope] > 0
        ), f"missing namespace scope category: {req_scope}"


def test_conditions_genl_declarative_gates(conditions):
    """Verify GENL_ADMIN_PERM and GENL_UNS_ADMIN_PERM declarative gates."""
    genl_rows = [
        r for r in conditions if r["call"].startswith("__genl_ops_gate__:")
    ]
    by_call = Counter(r["call"] for r in genl_rows)
    bad_genl = [
        r
        for r in genl_rows
        if r["argument"] != "CAP_NET_ADMIN"
        or (
            r["call"] == "__genl_ops_gate__:init_user_ns"
            and r["type"] != "capable"
        )
        or (
            r["call"] == "__genl_ops_gate__:net_ns"
            and r["type"] != "ns_capable"
        )
    ]
    report(
        "declarative genl_ops gates",
        {
            "total_genl_gates": len(genl_rows),
            "by_call": dict(by_call),
            "bad_genl": len(bad_genl),
        },
    )
    assert len(genl_rows) >= 90, f"too few genl_ops gates: {len(genl_rows)}"
    assert by_call["__genl_ops_gate__:init_user_ns"] >= 60
    assert by_call["__genl_ops_gate__:net_ns"] >= 15
    assert not bad_genl, f"malformed genl_ops gate rows: {bad_genl[:3]}"


def _verify_condition_row(
    row: dict[str, str],
    kernel: str,
    file_cache: dict[str, list[str]],
) -> tuple[bool, bool]:
    """Return `(def_ok, span_ok)` for a single capability condition row."""

    def _get_lines(rel_path: str) -> list[str]:
        if rel_path not in file_cache:
            full = _locate_kernel_source_file(rel_path, kernel)
            if not full:
                file_cache[rel_path] = []
            else:
                with open(
                    full, "r", encoding="utf-8", errors="ignore"
                ) as fh:
                    file_cache[rel_path] = fh.read().splitlines()
        return file_cache[rel_path]

    def_file, def_sl, def_el = _parse_loc(row["definition"])
    call_file, call_sl, call_el = _parse_loc(row["call_location"])
    def_lines = _get_lines(def_file)
    call_lines = _get_lines(call_file)

    def_window = "\n".join(
        def_lines[max(0, def_sl - 15) : min(len(def_lines), def_el + 25)]
    )
    def_ok = bool(def_lines) and (
        any(tok in def_window for tok in CAP_SOURCE_TOKENS)
        or any("capable(" in ln for ln in def_lines)
        or ("if (" in def_window and "return " in def_window)
    )
    span_ok = bool(call_lines) and 1 <= call_sl <= call_el <= len(call_lines)
    return def_ok, span_ok


def test_conditions_source_verification_300_samples(conditions, kernel):
    """Verify 300 sampled capability gates against kernel C source files."""
    cap_rows = [
        r for r in conditions if r["type"] in ("capable", "ns_capable")
    ]
    probe_file, _, _ = _parse_loc(cap_rows[0]["definition"])
    if not _locate_kernel_source_file(probe_file, kernel):
        pytest.skip(f"kernel C source tree not found on disk for {kernel}")

    sample = random.Random(42).sample(cap_rows, min(300, len(cap_rows)))
    file_cache: dict[str, list[str]] = {}
    verified_defs = 0
    verified_spans = 0
    failures = []

    for r in sample:
        def_ok, span_ok = _verify_condition_row(r, kernel, file_cache)
        verified_defs += int(def_ok)
        verified_spans += int(span_ok)
        if not (def_ok and span_ok):
            failures.append((r["definition"], r["call"], r["call_location"]))

    report(
        f"300-sample C source verification [{kernel}]",
        {
            "sampled": len(sample),
            "verified_defs": pct(verified_defs, len(sample)),
            "verified_spans": pct(verified_spans, len(sample)),
            "failures": len(failures),
        },
    )
    assert (
        verified_defs == len(sample) and verified_spans == len(sample)
    ), f"source verification failed on {len(failures)} rows: {failures[:5]}"


def test_conditions_distribution(conditions, baseline_path):
    """Verify conditions row counts do not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "conditions")
    if not base or not base.get("rows"):
        pytest.skip("no baseline recorded for conditions")
    counts = Counter(r["type"] for r in conditions)
    span_rows = sum(
        1 for r in conditions if r["call"].startswith("__guarded_span__:")
    )
    genl_rows = sum(
        1 for r in conditions if r["call"].startswith("__genl_ops_gate__:")
    )
    ratio = len(conditions) / base["rows"]
    cap_ratio = counts["capable"] / base["capable_rows"]
    nscap_ratio = counts["ns_capable"] / base["ns_capable_rows"]
    report(
        "conditions distribution",
        {
            "rows": len(conditions),
            "baseline rows": base["rows"],
            "ratio vs baseline": f"{ratio:.2f}x",
            "capable_rows": counts["capable"],
            "baseline capable_rows": base["capable_rows"],
            "ns_capable_rows": counts["ns_capable"],
            "baseline ns_capable_rows": base["ns_capable_rows"],
            "guarded_span_rows": span_rows,
            "genl_gate_rows": genl_rows,
        },
    )
    assert (
        ratio >= 0.75
    ), f"conditions row count dropped to {ratio:.1%} of baseline"
    assert (
        cap_ratio >= 0.75
    ), f"capable_rows dropped to {cap_ratio:.1%} of baseline"
    assert (
        nscap_ratio >= 0.75
    ), f"ns_capable_rows dropped to {nscap_ratio:.1%} of baseline"
    if base.get("guarded_span_rows"):
        span_ratio = span_rows / base["guarded_span_rows"]
        assert (
            span_ratio >= 0.75
        ), f"guarded_span_rows dropped to {span_ratio:.1%} of baseline"
    if base.get("genl_gate_rows"):
        genl_ratio = genl_rows / base["genl_gate_rows"]
        assert (
            genl_ratio >= 0.75
        ), f"genl_gate_rows dropped to {genl_ratio:.1%} of baseline"
