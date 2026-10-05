"""Data-quality checks for `entry-node-pairs.ql` and `entry_node` table."""
from __future__ import annotations

import collections
import os
import statistics

from common import group_sets, load_baseline, pct, report
import pytest

EXPECTED_ENTRY_KINDS = {
    "compat_syscall",
    "page_fault",
    "net_rx",
    "vfs_writeback",
    "vfs_reclaim",
    "io_uring",
    "bpf_entry",
    "device_usb",
}

EXPECTED_KIND_MIN_ROOTS = {
    "bpf_entry": 250,
    "compat_syscall": 100,
    "vfs_reclaim": 45,
    "device_usb": 25,
    "net_rx": 11,
    "io_uring": 4,
    "page_fault": 2,
    "vfs_writeback": 1,
}

FORBIDDEN_CHOKEPOINT_SEEDS = {
    "handle_mm_fault",
    "do_page_fault",
    "nf_hook_slow",
    "wb_writeback",
    "writeback_inodes_wb",
    "delayed_fput",
    "__fput_sync",
}

SAMPLE_QUOTAS_300 = {
    "bpf_entry": 60,
    "compat_syscall": 60,
    "vfs_reclaim": 45,
    "device_usb": 45,
    "net_rx": 35,
    "io_uring": 25,
    "page_fault": 15,
    "vfs_writeback": 15,
}

_MACRO_DEF_PREFIXES = (
    "____",
    "__do_compat_sys_ia32_",
    "__do_compat_sys_",
    "__do_sys_",
    "__ia32_compat_sys_",
    "__ia32_sys_",
    "__x64_sys_",
    "__se_sys_",
    "__se_compat_sys_",
)

_MACRO_DEF_KEYWORDS = (
    "DEFINE_",
    "DECLARE_",
    "SYSCALL_",
    "BPF_CALL_",
    "BUILDIO",
    "TRACE_EVENT",
    "__init",
    "MODULE_",
    "LOCK_",
    " ops_",
    "ATOMIC_",
    "PAGEFLAG",
    "TESTPAGEFLAG",
    "SETPAGEFLAG",
    "CLEARPAGEFLAG",
)


def _locate_kernel_source_file(raw_file: str, kernel: str) -> str | None:
    """Resolve `raw_file` to an on-disk kernel source file if available."""
    if not raw_file:
        return None
    if os.path.isfile(raw_file):
        return raw_file

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
        candidate = os.path.join(repo_dir, raw_file)
        if os.path.isfile(candidate):
            return candidate
    return None


def _parse_loc(loc_str: str) -> tuple[str, int, int] | None:
    """Parse `file:sl:sc:el:ec` or `file:sl` into `(file, sl, el)`."""
    if not loc_str:
        return None
    parts = loc_str.split(":")
    if len(parts) >= 5 and parts[1].isdigit() and parts[3].isdigit():
        return parts[0], int(parts[1]), int(parts[3])
    if len(parts) >= 2 and parts[1].isdigit():
        line_no = int(parts[1])
        return parts[0], line_no, line_no
    return None


def _verify_fn_def_in_source(
    fn_name: str, lines: list[str], sl: int, el: int
) -> str | None:
    """Verify `fn_name` is defined around `sl..el` in `lines`."""
    if not (1 <= sl <= len(lines) and 1 <= el <= len(lines) and sl <= el):
        return None
    win = "".join(lines[max(0, sl - 6) : min(len(lines), el + 6)])
    if fn_name in win:
        return "direct"
    base = fn_name
    for pref in _MACRO_DEF_PREFIXES:
        if base.startswith(pref):
            base = base[len(pref) :]
            break
    if base != fn_name and base in win:
        return "macro"
    if any(kw in win for kw in _MACRO_DEF_KEYWORDS):
        return "macro"
    return None


def _verify_root_kind_in_source(
    kind: str, entry: str, win: str, file_text: str
) -> bool:
    """Verify `entry` has C source registration matching `kind`."""
    result = False
    if kind == "compat_syscall":
        result = "COMPAT_SYSCALL_DEFINE" in win or "SYSCALL32_DEFINE" in win
    elif kind == "page_fault":
        result = (
            entry in ("exc_page_fault", "do_user_addr_fault") and entry in win
        )
    elif kind in ("net_rx", "io_uring", "vfs_writeback"):
        result = entry in win
    elif kind == "vfs_reclaim":
        core_reclaim = (
            "shrink_slab",
            "super_cache_scan",
            "prune_icache_sb",
            "prune_dcache_sb",
        )
        result = (entry in core_reclaim and entry in win) or (
            any(
                k in file_text
                for k in ("scan_objects", "count_objects", "shrinker")
            )
            and entry in file_text
        )
    elif kind == "bpf_entry":
        if entry.startswith("____"):
            result = "BPF_CALL_" in win and entry[4:] in file_text
        else:
            result = (
                any(
                    k in file_text
                    for k in ("BTF_ID_FLAGS", "__bpf_kfunc", "bpf_func_proto")
                )
                and entry in file_text
            )
    elif kind == "device_usb":
        result = (
            any(
                k in file_text
                for k in (
                    "usb_driver",
                    "hid_driver",
                    "virtio_driver",
                    "hv_driver",
                    "usb_fill_",
                    "->complete",
                    ".complete",
                )
            )
            and entry in file_text
        )
    return result


def test_entry_node_pairs_not_empty(entry_node_pairs, kernel):
    """Verify entry_node_pairs reachability closure is non-empty."""
    report(
        f"entry_node_pairs rows [{kernel}]",
        {"rows": len(entry_node_pairs)},
    )
    assert (
        entry_node_pairs
    ), "no reachability rows -- the closure produced nothing"


def test_entry_seeds_and_taxonomy(entry_node_pairs):
    """Verify all 8 entry_kind categories, root counts, and exclusions."""
    kinds = {r["entry_kind"] for r in entry_node_pairs}
    unknown_kinds = kinds - EXPECTED_ENTRY_KINDS
    missing_kinds = EXPECTED_ENTRY_KINDS - kinds

    seeds = {r["entry"] for r in entry_node_pairs}
    do_sys_seeds = {s for s in seeds if s.startswith("__do_sys_")}
    chokepoint_seeds = seeds & FORBIDDEN_CHOKEPOINT_SEEDS

    by_kind = group_sets(entry_node_pairs, "entry_kind", "entry")
    bad_compat = {
        s
        for s in by_kind.get("compat_syscall", set())
        if not s.startswith("__do_compat_sys_")
    }
    bpf_seeds = by_kind.get("bpf_entry", set())
    bpf_helpers = {s for s in bpf_seeds if s.startswith("____")}
    bpf_kfuncs = {s for s in bpf_seeds if not s.startswith("____")}

    below_min = {
        k: (len(by_kind.get(k, set())), min_cnt)
        for k, min_cnt in EXPECTED_KIND_MIN_ROOTS.items()
        if len(by_kind.get(k, set())) < min_cnt
    }

    report(
        "entry seeds by kind",
        {
            k: len(by_kind.get(k, set()))
            for k in sorted(EXPECTED_ENTRY_KINDS)
        },
    )
    report(
        "bpf_entry breakdown",
        {
            "BPF_CALL_x helper bodies (____*)": len(bpf_helpers),
            "BTF_ID_FLAGS kfuncs / direct": len(bpf_kfuncs),
        },
    )
    assert not unknown_kinds, f"unexpected entry_kind values: {unknown_kinds}"
    assert not missing_kinds, f"missing entry_kind categories: {missing_kinds}"
    assert not do_sys_seeds, (
        f"__do_sys_ seeds leaked into entry_node: {do_sys_seeds}"
    )
    assert not chokepoint_seeds, (
        f"chokepoint functions seeded as roots: {chokepoint_seeds}"
    )
    assert not bad_compat, (
        f"non-__do_compat_sys_ seeds in compat_syscall: {bad_compat}"
    )
    assert bpf_helpers, "expected BPF_CALL_x ____* helper bodies in bpf_entry"
    assert bpf_kfuncs, "expected BTF_ID_FLAGS kfuncs in bpf_entry"
    assert not below_min, (
        f"entry_kind root counts below minimum (actual, min): {below_min}"
    )


def test_reachability_is_irreflexive(entry_node_pairs):
    """Verify no entry root reaches itself (root excluded from edges+)."""
    self_rows = [
        r for r in entry_node_pairs if r["entry"] == r["function"]
    ]
    report(
        "self-reachability",
        {"rows where entry == function": len(self_rows)},
    )
    assert not self_rows


def test_canonical_reachability_and_distribution(entry_node_pairs):
    """Verify canonical intermediate functions are reached from true entries."""
    reach = group_sets(entry_node_pairs, "entry", "function")
    counts = sorted(len(v) for v in reach.values())
    median = statistics.median(counts)
    report(
        "per-entry reach",
        {
            "min": counts[0],
            "median": median,
            "max": counts[-1],
            "distinct_entries": len(counts),
        },
    )
    assert "handle_mm_fault" in reach.get("do_user_addr_fault", set()), (
        "do_user_addr_fault should transitively reach handle_mm_fault"
    )
    assert "do_user_addr_fault" in reach.get("exc_page_fault", set()), (
        "exc_page_fault should transitively reach do_user_addr_fault"
    )
    assert "wb_writeback" in reach.get("wb_workfn", set()), (
        "wb_workfn should transitively reach wb_writeback"
    )
    assert "ip_rcv_core" in reach.get("ip_rcv", set()), (
        "ip_rcv should transitively reach ip_rcv_core"
    )
    assert "tcp_v4_do_rcv" in reach.get("tcp_v4_rcv", set()), (
        "tcp_v4_rcv should transitively reach tcp_v4_do_rcv"
    )
    assert "prune_icache_sb" in reach.get("super_cache_scan", set()), (
        "super_cache_scan should transitively reach prune_icache_sb"
    )
    assert "io_issue_sqe" in reach.get("io_wq_submit_work", set()), (
        "io_wq_submit_work should transitively reach io_issue_sqe"
    )
    assert "crash_kexec" in reach, (
        "expected BTF kfunc crash_kexec as an active bpf_entry root"
    )


def test_reached_functions_exist_in_function_locations(
    entry_node_pairs, function_locations
):
    """Every reached function should be a function the extractor recorded."""
    known = {r["function_name"] for r in function_locations}
    reached = {r["function"] for r in entry_node_pairs}
    missing = reached - known
    rate = pct(len(reached & known), len(reached))
    report(
        "reached vs function_locations",
        {
            "reached functions": len(reached),
            "known functions": len(known),
            "present %": f"{rate:.1f}",
            "missing": len(missing),
        },
    )
    assert rate >= 95.0, (
        f"only {rate:.1f}% of reached functions appear in function_locations"
    )


def _collect_roots_and_sample(
    entry_node: list[dict],
) -> tuple[dict[tuple[str, str], str], list[dict]]:
    """Collect active root locations and a 300-row stratified sample."""
    roots_map: dict[tuple[str, str], str] = {}
    per_root_count: dict[tuple[str, str], int] = collections.Counter()
    seen_fn_by_kind: dict[str, set[str]] = collections.defaultdict(set)
    by_kind_rows: dict[str, list[dict]] = collections.defaultdict(list)
    for row in entry_node:
        kind = row["entry_kind"]
        key = (kind, row["entry"])
        if key not in roots_map and row.get("entry_location"):
            roots_map[key] = row["entry_location"]
        fn = row["function"]
        if (
            per_root_count[key] < 20
            and len(by_kind_rows[kind]) < 2400
            and fn not in seen_fn_by_kind[kind]
        ):
            per_root_count[key] += 1
            seen_fn_by_kind[kind].add(fn)
            by_kind_rows[kind].append(row)

    sampled = []
    for kind, quota in sorted(SAMPLE_QUOTAS_300.items()):
        rows = by_kind_rows[kind]
        step = max(1, len(rows) // quota)
        sampled.extend([rows[i] for i in range(0, len(rows), step)][:quota])
    return roots_map, sampled


class _SourceVerifier:
    """Caches kernel source files and verifies entry roots and pairs."""

    def __init__(self, kernel: str) -> None:
        self.kernel = kernel
        self.cache: dict[str, tuple[list[str] | None, str]] = {}
        _, helpers_txt = self.get_source("kernel/bpf/helpers.c")
        _, tcp_ca_txt = self.get_source("net/ipv4/bpf_tcp_ca.c")
        self.central_kfunc_txt = helpers_txt + "\n" + tcp_ca_txt

    def get_source(self, rel_path: str) -> tuple[list[str] | None, str]:
        """Return `(lines, full_text)` for `rel_path` in the kernel repo."""
        if rel_path not in self.cache:
            src_path = _locate_kernel_source_file(rel_path, self.kernel)
            if not src_path:
                self.cache[rel_path] = (None, "")
            else:
                with open(
                    src_path, encoding="utf-8", errors="replace"
                ) as src_file:
                    lines = src_file.readlines()
                self.cache[rel_path] = (lines, "".join(lines))
        return self.cache[rel_path]

    def check_root(self, kind: str, entry: str, eloc_str: str) -> bool:
        """Verify an `(entry_kind, entry)` root against its C source file."""
        parsed = _parse_loc(eloc_str)
        if not parsed:
            return False
        lines, file_text = self.get_source(parsed[0])
        if lines is None or not _verify_fn_def_in_source(
            entry, lines, parsed[1], parsed[2]
        ):
            return False
        win = "".join(
            lines[max(0, parsed[1] - 6) : min(len(lines), parsed[2] + 6)]
        )
        if _verify_root_kind_in_source(kind, entry, win, file_text):
            return True
        return (
            kind == "bpf_entry"
            and not entry.startswith("____")
            and "BTF_ID_FLAGS" in self.central_kfunc_txt
            and entry in self.central_kfunc_txt
        )

    def check_pair(self, row: dict) -> str | None:
        """Verify an `entry_node` pair ('direct', 'macro', or None)."""
        ep = _parse_loc(row["entry_location"])
        fp = _parse_loc(row["function_location"])
        if not ep or not fp:
            return None
        elines, _ = self.get_source(ep[0])
        flines, _ = self.get_source(fp[0])
        if elines is None or flines is None:
            return None
        if not self.check_root(
            row["entry_kind"], row["entry"], row["entry_location"]
        ):
            return None
        return _verify_fn_def_in_source(row["function"], flines, fp[1], fp[2])

    def verify_roots(
        self, roots_map: dict[tuple[str, str], str]
    ) -> tuple[int, list[tuple[str, str, str]]]:
        """Verify all roots in `roots_map` and return `(checked, unmatched)`."""
        unmatched = []
        checked = 0
        for (kind, entry), eloc_str in sorted(roots_map.items()):
            parsed = _parse_loc(eloc_str)
            if parsed and self.get_source(parsed[0])[0] is not None:
                checked += 1
                if not self.check_root(kind, entry, eloc_str):
                    unmatched.append((kind, entry, eloc_str))
        return checked, unmatched


def test_entry_node_source_code_verification(entry_node, kernel):
    """Verify all roots and 300 stratified pairs against kernel C source."""
    if not any(
        r.get("entry_location") and r["entry_location"].count(":") >= 4
        for r in entry_node[:100]
    ):
        pytest.skip(
            "entry_node does not have full locations (pass --syscall-node-locs "
            "or --sqlite-db)"
        )

    roots_map, sampled = _collect_roots_and_sample(entry_node)
    verifier = _SourceVerifier(kernel)
    checked_roots, unmatched_roots = verifier.verify_roots(roots_map)
    if checked_roots == 0:
        pytest.skip("kernel source files not available on disk")

    counts = collections.Counter()
    unmatched_pairs = []
    for row in sampled:
        kind_match = verifier.check_pair(row)
        counts["checked"] += 1
        if kind_match in ("direct", "macro"):
            counts[kind_match] += 1
        else:
            unmatched_pairs.append(
                (row["entry_kind"], row["entry"], row["function"])
            )

    verified_roots = checked_roots - len(unmatched_roots)
    root_rate = pct(verified_roots, checked_roots)
    verified_pairs = counts["direct"] + counts["macro"]
    pair_rate = pct(verified_pairs, counts["checked"])
    report(
        "source-code verification (all roots + 300 stratified pairs)",
        {
            "active roots verified": (
                f"{verified_roots}/{checked_roots} ({root_rate:.1f}%)"
            ),
            "sampled pairs checked": counts["checked"],
            "direct fn symbol matches": (
                f"{counts['direct']} "
                f"({pct(counts['direct'], counts['checked']):.1f}%)"
            ),
            "macro-expanded fn matches": counts["macro"],
            "total pairs verified": (
                f"{verified_pairs}/{counts['checked']} ({pair_rate:.1f}%)"
            ),
        },
    )
    assert root_rate >= 99.0, (
        f"root source verification rate {root_rate:.1f}% < 99.0%; "
        f"unmatched roots: {unmatched_roots[:5]}"
    )
    assert pair_rate >= 98.0, (
        f"pair source verification rate {pair_rate:.1f}% < 98.0%; "
        f"unmatched pairs: {unmatched_pairs[:5]}"
    )


def test_entry_node_distribution(entry_node_pairs, baseline_path):
    """Verify entry_node row count does not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "entry_node")
    if not base:
        pytest.skip("no baseline recorded for entry_node (--baseline)")
    reach = group_sets(entry_node_pairs, "entry", "function")
    mean_reach = statistics.mean(len(v) for v in reach.values())
    report(
        "distribution",
        {
            "rows": len(entry_node_pairs),
            "baseline rows": base.get("rows"),
            "mean reach": f"{mean_reach:.0f}",
            "baseline mean reach": base.get("mean_reach"),
        },
    )
    if base.get("rows"):
        ratio = len(entry_node_pairs) / base["rows"]
        assert ratio >= 0.75, (
            f"row count dropped to {ratio:.1%} of baseline "
            f"({len(entry_node_pairs)} vs {base['rows']})"
        )
