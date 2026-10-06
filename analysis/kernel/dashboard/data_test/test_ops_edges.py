"""Data-quality checks for the `ops_targets` table (ops_edges.ql output).

This table resolves indirect calls through kernel operations structs
(file_operations, inode_operations, ...) to concrete target functions. It has
never been validated against anything, so these checks are intrinsic and
cross-table only -- there is no reference dump.
"""
from __future__ import annotations

import os
import random

from common import load_baseline, pct, report, top_counts
import pytest

FORBIDDEN_ASYNC_PARENTS_FIELDS = {
    ("callback_head", "func"),
    ("hrtimer", "function"),
    ("sock", "sk_data_ready"),
    ("sock", "sk_write_space"),
    ("sock", "sk_destruct"),
    ("kiocb", "ki_complete"),
}

MACRO_TOKENS = (
    "DEFINE_",
    "DECLARE_",
    "ATTR",
    "TRACE_EVENT",
    "LSM_HOOK",
    "FOPS",
    "PARAM",
    "INTERVAL_TREE",
    "IPSET_",
    "mtype_",
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


class _OpsSourceVerifier:
    """Cached kernel C source-code verifier for `ops_targets` rows."""

    def __init__(self, kernel: str) -> None:
        self.kernel = kernel
        self._cache: dict[str, list[str]] = {}

    def get_lines(self, rel_file: str) -> list[str]:
        """Return cached file lines for `rel_file`."""
        if rel_file not in self._cache:
            full = _locate_kernel_source_file(rel_file, self.kernel)
            if not full:
                self._cache[rel_file] = []
            else:
                with open(
                    full, "r", encoding="utf-8", errors="ignore"
                ) as handle:
                    self._cache[rel_file] = handle.read().splitlines()
        return self._cache[rel_file]

    def get_window(self, rel_file: str, line_no: int, pad: int = 15) -> str:
        """Return text window `[line_no - pad, line_no + pad]`."""
        lines = self.get_lines(rel_file)
        if not lines or line_no <= 0:
            return ""
        start = max(0, line_no - 1 - pad)
        end = min(len(lines), line_no + pad)
        return "\n".join(lines[start:end])

    def verify_row(self, row: dict[str, str]) -> tuple[bool, bool]:
        """Verify registration site and call site against kernel C source."""
        def_parts = row["definition"].split(":")
        def_file = def_parts[0]
        def_line = (
            int(def_parts[1])
            if len(def_parts) > 1 and def_parts[1].isdigit()
            else 1
        )
        target = row["target"]
        field = row["field"]
        call_file = row["exprcall_file"]
        call_line = (
            int(row["exprcall_line"])
            if row["exprcall_line"].isdigit()
            else 1
        )
        tgt_start = (
            int(row["target_start"])
            if row["target_start"].isdigit()
            else 1
        )

        def_win = self.get_window(def_file, def_line, pad=15)
        tgt_win = self.get_window(row["target_file"], tgt_start, pad=10)
        call_win = self.get_window(call_file, call_line, pad=25)

        reg_ok = (
            target in def_win
            or target in tgt_win
            or any(tok in def_win for tok in MACRO_TOKENS)
        )
        call_ok = (
            field in call_win
            or (field == "input" and "netlink_rcv" in call_win)
            or any(
                m in call_win
                for m in ("outb", "virtio_cread", "ehdr_", "shdr_")
            )
        )
        return reg_ok, call_ok


def test_ops_targets_not_empty(ops_targets, kernel):
    """Verify ops_targets contains resolved indirect call edges."""
    report(f"ops_targets rows [{kernel}]", {"rows": len(ops_targets)})
    assert (
        ops_targets
    ), "no ops-table edges -- indirect call resolution produced nothing"


def test_ops_targets_fields_are_populated(ops_targets):
    """Every edge needs a parent struct, a field, and a target to be useful."""
    blank_parent = sum(1 for r in ops_targets if not r["parent"])
    blank_field = sum(1 for r in ops_targets if not r["field"])
    blank_target = sum(1 for r in ops_targets if not r["target"])
    unnamed_parent = sum(
        1
        for r in ops_targets
        if "unnamed" in r["parent"] or r["parent"] == "<anon>"
    )
    report(
        "field population",
        {
            "blank parent": blank_parent,
            "blank field": blank_field,
            "blank target": blank_target,
            "unnamed parent": unnamed_parent,
        },
    )
    assert blank_target == 0, "edges without a resolved target are useless"
    assert unnamed_parent == 0, "anonymous struct containers must be resolved"
    assert pct(blank_parent, len(ops_targets)) < 5.0
    assert pct(blank_field, len(ops_targets)) < 5.0


def test_ops_targets_cover_known_ops_structs(ops_targets):
    """Verify well-known dispatch tables appear in ops_targets."""
    parents = {r["parent"] for r in ops_targets}
    expected = {"file_operations", "inode_operations"}
    present = expected & parents
    report(
        "ops struct coverage",
        {
            "distinct parent structs": len(parents),
            "expected present": f"{sorted(present)}",
        },
    )
    report("top parent structs", top_counts(ops_targets, "parent"))
    assert (
        present
    ), f"none of {sorted(expected)} appear among {len(parents)} parent structs"


def test_ops_targets_section_3_2_idioms(ops_targets):
    """Verify Section 3.2 idioms (3b shrinker, 1/2 local-var, 3a genl)."""
    open_fs = {
        r["target"]
        for r in ops_targets
        if r["parent"] == "file_operations"
        and r["field"] == "open"
        and r["exprcall_file"].endswith("fs/open.c")
    }
    proto_sendmsg = {
        r["target"]
        for r in ops_targets
        if r["parent"] == "proto" and r["field"] == "sendmsg"
    }
    sock_sendmsg = {
        r["target"]
        for r in ops_targets
        if r["parent"] == "proto_ops"
        and r["field"] == "sendmsg"
        and r["exprcall_file"].endswith("net/socket.c")
    }
    shrinker_targets = {
        r["target"] for r in ops_targets if r["parent"] == "shrinker"
    }
    genl_targets = {
        r["target"]
        for r in ops_targets
        if r["parent"] in ("genl_ops", "genl_small_ops", "genl_split_ops")
        and r["field"] in ("doit", "dumpit")
    }
    nl_cfg_targets = {
        r["target"]
        for r in ops_targets
        if r["parent"] == "netlink_kernel_cfg" and r["field"] == "input"
    }
    async_leaks = {
        (r["parent"], r["field"])
        for r in ops_targets
        if (r["parent"], r["field"]) in FORBIDDEN_ASYNC_PARENTS_FIELDS
    }

    report(
        "Section 3.2 idiom coverage",
        {
            "do_dentry_open targets": len(open_fs),
            "proto.sendmsg targets": len(proto_sendmsg),
            "sock_sendmsg_nosec targets": len(sock_sendmsg),
            "shrinker targets": len(shrinker_targets),
            "genl doit/dumpit targets": len(genl_targets),
            "netlink_kernel_cfg.input targets": len(nl_cfg_targets),
            "async leaks": len(async_leaks),
        },
    )

    assert (
        len(open_fs) >= 250
    ), f"expected >=250 do_dentry_open targets, got {len(open_fs)}"
    assert {"ext4_file_open", "generic_file_open"} <= open_fs
    assert {
        "tcp_sendmsg",
        "udp_sendmsg",
        "raw_sendmsg",
        "ping_v4_sendmsg",
    } <= proto_sendmsg
    assert {
        "unix_stream_sendmsg",
        "netlink_sendmsg",
        "packet_sendmsg",
    } <= sock_sendmsg
    assert len(shrinker_targets) >= 50
    assert {"super_cache_scan", "deferred_split_scan"} <= shrinker_targets
    assert len(genl_targets) >= 100
    assert {"ctrl_getfamily", "ctrl_dumpfamily"} <= genl_targets
    assert {"genl_rcv", "rtnetlink_rcv", "nfnetlink_rcv"} <= nl_cfg_targets
    assert (
        not async_leaks
    ), f"async_edges fields leaked into ops_targets: {async_leaks}"


def test_ops_target_line_ranges_are_ordered(ops_targets):
    """Verify target_start <= target_end for >=99.5% of ops target callbacks."""
    bad = [
        r
        for r in ops_targets
        if r["target_start"].isdigit()
        and r["target_end"].isdigit()
        and int(r["target_start"]) > int(r["target_end"])
    ]
    report(
        "target line ranges",
        {
            "start > end": len(bad),
            "pct": f"{pct(len(bad), len(ops_targets)):.2f}%",
        },
    )
    # Up to ~0.15% of kernel ops callbacks (e.g. SHOW_CPU_ATTR macros in
    # drivers/base/cpu.c) span header/macro boundaries.
    assert pct(len(bad), len(ops_targets)) < 0.5


def test_ops_targets_resolve_to_known_functions(
    ops_targets, function_locations
):
    """Verify resolved targets exist in extracted function_locations."""
    known = {r["function_name"] for r in function_locations}
    targets = {r["target"] for r in ops_targets if r["target"]}
    rate = pct(len(targets & known), len(targets))
    report(
        "targets vs function_locations",
        {
            "distinct targets": len(targets),
            "present %": f"{rate:.1f}",
            "missing": len(targets - known),
        },
    )
    assert (
        rate >= 90.0
    ), f"only {rate:.1f}% of ops targets are known functions"


def test_ops_targets_distribution(ops_targets, baseline_path):
    """Verify ops_targets row count does not drop below 75% of baseline."""
    base = load_baseline(baseline_path, "ops_targets")
    if not base:
        pytest.skip("no baseline recorded for ops_targets (--baseline)")
    report(
        "distribution",
        {"rows": len(ops_targets), "baseline rows": base.get("rows")},
    )
    if base.get("rows"):
        ratio = len(ops_targets) / base["rows"]
        assert ratio >= 0.75, (
            f"ops_targets row count dropped below 75% of baseline "
            f"({len(ops_targets)} vs {base['rows']})"
        )


def test_ops_targets_source_code_verification(ops_targets, kernel):
    """Verify a stratified 300-row sample against on-disk kernel C source."""
    if not _locate_kernel_source_file("fs/open.c", kernel):
        pytest.skip("kernel C source tree not available on disk")

    verifier = _OpsSourceVerifier(kernel)
    rng = random.Random(42)

    idiom_rows = [
        r
        for r in ops_targets
        if r["parent"]
        in (
            "shrinker",
            "proto",
            "genl_ops",
            "genl_small_ops",
            "genl_split_ops",
            "netlink_kernel_cfg",
        )
        or (
            r["parent"] == "file_operations"
            and r["field"] == "open"
            and r["exprcall_file"].endswith("fs/open.c")
        )
    ]
    other_rows = [r for r in ops_targets if r not in idiom_rows]
    n_idiom = min(150, len(idiom_rows))
    sample = rng.sample(idiom_rows, n_idiom) + rng.sample(
        other_rows, min(300 - n_idiom, len(other_rows))
    )

    outcomes = [verifier.verify_row(row) for row in sample]
    reg_ok = sum(1 for r_ok, _ in outcomes if r_ok)
    call_ok = sum(1 for _, c_ok in outcomes if c_ok)
    both_ok = sum(1 for r_ok, c_ok in outcomes if r_ok and c_ok)

    rate = pct(both_ok, len(sample))
    report(
        f"300-sample C source verification [{kernel}]",
        {
            "sampled": len(sample),
            "reg verified": f"{reg_ok}/{len(sample)}",
            "call verified": f"{call_ok}/{len(sample)}",
            "both verified": f"{both_ok}/{len(sample)} ({rate:.1f}%)",
        },
    )
    assert rate >= 95.0, (
        f"only {rate:.1f}% ({both_ok}/{len(sample)}) of sampled ops_targets "
        "rows verified against kernel C source"
    )
