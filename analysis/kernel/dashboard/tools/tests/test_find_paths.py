#!/usr/bin/env python3
"""Unit tests for tools/find_paths.py."""

import os
import sqlite3
import unittest
from unittest.mock import patch

from tools import find_paths
from tools.tests.fixtures import (
    BaseToolsTestCase,
    create_async_edges_schema,
    create_entry_node_schema,
    create_kconfig_schema,
    create_syzkaller_schema,
)


class TestFindPaths(BaseToolsTestCase):
    """Test suite for callgraph reachability path finding."""

    def setUp(self):
        """Set up temporary SQLite database with sample callgraph tables."""
        super().setUp()
        self.insert_rows(
            function_locations=[
                ("__do_sys_foo", "fs/read.c", 10, 30),
                ("vfs_foo", "fs/read.c", 40, 60),
                ("target_worker", "fs/internal.c", 100, 150),
                ("ops_callback", "drivers/bar.c", 200, 250),
            ],
            syscall_node=[
                ("__do_sys_foo", "vfs_foo", "fs/read.c:10", "fs/read.c:40"),
                (
                    "__do_sys_foo",
                    "target_worker",
                    "fs/read.c:10",
                    "fs/internal.c:100",
                ),
                (
                    "__do_sys_foo",
                    "ops_callback",
                    "fs/read.c:10",
                    "drivers/bar.c:200",
                ),
            ],
            locations=[
                (1, "__do_sys_foo", "fs/read.c", 10),
                (2, "call to vfs_foo", "fs/read.c", 20),
                (3, "vfs_foo", "fs/read.c", 40),
                (4, "call to target_worker", "fs/read.c", 50),
                (5, "target_worker", "fs/internal.c", 100),
            ],
            edges=[
                (1, 2, "callgraph-all"),
                (3, 4, "callgraph-all"),
            ],
            ops_targets=[
                (
                    "def",
                    "foo_ops",
                    "bar",
                    "ops_callback",
                    "drivers/bar.c",
                    200,
                    250,
                    "fs/read.c",
                    55,
                    40,
                    60,
                ),
            ],
        )

    def test_ensure_indexes(self):
        """Verify SQLite indexes are created on the database."""
        find_paths.ensure_indexes(self.conn)
        cur = self.conn.cursor()
        cur.execute('SELECT count(*) FROM sqlite_master WHERE type="index"')
        cnt = cur.fetchone()[0]
        self.assertGreaterEqual(cnt, 8)

    def test_get_enclosing_function(self):
        """Verify enclosing function lookup by file path and line number."""
        fn = find_paths.get_enclosing_function(self.conn, "fs/internal.c", 125)
        self.assertIsNotNone(fn)
        self.assertEqual(fn[0], "target_worker")
        self.assertEqual(fn[1], "fs/internal.c")
        self.assertEqual(fn[2], 100)
        self.assertEqual(fn[3], 150)

        # Suffix matching
        fn_suffix = find_paths.get_enclosing_function(
            self.conn, "internal.c", 125
        )
        self.assertEqual(fn_suffix[0], "target_worker")

        # Line outside any function
        fn_none = find_paths.get_enclosing_function(
            self.conn, "fs/internal.c", 999
        )
        self.assertIsNone(fn_none)

    def test_get_reachable_syscalls(self):
        """Verify syscall reachability lookup for a target function."""
        syss = find_paths.get_reachable_syscalls(self.conn, "target_worker")
        self.assertEqual(syss, ["__do_sys_foo"])

    def test_direct_call_path(self):
        """Verify shortest direct call path reconstruction."""
        target_info, paths = find_paths.find_paths_to_line(
            self.db_path, "fs/internal.c", 125, target_syscall="__do_sys_foo"
        )
        self.assertEqual(target_info["function"], "target_worker")
        self.assertIn("__do_sys_foo", paths)
        p = paths["__do_sys_foo"]
        self.assertEqual(len(p), 3)
        self.assertEqual(p[0]["function"], "__do_sys_foo")
        self.assertEqual(p[0]["call_site_line"], 20)
        self.assertEqual(p[1]["function"], "vfs_foo")
        self.assertEqual(p[1]["call_site_line"], 50)
        self.assertEqual(p[2]["function"], "target_worker")

    def test_indirect_ops_call_path(self):
        """Verify call path reconstruction across indirect ops_targets hops."""
        target_info, paths = find_paths.find_paths_to_line(
            self.db_path, "drivers/bar.c", 210, target_syscall="__do_sys_foo"
        )
        self.assertEqual(target_info["function"], "ops_callback")
        self.assertIn("__do_sys_foo", paths)
        p = paths["__do_sys_foo"]
        self.assertEqual(len(p), 3)
        self.assertEqual(p[0]["function"], "__do_sys_foo")
        self.assertEqual(p[1]["function"], "vfs_foo")
        self.assertEqual(p[1]["call_type"], "indirect")
        self.assertEqual(p[1]["details"], "foo_ops->bar")
        self.assertEqual(p[2]["function"], "ops_callback")

    def test_formats(self):
        """Verify tree, mermaid, and list output formatters."""
        target_info, paths = find_paths.find_paths_to_line(
            self.db_path, "fs/internal.c", 125, target_syscall="__do_sys_foo"
        )
        tree = find_paths.format_tree(paths, target_info)
        self.assertIn("[Syscall Entry] __do_sys_foo", tree)
        self.assertIn("vfs_foo", tree)
        self.assertIn("[Target Line] target_worker", tree)

        mermaid = find_paths.format_mermaid(paths)
        self.assertIn("graph TD", mermaid)
        self.assertIn("__do_sys_foo", mermaid)

        lst = find_paths.format_list(paths)
        self.assertIn("__do_sys_foo (fs/read.c:20) -> vfs_foo", lst)

    def test_cli(self):
        """Verify CLI execution with valid file and line arguments."""
        with patch(
            "sys.argv",
            [
                "find_paths.py",
                "--db",
                self.db_path,
                "--file",
                "fs/internal.c",
                "--line",
                "125",
            ],
        ):
            try:
                find_paths.main()
            except SystemExit as e:
                self.assertEqual(e.code, 0)

    def test_cli_missing_db(self):
        """Verify CLI exits with error when --db argument is missing."""
        with patch(
            "sys.argv",
            ["find_paths.py", "--file", "fs/internal.c", "--line", "125"],
        ):
            with self.assertRaises(SystemExit):
                find_paths.main()

    def test_syzkaller_db_param(self):
        """Verify Syzkaller database correlation parameter handling."""
        target_info, _ = find_paths.find_paths_to_line(
            self.db_path, "fs/internal.c", 125, target_syscall="__do_sys_foo"
        )
        self.assertFalse(target_info["syzkaller"]["configured"])

        syzk_path = os.path.join(self.tmp_dir, "syzkaller_test.db")
        syzk_conn = sqlite3.connect(syzk_path)
        create_syzkaller_schema(syzk_conn.cursor())
        syzk_conn.commit()
        syzk_conn.close()

        target_info_syzk, _ = find_paths.find_paths_to_line(
            self.db_path,
            "fs/internal.c",
            125,
            target_syscall="__do_sys_foo",
            syzkaller_db=syzk_path,
        )
        self.assertTrue(target_info_syzk["syzkaller"]["configured"])

    def test_kconfig_configs_and_else_polarity(self):
        """Verify configs (#ifdef/#else/Makefile) and kconfig_symbols lookup."""
        cur = self.conn.cursor()
        create_kconfig_schema(cur)
        cur.executemany(
            "INSERT INTO configs VALUES (?, ?, ?, ?, ?)",
            [
                ("CONFIG_FS_INTERNAL", "fs/internal.c", 1, 200, 0),
                ("CONFIG_FAST_PATH", "fs/internal.c", 100, 150, 120),
            ],
        )
        cur.execute(
            "INSERT INTO kconfig_symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "CONFIG_FS_INTERNAL",
                "bool",
                "Internal FS",
                "FS_CORE",
                "",
                "y",
                "y",
                "fs/Kconfig",
                10,
            ),
        )
        self.conn.commit()

        # Line 110 is before #else (120) -> CONFIG_FAST_PATH
        cfgs_before = find_paths.get_line_configs(
            self.conn, "fs/internal.c", 110
        )
        self.assertEqual(
            cfgs_before, ["CONFIG_FS_INTERNAL", "CONFIG_FAST_PATH"]
        )

        # Line 125 is after #else (120) -> !CONFIG_FAST_PATH
        target_info, paths = find_paths.find_paths_to_line(
            self.db_path, "fs/internal.c", 125, target_syscall="__do_sys_foo"
        )
        self.assertEqual(
            target_info["configs"],
            ["CONFIG_FS_INTERNAL", "!CONFIG_FAST_PATH"],
        )
        self.assertIn("CONFIG_FS_INTERNAL", target_info["kconfig_metadata"])
        tree = find_paths.format_tree(paths, target_info)
        self.assertIn(
            "Kernel Configs (Target): CONFIG_FS_INTERNAL, !CONFIG_FAST_PATH",
            tree,
        )
        self.assertIn("[Kconfig: CONFIG_FS_INTERNAL, !CONFIG_FAST_PATH]", tree)

    def test_async_edges_path_resolution(self):
        """Verify async_edges bridges asynchronous callbacks to syscalls."""
        cur = self.conn.cursor()
        create_async_edges_schema(cur)
        cur.execute(
            "INSERT INTO function_locations VALUES (?, ?, ?, ?)",
            ("async_work_fn", "fs/internal.c", 300, 320),
        )
        cur.execute(
            "INSERT INTO async_edges VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "target_worker",
                "async_work_fn",
                "workqueue",
                "arg",
                "fs/internal.c",
                130,
                "process",
            ),
        )
        self.conn.commit()

        syscalls = find_paths.get_reachable_syscalls(self.conn, "async_work_fn")
        self.assertIn("__do_sys_foo", syscalls)

        target_info, paths = find_paths.find_paths_to_line(
            self.db_path, "fs/internal.c", 310, target_syscall="__do_sys_foo"
        )
        self.assertEqual(target_info["function"], "async_work_fn")
        self.assertIn("__do_sys_foo", paths)
        path = paths["__do_sys_foo"]
        self.assertEqual(path[-2]["function"], "target_worker")
        self.assertEqual(path[-2]["call_type"], "async")
        self.assertEqual(path[-2]["details"], "workqueue/arg (process)")

        # Verify D1 (multi-depth bridging collects syscalls from deeper callers)
        # and D3 (duplicate call site at same caller/line is deduplicated)
        cur.executemany(
            "INSERT INTO function_locations VALUES (?, ?, ?, ?)",
            [
                ("__do_sys_bar", "fs/read.c", 400, 420),
                ("intermediate_helper", "fs/internal.c", 430, 450),
            ],
        )
        cur.execute(
            "INSERT INTO syscall_node VALUES (?, ?, ?, ?)",
            (
                "__do_sys_bar",
                "__do_sys_bar",
                "fs/read.c:400",
                "fs/read.c:400",
            ),
        )
        cur.executemany(
            "INSERT INTO async_edges VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "intermediate_helper",
                    "async_work_fn",
                    "workqueue",
                    "init",
                    "fs/internal.c",
                    35,
                    "kthread",
                ),
                (
                    "__do_sys_bar",
                    "intermediate_helper",
                    "timer",
                    "arg",
                    "fs/read.c",
                    410,
                    "softirq",
                ),
                # Duplicate site at target_worker:130 should be deduplicated
                (
                    "target_worker",
                    "async_work_fn",
                    "workqueue",
                    "assign",
                    "fs/internal.c",
                    130,
                    "kthread",
                ),
            ],
        )
        # Also insert a direct edge at the same call site (target_worker:130)
        # to verify deduplication upgrades "direct" to the richer "async" label.
        cur.executemany(
            "INSERT INTO locations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (10, 1, "target_worker", "fs/internal.c", 100, 1, 150, 1),
                (11, 1, "async_work_fn", "fs/internal.c", 130, 1, 130, 10),
            ],
        )
        cur.execute("INSERT INTO edges VALUES (?, ?, ?, ?)", (10, 10, 11, "r"))
        self.conn.commit()

        callers = find_paths.get_callers(self.conn, "async_work_fn")
        tw_callers = [c for c in callers if c[0] == "target_worker"]
        self.assertEqual(len(tw_callers), 1)
        self.assertEqual(tw_callers[0][4], "async")
        self.assertIn("workqueue/", tw_callers[0][5])

        all_syscalls = find_paths.get_reachable_syscalls(
            self.conn, "async_work_fn"
        )
        self.assertEqual(all_syscalls, ["__do_sys_bar", "__do_sys_foo"])

    def test_entry_node_reachability_and_path(self):
        """Verify entry_node reachability and path resolution."""
        create_entry_node_schema(self.conn.cursor())
        self.insert_rows(
            function_locations=[
                ("ip_rcv", "net/ipv4/ip_input.c", 500, 540),
                ("tcp_v4_rcv", "net/ipv4/tcp_ipv4.c", 2000, 2100),
            ],
            entry_node=[
                (
                    "net_rx",
                    "ip_rcv",
                    "tcp_v4_rcv",
                    "net/ipv4/ip_input.c:500",
                    "net/ipv4/tcp_ipv4.c:2000",
                ),
            ],
            locations=[
                (20, "ip_rcv", "net/ipv4/ip_input.c", 500),
                (21, "call to tcp_v4_rcv", "net/ipv4/ip_input.c", 525),
            ],
            edges=[(20, 21, "callgraph-all")],
        )

        entries = find_paths.get_reachable_entries(self.conn, "tcp_v4_rcv")
        self.assertEqual(entries, [{"entry_kind": "net_rx", "entry": "ip_rcv"}])

        target_info, paths = find_paths.find_paths_to_line(
            self.db_path, "net/ipv4/tcp_ipv4.c", 2050
        )
        self.assertEqual(target_info["function"], "tcp_v4_rcv")
        self.assertEqual(len(target_info["all_entries"]), 1)
        self.assertIn("ip_rcv", paths)
        self.assertEqual(paths["ip_rcv"][0]["entry_kind"], "net_rx")

        tree = find_paths.format_tree(paths, target_info)
        self.assertIn("[Entry: net_rx] ip_rcv", tree)
        self.assertIn("Non-Syscall Entries (CodeQL):", tree)

    def test_expr_source_call_edge_caller_resolution(self):
        """Verify ExprSourceCallEdge rows resolve via function_locations."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO function_locations VALUES (?, ?, ?, ?)",
            ("netlink_rcv_skb", "net/netlink/af_netlink.c", 2490, 2530),
        )
        cur.executemany(
            "INSERT INTO locations (id, message, uri, startLine) VALUES"
            " (?, ?, ?, ?)",
            [
                (30, "cb", "net/netlink/af_netlink.c", 2507),
                (31, "genl_rcv_msg", "net/netlink/genetlink.c", 900),
            ],
        )
        cur.execute(
            "INSERT INTO edges (source_location_id, target_location_id,"
            " rule_id) VALUES (?, ?, ?)",
            (30, 31, "callgraph-all"),
        )
        self.conn.commit()

        callers = find_paths.get_callers(self.conn, "genl_rcv_msg")
        self.assertEqual(len(callers), 1)
        self.assertEqual(callers[0][0], "netlink_rcv_skb")
        self.assertEqual(callers[0][1], "net/netlink/af_netlink.c")
        self.assertEqual(callers[0][2], 2490)
        self.assertEqual(callers[0][3], 2507)
        self.assertEqual(callers[0][4], "direct")


if __name__ == "__main__":
    unittest.main()
