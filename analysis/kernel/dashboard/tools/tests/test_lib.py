#!/usr/bin/env python3
"""Direct unit tests for shared library modules in tools/lib/."""

import argparse
import io
import os
import sqlite3
from unittest.mock import patch

from tools.lib import callgraph, metadata, privilege
from tools.tests.fixtures import (
    BaseToolsTestCase,
    create_async_edges_schema,
    create_entry_node_schema,
    create_kconfig_schema,
    create_syzkaller_schema,
)


class TestLibCallgraph(BaseToolsTestCase):
    """Unit tests for tools.lib.callgraph."""

    def setUp(self):
        """Populate base callgraph fixture tables."""
        super().setUp()
        self.insert_rows(
            function_locations=[
                ("__do_sys_read", "linux/fs/read_write.c", 10, 30),
                ("ksys_read", "fs/read_write.c", 40, 70),
                ("vfs_read", "fs/read_write.c", 80, 120),
                (" orphan_fn", "fs/read_write.c", 130, 150),
            ],
            syscall_node=[
                (
                    "__do_sys_read",
                    "ksys_read",
                    "fs/read_write.c:10",
                    "fs/read_write.c:40",
                ),
                (
                    "__do_sys_read",
                    "vfs_read",
                    "fs/read_write.c:10",
                    "fs/read_write.c:80",
                ),
            ],
            locations=[
                (1, "__do_sys_read", "fs/read_write.c", 10),
                (2, "call to ksys_read", "fs/read_write.c", 20),
                (3, "ksys_read", "fs/read_write.c", 40),
                (4, "call to vfs_read", "fs/read_write.c", 55),
            ],
            edges=[
                (1, 2, "callgraph-all"),
                (3, 4, "callgraph-all"),
            ],
        )

    def test_clean_file_path_and_table_exists(self):
        """Verify path normalization and table existence checks."""
        self.assertEqual(
            callgraph.clean_file_path("/linux/fs/read_write.c"),
            "fs/read_write.c",
        )
        cur = self.conn.cursor()
        self.assertTrue(callgraph.table_exists(cur, "function_locations"))
        self.assertFalse(callgraph.table_exists(cur, "nonexistent_table"))

    def test_open_databases_and_indexes(self):
        """Verify open_databases opens DBs, builds indexes, and checks paths."""
        with self.assertRaises(FileNotFoundError):
            callgraph.open_databases(os.path.join(self.tmp_dir, "missing.db"))

        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            conn, syzk_conn = callgraph.open_databases(
                self.db_path, verbose=True
            )
            self.assertIsNone(syzk_conn)
            self.assertIn("Creating", stderr.getvalue())
            # Second call is a no-op when indexes already exist
            callgraph.ensure_indexes(conn, verbose=True)
            conn.close()

    def test_function_lookup_helpers(self):
        """Verify get_enclosing_function, get_function_by_name, batch load."""
        enc = callgraph.get_enclosing_function(self.conn, "fs/read_write.c", 50)
        self.assertEqual(enc, ("ksys_read", "fs/read_write.c", 40, 70))
        self.assertIsNone(
            callgraph.get_enclosing_function(self.conn, "fs/read_write.c", 999)
        )

        by_name = callgraph.get_function_by_name(self.conn, "__do_sys_read")
        self.assertEqual(by_name, ("__do_sys_read", "fs/read_write.c", 10, 30))
        self.assertIsNone(
            callgraph.get_function_by_name(self.conn, "missing_fn")
        )

        grouped = callgraph.load_functions_for_files(
            self.conn, ["fs/read_write.c"]
        )
        self.assertIn("fs/read_write.c", grouped)
        self.assertGreaterEqual(len(grouped["fs/read_write.c"]), 3)

    def test_iter_pruned_callers_and_roots(self):
        """Verify caller pruning and syscall root matching."""
        reach = callgraph.load_target_reachable_set(self.conn, "__do_sys_read")
        self.assertIsNotNone(reach)
        self.assertIn("ksys_read", reach)
        self.assertIn("__do_sys_read", reach)

        callers = callgraph.iter_pruned_callers(
            self.conn, "vfs_read", reach, allow_prune=True
        )
        self.assertEqual(len(callers), 1)
        self.assertEqual(callers[0][0], "ksys_read")

        self.assertTrue(callgraph.is_syscall_root("__do_sys_read", "read"))
        self.assertTrue(callgraph.is_syscall_root("__x64_sys_read", "read"))
        self.assertFalse(callgraph.is_syscall_root("vfs_read", "read"))

    def test_entry_roots_and_select_eval_roots(self):
        """Verify entry_node root helpers and select_eval_roots filtering."""
        create_entry_node_schema(self.conn.cursor())
        self.insert_rows(
            entry_node=[
                (
                    "net_rx",
                    "ip_rcv",
                    "vfs_read",
                    "net/ipv4/ip_input.c:10",
                    "fs/read_write.c:80",
                ),
            ]
        )
        roots = callgraph.load_entry_roots(self.conn)
        self.assertEqual(roots, {"ip_rcv": "net_rx"})
        self.assertEqual(
            callgraph.is_entry_root("ip_rcv", "net_rx", roots), "net_rx"
        )
        self.assertIsNone(
            callgraph.is_entry_root("ip_rcv", "other_entry", roots)
        )

        target_info = {
            "all_syscalls": ["__do_sys_read", "__do_sys_write"],
            "all_entries": [{"entry_kind": "net_rx", "entry": "ip_rcv"}],
        }
        self.assertEqual(
            callgraph.select_eval_roots(target_info, target_syscall="read"),
            ["__do_sys_read"],
        )
        self.assertEqual(
            callgraph.select_eval_roots(
                target_info, all_syscalls=True, limit_syscalls=2
            ),
            ["__do_sys_read", "__do_sys_write"],
        )
        self.assertIsNone(callgraph.select_eval_roots(target_info))

    def test_formatting_banners_and_labels(self):
        """Verify format_root_label and format_target_banner."""
        self.assertEqual(
            callgraph.format_root_label({"entry_kind": "syscall"}),
            "[Syscall Entry]",
        )
        self.assertEqual(
            callgraph.format_root_label({"entry_kind": "net_rx"}),
            "[Entry: net_rx]",
        )
        banner = callgraph.format_target_banner({
            "file": "fs/read_write.c",
            "line": 85,
            "function": "vfs_read",
            "span": (80, 120),
        })
        self.assertEqual(len(banner), 2)
        self.assertIn("Function Span: lines 80 - 120", banner[1])


class TestLibMetadata(BaseToolsTestCase):
    """Unit tests for tools.lib.metadata."""

    def setUp(self):
        """Set up base CodeQL and Syzkaller tables."""
        super().setUp()
        self.syzk_path = os.path.join(self.tmp_dir, "syzk.db")
        self.syzk_conn = sqlite3.connect(self.syzk_path)
        create_syzkaller_schema(self.syzk_conn.cursor())
        cur = self.syzk_conn.cursor()
        cur.execute("INSERT INTO file_path VALUES (1, 'fs/read_write.c')")
        cur.execute("INSERT INTO syscalls VALUES ('p1', 'read')")
        cur.execute("INSERT INTO syzk_prog VALUES ('p1', 'r0 = open()')")
        cur.execute("INSERT INTO syzk_cov VALUES (1, 'vfs_read', 90, 'p1')")
        self.syzk_conn.commit()

        create_kconfig_schema(self.conn.cursor())
        self.insert_rows(
            function_locations=[
                ("vfs_read", "fs/read_write.c", 80, 120),
            ],
        )
        c_cur = self.conn.cursor()
        c_cur.execute(
            "INSERT INTO configs VALUES (?, ?, ?, ?, ?)",
            ("CONFIG_A && CONFIG_B", "fs/read_write.c", 80, 120, 100),
        )
        c_cur.execute(
            "INSERT INTO kconfig_symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("CONFIG_A", "bool", "Prompt A", "", "", "y", "y", "Kconfig", 1),
        )
        self.conn.commit()

    def tearDown(self):
        """Close Syzkaller connection and clean up."""
        self.syzk_conn.close()
        super().tearDown()

    def test_syzkaller_coverage_helpers(self):
        """Verify get_syzkaller_coverage and is_line_covered_by_syzkaller."""
        unconf = metadata.get_syzkaller_coverage(None, "fs/read_write.c", 90)
        self.assertFalse(unconf["configured"])

        untracked = metadata.get_syzkaller_coverage(
            self.syzk_conn, "fs/untracked.c", 10
        )
        self.assertFalse(untracked["file_tracked"])

        cov = metadata.get_syzkaller_coverage(
            self.syzk_conn, "fs/read_write.c", 90, fn_span=(80, 120)
        )
        self.assertTrue(cov["line_covered"])
        self.assertTrue(cov["fn_covered"])
        self.assertEqual(cov["syscalls"], ["read"])
        self.assertTrue(
            metadata.is_line_covered_by_syzkaller(
                self.syzk_conn, "fs/read_write.c", 90
            )
        )
        self.assertFalse(
            metadata.is_line_covered_by_syzkaller(
                self.syzk_conn, "fs/read_write.c", 95
            )
        )

    def test_kconfig_and_step_builders(self):
        """Verify Kconfig inversion, metadata lookup, and step builders."""
        self.assertEqual(
            metadata.get_line_configs(self.conn, "fs/x.c", None), []
        )
        # On exact #else line (100), guard is skipped; after #else, inverted
        self.assertEqual(
            metadata.get_line_configs(self.conn, "fs/read_write.c", 100), []
        )
        after_else = metadata.get_line_configs(
            self.conn, "fs/read_write.c", 110
        )
        self.assertEqual(after_else, ["!(CONFIG_A && CONFIG_B)"])
        kmeta = metadata.get_kconfig_metadata(self.conn, after_else)
        self.assertIn("CONFIG_A", kmeta)

        t_info = metadata.build_target_info(
            self.conn,
            self.syzk_conn,
            "fs/read_write.c",
            90,
            is_function_entry=False,
        )
        self.assertEqual(t_info["function"], "vfs_read")
        self.assertFalse(t_info["is_function_entry"])

        caller_row = ("ksys_read", "fs/read_write.c", 40, 90, "direct", "")
        step = metadata.make_caller_step(self.conn, self.syzk_conn, caller_row)
        self.assertTrue(step["syzk_covered"])
        self.assertEqual(step["configs"], ["CONFIG_A && CONFIG_B"])

    def test_cli_helpers(self):
        """Verify shared CLI parser registration and setup helpers."""
        parser = argparse.ArgumentParser()
        metadata.add_common_cli_args(parser, include_reachability_flags=True)
        args = parser.parse_args(
            ["--db", self.db_path, "--function", "vfs_read", "--all-syscalls"]
        )
        is_entry = metadata.handle_common_cli_setup(args, parser)
        self.assertTrue(is_entry)
        self.assertEqual(args.file, "fs/read_write.c")
        self.assertEqual(args.line, 80)

        kwargs = metadata.extract_reachability_cli_kwargs(args, is_entry)
        self.assertTrue(kwargs["all_syscalls"])
        self.assertTrue(kwargs["is_function_entry"])


class TestLibPrivilege(BaseToolsTestCase):
    """Unit tests for tools.lib.privilege."""

    def setUp(self):
        """Populate capability conditions and macro invocations."""
        super().setUp()
        create_async_edges_schema(self.conn.cursor())
        self.insert_rows(
            function_locations=[
                ("gated_fn", "net/core.c", 10, 50),
            ],
            conditions=[
                (
                    "capable",
                    "net/core.c:15:5:15:11",
                    "net/core.c:15:2:20:10",
                    "12",
                    "__guarded_span__:init_user_ns",
                    "net/core.c:15:1:30:1",
                ),
                (
                    "sysctl",
                    "net/core.c:5:1:5:20",
                    "net/core.c:18:2:25:10",
                    "sysctl_net_ opt",
                    "call to helper",
                    "net/core.c:20:5:20:15",
                ),
            ],
            macroinvocation_locations=[
                ("CAP_NET_ADMIN", "net/core.c", 15, 15),
            ],
        )

    def test_capability_formatting_and_dedup(self):
        """Verify format_capability, deduplicate_gates, and add_call_span."""
        self.assertEqual(
            privilege.format_capability(
                "capable", "12", {"12": "CAP_NET_ADMIN"}
            ),
            "capable(CAP_NET_ADMIN)",
        )
        self.assertEqual(
            privilege.format_capability("capable", "99"), "capable(CAP_99)"
        )

        gates = [
            {
                "type": "ns_capable",
                "argument": "12",
                "condition": "net/core.c:15:2:20:10",
                "max_controlled_line": 25,
            },
            {
                "type": "ns_capable",
                "argument": "12",
                "condition": "net/core.c:15:2:20:10",
                "ns_scope": "net_ns",
                "max_controlled_line": 35,
            },
        ]
        deduped = privilege.deduplicate_gates(gates)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["ns_scope"], "net_ns")
        self.assertEqual(deduped[0]["max_controlled_line"], 35)

        span_map = {}
        self.assertIsNone(privilege.add_call_span(span_map, "bad_loc", {}))

    def test_gates_tunables_and_classification(self):
        """Verify condition gates, runtime tunables, and classify_gates."""
        call_gates, func_gates, cap_map = privilege.load_condition_gates(
            self.conn, verbose=False
        )
        self.assertEqual(cap_map.get("12"), "CAP_NET_ADMIN")
        site_gates = privilege.get_call_site_gates(
            call_gates, func_gates, "net/core.c", 22, caller_fn="gated_fn"
        )
        self.assertEqual(len(site_gates), 1)
        self.assertEqual(
            privilege.classify_gates(site_gates, cap_map=cap_map),
            "REACHABLE, BUT ONLY BEHIND capable(CAP_NET_ADMIN)",
        )

        call_tun, func_tun = privilege.load_runtime_tunables(self.conn)
        self.assertIn(("net/core.c", 20), call_tun)
        self.assertIn("gated_fn", func_tun)

        wb_pre = privilege.get_entry_precondition("wb_workfn", "vfs_writeback")
        self.assertEqual(wb_pre["trigger_directness"], "indirect")
        self.assertEqual(wb_pre["baseline_cost"], privilege.COST_INDIRECT_ENTRY)
