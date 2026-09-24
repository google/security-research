#!/usr/bin/env python3
# pylint: disable=duplicate-code
"""Unit tests for tools/inspect_calls.py."""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

try:
    from tools import inspect_calls
except ImportError:
    parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    import inspect_calls  # pylint: disable=import-error


class TestInspectCalls(
    unittest.TestCase
):  # pylint: disable=too-many-public-methods
    """Test suite for 1-hop and multi-hop callgraph inspection."""

    def setUp(self):
        """Set up temporary CodeQL and Syzkaller databases."""
        self.tmp_dir = (
            tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        )
        self.db_path = os.path.join(self.tmp_dir.name, "test_codeql.db")
        self.syzk_path = os.path.join(self.tmp_dir.name, "test_syzkaller.db")

        # Set up CodeQL DB
        self.conn = sqlite3.connect(self.db_path)
        cur = self.conn.cursor()

        # Create schema
        cur.execute("""
            CREATE TABLE function_locations (
                function_name TEXT,
                file_path TEXT,
                start_line INTEGER,
                end_line INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE syscall_node (
                syscall TEXT,
                function TEXT,
                syscall_location TEXT,
                function_location TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE locations (
                id INTEGER PRIMARY KEY,
                threadFlow_id INTEGER,
                message TEXT,
                uri TEXT,
                startLine INTEGER,
                startColumn INTEGER,
                endLine INTEGER,
                endColumn INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE edges (
                id INTEGER PRIMARY KEY,
                source_location_id INTEGER,
                target_location_id INTEGER,
                rule_id TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE ops_targets (
                definition TEXT,
                parent TEXT,
                field TEXT,
                target TEXT,
                target_file TEXT,
                target_start INTEGER,
                target_end INTEGER,
                exprcall_file TEXT,
                exprcall_line INTEGER,
                exprcall_parent_start INTEGER,
                exprcall_parent_end INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE conditions (
                type TEXT,
                definition TEXT,
                condition TEXT,
                argument TEXT,
                call TEXT,
                call_location TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE macroinvocation_locations (
                macroinvocation_name TEXT,
                file_path TEXT,
                start_line INTEGER,
                end_line INTEGER
            )
        """)

        # Insert function spans
        cur.executemany(
            """
            INSERT INTO function_locations VALUES (?, ?, ?, ?)
        """,
            [
                ("__do_sys_sample", "fs/sample.c", 10, 30),
                ("vfs_dispatcher", "fs/sample.c", 40, 70),
                ("direct_callee", "fs/helper.c", 10, 30),
                ("shmem_reader", "mm/shmem.c", 100, 140),
                ("ext4_reader", "fs/ext4/file.c", 200, 240),
                ("shmem_internal", "mm/shmem.c", 20, 50),
                ("leaf_helper", "fs/leaf.c", 10, 20),
                ("isolated_root", "kernel/root.c", 10, 30),
                ("cycle_a", "fs/cycle.c", 10, 30),
                ("cycle_b", "fs/cycle.c", 40, 60),
                ("multi_dispatcher", "fs/multi.c", 10, 40),
                ("poll_cand1", "fs/poll1.c", 10, 30),
                ("poll_cand2", "fs/poll2.c", 10, 30),
                ("poll_cand3", "fs/poll3.c", 10, 30),
                ("poll_cand4", "fs/poll4.c", 10, 30),
                ("poll_cand5", "fs/poll5.c", 10, 30),
            ],
        )

        # Syscall reachability
        cur.executemany(
            """
            INSERT INTO syscall_node VALUES (?, ?, ?, ?)
        """,
            [
                (
                    "__do_sys_sample",
                    "vfs_dispatcher",
                    "fs/sample.c:10",
                    "fs/sample.c:40",
                ),
                (
                    "__do_sys_sample",
                    "direct_callee",
                    "fs/sample.c:10",
                    "fs/helper.c:10",
                ),
                (
                    "__do_sys_sample",
                    "shmem_reader",
                    "fs/sample.c:10",
                    "mm/shmem.c:100",
                ),
            ],
        )

        # Locations
        cur.executemany(
            """
            INSERT INTO locations (id, message, uri, startLine)
            VALUES (?, ?, ?, ?)
        """,
            [
                (1, "__do_sys_sample", "fs/sample.c", 10),
                (2, "call to vfs_dispatcher", "fs/sample.c", 20),
                (3, "vfs_dispatcher", "fs/sample.c", 40),
                (4, "call to direct_callee", "fs/sample.c", 45),
                (5, "direct_callee", "fs/helper.c", 10),
                (6, "shmem_reader", "mm/shmem.c", 100),
                (7, "call to shmem_internal", "mm/shmem.c", 120),
                (8, "shmem_internal", "mm/shmem.c", 20),
                (9, "call to leaf_helper", "fs/helper.c", 25),
                (10, "leaf_helper", "fs/leaf.c", 10),
                (11, "cycle_a", "fs/cycle.c", 10),
                (12, "call to cycle_b", "fs/cycle.c", 20),
                (13, "cycle_b", "fs/cycle.c", 40),
                (14, "call to cycle_a", "fs/cycle.c", 50),
            ],
        )

        # Direct Edges
        cur.executemany(
            """
            INSERT INTO edges (source_location_id, target_location_id, rule_id)
            VALUES (?, ?, ?)
        """,
            [
                (1, 2, "callgraph-all"),
                (2, 3, "callgraph-all"),
                (3, 4, "callgraph-all"),
                (4, 5, "callgraph-all"),
                (5, 9, "callgraph-all"),
                (9, 10, "callgraph-all"),
                (6, 7, "callgraph-all"),
                (7, 8, "callgraph-all"),
                (11, 12, "callgraph-all"),
                (12, 13, "callgraph-all"),
                (13, 14, "callgraph-all"),
                (14, 11, "callgraph-all"),
            ],
        )

        # Indirect dispatches in ops_targets
        cur.executemany(
            """
            INSERT INTO ops_targets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            [
                (
                    "d1",
                    "file_operations",
                    "read_iter",
                    "shmem_reader",
                    "mm/shmem.c",
                    100,
                    140,
                    "fs/sample.c",
                    55,
                    40,
                    70,
                ),
                (
                    "d2",
                    "file_operations",
                    "read_iter",
                    "ext4_reader",
                    "fs/ext4/file.c",
                    200,
                    240,
                    "fs/sample.c",
                    55,
                    40,
                    70,
                ),
                (
                    "p1",
                    "file_operations",
                    "poll",
                    "poll_cand1",
                    "fs/poll1.c",
                    10,
                    30,
                    "fs/multi.c",
                    25,
                    10,
                    40,
                ),
                (
                    "p2",
                    "file_operations",
                    "poll",
                    "poll_cand2",
                    "fs/poll2.c",
                    10,
                    30,
                    "fs/multi.c",
                    25,
                    10,
                    40,
                ),
                (
                    "p3",
                    "file_operations",
                    "poll",
                    "poll_cand3",
                    "fs/poll3.c",
                    10,
                    30,
                    "fs/multi.c",
                    25,
                    10,
                    40,
                ),
                (
                    "p4",
                    "file_operations",
                    "poll",
                    "poll_cand4",
                    "fs/poll4.c",
                    10,
                    30,
                    "fs/multi.c",
                    25,
                    10,
                    40,
                ),
                (
                    "p5",
                    "file_operations",
                    "poll",
                    "poll_cand5",
                    "fs/poll5.c",
                    10,
                    30,
                    "fs/multi.c",
                    25,
                    10,
                    40,
                ),
            ],
        )

        # Conditions: call to direct_callee at line 45 gated by capable(21)
        cur.executemany(
            """
            INSERT INTO conditions VALUES (?, ?, ?, ?, ?, ?)
        """,
            [
                (
                    "capable",
                    "fs/sample.c:42:5:42:11",
                    "fs/sample.c:42:2:46:10",
                    "21",
                    "call to direct_callee",
                    "fs/sample.c:45:2:45:15",
                ),
            ],
        )

        cur.executemany(
            """
            INSERT INTO macroinvocation_locations VALUES (?, ?, ?, ?)
        """,
            [
                ("CAP_SYS_ADMIN", "fs/sample.c", 42, 42),
            ],
        )

        self.conn.commit()

        # Set up dummy Syzkaller DB
        syzk_conn = sqlite3.connect(self.syzk_path)
        s_cur = syzk_conn.cursor()
        s_cur.execute(
            "CREATE TABLE file_path"
            " (file_id INTEGER PRIMARY KEY, file_path TEXT)"
        )
        s_cur.execute(
            "CREATE TABLE syzk_cov"
            " (file_id INTEGER, code_line_no INTEGER, prog_id INTEGER)"
        )
        s_cur.execute("INSERT INTO file_path VALUES (1, 'fs/sample.c')")
        s_cur.execute("INSERT INTO syzk_cov VALUES (1, 45, 101)")
        syzk_conn.commit()
        syzk_conn.close()

    def tearDown(self):
        """Close database connection and clean up temporary directory."""
        self.conn.close()
        self.tmp_dir.cleanup()

    def test_get_function_by_name(self):
        """Verify function metadata lookup by function name."""
        fn_info = inspect_calls.get_function_by_name(
            self.conn, "vfs_dispatcher"
        )
        self.assertIsNotNone(fn_info)
        name, file_path, start_l, end_l = fn_info
        self.assertEqual(name, "vfs_dispatcher")
        self.assertEqual(file_path, "fs/sample.c")
        self.assertEqual(start_l, 40)
        self.assertEqual(end_l, 70)

    def test_direct_callers(self):
        """Verify direct caller extraction from edges and locations."""
        callers = inspect_calls.get_callers_for_function(
            self.conn, "vfs_dispatcher"
        )
        direct = [c for c in callers if c["call_type"] == "direct"]
        self.assertEqual(len(direct), 1)
        self.assertEqual(direct[0]["caller"], "__do_sys_sample")
        self.assertEqual(direct[0]["file"], "fs/sample.c")
        self.assertEqual(direct[0]["call_site_line"], 20)
        self.assertTrue(direct[0]["is_syscall"])

    def test_indirect_callers(self):
        """Verify indirect caller extraction via ops_targets table."""
        callers = inspect_calls.get_callers_for_function(
            self.conn, "shmem_reader"
        )
        indirect = [c for c in callers if c["call_type"] == "indirect"]
        self.assertEqual(len(indirect), 1)
        self.assertEqual(indirect[0]["caller"], "vfs_dispatcher")
        self.assertEqual(indirect[0]["file"], "fs/sample.c")
        self.assertEqual(indirect[0]["call_site_line"], 55)
        self.assertEqual(indirect[0]["dispatch"], "file_operations->read_iter")

    def test_direct_callees(self):
        """Verify direct function call sites inside a function span."""
        callees = inspect_calls.get_callees_for_function(
            self.conn, "vfs_dispatcher", "fs/sample.c", 40, 70
        )
        direct = [c for c in callees if c["call_type"] == "direct"]
        self.assertEqual(len(direct), 1)
        self.assertEqual(direct[0]["callee"], "direct_callee")
        self.assertEqual(direct[0]["call_site_line"], 45)
        self.assertEqual(direct[0]["file"], "fs/helper.c")

    def test_indirect_callees(self):
        """Verify indirect dispatch sites and candidate targets in function."""
        callees = inspect_calls.get_callees_for_function(
            self.conn, "vfs_dispatcher", "fs/sample.c", 40, 70
        )
        indirect = [c for c in callees if c["call_type"] == "indirect"]
        self.assertEqual(len(indirect), 1)
        self.assertEqual(indirect[0]["call_site_line"], 55)
        self.assertEqual(indirect[0]["dispatch"], "file_operations->read_iter")
        candidate_names = {
            cand["target"] for cand in indirect[0]["candidates"]
        }
        self.assertIn("shmem_reader", candidate_names)
        self.assertIn("ext4_reader", candidate_names)

    def test_depth_2_callers(self):
        """Verify multi-hop caller tree traversal."""
        target_info, callers, _ = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="shmem_reader",
            depth=2,
            show_callees=False,
        )
        self.assertEqual(target_info["function"], "shmem_reader")
        self.assertEqual(len(callers), 1)
        hop1 = callers[0]
        self.assertEqual(hop1["caller"], "vfs_dispatcher")
        self.assertEqual(len(hop1["callers"]), 1)
        hop2 = hop1["callers"][0]
        self.assertEqual(hop2["caller"], "__do_sys_sample")
        self.assertTrue(hop2["is_syscall"])

    def test_depth_2_callees(self):
        """Verify multi-hop callee tree traversal."""
        target_info, _, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="shmem_reader",
            depth=2,
            show_callers=False,
        )
        self.assertEqual(target_info["function"], "shmem_reader")
        self.assertEqual(len(callees), 1)
        callee_step = callees[0]
        self.assertEqual(callee_step["callee"], "shmem_internal")
        self.assertEqual(callee_step["call_site_line"], 120)

    def test_leaf_function_no_callees(self):
        """Verify inspection of a leaf function with no outgoing calls."""
        target_info, _, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="leaf_helper",
            show_callers=False,
            show_callees=True,
        )
        self.assertEqual(target_info["function"], "leaf_helper")
        self.assertEqual(len(callees), 0)
        summary = inspect_calls.format_summary(
            target_info, [], callees, show_callers=False, show_callees=True
        )
        self.assertIn(
            "(No outgoing function calls found within function body)", summary
        )

    def test_isolated_root_no_callers(self):
        """Verify inspection of an isolated root function with no callers."""
        target_info, callers, _ = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="isolated_root",
            show_callers=True,
            show_callees=False,
        )
        self.assertEqual(target_info["function"], "isolated_root")
        self.assertEqual(len(callers), 0)
        summary = inspect_calls.format_summary(
            target_info, callers, [], show_callers=True, show_callees=False
        )
        self.assertIn(
            "(No callers found in database - possible top-level entry,"
            " syscall root, or dead code)",
            summary,
        )

    def test_recursive_cycle_prevention(self):
        """Verify cycle detection prevents infinite recursion."""
        target_info, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path, function_name="cycle_a", depth=3
        )
        self.assertEqual(target_info["function"], "cycle_a")
        self.assertTrue(len(callers) > 0)
        self.assertTrue(len(callees) > 0)

    def test_candidate_limit_truncation(self):
        """Verify truncation of indirect dispatch candidates at limit."""
        target_info, _, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="multi_dispatcher",
            show_callers=False,
            show_callees=True,
        )
        self.assertEqual(len(callees), 1)
        summary_limited = inspect_calls.format_summary(
            target_info,
            [],
            callees,
            show_callers=False,
            show_callees=True,
            candidate_limit=2,
        )
        self.assertIn(
            "... and 3 more candidate(s) (use --all to show all)",
            summary_limited,
        )

    def test_candidate_show_all(self):
        """Verify --all displays all indirect dispatch candidates."""
        target_info, _, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="multi_dispatcher",
            show_callers=False,
            show_callees=True,
        )
        summary_all = inspect_calls.format_summary(
            target_info,
            [],
            callees,
            show_callers=False,
            show_callees=True,
            candidate_limit=2,
            show_all=True,
        )
        self.assertNotIn("more candidate(s)", summary_all)
        self.assertIn("poll_cand1", summary_all)
        self.assertIn("poll_cand5", summary_all)

    def test_syzkaller_coverage_integration(self):
        """Verify Syzkaller coverage tags on call sites."""
        target_info, _, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="vfs_dispatcher",
            syzkaller_db=self.syzk_path,
        )
        direct = [c for c in callees if c["call_type"] == "direct"]
        self.assertTrue(direct[0]["syzk_covered"])
        summary = inspect_calls.format_summary(
            target_info, [], callees, show_callers=False, show_callees=True
        )
        self.assertIn("[COVERED]", summary)

    def test_inspect_by_file_and_line(self):
        """Verify resolving target function from file path and line number."""
        target_info, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path, file_path="fs/sample.c", line_number=50
        )
        self.assertEqual(target_info["function"], "vfs_dispatcher")
        self.assertEqual(target_info["query_line"], 50)
        self.assertTrue(len(callers) > 0)
        self.assertTrue(len(callees) > 0)

    def test_direction_modes(self):
        """Verify callers-only, callees-only, and both direction modes."""
        _, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="vfs_dispatcher",
            show_callers=True,
            show_callees=False,
        )
        self.assertTrue(len(callers) > 0)
        self.assertEqual(len(callees), 0)

        _, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="vfs_dispatcher",
            show_callers=False,
            show_callees=True,
        )
        self.assertEqual(len(callers), 0)
        self.assertTrue(len(callees) > 0)

        _, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="vfs_dispatcher",
            show_callers=True,
            show_callees=True,
        )
        self.assertTrue(len(callers) > 0)
        self.assertTrue(len(callees) > 0)

    def test_capability_gating_annotation(self):
        """Verify capability gate annotations on outgoing calls."""
        _, _, callees = inspect_calls.inspect_function_calls(
            self.db_path, function_name="vfs_dispatcher"
        )
        direct = [c for c in callees if c["call_type"] == "direct"]
        self.assertEqual(len(direct), 1)
        self.assertTrue(len(direct[0]["gates"]) > 0)
        self.assertEqual(
            direct[0]["gates"][0]["cap_str"], "capable(CAP_SYS_ADMIN)"
        )

    def test_format_summary(self):
        """Verify summary formatting of callers and callees."""
        target_info, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path, function_name="vfs_dispatcher"
        )
        summary = inspect_calls.format_summary(target_info, callers, callees)
        self.assertIn("FUNCTION CALL INSPECTION: 'vfs_dispatcher'", summary)
        self.assertIn("INCOMING CALLERS", summary)
        self.assertIn("OUTGOING CALLEES", summary)
        self.assertIn("__do_sys_sample", summary)
        self.assertIn("direct_callee", summary)
        self.assertIn("file_operations->read_iter", summary)
        self.assertIn("shmem_reader", summary)

    def test_format_list(self):
        """Verify flat list formatting of callers and callees."""
        target_info, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path, function_name="vfs_dispatcher"
        )
        flat_list = inspect_calls.format_list(target_info, callers, callees)
        self.assertIn("CALLER [direct  ] __do_sys_sample", flat_list)
        self.assertIn(
            "CALLEE [direct  ] vfs_dispatcher (line 45) -> direct_callee",
            flat_list,
        )
        self.assertIn(
            "CALLEE [indirect] vfs_dispatcher (line 55) ->"
            " file_operations->read_iter -> shmem_reader",
            flat_list,
        )

    def test_format_list_with_depth(self):
        """Verify multi-hop hop tags in flat list formatting."""
        target_info, callers, _ = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="shmem_reader",
            depth=2,
            show_callees=False,
        )
        flat_list = inspect_calls.format_list(
            target_info, callers, [], show_callees=False, max_depth=2
        )
        self.assertIn("CALLER [hop 1] [indirect] vfs_dispatcher", flat_list)
        self.assertIn(
            "via file_operations->read_iter -> shmem_reader", flat_list
        )
        self.assertIn("CALLER [hop 2] [direct  ] __do_sys_sample", flat_list)
        self.assertIn("-> vfs_dispatcher", flat_list)

    def test_format_json(self):
        """Verify JSON serialization of inspect_function_calls output."""
        target_info, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path, function_name="vfs_dispatcher"
        )
        payload = {
            "target": target_info,
            "callers": callers,
            "callees": callees,
        }
        json_str = json.dumps(payload, indent=2)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["target"]["function"], "vfs_dispatcher")
        self.assertEqual(len(parsed["callers"]), 1)
        self.assertEqual(len(parsed["callees"]), 2)

    def test_cli_execution_function(self):
        """Verify CLI execution with --function and --format summary."""
        with patch(
            "sys.argv",
            [
                "inspect_calls.py",
                "--db",
                self.db_path,
                "--function",
                "vfs_dispatcher",
                "--format",
                "summary",
            ],
        ):
            try:
                inspect_calls.main()
            except SystemExit as e:
                self.assertEqual(e.code, 0)

    def test_cli_execution_file_line(self):
        """Verify CLI execution with --file, --line, and --format json."""
        with patch(
            "sys.argv",
            [
                "inspect_calls.py",
                "--db",
                self.db_path,
                "--file",
                "fs/sample.c",
                "--line",
                "50",
                "--format",
                "json",
            ],
        ):
            try:
                inspect_calls.main()
            except SystemExit as e:
                self.assertEqual(e.code, 0)

    def test_cli_missing_db(self):
        """Verify CLI exits when required --db argument is missing."""
        with patch(
            "sys.argv", ["inspect_calls.py", "--function", "vfs_dispatcher"]
        ):
            with self.assertRaises(SystemExit):
                inspect_calls.main()

    def test_unknown_function_error(self):
        """Verify ValueError is raised when target function is not found."""
        with self.assertRaises(ValueError):
            inspect_calls.inspect_function_calls(
                self.db_path, function_name="nonexistent_fn"
            )


if __name__ == "__main__":
    unittest.main()
