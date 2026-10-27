#!/usr/bin/env python3
"""Unit tests for tools/inspect_calls.py."""

import json
import os
import sqlite3
import unittest
from unittest.mock import patch

from tools import inspect_calls
from tools.tests.fixtures import BaseToolsTestCase


class InspectCallsTestBase(BaseToolsTestCase):
    """Base fixture with callgraph and Syzkaller tables for inspect_calls."""

    def setUp(self):
        """Set up temporary CodeQL and Syzkaller databases."""
        super().setUp()
        self.syzk_path = os.path.join(self.tmp_dir, "test_syzkaller.db")
        self.insert_rows(
            function_locations=[
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
            syscall_node=[
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
            locations=[
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
            edges=[
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
            ops_targets=[
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
            conditions=[
                (
                    "capable",
                    "fs/sample.c:42:5:42:11",
                    "fs/sample.c:42:2:46:10",
                    "21",
                    "call to direct_callee",
                    "fs/sample.c:45:2:45:15",
                ),
            ],
            macroinvocation_locations=[
                ("CAP_SYS_ADMIN", "fs/sample.c", 42, 42),
            ],
        )

        # Set up dummy Syzkaller DB
        syzk_conn = sqlite3.connect(self.syzk_path)
        s_cur = syzk_conn.cursor()
        s_cur.execute(
            "CREATE TABLE file_path (file_id INTEGER PRIMARY KEY, file_path"
            " TEXT)"
        )
        s_cur.execute(
            "CREATE TABLE syzk_cov"
            " (file_id INTEGER, code_line_no INTEGER, prog_id INTEGER)"
        )
        s_cur.execute("INSERT INTO file_path VALUES (1, 'fs/sample.c')")
        s_cur.execute("INSERT INTO syzk_cov VALUES (1, 45, 101)")
        syzk_conn.commit()
        syzk_conn.close()


class TestInspectCallsCore(InspectCallsTestBase):
    """Test suite for 1-hop and multi-hop callgraph traversal."""

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
        candidate_names = {cand["target"] for cand in indirect[0]["candidates"]}
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


class TestInspectCallsFormatting(InspectCallsTestBase):
    """Test suite for callgraph summary formatting, coverage, and CLI."""

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

    def test_async_callers_and_callees(self):
        """Verify async_edges callers and callees are discovered."""
        cur = self.conn.cursor()
        cur.execute(
            "CREATE TABLE async_edges ("
            "caller TEXT, callee TEXT, mechanism TEXT, form TEXT,"
            " file TEXT, line INTEGER, context TEXT,"
            " caller_file TEXT, callee_file TEXT)"
        )
        cur.execute(
            "INSERT INTO function_locations VALUES (?, ?, ?, ?)",
            ("wq_handler", "fs/sample.c", 80, 100),
        )
        cur.execute(
            "INSERT INTO async_edges VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "vfs_dispatcher",
                "wq_handler",
                "workqueue",
                "assign",
                "fs/sample.c",
                60,
                "kthread",
                "fs/sample.c",
                "fs/sample.c",
            ),
        )
        self.conn.commit()

        _, callers, _ = inspect_calls.inspect_function_calls(
            self.db_path, function_name="wq_handler", show_callees=False
        )
        async_c = [c for c in callers if c["call_type"] == "async"]
        self.assertEqual(len(async_c), 1)
        self.assertEqual(async_c[0]["caller"], "vfs_dispatcher")
        self.assertEqual(async_c[0]["call_site_line"], 60)
        self.assertEqual(async_c[0]["dispatch"], "workqueue/assign (kthread)")

        t_info, _, callees = inspect_calls.inspect_function_calls(
            self.db_path, function_name="vfs_dispatcher", show_callers=False
        )
        async_callees = [c for c in callees if c["call_type"] == "async"]
        self.assertEqual(len(async_callees), 1)
        self.assertEqual(async_callees[0]["callee"], "wq_handler")
        self.assertEqual(async_callees[0]["call_site_line"], 60)

        summary = inspect_calls.format_summary(t_info, callers, callees)
        self.assertIn("Async Dispatchers (via async_edges):", summary)
        self.assertIn("[async via workqueue/assign (kthread)]", summary)
        flat = inspect_calls.format_list(t_info, callers, callees)
        self.assertIn("CALLEE [async   ]", flat)

    def test_ambiguous_symbol_disambiguation(self):
        """Verify colliding functions require --file unless allow_ambiguous."""
        cur = self.conn.cursor()
        cur.executemany(
            "INSERT INTO function_locations VALUES (?, ?, ?, ?)",
            [
                ("seq_show", "fs/proc/nommu.c", 30, 60),
                ("seq_show", "fs/proc/task_mmu.c", 100, 150),
            ],
        )
        self.conn.commit()

        with self.assertRaises(ValueError) as ctx:
            inspect_calls.inspect_function_calls(
                self.db_path, function_name="seq_show"
            )
        self.assertIn("AMBIGUOUS_SYMBOL", str(ctx.exception))

        t_info, _, _ = inspect_calls.inspect_function_calls(
            self.db_path,
            function_name="seq_show",
            file_path="fs/proc/task_mmu.c",
        )
        self.assertEqual(t_info["file"], "fs/proc/task_mmu.c")

        with self.assertRaises(ValueError):
            inspect_calls.inspect_function_calls(
                self.db_path,
                function_name="seq_show",
                file_path="fs/proc/uncompiled.c",
            )


class TestInspectCallsOpsIntegration(BaseToolsTestCase):
    """Tests for unified ops_targets registrations, siblings, & slot modes."""

    def setUp(self) -> None:
        """Set up sample ops_targets, function_locations, and conditions."""
        super().setUp()
        self.insert_rows(
            function_locations=[
                ("vfs_read", "fs/read_write.c", 450, 490),
                ("msr_open", "arch/x86/kernel/msr.c", 200, 225),
                ("msr_read", "arch/x86/kernel/msr.c", 50, 90),
                ("msr_write", "arch/x86/kernel/msr.c", 95, 135),
            ],
            ops_targets=[
                (
                    "arch/x86/kernel/msr.c:227:1:235:1",
                    "file_operations",
                    "open",
                    "msr_open",
                    "arch/x86/kernel/msr.c",
                    200,
                    225,
                    "fs/open.c",
                    800,
                    790,
                    820,
                ),
                (
                    "arch/x86/kernel/msr.c:227:1:235:1",
                    "file_operations",
                    "read",
                    "msr_read",
                    "arch/x86/kernel/msr.c",
                    50,
                    90,
                    "fs/read_write.c",
                    460,
                    450,
                    490,
                ),
                (
                    "arch/x86/kernel/msr.c:227:1:235:1",
                    "file_operations",
                    "write",
                    "msr_write",
                    "arch/x86/kernel/msr.c",
                    95,
                    135,
                    "fs/read_write.c",
                    580,
                    570,
                    610,
                ),
            ],
            conditions=[
                (
                    "capable",
                    "arch/x86/kernel/msr.c:205:7:205:13",
                    "arch/x86/kernel/msr.c:205:2:206:16",
                    "CAP_SYS_RAWIO",
                    "__guarded_span__:init_user_ns",
                    "arch/x86/kernel/msr.c:205:1:224:1",
                ),
            ],
        )

    def test_unified_indirect_caller_gates_and_ops_siblings(self) -> None:
        """Verify inspect_function_calls attaches .open gates & ops siblings."""
        t_info, callers, callees = inspect_calls.inspect_function_calls(
            self.db_path, function_name="msr_read"
        )
        self.assertEqual(len(callers), 1)
        self.assertEqual(callers[0]["caller"], "vfs_read")
        self.assertTrue(
            any("CAP_SYS_RAWIO" in g["cap_str"] for g in callers[0]["gates"])
        )
        regs = t_info.get("ops_registrations", [])
        self.assertEqual(len(regs), 1)
        sib_fields = {s["field"]: s["target"] for s in regs[0]["siblings"]}
        self.assertEqual(sib_fields["open"], "msr_open")
        self.assertEqual(sib_fields["write"], "msr_write")

        summary = inspect_calls.format_summary(t_info, callers, callees)
        self.assertIn("OPS TABLE REGISTRATIONS & SIBLINGS", summary)
        self.assertIn("Acquisition Gate(s): capable(CAP_SYS_RAWIO)", summary)
        self.assertIn(".open=msr_open", summary)

    def test_forward_slot_inspection_and_cli(self) -> None:
        """Verify --struct/--field forward slot inspection via inspect_calls."""
        res = inspect_calls.inspect_ops_slot(
            self.db_path, "file_operations", field_name="read"
        )
        self.assertEqual(res["slot_count"], 1)
        slot = res["slots"][0]
        self.assertEqual(slot["callbacks"][0]["target"], "msr_read")
        self.assertIn(
            "CAP_SYS_RAWIO",
            slot["callbacks"][0]["acquisition_gates"][0]["cap_str"],
        )

        with patch(
            "sys.argv",
            [
                "inspect_calls.py",
                "--db",
                self.db_path,
                "--struct",
                "file_operations",
                "--field",
                "read",
            ],
        ):
            inspect_calls.main()


if __name__ == "__main__":
    unittest.main()
