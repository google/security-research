#!/usr/bin/env python3
"""
Unit tests for Tools/check_privilege.py: Gating-Aware Privilege Reachability Analysis.
"""

import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import check_privilege


class TestCheckPrivilege(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_codeql.db")
        self.conn = sqlite3.connect(self.db_path)
        cur = self.conn.cursor()

        # Create CodeQL schema
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

        # Functions:
        # 1. Unprivileged path:
        #    __do_sys_unpriv (fs/unpriv.c:10-30) -> unpriv_worker (fs/unpriv.c:40-60)
        # 2. Privileged path (CAP_SYS_ADMIN / 21):
        #    __do_sys_admin (kernel/admin.c:10-30) -> admin_worker (kernel/admin.c:40-60)
        # 3. User namespace path (CAP_NET_ADMIN / 12 via ns_capable):
        #    __do_sys_net (net/net.c:10-30) -> net_worker (net/net.c:40-60)
        # 4. Semi-gated function with internal capability check at line 30:
        #    semi_gated_worker (fs/semi.c:10-50)
        # 5. Dual path worker reachable via both admin and unprivileged routes:
        #    dual_path_worker (fs/dual.c:10-50)
        # 6. Unreachable internal function:
        #    unreachable_internal (kernel/sched.c:100-120)
        cur.executemany("""
            INSERT INTO function_locations VALUES (?, ?, ?, ?)
        """, [
            ("__do_sys_unpriv", "fs/unpriv.c", 10, 30),
            ("unpriv_worker", "fs/unpriv.c", 40, 60),
            ("__do_sys_admin", "kernel/admin.c", 10, 30),
            ("admin_worker", "kernel/admin.c", 40, 60),
            ("__do_sys_net", "net/net.c", 10, 30),
            ("net_worker", "net/net.c", 40, 60),
            ("semi_gated_worker", "fs/semi.c", 10, 50),
            ("dual_path_worker", "fs/dual.c", 10, 50),
            ("unreachable_internal", "kernel/sched.c", 100, 120),
        ])

        # Syscall reachability
        cur.executemany("""
            INSERT INTO syscall_node VALUES (?, ?, ?, ?)
        """, [
            ("__do_sys_unpriv", "unpriv_worker", "fs/unpriv.c:10", "fs/unpriv.c:40"),
            ("__do_sys_admin", "admin_worker", "kernel/admin.c:10", "kernel/admin.c:40"),
            ("__do_sys_net", "net_worker", "net/net.c:10", "net/net.c:40"),
            ("__do_sys_unpriv", "semi_gated_worker", "fs/unpriv.c:10", "fs/semi.c:10"),
            ("__do_sys_admin", "dual_path_worker", "kernel/admin.c:10", "fs/dual.c:10"),
            ("__do_sys_unpriv", "dual_path_worker", "fs/unpriv.c:10", "fs/dual.c:10"),
        ])

        # Locations and Edges:
        # unpriv: 1 -> 2
        # admin: 3 -> 4
        # net: 5 -> 6
        # semi: 1 -> 10
        # dual via admin: 3 -> 12
        # dual via unpriv: 1 -> 13
        cur.executemany("""
            INSERT INTO locations (id, message, uri, startLine) VALUES (?, ?, ?, ?)
        """, [
            (1, "__do_sys_unpriv", "fs/unpriv.c", 10),
            (2, "call to unpriv_worker", "fs/unpriv.c", 20),
            (3, "__do_sys_admin", "kernel/admin.c", 10),
            (4, "call to admin_worker", "kernel/admin.c", 20),
            (5, "__do_sys_net", "net/net.c", 10),
            (6, "call to net_worker", "net/net.c", 20),
            (7, "unpriv_worker", "fs/unpriv.c", 40),
            (8, "admin_worker", "kernel/admin.c", 40),
            (9, "net_worker", "net/net.c", 40),
            (10, "call to semi_gated_worker", "fs/unpriv.c", 22),
            (11, "semi_gated_worker", "fs/semi.c", 10),
            (12, "call to dual_path_worker", "kernel/admin.c", 25),
            (13, "call to dual_path_worker", "fs/unpriv.c", 24),
            (14, "dual_path_worker", "fs/dual.c", 10),
        ])

        cur.executemany("""
            INSERT INTO edges (source_location_id, target_location_id, rule_id) VALUES (?, ?, ?)
        """, [
            (1, 2, "callgraph-all"),
            (3, 4, "callgraph-all"),
            (5, 6, "callgraph-all"),
            (1, 10, "callgraph-all"),
            (3, 12, "callgraph-all"),
            (1, 13, "callgraph-all"),
        ])

        # Capability Conditions:
        # 1. admin path has capable(21) at line 15 dominating call to admin_worker at line 20
        # 2. admin path has capable(21) at line 15 dominating call to dual_path_worker at line 25
        # 3. net path has ns_capable(12) at line 15 dominating call to net_worker at line 20
        # 4. semi_gated_worker has internal capable(21) check at line 30
        cur.executemany("""
            INSERT INTO conditions VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (
                "capable",
                "kernel/admin.c:15:7:15:13",
                "kernel/admin.c:15:2:16:16",
                "21",
                "call to admin_worker",
                "kernel/admin.c:20:5:20:17",
            ),
            (
                "capable",
                "kernel/admin.c:15:7:15:13",
                "kernel/admin.c:15:2:16:16",
                "21",
                "call to dual_path_worker",
                "kernel/admin.c:25:5:25:17",
            ),
            (
                "ns_capable",
                "kernel/capability.c:450:9:450:18",
                "kernel/admin.c:15:2:16:16",
                "cap",
                "call to admin_worker",
                "kernel/admin.c:20:5:20:17",
            ),
            (
                "ns_capable",
                "net/net.c:15:7:15:16",
                "net/net.c:15:2:16:16",
                "12",
                "call to net_worker",
                "net/net.c:20:5:20:15",
            ),
            (
                "capable",
                "fs/semi.c:30:5:30:11",
                "fs/semi.c:30:2:32:10",
                "21",
                "call to notify_semi",
                "fs/semi.c:35:2:35:10",
            ),
        ])

        # Macro invocations in DB for dynamic capability mapping
        cur.executemany("""
            INSERT INTO macroinvocation_locations VALUES (?, ?, ?, ?)
        """, [
            ("CAP_SYS_ADMIN", "kernel/admin.c", 15, 15),
            ("CAP_NET_ADMIN", "net/net.c", 15, 15),
            ("CAP_SYS_ADMIN", "fs/semi.c", 30, 30),
        ])

        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmp_dir.cleanup()

    def test_load_capability_map(self):
        cap_map = check_privilege.load_capability_map(self.conn)
        self.assertEqual(cap_map.get("21"), "CAP_SYS_ADMIN")
        self.assertEqual(cap_map.get("12"), "CAP_NET_ADMIN")

    def test_format_capability(self):
        cap_map = check_privilege.load_capability_map(self.conn)
        self.assertEqual(
            check_privilege.format_capability("capable", "21", cap_map=cap_map),
            "capable(CAP_SYS_ADMIN)",
        )
        self.assertEqual(
            check_privilege.format_capability("ns_capable", "12", cap_map=cap_map),
            "ns_capable(CAP_NET_ADMIN)",
        )
        self.assertEqual(
            check_privilege.format_capability("ns_capable", "cap", cap_map=cap_map),
            "ns_capable(cap)",
        )

    def test_deduplicate_gates(self):
        gates = [
            {"type": "ns_capable", "argument": "cap", "condition": "c1"},
            {"type": "capable", "argument": "21", "condition": "c1"},
        ]
        deduped = check_privilege.deduplicate_gates(gates)
        # Should retain only the concrete capable(21)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["type"], "capable")
        self.assertEqual(deduped[0]["argument"], "21")

    def test_load_condition_gates(self):
        call_gates, func_gates, cap_map = check_privilege.load_condition_gates(self.conn)
        self.assertIn(("kernel/admin.c", 20), call_gates)
        self.assertIn(("net/net.c", 20), call_gates)
        self.assertNotIn(("fs/unpriv.c", 20), call_gates)
        self.assertEqual(cap_map.get("21"), "CAP_SYS_ADMIN")

    def test_ungated_verdict(self):
        target_info, verdict, primary, _ = check_privilege.analyze_target_privilege(
            self.db_path, "fs/unpriv.c", 50
        )
        self.assertEqual(target_info["function"], "unpriv_worker")
        self.assertEqual(verdict, "REACHABLE WITH NO PRIVILEGE (UNGATED)")
        self.assertEqual(len(primary["gates"]), 0)
        self.assertEqual(primary["syscall"], "__do_sys_unpriv")

    def test_root_gated_verdict(self):
        target_info, verdict, primary, _ = check_privilege.analyze_target_privilege(
            self.db_path, "kernel/admin.c", 50
        )
        self.assertEqual(target_info["function"], "admin_worker")
        self.assertEqual(verdict, "REACHABLE, BUT ONLY BEHIND CAP_SYS_ADMIN")
        self.assertEqual(len(primary["gates"]), 1)
        self.assertEqual(primary["gates"][0]["cap_str"], "capable(CAP_SYS_ADMIN)")

    def test_userns_gated_verdict(self):
        target_info, verdict, primary, _ = check_privilege.analyze_target_privilege(
            self.db_path, "net/net.c", 50
        )
        self.assertEqual(target_info["function"], "net_worker")
        self.assertEqual(verdict, "REACHABLE BEHIND USER NAMESPACE CAPABILITY")
        self.assertEqual(len(primary["gates"]), 1)
        self.assertEqual(primary["gates"][0]["cap_str"], "ns_capable(CAP_NET_ADMIN)")

    def test_unreachable_verdict(self):
        target_info, verdict, _, _ = check_privilege.analyze_target_privilege(
            self.db_path, "kernel/sched.c", 110
        )
        self.assertEqual(target_info["function"], "unreachable_internal")
        self.assertEqual(verdict, "UNREACHABLE")

    def test_format_summary(self):
        target_info, verdict, primary, all_res = check_privilege.analyze_target_privilege(
            self.db_path, "fs/unpriv.c", 50
        )
        summary = check_privilege.format_summary(target_info, verdict, primary, all_res)
        self.assertIn("VERDICT: REACHABLE WITH NO PRIVILEGE (UNGATED)", summary)
        self.assertIn("Privilege Level: Unprivileged (No capabilities required)", summary)
        self.assertIn("Gating Status:   Ungated route available from userspace", summary)
        self.assertIn("Access Scope:    Reachable via standard userspace system calls", summary)
        self.assertIn("__do_sys_unpriv", summary)

    def test_format_tree_and_paths(self):
        target_info, verdict, primary, all_res = check_privilege.analyze_target_privilege(
            self.db_path, "kernel/admin.c", 50
        )
        tree = check_privilege.format_tree(target_info, primary, all_res)
        self.assertIn("[Syscall: __do_sys_admin -> REACHABLE, BUT ONLY BEHIND CAP_SYS_ADMIN]", tree)
        self.assertIn("[GATED: capable(CAP_SYS_ADMIN)]", tree)

        paths_str = check_privilege.format_paths(primary, all_res)
        self.assertIn("[REACHABLE, BUT ONLY BEHIND CAP_SYS_ADMIN]", paths_str)
        self.assertIn(
            "__do_sys_admin(kernel/admin.c:20)[capable(CAP_SYS_ADMIN)] -> admin_worker",
            paths_str,
        )

    def test_cli_execution(self):
        with patch("sys.argv", [
            "check_privilege.py",
            "--db", self.db_path,
            "--file", "fs/unpriv.c",
            "--line", "50",
            "--format", "summary"
        ]):
            try:
                check_privilege.main()
            except SystemExit as e:
                self.assertEqual(e.code, 0)

    def test_cli_function_flag(self):
        with patch("sys.argv", [
            "check_privilege.py",
            "--db", self.db_path,
            "--function", "admin_worker",
            "--format", "json"
        ]):
            try:
                check_privilege.main()
            except SystemExit as e:
                self.assertEqual(e.code, 0)

    def test_cli_missing_db(self):
        with patch("sys.argv", [
            "check_privilege.py",
            "--file", "fs/unpriv.c",
            "--line", "50"
        ]):
            with self.assertRaises(SystemExit):
                check_privilege.main()

    def test_semi_gated_function_entry(self):
        target_info, verdict, primary, _ = check_privilege.analyze_target_privilege(
            self.db_path, "fs/semi.c", 10, is_function_entry=True
        )
        self.assertEqual(target_info["function"], "semi_gated_worker")
        self.assertEqual(verdict, "REACHABLE WITH NO PRIVILEGE (UNGATED)")
        self.assertEqual(len(primary["gates"]), 0)
        self.assertEqual(len(target_info["internal_gates"]), 1)
        self.assertEqual(
            target_info["internal_gates"][0]["cap_str"], "capable(CAP_SYS_ADMIN)"
        )
        self.assertEqual(target_info["internal_gates"][0]["check_line"], 30)

        # Verify summary output notes the internal gate
        summary = check_privilege.format_summary(target_info, verdict, primary, [primary])
        self.assertIn("Internal Function Capability Gates:", summary)
        self.assertIn("capable(CAP_SYS_ADMIN)", summary)
        self.assertIn("Note: Function entry at line 10 is ungated", summary)

    def test_semi_gated_interior_line(self):
        target_info, verdict, primary, _ = check_privilege.analyze_target_privilege(
            self.db_path, "fs/semi.c", 35, is_function_entry=False
        )
        self.assertEqual(target_info["function"], "semi_gated_worker")
        self.assertEqual(verdict, "REACHABLE, BUT ONLY BEHIND CAP_SYS_ADMIN")
        self.assertEqual(len(primary["gates"]), 1)
        self.assertEqual(
            primary["gates"][0]["cap_str"], "capable(CAP_SYS_ADMIN)"
        )

    def test_dual_path_prefers_ungated_route(self):
        target_info, verdict, primary, _ = check_privilege.analyze_target_privilege(
            self.db_path, "fs/dual.c", 10
        )
        self.assertEqual(target_info["function"], "dual_path_worker")
        # Dijkstra search must choose the unprivileged route over the admin route
        self.assertEqual(verdict, "REACHABLE WITH NO PRIVILEGE (UNGATED)")
        self.assertEqual(primary["syscall"], "__do_sys_unpriv")
        self.assertEqual(len(primary["gates"]), 0)

    def test_syscall_root_directly(self):
        target_info, verdict, primary, _ = check_privilege.analyze_target_privilege(
            self.db_path, "fs/unpriv.c", 10
        )
        self.assertEqual(target_info["function"], "__do_sys_unpriv")
        self.assertEqual(verdict, "REACHABLE WITH NO PRIVILEGE (UNGATED)")
        self.assertEqual(len(primary["path"]), 1)
        self.assertEqual(primary["path"][0]["call_type"], "target")

    def test_all_syscalls_evaluation(self):
        target_info, verdict, primary, all_results = check_privilege.analyze_target_privilege(
            self.db_path, "fs/dual.c", 10, all_syscalls=True
        )
        self.assertEqual(verdict, "REACHABLE WITH NO PRIVILEGE (UNGATED)")
        self.assertEqual(len(all_results), 2)
        syscall_names = {r["syscall"] for r in all_results}
        self.assertIn("__do_sys_unpriv", syscall_names)
        self.assertIn("__do_sys_admin", syscall_names)

    def test_json_format_serialization(self):
        target_info, verdict, primary, all_results = check_privilege.analyze_target_privilege(
            self.db_path, "fs/semi.c", 10, is_function_entry=True
        )
        import json
        payload = {
            "target": target_info,
            "overall_verdict": verdict,
            "primary_result": primary,
            "all_results": all_results,
        }
        json_str = json.dumps(payload, indent=2)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["overall_verdict"], "REACHABLE WITH NO PRIVILEGE (UNGATED)")
        self.assertIn("internal_gates", parsed["target"])
        self.assertEqual(len(parsed["target"]["internal_gates"]), 1)


if __name__ == "__main__":
    unittest.main()
