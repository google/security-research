#!/usr/bin/env python3

import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import find_paths


class TestFindPaths(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_codeql.db")
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

        # Insert test data
        # Functions:
        # __do_sys_foo: fs/read.c (10-30)
        # vfs_foo: fs/read.c (40-60)
        # target_worker: fs/internal.c (100-150)
        # ops_callback: drivers/bar.c (200-250)
        cur.executemany("""
            INSERT INTO function_locations VALUES (?, ?, ?, ?)
        """, [
            ("__do_sys_foo", "fs/read.c", 10, 30),
            ("vfs_foo", "fs/read.c", 40, 60),
            ("target_worker", "fs/internal.c", 100, 150),
            ("ops_callback", "drivers/bar.c", 200, 250),
        ])

        # Syscall reachability:
        cur.executemany("""
            INSERT INTO syscall_node VALUES (?, ?, ?, ?)
        """, [
            ("__do_sys_foo", "vfs_foo", "fs/read.c:10", "fs/read.c:40"),
            ("__do_sys_foo", "target_worker", "fs/read.c:10", "fs/internal.c:100"),
            ("__do_sys_foo", "ops_callback", "fs/read.c:10", "drivers/bar.c:200"),
        ])

        # Locations:
        # 1: __do_sys_foo (fs/read.c:10)
        # 2: call to vfs_foo (fs/read.c:20)
        # 3: vfs_foo (fs/read.c:40)
        # 4: call to target_worker (fs/read.c:50)
        # 5: target_worker (fs/internal.c:100)
        cur.executemany("""
            INSERT INTO locations (id, message, uri, startLine) VALUES (?, ?, ?, ?)
        """, [
            (1, "__do_sys_foo", "fs/read.c", 10),
            (2, "call to vfs_foo", "fs/read.c", 20),
            (3, "vfs_foo", "fs/read.c", 40),
            (4, "call to target_worker", "fs/read.c", 50),
            (5, "target_worker", "fs/internal.c", 100),
        ])

        # Edges:
        # 1 -> 2 (__do_sys_foo -> call to vfs_foo)
        # 3 -> 4 (vfs_foo -> call to target_worker)
        cur.executemany("""
            INSERT INTO edges (source_location_id, target_location_id, rule_id) VALUES (?, ?, ?)
        """, [
            (1, 2, "callgraph-all"),
            (3, 4, "callgraph-all"),
        ])

        # Ops targets:
        # ops_callback called indirectly from vfs_foo at fs/read.c:55 via foo_ops->bar
        cur.execute("""
            INSERT INTO ops_targets VALUES (
                "def", "foo_ops", "bar", "ops_callback", "drivers/bar.c", 200, 250,
                "fs/read.c", 55, 40, 60
            )
        """)

        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmp_dir.cleanup()

    def test_ensure_indexes(self):
        find_paths.ensure_indexes(self.conn)
        cur = self.conn.cursor()
        cur.execute("SELECT count(*) FROM sqlite_master WHERE type=\"index\"")
        cnt = cur.fetchone()[0]
        self.assertGreaterEqual(cnt, 8)

    def test_get_enclosing_function(self):
        # Line within target_worker
        fn = find_paths.get_enclosing_function(self.conn, "fs/internal.c", 125)
        self.assertIsNotNone(fn)
        self.assertEqual(fn[0], "target_worker")
        self.assertEqual(fn[1], "fs/internal.c")
        self.assertEqual(fn[2], 100)
        self.assertEqual(fn[3], 150)

        # Suffix matching
        fn_suffix = find_paths.get_enclosing_function(self.conn, "internal.c", 125)
        self.assertEqual(fn_suffix[0], "target_worker")

        # Line outside any function
        fn_none = find_paths.get_enclosing_function(self.conn, "fs/internal.c", 999)
        self.assertIsNone(fn_none)

    def test_get_reachable_syscalls(self):
        syss = find_paths.get_reachable_syscalls(self.conn, "target_worker")
        self.assertEqual(syss, ["__do_sys_foo"])

    def test_direct_call_path(self):
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
        with patch("sys.argv", [
            "find_paths.py", "--db", self.db_path, "--file", "fs/internal.c", "--line", "125"
        ]):
            # Should run without raising SystemExit (or exit 0)
            try:
                find_paths.main()
            except SystemExit as e:
                self.assertEqual(e.code, 0)

    def test_cli_missing_db(self):
        with patch("sys.argv", [
            "find_paths.py", "--file", "fs/internal.c", "--line", "125"
        ]):
            with self.assertRaises(SystemExit):
                find_paths.main()

    def test_syzkaller_db_param(self):
        # Without syzkaller_db param, dynamic coverage is not configured
        target_info, _ = find_paths.find_paths_to_line(
            self.db_path, "fs/internal.c", 125, target_syscall="__do_sys_foo"
        )
        self.assertFalse(target_info["syzkaller"]["configured"])

        # With syzkaller_db param pointing to valid DB
        syzk_path = os.path.join(self.tmp_dir.name, "syzkaller_test.db")
        syzk_conn = sqlite3.connect(syzk_path)
        syzk_conn.execute("CREATE TABLE file_path (file_id INTEGER PRIMARY KEY, file_path TEXT)")
        syzk_conn.execute("CREATE TABLE syzk_cov (file_id INTEGER, code_line_no INTEGER, prog_id INTEGER)")
        syzk_conn.execute("CREATE TABLE syscalls (prog_id INTEGER, syscall TEXT)")
        syzk_conn.execute("CREATE TABLE syzk_prog (prog_id INTEGER, prog_code TEXT)")
        syzk_conn.commit()
        syzk_conn.close()

        target_info_syzk, _ = find_paths.find_paths_to_line(
            self.db_path, "fs/internal.c", 125, target_syscall="__do_sys_foo", syzkaller_db=syzk_path
        )
        self.assertTrue(target_info_syzk["syzkaller"]["configured"])


if __name__ == "__main__":
    unittest.main()
