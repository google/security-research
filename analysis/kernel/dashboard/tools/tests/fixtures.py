"""Shared SQLite schema and test case fixtures for Dashboard CLI tools."""

import os
import shutil
import sqlite3
import tempfile
import unittest


def create_base_codeql_schema(cur: sqlite3.Cursor) -> None:
    """Create standard CodeQL SQLite tables used across tool unit tests."""
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


def create_syzkaller_schema(cur: sqlite3.Cursor) -> None:
    """Create standard Syzkaller coverage SQLite tables for unit tests."""
    cur.execute(
        "CREATE TABLE file_path (file_id INTEGER PRIMARY KEY, file_path TEXT)"
    )
    cur.execute("CREATE TABLE syscalls (prog_id TEXT, syscall TEXT)")
    cur.execute("CREATE TABLE syzk_prog (prog_id TEXT, prog_code TEXT)")
    cur.execute(
        "CREATE TABLE syzk_cov ("
        "file_id INTEGER, func_name TEXT, code_line_no INTEGER, prog_id TEXT)"
    )


def create_kconfig_schema(cur: sqlite3.Cursor) -> None:
    """Create Kconfig configs and kconfig_symbols tables for unit tests."""
    cur.execute("""
        CREATE TABLE configs (
            config TEXT,
            path TEXT,
            ifdef INTEGER,
            endif INTEGER,
            else_ INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE kconfig_symbols (
            config TEXT NOT NULL,
            type TEXT,
            prompt TEXT,
            depends_on TEXT,
            select_list TEXT,
            default_val TEXT,
            build_val TEXT,
            kconfig_file TEXT NOT NULL,
            line_no INTEGER NOT NULL
        )
    """)


def create_async_edges_schema(cur: sqlite3.Cursor) -> None:
    """Create async_edges table for unit tests."""
    cur.execute("""
        CREATE TABLE async_edges (
            caller TEXT NOT NULL,
            callee TEXT NOT NULL,
            mechanism TEXT NOT NULL,
            form TEXT NOT NULL,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            context TEXT NOT NULL
        )
    """)


def create_entry_node_schema(cur: sqlite3.Cursor) -> None:
    """Create entry_node table for unit tests."""
    cur.execute("""
        CREATE TABLE entry_node (
            entry_kind TEXT NOT NULL,
            entry TEXT NOT NULL,
            function TEXT NOT NULL,
            entry_location TEXT NOT NULL,
            function_location TEXT NOT NULL
        )
    """)


_TABLE_INSERT_SQL = {
    "function_locations": "INSERT INTO function_locations VALUES (?, ?, ?, ?)",
    "syscall_node": "INSERT INTO syscall_node VALUES (?, ?, ?, ?)",
    "locations": (
        "INSERT INTO locations (id, message, uri, startLine)"
        " VALUES (?, ?, ?, ?)"
    ),
    "edges": (
        "INSERT INTO edges (source_location_id, target_location_id, rule_id)"
        " VALUES (?, ?, ?)"
    ),
    "ops_targets": (
        "INSERT INTO ops_targets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ),
    "conditions": "INSERT INTO conditions VALUES (?, ?, ?, ?, ?, ?)",
    "macroinvocation_locations": (
        "INSERT INTO macroinvocation_locations VALUES (?, ?, ?, ?)"
    ),
    "entry_node": "INSERT INTO entry_node VALUES (?, ?, ?, ?, ?)",
    "async_edges": "INSERT INTO async_edges VALUES (?, ?, ?, ?, ?, ?, ?)",
}


class BaseToolsTestCase(unittest.TestCase):
    """Base test case managing a temporary directory and SQLite connection."""

    def setUp(self) -> None:
        """Create temporary directory and initialize base CodeQL SQLite DB."""
        super().setUp()
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_codeql.db")
        self.conn = sqlite3.connect(self.db_path)
        create_base_codeql_schema(self.conn.cursor())

    def insert_rows(self, **table_rows: list[tuple[object, ...]]) -> None:
        """Insert rows into one or more test SQLite tables and commit."""
        cur = self.conn.cursor()
        for table_name, rows in table_rows.items():
            if rows:
                cur.executemany(_TABLE_INSERT_SQL[table_name], rows)
        self.conn.commit()

    def tearDown(self) -> None:
        """Close SQLite connections and remove temporary directory."""
        self.conn.close()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        super().tearDown()
