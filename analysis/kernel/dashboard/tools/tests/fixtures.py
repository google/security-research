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


def create_git_log_schema(cur: sqlite3.Cursor) -> None:
    """Create git_log table for unit tests."""
    cur.execute("""
        CREATE TABLE git_log (
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            author_date INTEGER NOT NULL,
            `commit` TEXT NOT NULL,
            data TEXT NOT NULL,
            function_name TEXT NOT NULL DEFAULT ''
        )
    """)


def create_struct_schemas(cur: sqlite3.Cursor) -> None:
    """Create struct, BTF types, alloc, and field_access tables for tests."""
    cur.execute("""
        CREATE TABLE struct_locations (
            struct_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            byte_size INTEGER NOT NULL,
            member_count INTEGER NOT NULL,
            is_anonymous INTEGER NOT NULL,
            is_typedef INTEGER NOT NULL,
            has_flex_member INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE struct_fields (
            struct_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            start_line INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            field_path TEXT NOT NULL,
            field_type TEXT NOT NULL,
            byte_offset INTEGER NOT NULL,
            bit_offset INTEGER,
            bit_size INTEGER,
            is_funcptr INTEGER NOT NULL,
            is_flex INTEGER NOT NULL,
            array_len INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE types (
            struct_name TEXT,
            struct_size INTEGER,
            parent_type TEXT,
            kind TEXT,
            type TEXT,
            name TEXT,
            bits_offset INTEGER,
            nr_bits INTEGER,
            bits_end INTEGER,
            is_flex INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE allocs (
            call_value TEXT,
            type_value TEXT,
            objectSize_value TEXT,
            allocSizeMin_value TEXT,
            allocSizeMax_value TEXT,
            allocSize_value TEXT,
            flagsMin_value TEXT,
            flagsMax_value TEXT,
            flags_value TEXT,
            call_uri TEXT,
            call_startLine INTEGER,
            call_startColumn INTEGER,
            depth_value TEXT,
            type_uri TEXT,
            type_startLine TEXT,
            type_startColumn TEXT,
            is_flexible TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE kmalloc_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_site TEXT,
            call_expr TEXT,
            struct_type TEXT,
            struct_def TEXT,
            struct_size INTEGER,
            flags TEXT,
            alloc_size INTEGER,
            sizeof_expr TEXT,
            is_flexible TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE field_access (
            type TEXT,
            field TEXT,
            parent TEXT,
            location TEXT,
            function_name TEXT,
            file_path TEXT,
            line INTEGER
        )
    """)


def create_all_extended_schemas(cur: sqlite3.Cursor) -> None:
    """Create entry, async, kconfig, syzkaller, git_log, and struct tables."""
    create_entry_node_schema(cur)
    create_async_edges_schema(cur)
    create_kconfig_schema(cur)
    create_syzkaller_schema(cur)
    create_git_log_schema(cur)
    create_struct_schemas(cur)


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
    "struct_locations": (
        "INSERT INTO struct_locations"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ),
    "struct_fields": (
        "INSERT INTO struct_fields"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ),
    "types": "INSERT INTO types VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "allocs": (
        "INSERT INTO allocs"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ),
    "kmalloc_calls": (
        "INSERT INTO kmalloc_calls ("
        "call_site, call_expr, struct_type, struct_def, struct_size,"
        " flags, alloc_size, sizeof_expr, is_flexible"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ),
    "field_access": (
        "INSERT INTO field_access VALUES (?, ?, ?, ?, ?, ?, ?)"
    ),
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


class ExtendedToolsTestCase(BaseToolsTestCase):
    """Base test case with entry_node, async_edges, kconfig, syzk, & git_log."""

    def setUp(self) -> None:
        """Initialize base and extended schemas."""
        super().setUp()
        create_all_extended_schemas(self.conn.cursor())
