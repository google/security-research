"""Unit tests for data.lib.validation and data.lib.db."""

import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from data.lib.db import execute_sqlite_batch, open_sqlite_db
from data.lib.validation import (
    can_create_file,
    can_read_dir,
    can_read_file,
    join_continuation_lines,
    verify_cli_tools,
)


class TestValidationHelpers(unittest.TestCase):
    """Tests for directory, file, CLI tool, and line-continuation helpers."""

    def test_can_read_dir_valid_and_invalid(self):
        """Verifies can_read_dir accepts valid dirs and rejects missing ones."""
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(can_read_dir(tmpdir), os.path.abspath(tmpdir))
        with self.assertRaises(ValueError):
            can_read_dir("/nonexistent_directory_xyz_987")

    def test_can_read_file_valid_and_invalid(self):
        """Verifies can_read_file accepts readable files and rejects missing."""
        with tempfile.NamedTemporaryFile() as tmpfile:
            self.assertEqual(can_read_file(tmpfile.name), tmpfile.name)
        with self.assertRaises(ValueError):
            can_read_file("/nonexistent_file_xyz_987.txt")

    def test_can_create_file_valid_relative_and_invalid(self):
        """Verifies can_create_file handles absolute, relative, and bad dirs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "output.db")
            self.assertEqual(can_create_file(target), target)

        rel_name = "relative_output.db"
        self.assertEqual(
            can_create_file(rel_name), os.path.join(os.getcwd(), rel_name)
        )

        with self.assertRaises(ValueError):
            can_create_file("/nonexistent_directory_xyz_987/output.db")

    @patch("subprocess.run")
    def test_verify_cli_tools_success_and_failure(self, mock_run):
        """Verifies verify_cli_tools checks each tool and propagates errors."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0
        )
        verify_cli_tools([["git", "--version"], ["parallel", "--version"]])
        self.assertEqual(mock_run.call_count, 2)

        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        with self.assertRaises(subprocess.CalledProcessError):
            verify_cli_tools([["git", "--version"]])

    def test_join_continuation_lines(self):
        """Verifies backslash line continuations and comments are normalized."""
        raw = [
            "# Top comment\n",
            "obj-$(CONFIG_FOO) += a.o \\\n",
            "                     b.o # inline comment\n",
            "obj-$(CONFIG_BAR) += c.o\n",
        ]
        joined = join_continuation_lines(raw)
        self.assertEqual(
            joined,
            [
                (2, "obj-$(CONFIG_FOO) += a.o b.o"),
                (4, "obj-$(CONFIG_BAR) += c.o"),
            ],
        )


class TestDbHelpers(unittest.TestCase):
    """Tests for open_sqlite_db and execute_sqlite_batch."""

    def test_open_sqlite_db_and_batch_idempotency(self):
        """Verifies execute_sqlite_batch drop_table and open_sqlite_db."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "sample.db")
            create_sql = "CREATE TABLE IF NOT EXISTS items (name TEXT, val INT)"
            insert_sql = "INSERT INTO items (name, val) VALUES (?, ?)"

            execute_sqlite_batch(
                db_path,
                create_sql,
                insert_sql,
                [("a", 1), ("b", 2)],
                drop_table="items",
            )
            execute_sqlite_batch(
                db_path,
                create_sql,
                insert_sql,
                [("c", 3)],
                drop_table="items",
            )

            with open_sqlite_db(db_path, fast_pragmas=False) as conn:
                rows = conn.execute(
                    "SELECT name, val FROM items ORDER BY val"
                ).fetchall()
            self.assertEqual(rows, [("c", 3)])


if __name__ == "__main__":
    unittest.main()
