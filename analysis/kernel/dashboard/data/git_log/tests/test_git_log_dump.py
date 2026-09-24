#!/usr/bin/env python3
"""Unit tests for git_log_dump.py Git log extraction and SQLite storage."""

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Add parent directory to sys.path
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import git_log_dump  # pylint: disable=wrong-import-position


class TestValidationHelpers(unittest.TestCase):
    """Test directory and file path validation helper functions."""

    def test_can_read_dir_valid(self):
        """Test can_read_dir with an existing temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(git_log_dump.can_read_dir(tmpdir), tmpdir)

    def test_can_read_dir_invalid(self):
        """Test can_read_dir raises ValueError for nonexistent directory."""
        with self.assertRaises(ValueError):
            git_log_dump.can_read_dir("/non_existent_directory_xyz123")

    def test_can_create_file_valid(self):
        """Test can_create_file with a writable directory path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.db")
            self.assertEqual(git_log_dump.can_create_file(filepath), filepath)

    def test_can_create_file_relative(self):
        """Test can_create_file resolves relative filenames against cwd."""
        filename = "relative_test.db"
        expected = os.path.join(os.getcwd(), filename)
        self.assertEqual(git_log_dump.can_create_file(filename), expected)

    def test_can_create_file_invalid(self):
        """Test can_create_file raises ValueError for nonexistent parent dir."""
        with self.assertRaises(ValueError):
            git_log_dump.can_create_file(
                "/non_existent_directory_xyz123/file.db"
            )

    def test_can_read_file_valid(self):
        """Test can_read_file with an existing readable file."""
        with tempfile.NamedTemporaryFile() as tmpfile:
            self.assertEqual(
                git_log_dump.can_read_file(tmpfile.name), tmpfile.name
            )

    def test_can_read_file_invalid(self):
        """Test can_read_file raises ValueError for nonexistent file."""
        with self.assertRaises(ValueError):
            git_log_dump.can_read_file("/non_existent_file_xyz123.txt")


class TestCheckTools(unittest.TestCase):
    """Test external binary availability check."""

    @patch("subprocess.run")
    def test_check_tools_success(self, mock_run):
        """Test check_tools succeeds when git and parallel return 0."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0
        )
        try:
            git_log_dump.check_tools()
        except subprocess.CalledProcessError as exc:
            self.fail(f"check_tools raised exception on success: {exc}")
        self.assertEqual(mock_run.call_count, 2)

    @patch("subprocess.run")
    def test_check_tools_failure(self, mock_run):
        """Test check_tools propagates CalledProcessError when tool fails."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        with self.assertRaises(subprocess.CalledProcessError):
            git_log_dump.check_tools()


class TestSetupRepository(unittest.TestCase):
    """Test repository opening and unshallow/commit-graph configuration."""

    @patch("git.Repo")
    def test_setup_repository_unshallow_when_shallow(self, mock_repo_cls):
        """Test setup_repository fetches --unshallow when repo is shallow."""
        mock_repo = MagicMock()
        mock_repo.git.rev_parse.return_value = "true"
        mock_repo.head.commit.hexsha = "abcdef1234567890"
        mock_repo_cls.return_value = mock_repo

        repo = git_log_dump.setup_repository("/tmp/fake_kernel_dir")
        self.assertEqual(repo, mock_repo)
        mock_repo.git.fetch.assert_called_once_with("--unshallow")

    @patch("git.Repo")
    def test_setup_repository_not_shallow(self, mock_repo_cls):
        """Test setup_repository skips fetch when repo is already full."""
        mock_repo = MagicMock()
        mock_repo.git.rev_parse.return_value = "false"
        mock_repo.head.commit.hexsha = "abcdef1234567890"
        mock_repo_cls.return_value = mock_repo

        repo = git_log_dump.setup_repository("/tmp/fake_kernel_dir")
        self.assertEqual(repo, mock_repo)
        mock_repo.git.fetch.assert_not_called()


class TestCreateLogTable(unittest.TestCase):
    """Test git_log table population from parallel git log output."""

    def setUp(self):
        super().setUp()
        self.repo_dir = tempfile.mkdtemp()

        self.real_functions = [
            ("error", "arch/x86/boot/compressed/error.c", 18, 24),
            ("isxdigit", "arch/x86/boot/ctype.h", 11, 19),
            ("set_bit", "arch/x86/boot/bitops.h", 40, 42),
            ("offset_to_ptr", "include/linux/compiler.h", 266, 268),
        ]

        for _, rel_path, _, end_line in self.real_functions:
            full_path = os.path.join(self.repo_dir, rel_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            lines = [
                f"/* Line {i} */\n" for i in range(1, max(end_line + 5, 300))
            ]
            with open(full_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

        self.mock_repo = MagicMock()
        self.mock_repo.git.rev_parse.return_value = self.repo_dir
        self.conn = sqlite3.connect(":memory:")

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.repo_dir)
        super().tearDown()

    @patch("subprocess.run")
    def test_create_log_table_real_functions_success(self, mock_subproc):
        """Test create_log_table inserts records for tracked functions."""
        tracked_files_list = (
            "\n".join([f[1] for f in self.real_functions]) + "\n"
        )
        commit_sha = "11223344556677889900aabbccddeeff11223344"

        def fake_run(cmd, *_args, **kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=tracked_files_list
                )
            stdout = kwargs.get("stdout")
            if stdout and hasattr(stdout, "write"):
                for _, rel_path, start, end in self.real_functions:
                    stdout.write(
                        f"{start},{end}:{rel_path},1680000000,{commit_sha}\n"
                    )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        count = git_log_dump.create_log_table(
            self.mock_repo, 4, self.conn, self.real_functions
        )

        self.assertEqual(count, len(self.real_functions))

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT start_line, end_line, file_path, author_date, "
            "`commit`, data FROM git_log"
        )
        rows = cursor.fetchall()
        self.assertEqual(len(rows), len(self.real_functions))

    @patch("subprocess.run")
    def test_create_log_table_untracked_generated_files(self, mock_subproc):
        """Test create_log_table filters out untracked generated files."""
        mixed_functions = self.real_functions + [
            ("inat_lookup", "arch/x86/lib/inat-tables.c", 10, 20),
            ("printf", "include/x86_64-linux-gnu/bits/stdio.h", 5, 15),
        ]
        tracked_files_list = (
            "\n".join([f[1] for f in self.real_functions]) + "\n"
        )
        commit_sha = "11223344556677889900aabbccddeeff11223344"

        def fake_run(cmd, *_args, **kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=tracked_files_list
                )
            stdout = kwargs.get("stdout")
            if stdout and hasattr(stdout, "write"):
                for _, rel_path, start, end in self.real_functions:
                    stdout.write(
                        f"{start},{end}:{rel_path},1680000000,{commit_sha}\n"
                    )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        count = git_log_dump.create_log_table(
            self.mock_repo, 4, self.conn, mixed_functions, force=True
        )
        self.assertEqual(count, len(self.real_functions))

    @patch("subprocess.run")
    def test_create_log_table_missing_log_data(self, mock_subproc):
        """Test create_log_table raises ValueError when output is empty."""

        def fake_run(cmd, *_args, **_kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout="arch/x86/boot/compressed/error.c\n",
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        with self.assertRaises(ValueError):
            git_log_dump.create_log_table(
                self.mock_repo, 4, self.conn, [self.real_functions[0]]
            )

    @patch("subprocess.run")
    def test_create_log_table_invalid_chunk_format(self, mock_subproc):
        """Test create_log_table raises ValueError on malformed log line."""

        def fake_run(cmd, *_args, **kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout="arch/x86/boot/compressed/error.c\n",
                )
            stdout = kwargs.get("stdout")
            if stdout and hasattr(stdout, "write"):
                stdout.write("invalid_format_line\n")
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        with self.assertRaises(ValueError):
            git_log_dump.create_log_table(
                self.mock_repo, 4, self.conn, [self.real_functions[0]]
            )


class TestCreateSqlDb(unittest.TestCase):
    """Test create_sql_db end-to-end reading from function_locations."""

    def setUp(self):
        super().setUp()
        self.tmp_dir = tempfile.mkdtemp()

        self.codeql_db_path = os.path.join(self.tmp_dir, "codeql.db")
        conn = sqlite3.connect(self.codeql_db_path)
        conn.execute(
            """CREATE TABLE function_locations (
                function_name TEXT, file_path TEXT,
                start_line INT, end_line INT
            );"""
        )
        sample_rows = [
            ("error", "arch/x86/boot/compressed/error.c", 18, 24),
            ("isxdigit", "arch/x86/boot/ctype.h", 11, 19),
            ("set_bit", "arch/x86/boot/bitops.h", 40, 42),
            ("offset_to_ptr", "include/linux/compiler.h", 266, 268),
        ]
        conn.executemany(
            "INSERT INTO function_locations VALUES (?, ?, ?, ?);", sample_rows
        )
        conn.commit()
        conn.close()

        self.db_file_path = os.path.join(self.tmp_dir, "git_log.db")
        self.mock_repo = MagicMock()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)
        super().tearDown()

    @patch("git_log_dump.create_log_table")
    def test_create_sql_db_success(self, mock_create_log_table):
        """Test create_sql_db queries function_locations and creates table."""
        mock_create_log_table.return_value = 4
        git_log_dump.create_sql_db(
            self.db_file_path,
            self.codeql_db_path,
            4,
            self.mock_repo,
            force=True,
        )
        mock_create_log_table.assert_called_once()
        self.assertEqual(len(mock_create_log_table.call_args[0][3]), 4)

    def test_create_sql_db_empty_codeql(self):
        """Test create_sql_db raises ValueError when function_locations empty."""
        empty_codeql_path = os.path.join(self.tmp_dir, "empty_codeql.db")
        conn = sqlite3.connect(empty_codeql_path)
        conn.execute(
            """CREATE TABLE function_locations (
                function_name TEXT, file_path TEXT,
                start_line INT, end_line INT
            );"""
        )
        conn.commit()
        conn.close()

        with self.assertRaises(ValueError):
            git_log_dump.create_sql_db(
                self.db_file_path, empty_codeql_path, 4, self.mock_repo
            )


class TestMain(unittest.TestCase):
    """Test CLI argument parsing and main entry point."""

    @patch("git_log_dump.check_tools")
    @patch("git_log_dump.create_sql_db")
    @patch("git_log_dump.setup_repository")
    def test_main_defaults_db_file_to_codeql_db(
        self, mock_setup_repo, mock_create_sql_db, mock_check_tools
    ):
        """Test main defaults --db_file to --codeql_db when omitted."""
        mock_repo_obj = MagicMock()
        mock_setup_repo.return_value = mock_repo_obj

        with patch(
            "sys.argv",
            [
                "git_log_dump.py",
                "--repo_dir",
                "/tmp/fake_dir",
                "--codeql_db",
                __file__,
            ],
        ):
            with patch(
                "git_log_dump.can_read_dir", return_value="/tmp/fake_dir"
            ):
                git_log_dump.main()

        mock_check_tools.assert_called_once()
        mock_setup_repo.assert_called_once_with("/tmp/fake_dir")
        mock_create_sql_db.assert_called_once()
        self.assertEqual(mock_create_sql_db.call_args[0][0], __file__)
        self.assertEqual(mock_create_sql_db.call_args[0][1], __file__)

    def test_main_missing_required_args(self):
        """Test main exits when required --codeql_db argument is missing."""
        with patch(
            "sys.argv", ["git_log_dump.py", "--repo_dir", "/tmp/fake_dir"]
        ):
            with self.assertRaises(SystemExit):
                git_log_dump.main()


if __name__ == "__main__":
    unittest.main()
