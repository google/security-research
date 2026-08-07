#!/usr/bin/env python3

import os
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

import git_log_dump


class TestValidationHelpers(unittest.TestCase):
    def test_repo_url_valid(self):
        url = "https://github.com/torvalds/linux.git"
        self.assertEqual(git_log_dump.repo_url(url), url)

    def test_repo_url_invalid(self):
        with self.assertRaises(ValueError):
            git_log_dump.repo_url("invalid_url_without_scheme")

    def test_can_create_file_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.db")
            self.assertEqual(git_log_dump.can_create_file(filepath), filepath)

    def test_can_create_file_relative(self):
        filename = "relative_test.db"
        expected = os.path.join(os.getcwd(), filename)
        self.assertEqual(git_log_dump.can_create_file(filename), expected)

    def test_can_create_file_invalid(self):
        with self.assertRaises(ValueError):
            git_log_dump.can_create_file("/non_existent_directory_xyz123/file.db")

    def test_can_read_file_valid(self):
        with tempfile.NamedTemporaryFile() as tmpfile:
            self.assertEqual(git_log_dump.can_read_file(tmpfile.name), tmpfile.name)

    def test_can_read_file_invalid(self):
        with self.assertRaises(ValueError):
            git_log_dump.can_read_file("/non_existent_file_xyz123.txt")

    def test_clone_progress(self):
        progress = git_log_dump.CloneProgress()
        try:
            progress.update(0, 50, 100, "Downloading")
        except Exception as e:
            self.fail(f"CloneProgress.update raised an exception: {e}")


class TestCheckTools(unittest.TestCase):
    @patch("subprocess.run")
    def test_check_tools_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        try:
            git_log_dump.check_tools()
        except Exception as e:
            self.fail(f"check_tools raised exception on success: {e}")
        self.assertEqual(mock_run.call_count, 2)

    @patch("subprocess.run")
    def test_check_tools_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        with self.assertRaises(subprocess.CalledProcessError):
            git_log_dump.check_tools()


class TestCreateLogTable(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = self.tmp_dir.name

        # Create sample files based on real CodeQL function locations from fun.db
        self.real_functions = [
            ("error", "arch/x86/boot/compressed/error.c", 18, 24),
            ("isxdigit", "arch/x86/boot/ctype.h", 11, 19),
            ("set_bit", "arch/x86/boot/bitops.h", 40, 42),
            ("offset_to_ptr", "include/linux/compiler.h", 266, 268),
        ]

        for _, rel_path, start_line, end_line in self.real_functions:
            full_path = os.path.join(self.repo_dir, rel_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            lines = [f"/* Line {i} */\n" for i in range(1, max(end_line + 5, 300))]
            with open(full_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

        self.mock_repo = MagicMock()
        self.mock_repo.git.rev_parse.return_value = self.repo_dir
        self.conn = sqlite3.connect(":memory:")

    def tearDown(self):
        self.conn.close()
        self.tmp_dir.cleanup()

    @patch("subprocess.run")
    def test_create_log_table_real_functions_success(self, mock_subproc):
        tracked_files_list = "\n".join([f[1] for f in self.real_functions]) + "\n"

        def fake_run(cmd, *args, **kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=tracked_files_list
                )
            stdout = kwargs.get("stdout")
            if stdout and hasattr(stdout, "write"):
                for _, rel_path, start, end in self.real_functions:
                    stdout.write(
                        f"{start},{end}:{rel_path},1680000000,11223344556677889900aabbccddeeff11223344\n"
                    )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        count = git_log_dump.create_log_table(
            self.mock_repo, 4, self.conn, self.real_functions
        )

        self.assertEqual(count, len(self.real_functions))

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT start_line, end_line, file_path, author_date, `commit`, data FROM git_log"
        )
        rows = cursor.fetchall()
        self.assertEqual(len(rows), len(self.real_functions))

    @patch("subprocess.run")
    def test_create_log_table_untracked_generated_files(self, mock_subproc):
        # Mix of tracked kernel files and untracked build artifacts (e.g. inat-tables.c, stdio.h)
        mixed_functions = self.real_functions + [
            ("inat_lookup", "arch/x86/lib/inat-tables.c", 10, 20),
            ("printf", "include/x86_64-linux-gnu/bits/stdio.h", 5, 15),
        ]
        tracked_files_list = "\n".join([f[1] for f in self.real_functions]) + "\n"

        def fake_run(cmd, *args, **kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=tracked_files_list
                )
            stdout = kwargs.get("stdout")
            if stdout and hasattr(stdout, "write"):
                for _, rel_path, start, end in self.real_functions:
                    stdout.write(
                        f"{start},{end}:{rel_path},1680000000,11223344556677889900aabbccddeeff11223344\n"
                    )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        count = git_log_dump.create_log_table(
            self.mock_repo, 4, self.conn, mixed_functions, force=True
        )
        self.assertEqual(count, len(self.real_functions))

    @patch("subprocess.run")
    def test_create_log_table_missing_log_data(self, mock_subproc):
        def fake_run(cmd, *args, **kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="arch/x86/boot/compressed/error.c\n"
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        with self.assertRaises(ValueError):
            git_log_dump.create_log_table(
                self.mock_repo, 4, self.conn, [self.real_functions[0]]
            )

    @patch("subprocess.run")
    def test_create_log_table_invalid_chunk_format(self, mock_subproc):
        def fake_run(cmd, *args, **kwargs):
            if "ls-files" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="arch/x86/boot/compressed/error.c\n"
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
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

        # Create CodeQL DB modeled after /usr/local/google/home/ametla/fun.db
        self.codeql_db_path = os.path.join(self.tmp_dir.name, "codeql.db")
        conn = sqlite3.connect(self.codeql_db_path)
        conn.execute(
            """CREATE TABLE function_locations (
                function_name TEXT, file_path TEXT, start_line INT, end_line INT
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

        self.db_file_path = os.path.join(self.tmp_dir.name, "git_log.db")
        self.mock_repo = MagicMock()

    def tearDown(self):
        self.tmp_dir.cleanup()

    @patch("git_log_dump.create_log_table")
    def test_create_sql_db_success(self, mock_create_log_table):
        mock_create_log_table.return_value = 4
        git_log_dump.create_sql_db(
            self.db_file_path, self.codeql_db_path, 4, self.mock_repo, force=True
        )
        mock_create_log_table.assert_called_once()
        self.assertEqual(len(mock_create_log_table.call_args[0][3]), 4)

    def test_create_sql_db_with_real_fun_db(self):
        real_fun_db = "/usr/local/google/home/ametla/fun.db"
        if not os.path.exists(real_fun_db):
            self.skipTest(f"{real_fun_db} not found")

        with patch("git_log_dump.create_log_table") as mock_create_log_table:
            mock_create_log_table.return_value = 20076
            git_log_dump.create_sql_db(
                self.db_file_path, real_fun_db, 4, self.mock_repo, force=True
            )
            mock_create_log_table.assert_called_once()
            functions = mock_create_log_table.call_args[0][3]
            self.assertEqual(len(functions), 20076)
            self.assertEqual(functions[0][0], "error")
            self.assertEqual(functions[0][1], "arch/x86/boot/compressed/error.c")

    def test_create_sql_db_empty_codeql(self):
        empty_codeql_path = os.path.join(self.tmp_dir.name, "empty_codeql.db")
        conn = sqlite3.connect(empty_codeql_path)
        conn.execute(
            """CREATE TABLE function_locations (
                function_name TEXT, file_path TEXT, start_line INT, end_line INT
            );"""
        )
        conn.commit()
        conn.close()

        with self.assertRaises(ValueError):
            git_log_dump.create_sql_db(
                self.db_file_path, empty_codeql_path, 4, self.mock_repo
            )


class TestMain(unittest.TestCase):
    @patch("git_log_dump.check_tools")
    @patch("git_log_dump.create_sql_db")
    @patch("git_log_dump.setup_repository")
    def test_main_existing_repo(
        self, mock_setup_repo, mock_create_sql_db, mock_check_tools
    ):
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
            with patch("git_log_dump.can_read_dir", return_value="/tmp/fake_dir"):
                git_log_dump.main()

        mock_check_tools.assert_called_once()
        mock_setup_repo.assert_called_once_with(None, "/tmp/fake_dir", None)
        mock_create_sql_db.assert_called_once()

    @patch("git_log_dump.check_tools")
    @patch("git_log_dump.create_sql_db")
    @patch("git_log_dump.setup_repository")
    def test_main_clone_repo(
        self, mock_setup_repo, mock_create_sql_db, mock_check_tools
    ):
        mock_repo_obj = MagicMock()
        mock_setup_repo.return_value = mock_repo_obj

        with patch(
            "sys.argv",
            [
                "git_log_dump.py",
                "--repo_url",
                "https://github.com/torvalds/linux.git",
                "--commit",
                "master",
                "--codeql_db",
                __file__,
            ],
        ):
            git_log_dump.main()

        mock_check_tools.assert_called_once()
        mock_setup_repo.assert_called_once_with(
            "https://github.com/torvalds/linux.git", None, "master"
        )
        mock_create_sql_db.assert_called_once()
        expected_cpus = os.cpu_count() or 4
        self.assertEqual(mock_create_sql_db.call_args[0][2], expected_cpus)

    def test_main_url_missing_commit(self):
        with patch(
            "sys.argv",
            [
                "git_log_dump.py",
                "--repo_url",
                "https://github.com/torvalds/linux.git",
                "--codeql_db",
                __file__,
            ],
        ):
            with self.assertRaises(SystemExit):
                git_log_dump.main()

    def test_main_missing_codeql_db(self):
        with patch(
            "sys.argv",
            [
                "git_log_dump.py",
                "--repo_url",
                "https://github.com/torvalds/linux.git",
                "--commit",
                "master",
            ],
        ):
            with self.assertRaises(SystemExit):
                git_log_dump.main()


if __name__ == "__main__":
    unittest.main()
