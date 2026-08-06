#!/usr/bin/python3

import unittest
import sqlite3
import tempfile
import os
import sys
import subprocess
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
        # Ensure update method executes without error
        try:
            progress.update(0, 50, 100, "Downloading")
        except Exception as e:
            self.fail(f"CloneProgress.update raised an exception: {e}")


class TestCheckTools(unittest.TestCase):
    @patch("os.access")
    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_check_tools_success(self, mock_run, mock_exists, mock_access):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        mock_exists.return_value = True
        mock_access.return_value = True
        try:
            git_log_dump.check_tools()
        except Exception as e:
            self.fail(f"check_tools raised exception on success: {e}")
        self.assertEqual(mock_run.call_count, 1)

    @patch("subprocess.run")
    def test_check_tools_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        with self.assertRaises(subprocess.CalledProcessError):
            git_log_dump.check_tools()

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_check_tools_parallel_missing(self, mock_run, mock_exists):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        mock_exists.return_value = False
        with self.assertRaises(ValueError):
            git_log_dump.check_tools()


class TestCreateLogTable(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.repo_dir = self.tmp_dir.name

        # Create a sample file in fake repo
        self.rel_file_path = "net/socket.c"
        self.full_file_path = os.path.join(self.repo_dir, self.rel_file_path)
        os.makedirs(os.path.dirname(self.full_file_path), exist_ok=True)

        self.file_lines = [f"line {i}\n" for i in range(1, 31)]
        with open(self.full_file_path, "w", encoding="utf-8") as f:
            f.writelines(self.file_lines)

        self.mock_repo = MagicMock()
        self.mock_repo.git.rev_parse.return_value = self.repo_dir

        self.conn = sqlite3.connect(":memory:")

    def tearDown(self):
        self.conn.close()
        self.tmp_dir.cleanup()

    @patch("subprocess.run")
    def test_create_log_table_success(self, mock_subproc):
        function_locations = [
            ("sock_create", "net/socket.c", 10, 20),
        ]

        def fake_run(cmd, stdout=None, check=True):
            if stdout and hasattr(stdout, "write"):
                stdout.write(
                    "10,20:net/socket.c,1680000000,11223344556677889900aabbccddeeff11223344\n"
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        count = git_log_dump.create_log_table(
            self.mock_repo, 4, self.conn, function_locations
        )

        self.assertEqual(count, 1)

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT start_line, end_line, file_path, author_date, `commit`, data FROM git_log"
        )
        row = cursor.fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], 10)
        self.assertEqual(row[1], 20)
        self.assertEqual(row[2], "net/socket.c")
        self.assertEqual(row[3], 1680000000)
        self.assertEqual(row[4], "11223344556677889900aabbccddeeff11223344")
        expected_code = "".join(self.file_lines[9:20])
        self.assertEqual(row[5], expected_code)

    @patch("subprocess.run")
    def test_create_log_table_missing_log_data(self, mock_subproc):
        def fake_run(cmd, stdout=None, check=True):
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        with self.assertRaises(ValueError):
            git_log_dump.create_log_table(
                self.mock_repo, 4, self.conn, [("fn", "net/socket.c", 1, 5)]
            )

    @patch("subprocess.run")
    def test_create_log_table_invalid_chunk_format(self, mock_subproc):
        def fake_run(cmd, stdout=None, check=True):
            if stdout and hasattr(stdout, "write"):
                stdout.write("invalid_format_line\n")
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        with self.assertRaises(ValueError):
            git_log_dump.create_log_table(
                self.mock_repo, 4, self.conn, [("fn", "net/socket.c", 1, 5)]
            )

    @patch("subprocess.run")
    def test_create_log_table_missing_file_in_repo(self, mock_subproc):
        def fake_run(cmd, stdout=None, check=True):
            if stdout and hasattr(stdout, "write"):
                stdout.write("1,5:non_existent.c,1680000000,abcdef123456\n")
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_subproc.side_effect = fake_run

        count = git_log_dump.create_log_table(
            self.mock_repo,
            4,
            self.conn,
            [("fn", "non_existent.c", 1, 5)],
        )

        self.assertEqual(count, 1)

        cursor = self.conn.cursor()
        cursor.execute("SELECT data FROM git_log WHERE file_path='non_existent.c'")
        row = cursor.fetchone()
        self.assertEqual(row[0], "")  # Empty data for non-existent file


class TestCreateSqlDb(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

        # Create CodeQL DB
        self.codeql_db_path = os.path.join(self.tmp_dir.name, "codeql.db")
        conn = sqlite3.connect(self.codeql_db_path)
        conn.execute(
            """CREATE TABLE function_locations (
                function_name TEXT, file_path TEXT, start_line INT, end_line INT
            );"""
        )
        conn.execute(
            "INSERT INTO function_locations VALUES ('foo', 'net/socket.c', 10, 20);"
        )
        conn.commit()
        conn.close()

        self.db_file_path = os.path.join(self.tmp_dir.name, "git_log.db")
        self.mock_repo = MagicMock()

    def tearDown(self):
        self.tmp_dir.cleanup()

    @patch("git_log_dump.create_log_table")
    def test_create_sql_db_success(self, mock_create_log_table):
        mock_create_log_table.return_value = 1
        git_log_dump.create_sql_db(
            self.db_file_path, self.codeql_db_path, 4, self.mock_repo
        )
        mock_create_log_table.assert_called_once()

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
    @patch("git.Repo")
    @patch("os.path.exists")
    def test_main_existing_repo(
        self, mock_exists, mock_git_repo, mock_create_sql_db, mock_check_tools
    ):
        mock_exists.return_value = True
        mock_repo_obj = MagicMock()
        mock_git_repo.return_value = mock_repo_obj

        with patch(
            "sys.argv",
            [
                "git_log_dump.py",
                "--repo_url",
                "https://github.com/torvalds/linux.git",
                "--commit",
                "master",
                "--codeql_db",
                __file__,  # valid readable file for codeql_db
            ],
        ):
            git_log_dump.main()

        mock_check_tools.assert_called_once()
        mock_repo_obj.git.reset.assert_called_with("--hard", "master")
        mock_create_sql_db.assert_called_once()

    @patch("git_log_dump.check_tools")
    @patch("git_log_dump.create_sql_db")
    @patch("git.Repo.clone_from")
    @patch("os.path.exists")
    def test_main_clone_repo(
        self, mock_exists, mock_clone_from, mock_create_sql_db, mock_check_tools
    ):
        mock_exists.return_value = False
        mock_repo_obj = MagicMock()
        mock_clone_from.return_value = mock_repo_obj

        with patch(
            "sys.argv",
            [
                "git_log_dump.py",
                "--repo_url",
                "https://github.com/torvalds/linux.git",
                "--commit",
                "master",
                "--codeql_db",
                __file__,  # valid readable file for codeql_db
            ],
        ):
            git_log_dump.main()

        mock_check_tools.assert_called_once()
        mock_clone_from.assert_called_once()
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

    @patch("git_log_dump.check_tools")
    @patch("git_log_dump.create_sql_db")
    @patch("git.Repo")
    def test_main_local_folder_no_reset(
        self, mock_git_repo, mock_create_sql_db, mock_check_tools
    ):
        with tempfile.TemporaryDirectory() as tmp_local_repo:
            mock_repo_obj = MagicMock()
            mock_git_repo.return_value = mock_repo_obj

            with patch(
                "sys.argv",
                [
                    "git_log_dump.py",
                    "--repo_dir",
                    tmp_local_repo,
                    "--codeql_db",
                    __file__,  # valid readable file for codeql_db
                ],
            ):
                git_log_dump.main()

            mock_check_tools.assert_called_once()
            mock_git_repo.assert_called_with(tmp_local_repo)
            mock_repo_obj.git.reset.assert_not_called()
            mock_create_sql_db.assert_called_once()

    @patch("git_log_dump.check_tools")
    @patch("git_log_dump.create_sql_db")
    @patch("git.Repo")
    def test_main_local_folder_with_reset(
        self, mock_git_repo, mock_create_sql_db, mock_check_tools
    ):
        with tempfile.TemporaryDirectory() as tmp_local_repo:
            mock_repo_obj = MagicMock()
            mock_git_repo.return_value = mock_repo_obj

            with patch(
                "sys.argv",
                [
                    "git_log_dump.py",
                    "--repo_dir",
                    tmp_local_repo,
                    "--commit",
                    "v6.1.111",
                    "--codeql_db",
                    __file__,  # valid readable file for codeql_db
                ],
            ):
                git_log_dump.main()

            mock_check_tools.assert_called_once()
            mock_git_repo.assert_called_with(tmp_local_repo)
            mock_repo_obj.git.reset.assert_called_with("--hard", "v6.1.111")
            mock_create_sql_db.assert_called_once()


if __name__ == "__main__":
    unittest.main()
