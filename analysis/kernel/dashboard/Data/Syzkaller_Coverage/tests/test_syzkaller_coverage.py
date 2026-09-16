#!/usr/bin/python3
"""Unit tests for syzkaller_coverage.py including streaming JSONL parsing, syzk_sys/syscalls tables, and git-diff line remapping."""

import gzip
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import syzkaller_coverage as sk


class TestSyzkallerCoverage(unittest.TestCase):
    def test_get_syscalls_deduplication(self):
        """Verify get_syscalls extracts syscalls and deduplicates per-program pairs."""
        progs = [
            (
                0,
                (
                    "r0 = openat$foo(0xffffffffffffff9c, &(0x7f0000000000), 0x0, 0x0)\n"
                    "read(r0, &(0x7f0000000040), 0x10)\n"
                    "read(r0, &(0x7f0000000080), 0x20)\n"
                ),
            ),
            (
                1,
                "write(0x1, &(0x7f0000000000), 0x5)\n",
            ),
        ]
        pairs = sk.get_syscalls(progs)
        self.assertEqual(
            set(pairs),
            {
                (0, "openat"),
                (0, "read"),
                (1, "write"),
            },
        )
        self.assertEqual(len(pairs), 3)

    def test_streaming_jsonl_and_gzip_jsonl(self):
        """Test streaming JSONL parser with both uncompressed and gzipped JSONL files."""
        sample_records = [
            {
                "program": "openat$bar(0x0, 0x0)\nioctl(0x1, 0x2)\n",
                "coverage": [
                    {
                        "file_path": "fs/open.c",
                        "functions": [
                            {
                                "func_name": "do_sys_openat2",
                                "blocks": [
                                    {
                                        "hit_count": 3,
                                        "from_line": 100,
                                        "from_column": 1,
                                        "to_line": 105,
                                        "to_column": 2,
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]

        # 1. Test plain .jsonl streaming
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for rec in sample_records:
                f.write(json.dumps(rec) + "\n")
            plain_path = f.name

        try:
            sources_dict = sk.get_sk_cov_data(None, [plain_path])
            marker = sources_dict[plain_path]
            self.assertTrue(marker.startswith("__STREAM_FILE__:"))
            path_list, cov_list, prog_list = sk.get_json_data(marker)
            self.assertEqual(len(path_list), 1)
            self.assertEqual(path_list[0][1], "fs/open.c")
            self.assertEqual(len(prog_list), 1)
            self.assertGreater(len(cov_list), 0)
        finally:
            if os.path.exists(plain_path):
                os.remove(plain_path)

        # 2. Test gzipped .jsonl.gz streaming
        with tempfile.NamedTemporaryFile(suffix=".jsonl.gz", delete=False) as f:
            gz_path = f.name
        with gzip.open(gz_path, "wt", encoding="utf-8") as gz_file:
            for rec in sample_records:
                gz_file.write(json.dumps(rec) + "\n")

        try:
            self.assertTrue(sk.is_gzipped_file(gz_path))
            sources_dict = sk.get_sk_cov_data(None, [gz_path])
            marker = sources_dict[gz_path]
            self.assertTrue(marker.startswith("__STREAM_FILE__:"))
            path_list, cov_list, prog_list = sk.get_json_data(marker)
            self.assertEqual(len(path_list), 1)
            self.assertEqual(path_list[0][1], "fs/open.c")
            self.assertEqual(len(prog_list), 1)
        finally:
            if os.path.exists(gz_path):
                os.remove(gz_path)

    def test_create_sql_db_creates_syzk_sys_and_syscalls(self):
        """Test that create_sql_db creates all 5 tables including syzk_sys and syscalls."""
        sample_records = [
            {
                "program": "openat$bar(0x0, 0x0)\nioctl(0x1, 0x2)\n",
                "coverage": [
                    {
                        "file_path": "fs/open.c",
                        "functions": [
                            {
                                "func_name": "do_sys_openat2",
                                "blocks": [
                                    {
                                        "hit_count": 1,
                                        "from_line": 100,
                                        "from_column": 1,
                                        "to_line": 100,
                                        "to_column": 2,
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for rec in sample_records:
                f.write(json.dumps(rec) + "\n")
            jsonl_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            db_path = tmp_db.name

        try:
            sources_dict = sk.get_sk_cov_data(None, [jsonl_path])
            sk.create_sql_db(db_path, sources_dict)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            )
            tables = {row[0] for row in cursor.fetchall()}
            self.assertEqual(
                tables,
                {"file_path", "syzk_cov", "syzk_prog", "syzk_sys", "syscalls"},
            )

            cursor.execute("SELECT prog_id, syscall FROM syzk_sys ORDER BY syscall;")
            self.assertEqual(cursor.fetchall(), [(0, "ioctl"), (0, "openat")])

            cursor.execute("SELECT prog_id, syscall FROM syscalls ORDER BY syscall;")
            self.assertEqual(cursor.fetchall(), [(0, "ioctl"), (0, "openat")])

            conn.close()
        finally:
            if os.path.exists(jsonl_path):
                os.remove(jsonl_path)
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_extract_cov_commit(self):
        """Test auto-detection of coverage commit hash from filenames and content headers."""
        # 1. From filename pattern
        commit = sk.extract_cov_commit(
            ["/path/to/ci-upstream-kasan-gce-7d0a66e4.html"], {}
        )
        self.assertEqual(commit, "7d0a66e4")

        # 2. From JSONL content header
        commit = sk.extract_cov_commit(
            ["report.jsonl"],
            {"report.jsonl": '{"kernel_commit": "2f0c1cf72f4682178506f513bbf015e591b1aa4a", "program": "foo"}'},
        )
        self.assertEqual(commit, "2f0c1cf72f4682178506f513bbf015e591b1aa4a")

        # 3. From HTML content link
        commit = sk.extract_cov_commit(
            ["coverage.html"],
            {"coverage.html": '<html><a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcdef123456">commit</a></html>'},
        )
        self.assertEqual(commit, "abcdef123456")

    def test_parse_git_diff_u0_and_remap_line(self):
        """Test unified diff -U0 parser and line number translation across insertions, modifications, and deletions."""
        diff_text = (
            "diff --git a/fs/open.c b/fs/open.c\n"
            "index 1111111..2222222 100644\n"
            "--- a/fs/open.c\n"
            "+++ b/fs/open.c\n"
            "@@ -10,0 +11,3 @@\n"
            "+inserted 1\n"
            "+inserted 2\n"
            "+inserted 3\n"
            "@@ -50,4 +53,2 @@\n"
            "-old 50\n"
            "-old 51\n"
            "-old 52\n"
            "-old 53\n"
            "+new 53\n"
            "+new 54\n"
            "@@ -100,2 +98,0 @@\n"
            "-del 100\n"
            "-del 101\n"
        )
        changes = sk.parse_git_diff_u0(diff_text)
        self.assertIn("fs/open.c", changes)
        hunks = changes["fs/open.c"]["hunks"]

        # Line 10 (before insertion after line 10) -> unchanged (10)
        self.assertEqual(sk.remap_line(hunks, 10), 10)
        # Line 11 (first line after +3 insertion) -> 11 + 3 = 14
        self.assertEqual(sk.remap_line(hunks, 11), 14)
        # Line 49 (just before hunk at 50) -> 49 + 3 = 52
        self.assertEqual(sk.remap_line(hunks, 49), 52)
        # Line 50 (modified in place: 1st of 2 new lines) -> new_start (53) + 0 = 53
        self.assertEqual(sk.remap_line(hunks, 50), 53)
        # Line 51 (modified in place: 2nd of 2 new lines) -> new_start (53) + 1 = 54
        self.assertEqual(sk.remap_line(hunks, 51), 54)
        # Line 52 (deleted in 4->2 replacement) -> None
        self.assertIsNone(sk.remap_line(hunks, 52))
        # Line 54 (after hunk 2, cum_delta = +3 + (2 - 4) = +1) -> 54 + 1 = 55
        self.assertEqual(sk.remap_line(hunks, 54), 55)
        # Line 100 (pure deletion of 2 lines) -> None
        self.assertIsNone(sk.remap_line(hunks, 100))
        # Line 102 (after hunk 3, cum_delta = +1 - 2 = -1) -> 102 - 1 = 101
        self.assertEqual(sk.remap_line(hunks, 102), 101)

    def test_remap_coverage_data_end_to_end(self):
        """End-to-end test of remap_coverage_data against a real temporary Git repository."""
        with tempfile.TemporaryDirectory() as repo_dir:
            subprocess.run(["git", "init"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)

            os.makedirs(os.path.join(repo_dir, "fs"), exist_ok=True)
            os.makedirs(os.path.join(repo_dir, "net"), exist_ok=True)

            # Commit 1 (v6.18 base):
            # fs/open.c has 5 lines
            with open(os.path.join(repo_dir, "fs/open.c"), "w") as f:
                f.write("line1\nline2\nline3\nline4\nline5\n")
            # net/socket.c has 3 lines (will remain untouched)
            with open(os.path.join(repo_dir, "net/socket.c"), "w") as f:
                f.write("sock1\nsock2\nsock3\n")
            # fs/obsolete.c (will be deleted in commit 2)
            with open(os.path.join(repo_dir, "fs/obsolete.c"), "w") as f:
                f.write("obs1\nobs2\n")

            subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
            subprocess.run(["git", "commit", "-m", "v6.18 base"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL)
            cov_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir).decode().strip()

            # Commit 2 (v6.18.45 target):
            # Insert 2 lines at top of fs/open.c so old line 4 shifts to line 6
            with open(os.path.join(repo_dir, "fs/open.c"), "w") as f:
                f.write("new_header1\nnew_header2\nline1\nline2\nline3\nline4\nline5\n")
            # Delete fs/obsolete.c
            os.remove(os.path.join(repo_dir, "fs/obsolete.c"))

            subprocess.run(["git", "add", "-A"], cwd=repo_dir, check=True)
            subprocess.run(["git", "commit", "-m", "v6.18.45 target"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL)
            target_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir).decode().strip()

            # Coverage data generated at Commit 1 (cov_commit):
            # file 0: fs/open.c (line 4 covered by prog 0) -> should shift to line 6
            # file 1: net/socket.c (line 2 covered by prog 0) -> untouched, stays line 2
            # file 2: fs/obsolete.c (line 1 covered by prog 0) -> file deleted, should be dropped
            all_path = [
                (0, "fs/open.c"),
                (1, "net/socket.c"),
                (2, "fs/obsolete.c"),
            ]
            all_syzk_cov = [
                (0, 4, 0),
                (1, 2, 0),
                (2, 1, 0),
            ]

            new_all_path, new_all_cov = sk.remap_coverage_data(
                all_path, all_syzk_cov, repo_dir, cov_commit, target_commit
            )

            path_by_id = dict(new_all_path)
            self.assertEqual(set(path_by_id.values()), {"fs/open.c", "net/socket.c"})

            mapped_entries = {(path_by_id[fid], line, pid) for fid, line, pid in new_all_cov}
            self.assertEqual(
                mapped_entries,
                {
                    ("fs/open.c", 6, 0),
                    ("net/socket.c", 2, 0),
                },
            )


if __name__ == "__main__":
    unittest.main()
