#!/usr/bin/env python3
"""Unit and real-kernel verification tests for tools/fetch_body.py."""

import io
import json
import os
import unittest
from unittest.mock import patch

from tools import fetch_body
from tools.lib import source
from tools.tests.fixtures import ExtendedToolsTestCase


class TestFetchBodyUnit(ExtendedToolsTestCase):
    """Unit tests for atomic helpers in tools.lib.source and fetch_body CLI."""

    def setUp(self) -> None:
        """Populate synthetic CodeQL, git_log, Kconfig, & Syzkaller rows."""
        super().setUp()
        self.insert_rows(
            function_locations=[
                ("msr_open", "arch/x86/kernel/msr.c", 206, 213),
                ("seq_show", "fs/proc/fd.c", 23, 30),
                ("seq_show", "net/netfilter/nf_log.c", 346, 355),
            ],
            locations=[
                (1, "msr_open", "arch/x86/kernel/msr.c", 206),
                (2, "call to capable", "arch/x86/kernel/msr.c", 209),
                (3, "capable", "kernel/capability.c", 400),
            ],
            edges=[
                (1, 2, "callgraph-all"),
                (2, 3, "callgraph-all"),
            ],
            ops_targets=[
                (
                    "d1",
                    "file_operations",
                    "read_iter",
                    "msr_read_iter",
                    "arch/x86/kernel/msr.c",
                    50,
                    80,
                    "arch/x86/kernel/msr.c",
                    210,
                    206,
                    213,
                ),
            ],
            async_edges=[
                (
                    "msr_open",
                    "msr_work_fn",
                    "workqueue",
                    "schedule_work",
                    "arch/x86/kernel/msr.c",
                    211,
                    "process",
                ),
            ],
            conditions=[
                (
                    "capable",
                    "arch/x86/kernel/msr.c:209:7:209:13",
                    "arch/x86/kernel/msr.c:209:2:210:16",
                    "17",
                    "call to capable",
                    "arch/x86/kernel/msr.c:209:7:209:13",
                ),
            ],
            macroinvocation_locations=[
                ("CAP_SYS_RAWIO", "arch/x86/kernel/msr.c", 209, 209),
            ],
        )
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO git_log VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                206,
                213,
                "arch/x86/kernel/msr.c",
                1600000000,
                "6131ffaa1f09deadbeef",
                (
                    "static int msr_open(struct inode *inode, struct file"
                    " *file)\n{\n\t// body\n\tif"
                    " (!capable(CAP_SYS_RAWIO))\n\t\tfop_read();\n"
                    "\tschedule_work(&w);\n\treturn 0;\n}\n"
                ),
                "msr_open",
            ),
        )
        cur.execute(
            "INSERT INTO configs VALUES (?, ?, ?, ?, ?)",
            ("CONFIG_X86_MSR", "arch/x86/kernel/msr.c", 208, 212, 0),
        )
        cur.execute("INSERT INTO file_path VALUES (1, 'arch/x86/kernel/msr.c')")
        cur.execute("INSERT INTO syzk_cov VALUES (1, 'msr_open', 209, 'p1')")
        self.conn.commit()

        # Create synthetic repo_dir on disk
        self.repo_dir = os.path.join(self.tmp_dir, "repo")
        msr_dir = os.path.join(self.repo_dir, "arch", "x86", "kernel")
        os.makedirs(msr_dir, exist_ok=True)
        with open(os.path.join(msr_dir, "msr.c"), "w", encoding="utf-8") as f:
            for idx in range(1, 206):
                f.write(f"/* header line {idx} */\n")
            f.write(
                "static int msr_open(struct inode *inode, struct file *file)\n"
            )
            f.write("{\n")
            f.write("#ifdef CONFIG_X86_MSR\n")
            f.write("\tif (!capable(CAP_SYS_RAWIO))\n")
            f.write("\t\tfop_read();\n")
            f.write("\tschedule_work(&w);\n")
            f.write("#endif\n")
            f.write("}\n")
            f.write("/* trailing line 214 */\n")

    def test_fetch_from_repo_dir_with_annotations(self) -> None:
        """Verify disk slicing, context lines, and all inline annotations."""
        res = source.fetch_function_body(
            self.db_path,
            function_name="msr_open",
            repo_dir=self.repo_dir,
            context=1,
            annotate=True,
        )
        self.assertEqual(res["source"], "repo_dir")
        self.assertEqual(res["sig_start_line"], 206)
        self.assertEqual(res["end_line"], 213)
        self.assertEqual(res["window_start"], 205)
        self.assertEqual(res["window_end"], 214)

        by_ln = {r["line"]: r for r in res["lines"]}
        self.assertFalse(by_ln[205]["in_span"])
        self.assertTrue(by_ln[206]["in_span"])
        self.assertIn("KCONFIG: CONFIG_X86_MSR", by_ln[208]["annotations"])
        self.assertIn("GATE: capable(CAP_SYS_RAWIO)", by_ln[209]["annotations"])
        self.assertIn("CALLEE: capable", by_ln[209]["annotations"])
        self.assertIn("SYZKALLER: COVERED", by_ln[209]["annotations"])
        self.assertIn(
            "INDIRECT: file_operations->read_iter (1 target(s))",
            by_ln[210]["annotations"],
        )
        self.assertIn(
            "ASYNC: workqueue -> msr_work_fn", by_ln[211]["annotations"]
        )

        txt = source.format_body_text(res)
        self.assertIn("GATE: capable(CAP_SYS_RAWIO)", txt)

    def test_fetch_from_git_log_fallback_and_ambiguity(self) -> None:
        """Verify pure-DB git_log fallback and AMBIGUOUS_SYMBOL rejection."""
        res = source.fetch_function_body(
            self.db_path,
            function_name="msr_open",
            force_git_log=True,
        )
        self.assertEqual(res["source"], "git_log")
        self.assertEqual(res["lines"][0]["line"], 206)
        self.assertIn("static int msr_open", res["lines"][0]["code"])

        with self.assertRaises(ValueError) as ctx:
            source.fetch_function_body(self.db_path, function_name="seq_show")
        self.assertIn("AMBIGUOUS_SYMBOL", str(ctx.exception))

    def test_cli_execution(self) -> None:
        """Verify fetch_body CLI JSON output."""
        out = io.StringIO()
        with patch(
            "sys.argv",
            [
                "fetch_body.py",
                "--db",
                self.db_path,
                "--function",
                "msr_open",
                "--git-log-only",
                "--format",
                "json",
            ],
        ), patch("sys.stdout", out):
            fetch_body.main()
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["function"], "msr_open")
        self.assertEqual(payload["source"], "git_log")

    def test_up_to_line_and_callsite_snippet(self) -> None:
        """Verify --up-to-line truncation and fetch_callsite_snippet."""
        res = fetch_body.fetch_function_body(
            self.db_path,
            function_name="msr_open",
            up_to_line=209,
            context=1,
            force_git_log=True,
        )
        self.assertEqual(res["up_to_line"], 209)
        self.assertLessEqual(res["window_end"], 210)
        self.assertEqual(res["lines"][0]["line"], 206)

        snippet = source.fetch_callsite_snippet(
            self.conn, "arch/x86/kernel/msr.c", 209, context=1
        )
        self.assertTrue(any(s["is_focus_line"] for s in snippet))
        self.assertEqual([s["line"] for s in snippet], [208, 209, 210])


if __name__ == "__main__":
    unittest.main()
