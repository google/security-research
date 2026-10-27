#!/usr/bin/env python3
"""Unit and real-kernel verification tests for tools/locate_function.py."""

import io
import json
import os
import unittest
from unittest.mock import patch

from tools import locate_function
from tools.lib import callgraph, locator, metadata
from tools.tests.fixtures import ExtendedToolsTestCase


class TestLocateFunctionUnit(ExtendedToolsTestCase):
    """Unit tests for atomic helpers in tools.lib.locator and CLI."""

    def setUp(self) -> None:
        """Populate synthetic CodeQL, Kconfig, git_log, & Syzkaller rows."""
        super().setUp()
        self.insert_rows(
            function_locations=[
                ("__do_sys_read", "fs/read_write.c", 10, 30),
                ("vfs_read", "fs/read_write.c", 450, 479),
                ("probe", "drivers/net/a.c", 20, 60),
                ("probe", "drivers/usb/b.c", 100, 140),
                ("skb_headlen", "include/linux/skbuff.h", 2100, 2105),
                ("arch_do_signal", "arch/x86/kernel/signal.c", 80, 120),
                ("memcpy", "arch/x86/boot/compressed/string.c", 15, 35),
                ("ip_rcv", "net/ipv4/ip_input.c", 560, 572),
            ],
            syscall_node=[
                (
                    "__do_sys_read",
                    "vfs_read",
                    "fs/read_write.c:10",
                    "fs/read_write.c:450",
                ),
                (
                    "__do_sys_read",
                    "probe",
                    "fs/read_write.c:10",
                    "drivers/net/a.c:20",
                ),
            ],
            entry_node=[
                (
                    "net_rx",
                    "ip_rcv",
                    "vfs_read",
                    "net/ipv4/ip_input.c:560",
                    "fs/read_write.c:450",
                ),
            ],
            locations=[
                (1, "__do_sys_read", "fs/read_write.c", 10),
                (2, "call to vfs_read", "fs/read_write.c", 22),
                (3, "vfs_read", "fs/read_write.c", 450),
            ],
            edges=[
                (1, 2, "callgraph-all"),
                (2, 3, "callgraph-all"),
            ],
        )
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO git_log VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                450,
                479,
                "fs/read_write.c",
                1588929466,
                "775802c0571fb438cd4f6548a323f9e4cb89f5aa",
                (
                    "ssize_t vfs_read(struct file *file, char __user"
                    " *buf)\n{\n\treturn 0;\n}\n"
                ),
                "vfs_read",
            ),
        )
        cur.execute(
            "INSERT INTO configs VALUES (?, ?, ?, ?, ?)",
            ("CONFIG_NET", "drivers/net/a.c", 1, 200, 0),
        )
        cur.execute(
            "INSERT INTO configs VALUES (?, ?, ?, ?, ?)",
            ("CONFIG_FB_SM750", "drivers/staging/sm750fb/sm750.c", 1, 1200, 0),
        )
        cur.execute(
            "INSERT INTO kconfig_symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("CONFIG_NET", "bool", "Net", "", "", "y", "y", "net/Kconfig", 5),
        )
        cur.execute(
            "INSERT INTO kconfig_symbols VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "CONFIG_FB_SM750",
                "tristate",
                "SM750",
                "FB && PCI",
                "",
                "n",
                "n",
                "drivers/staging/sm750fb/Kconfig",
                1,
            ),
        )
        cur.execute("INSERT INTO file_path VALUES (1, 'fs/read_write.c')")
        cur.execute("INSERT INTO syzk_cov VALUES (1, 'vfs_read', 455, 'p1')")
        self.conn.commit()

    def test_classify_function_kind(self) -> None:
        """Verify semantic classification of function definitions."""
        self.assertEqual(
            locator.classify_function_kind(
                self.conn, "__do_sys_read", "fs/read_write.c"
            ),
            "entry_root:syscall",
        )
        self.assertEqual(
            locator.classify_function_kind(
                self.conn, "ip_rcv", "net/ipv4/ip_input.c"
            ),
            "entry_root:net_rx",
        )
        self.assertEqual(
            locator.classify_function_kind(
                self.conn, "skb_headlen", "include/linux/skbuff.h"
            ),
            "header_inline",
        )
        self.assertEqual(
            locator.classify_function_kind(
                self.conn, "arch_do_signal", "arch/x86/kernel/signal.c"
            ),
            "arch_specific",
        )
        self.assertEqual(
            locator.classify_function_kind(
                self.conn, "memcpy", "arch/x86/boot/compressed/string.c"
            ),
            "non_runtime_boot_or_tool",
        )
        self.assertEqual(
            locator.classify_function_kind(
                self.conn, "vfs_read", "fs/read_write.c"
            ),
            "tu_definition",
        )

    def test_detect_span_lines_git_log_and_legacy_repo(self) -> None:
        """Verify sig_start_line and body_start_line detection."""
        span = locator.detect_span_lines(
            self.conn, ("vfs_read", "fs/read_write.c", 450, 479)
        )
        self.assertEqual(
            span,
            {"sig_start_line": 450, "body_start_line": 451, "end_line": 479},
        )

        # Test upward signature recovery on a legacy DB where start_line is '{'
        src_dir = os.path.join(self.tmp_dir, "repo")
        os.makedirs(os.path.join(src_dir, "drivers", "net"), exist_ok=True)
        c_file = os.path.join(src_dir, "drivers", "net", "a.c")
        with open(c_file, "w", encoding="utf-8") as f:
            for i in range(1, 19):
                f.write(f"// line {i}\n")
            f.write("static int probe(struct pci_dev *dev)\n")
            f.write("{\n")
            for i in range(21, 61):
                f.write(f"\treturn 0; // {i}\n")
        legacy_span = locator.detect_span_lines(
            self.conn,
            ("probe", "drivers/net/a.c", 20, 60),
            repo_dir=src_dir,
        )
        self.assertEqual(legacy_span["sig_start_line"], 19)
        self.assertEqual(legacy_span["body_start_line"], 20)
        self.assertEqual(legacy_span["end_line"], 60)

    def test_locate_unique_and_ambiguous_functions(self) -> None:
        """Verify list-always contract for unique and colliding functions."""
        res_unique = locator.locate_functions(self.db_path, name="vfs_read")
        self.assertEqual(res_unique["count"], 1)
        self.assertFalse(res_unique["is_ambiguous"])
        cand = res_unique["candidates"][0]
        self.assertEqual(
            cand["key"],
            {"function_name": "vfs_read", "file_path": "fs/read_write.c"},
        )
        self.assertTrue(cand["syzkaller_covered"])
        self.assertEqual(cand["degree"]["direct_callers"], 1)
        self.assertEqual(cand["degree"]["reachable_syscalls"], 1)
        self.assertEqual(cand["degree"]["reachable_entries"], 1)
        self.assertIsNotNone(cand["git_meta"])

        res_ambig = locator.locate_functions(self.db_path, name="probe")
        self.assertEqual(res_ambig["count"], 2)
        self.assertTrue(res_ambig["is_ambiguous"])

        res_disambig = locator.locate_functions(
            self.db_path, name="probe", file_path="drivers/net/a.c"
        )
        self.assertEqual(res_disambig["count"], 1)
        self.assertFalse(res_disambig["is_ambiguous"])
        self.assertEqual(
            res_disambig["candidates"][0]["degree"]["reachable_syscalls"], 1
        )

    def test_non_runtime_filtering_and_match_modes(self) -> None:
        """Verify non-runtime filtering and substring/regex match modes."""
        res_boot = locator.locate_functions(self.db_path, name="memcpy")
        self.assertEqual(res_boot["count"], 0)

        res_boot_inc = locator.locate_functions(
            self.db_path, name="memcpy", include_non_runtime=True
        )
        self.assertEqual(res_boot_inc["count"], 1)
        self.assertEqual(
            res_boot_inc["candidates"][0]["kind"], "non_runtime_boot_or_tool"
        )

        res_sub = locator.locate_functions(
            self.db_path, name="sys_read", match_mode="substring"
        )
        self.assertEqual(res_sub["count"], 1)
        self.assertEqual(
            res_sub["candidates"][0]["key"]["function_name"], "__do_sys_read"
        )

        res_re = locator.locate_functions(
            self.db_path, name=r"^vfs_.*$", match_mode="regex"
        )
        self.assertEqual(res_re["count"], 1)

    def test_uncompiled_diagnosis_and_suggestions(self) -> None:
        """Verify fallback suggestions and uncompiled Kconfig diagnosis."""
        res_sug = locator.locate_functions(self.db_path, name="read")
        self.assertEqual(res_sug["count"], 0)
        self.assertIn("vfs_read", res_sug["suggestions"])
        self.assertIn("__do_sys_read", res_sug["suggestions"])

        res_uncomp = locator.locate_functions(
            self.db_path,
            name="lynxfb_pci_probe",
            file_path="drivers/staging/sm750fb/sm750.c",
        )
        self.assertEqual(res_uncomp["count"], 0)
        diag = res_uncomp["uncompiled_diagnosis"]
        self.assertIsNotNone(diag)
        self.assertFalse(diag["compiled"])
        self.assertEqual(
            diag["blocking_kconfigs"][0]["config"], "CONFIG_FB_SM750"
        )

    def test_cli_execution_and_ambiguity_helper(self) -> None:
        """Verify locate_function CLI and metadata ambiguity error helper."""
        out = io.StringIO()
        with patch(
            "sys.argv",
            [
                "locate_function.py",
                "--db",
                self.db_path,
                "--name",
                "vfs_read",
                "--format",
                "json",
            ],
        ), patch("sys.stdout", out):
            locate_function.main()
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["count"], 1)

        err_msg = metadata.format_ambiguous_symbol_error(
            "probe",
            callgraph.get_functions_by_name(self.conn, "probe"),
        )
        self.assertIn("AMBIGUOUS_SYMBOL", err_msg)
        self.assertIn("drivers/net/a.c", err_msg)
        self.assertIn("drivers/usb/b.c", err_msg)


if __name__ == "__main__":
    unittest.main()
