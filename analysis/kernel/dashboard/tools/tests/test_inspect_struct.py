#!/usr/bin/env python3
"""Unit tests for tools/inspect_struct.py and tools/lib/structs.py."""

import io
import json
import os
import unittest
from unittest.mock import patch

from tools import inspect_struct as cli_mod
from tools.lib import structs as structs_lib
from tools.tests.fixtures import ExtendedToolsTestCase


class TestInspectStruct(ExtendedToolsTestCase):
    """Test suite for struct layout, BTF parity, allocs, and field_access."""

    def setUp(self) -> None:
        """Seed struct, BTF, alloc, field_access, and callgraph fixtures."""
        super().setUp()
        self.insert_rows(
            function_locations=[
                ("alloc_demo", "net/core/demo.c", 10, 30),
                ("write_demo_fn", "net/core/demo.c", 35, 60),
                ("read_demo_fn", "net/core/demo.c", 65, 90),
                ("boot_helper", "arch/x86/boot/main.c", 1, 20),
            ],
            syscall_node=[
                (
                    "__do_sys_ioctl",
                    "alloc_demo",
                    "fs/ioctl.c:10",
                    "net/core/demo.c:10",
                ),
                (
                    "__do_sys_ioctl",
                    "write_demo_fn",
                    "fs/ioctl.c:10",
                    "net/core/demo.c:35",
                ),
            ],
            entry_node=[
                (
                    "netfilter_hook",
                    "nf_demo_hook",
                    "read_demo_fn",
                    "net/core/demo.c:5",
                    "net/core/demo.c:65",
                ),
            ],
            struct_locations=[
                ("demo_obj", "include/linux/demo.h", 10, 22, 32, 5, 0, 0, 1),
                ("demo_obj", "drivers/net/demo_drv.c", 50, 58, 16, 2, 0, 0, 0),
                ("boot_obj", "arch/x86/boot/boot.h", 1, 10, 8, 1, 0, 0, 0),
            ],
            struct_fields=[
                (
                    "demo_obj",
                    "include/linux/demo.h",
                    10,
                    "flags",
                    "flags",
                    "unsigned long",
                    0,
                    None,
                    None,
                    0,
                    0,
                    None,
                ),
                (
                    "demo_obj",
                    "include/linux/demo.h",
                    10,
                    "pkt_type",
                    "pkt_type",
                    "__u8",
                    8,
                    0,
                    3,
                    0,
                    0,
                    None,
                ),
                (
                    "demo_obj",
                    "include/linux/demo.h",
                    10,
                    "cookie",
                    "u.cookie",
                    "u64",
                    16,
                    None,
                    None,
                    0,
                    0,
                    None,
                ),
                (
                    "demo_obj",
                    "include/linux/demo.h",
                    10,
                    "destructor",
                    "destructor",
                    "void (*)(struct demo_obj *)",
                    24,
                    None,
                    None,
                    1,
                    0,
                    None,
                ),
                (
                    "demo_obj",
                    "include/linux/demo.h",
                    10,
                    "data",
                    "data",
                    "u8[]",
                    32,
                    None,
                    None,
                    0,
                    1,
                    0,
                ),
                (
                    "demo_obj",
                    "drivers/net/demo_drv.c",
                    50,
                    "drv_id",
                    "drv_id",
                    "int",
                    0,
                    None,
                    None,
                    0,
                    0,
                    None,
                ),
            ],
            types=[
                (
                    "demo_obj",
                    32,
                    "struct demo_obj",
                    "INT",
                    "unsigned long",
                    "flags",
                    0,
                    64,
                    64,
                    0,
                ),
                (
                    "demo_obj",
                    32,
                    "struct demo_obj",
                    "INT",
                    "__u8",
                    "pkt_type",
                    64,
                    3,
                    67,
                    0,
                ),
                (
                    "demo_obj",
                    32,
                    "struct demo_obj::union u",
                    "INT",
                    "u64",
                    "u.cookie",
                    128,
                    64,
                    192,
                    0,
                ),
                (
                    "demo_obj",
                    32,
                    "struct demo_obj",
                    "PTR",
                    "func_proto (void)(struct demo_obj *)",
                    "destructor",
                    192,
                    64,
                    256,
                    0,
                ),
                (
                    "demo_obj",
                    32,
                    "struct demo_obj",
                    "ARRAY<INT>",
                    "u8",
                    "data",
                    256,
                    0,
                    256,
                    1,
                ),
                (
                    "btf_only_struct",
                    16,
                    "struct btf_only_struct",
                    "INT",
                    "u64",
                    "val",
                    0,
                    64,
                    64,
                    0,
                ),
            ],
            kmalloc_calls=[
                (
                    "net/core/demo.c:18:10:18:45",
                    "call to kzalloc",
                    "demo_obj",
                    "include/linux/demo.h:10:1:10:15",
                    32,
                    "GFP_KERNEL",
                    None,
                    "struct_size(p, data, n)",
                    "true",
                ),
            ],
            allocs=[
                (
                    "call to kzalloc",
                    "demo_obj",
                    "32",
                    "32",
                    "4096",
                    "variable",
                    "3264",
                    "3264",
                    "GFP_KERNEL",
                    "net/core/demo.c",
                    18,
                    10,
                    "1",
                    "include/linux/demo.h",
                    "10",
                    "1",
                    "true",
                ),
            ],
            field_access=[
                (
                    "write",
                    "cookie",
                    "demo_obj",
                    "net/core/demo.c:45:2:45:18",
                    "write_demo_fn",
                    "net/core/demo.c",
                    45,
                ),
                (
                    "exec",
                    "destructor",
                    "demo_obj",
                    "net/core/demo.c:52:2:52:20",
                    "write_demo_fn",
                    "net/core/demo.c",
                    52,
                ),
                (
                    "read",
                    "cookie",
                    "demo_obj",
                    "net/core/demo.c:72:6:72:20",
                    "read_demo_fn",
                    "net/core/demo.c",
                    72,
                ),
            ],
            conditions=[
                (
                    "capable",
                    "net/core/demo.c:40:6:40:25",
                    "__guarded_span__",
                    "12",
                    "write_demo_fn",
                    "net/core/demo.c:38:1:60:1",
                ),
            ],
            ops_targets=[
                (
                    "net/core/demo.c:5",
                    "demo_obj",
                    "destructor",
                    "demo_dtor_cb",
                    "net/core/demo.c",
                    100,
                    110,
                    "net/core/demo.c",
                    52,
                    35,
                    60,
                ),
            ],
        )

    def test_normalize_struct_name(self) -> None:
        """Verify leading struct/union qualifiers are stripped."""
        self.assertEqual(
            structs_lib.normalize_struct_name("struct sk_buff"), "sk_buff"
        )
        self.assertEqual(
            structs_lib.normalize_struct_name("const union demo_u"), "demo_u"
        )
        self.assertEqual(
            structs_lib.normalize_struct_name("demo_obj"), "demo_obj"
        )

    def test_locate_definitions_and_disambiguation(self) -> None:
        """Verify multiple definitions, file filter, and boot exclusion."""
        defs = structs_lib.locate_struct_definitions(self.conn, "demo_obj")
        self.assertEqual(len(defs), 2)
        self.assertEqual(defs[0]["file"], "drivers/net/demo_drv.c")
        self.assertEqual(defs[1]["file"], "include/linux/demo.h")

        filtered = structs_lib.locate_struct_definitions(
            self.conn, "demo_obj", file_filter="demo.h"
        )
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["byte_size"], 32)
        self.assertTrue(filtered[0]["has_flex_member"])

        boot_defs = structs_lib.locate_struct_definitions(
            self.conn, "boot_obj"
        )
        self.assertEqual(boot_defs, [])

    def test_btf_fallback_when_not_in_struct_locations(self) -> None:
        """Verify BTF types fallback when struct is only in types table."""
        res = structs_lib.inspect_struct_with_conn(
            self.conn, "btf_only_struct"
        )
        self.assertEqual(res["count"], 1)
        d0 = res["definitions"][0]
        self.assertEqual(d0["source"], "btf_types")
        self.assertEqual(d0["byte_size"], 16)
        self.assertEqual(len(d0["fields"]), 1)
        self.assertEqual(d0["fields"][0]["field_name"], "val")

    def test_layout_and_btf_parity(self) -> None:
        """Verify field offsets, bitfields, flex arrays, and BTF match."""
        res = structs_lib.inspect_struct_with_conn(
            self.conn, "demo_obj", file_filter="include/linux/demo.h"
        )
        self.assertFalse(res["is_ambiguous"])
        d0 = res["definitions"][0]
        btf_val = d0["btf_validation"]
        self.assertTrue(btf_val["btf_present"])
        self.assertTrue(btf_val["size_match"])
        self.assertEqual(btf_val["checked_fields"], 5)
        self.assertEqual(btf_val["matched_fields"], 5)

        fields_by_path = {f["field_path"]: f for f in d0["fields"]}
        self.assertEqual(fields_by_path["u.cookie"]["byte_offset"], 16)
        self.assertTrue(fields_by_path["destructor"]["is_funcptr"])
        self.assertTrue(fields_by_path["data"]["is_flex"])
        self.assertEqual(fields_by_path["pkt_type"]["bit_size"], 3)

    def test_allocations_and_field_accesses(self) -> None:
        """Verify merged heap allocations and gated field_access sites."""
        res = structs_lib.inspect_struct_with_conn(
            self.conn, "struct demo_obj", file_filter="demo.h"
        )
        allocs = res["allocations"]
        self.assertEqual(len(allocs), 1)
        self.assertEqual(allocs[0]["function"], "alloc_demo")
        self.assertTrue(allocs[0]["is_syscall_reachable"])
        self.assertTrue(allocs[0]["is_flexible"])
        self.assertEqual(allocs[0]["size_max"], 4096)

        fa = res["field_accesses"]
        self.assertEqual(fa["counts"]["total"], 3)
        self.assertEqual(fa["counts"]["write"], 1)
        self.assertEqual(fa["counts"]["exec"], 1)
        self.assertEqual(fa["counts"]["read"], 1)

        write_item = fa["write"][0]
        self.assertEqual(write_item["function"], "write_demo_fn")
        self.assertTrue(write_item["is_syscall_reachable"])
        self.assertIn("CAP_NET_ADMIN", write_item["gates"][0]["cap_str"])

        read_item = fa["read"][0]
        self.assertTrue(read_item["is_entry_reachable"])

    def test_cli_json_and_text_with_shorthand_and_source(self) -> None:
        """Verify CLI --struct demo_obj.cookie and --include-source."""
        hdr_dir = os.path.join(self.tmp_dir, "include", "linux")
        os.makedirs(hdr_dir, exist_ok=True)
        hdr_file = os.path.join(hdr_dir, "demo.h")
        with open(hdr_file, "w", encoding="utf-8") as f:
            for i in range(1, 25):
                f.write(f"/* line {i} */ struct demo_obj_line_{i};\n")

        buf = io.StringIO()
        with patch(
            "sys.argv",
            [
                "inspect_struct.py",
                "--db",
                self.db_path,
                "--struct",
                "demo_obj.cookie",
                "--file",
                "demo.h",
                "--repo-dir",
                self.tmp_dir,
                "--include-source",
                "--format",
                "json",
            ],
        ), patch("sys.stdout", buf):
            cli_mod.main()
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["query"]["struct"], "demo_obj")
        self.assertEqual(payload["query"]["field"], "cookie")
        self.assertEqual(len(payload["definitions"][0]["fields"]), 1)
        self.assertTrue(len(payload["definitions"][0]["source_lines"]) > 0)

        text_buf = io.StringIO()
        with patch(
            "sys.argv",
            [
                "inspect_struct.py",
                "--db",
                self.db_path,
                "--struct",
                "demo_obj",
                "--format",
                "text",
            ],
        ), patch("sys.stdout", text_buf):
            cli_mod.main()
        text_out = text_buf.getvalue()
        self.assertIn("STRUCT & OBJECT LIFECYCLE INSPECTOR", text_out)
        self.assertIn("HEAP ALLOCATIONS (1):", text_out)
        self.assertIn("FIELD ACCESSES (total=3:", text_out)
        self.assertIn("OPS FUNCTION-POINTER SLOTS (1):", text_out)


if __name__ == "__main__":
    unittest.main()
