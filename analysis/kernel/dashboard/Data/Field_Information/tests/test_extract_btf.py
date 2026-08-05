#!/usr/bin/python3

import unittest
import sqlite3
import tempfile
import os
import sys
import importlib

# Ensure parent directory is in sys.path
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import module with hyphen
extract_btf = importlib.import_module("extract-btf")
get_shallow = extract_btf.get_shallow
create_types_table = extract_btf.create_types_table
create_sql_db = extract_btf.create_sql_db


class TestExtractBTF(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_basic_struct_and_pointer(self):
        """Test extraction of basic integer field and pointer to struct."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "int", "nr_bits": 32, "size": 4},
            2: {"id": 2, "kind": "STRUCT", "name": "target_struct", "size": 16, "members": []},
            3: {"id": 3, "kind": "PTR", "name": "", "type_id": 2},
            4: {
                "id": 4,
                "kind": "STRUCT",
                "name": "foo",
                "size": 16,
                "members": [
                    {"name": "val", "type_id": 1, "bits_offset": 0},
                    {"name": "ptr", "type_id": 3, "bits_offset": 64},
                ],
            },
        }

        # Test val
        res_val = get_shallow(types, "foo", 16, types[4]["members"][0], "foo")
        self.assertEqual(len(res_val), 1)
        self.assertEqual(res_val[0]["name"], "val")
        self.assertEqual(res_val[0]["kind"], "INT")
        self.assertEqual(res_val[0]["type"], "int")
        self.assertEqual(res_val[0]["bits_offset"], 0)
        self.assertEqual(res_val[0]["nr_bits"], 32)

        # Test ptr
        res_ptr = get_shallow(types, "foo", 16, types[4]["members"][1], "foo")
        self.assertEqual(len(res_ptr), 1)
        self.assertEqual(res_ptr[0]["name"], "ptr")
        self.assertEqual(res_ptr[0]["kind"], "PTR")
        self.assertEqual(res_ptr[0]["type"], "struct target_struct *")
        self.assertEqual(res_ptr[0]["bits_offset"], 64)
        self.assertEqual(res_ptr[0]["nr_bits"], 64)

    def test_anonymous_struct_and_union(self):
        """Test pointers pointing to anonymous structs and unions."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "int", "nr_bits": 32, "size": 4},
            2: {
                "id": 2,
                "kind": "STRUCT",
                "name": "(anon)",
                "size": 8,
                "members": [{"name": "f1", "type_id": 1, "bits_offset": 0}],
            },
            3: {
                "id": 3,
                "kind": "UNION",
                "name": "(anon)",
                "size": 8,
                "members": [{"name": "u1", "type_id": 1, "bits_offset": 0}],
            },
            4: {"id": 4, "kind": "PTR", "name": "", "type_id": 2},
            5: {"id": 5, "kind": "PTR", "name": "", "type_id": 3},
            6: {
                "id": 6,
                "kind": "STRUCT",
                "name": "outer",
                "size": 16,
                "members": [
                    {"name": "anon_struct_ptr", "type_id": 4, "bits_offset": 0},
                    {"name": "anon_union_ptr", "type_id": 5, "bits_offset": 64},
                ],
            },
        }

        res_s = get_shallow(types, "outer", 16, types[6]["members"][0], "outer")
        self.assertEqual(len(res_s), 1)
        self.assertEqual(res_s[0]["kind"], "PTR")
        self.assertIn("struct {int f1} *", res_s[0]["type"])

        res_u = get_shallow(types, "outer", 16, types[6]["members"][1], "outer")
        self.assertEqual(len(res_u), 1)
        self.assertEqual(res_u[0]["kind"], "PTR")
        self.assertIn("union {int u1} *", res_u[0]["type"])

    def test_typedef_handling(self):
        """Test TYPEDEF resolution and TYPEDEF naming for inline anonymous structs."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "unsigned int", "nr_bits": 32, "size": 4},
            2: {"id": 2, "kind": "TYPEDEF", "name": "u32", "type_id": 1},
            3: {
                "id": 3,
                "kind": "STRUCT",
                "name": "(anon)",
                "size": 4,
                "members": [{"name": "type", "type_id": 2, "bits_offset": 0}],
            },
            4: {"id": 4, "kind": "TYPEDEF", "name": "efi_memory_desc_t", "type_id": 3},
            5: {
                "id": 5,
                "kind": "STRUCT",
                "name": "holder",
                "size": 4,
                "members": [{"name": "desc", "type_id": 4, "bits_offset": 0}],
            },
        }

        res = get_shallow(types, "holder", 4, types[5]["members"][0], "holder")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["name"], "desc.type")
        self.assertEqual(res[0]["kind"], "INT")
        self.assertEqual(res[0]["parent_type"], "efi_memory_desc_t")
        self.assertEqual(types[3]["name"], "efi_memory_desc_t")

    def test_type_tag_and_modifiers(self):
        """Test modifiers like TYPE_TAG, CONST, VOLATILE, RESTRICT."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "int", "nr_bits": 32, "size": 4},
            2: {"id": 2, "kind": "TYPE_TAG", "name": "user", "type_id": 1},
            3: {"id": 3, "kind": "CONST", "name": "", "type_id": 2},
            4: {
                "id": 4,
                "kind": "STRUCT",
                "name": "tagged_struct",
                "size": 4,
                "members": [{"name": "user_ptr", "type_id": 3, "bits_offset": 0}],
            },
        }

        res = get_shallow(types, "tagged_struct", 4, types[4]["members"][0], "tagged_struct")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["kind"], "INT")
        self.assertEqual(res[0]["type"], "int")

    def test_array_and_flex_array(self):
        """Test array handling and bit end calculations."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "char", "nr_bits": 8, "size": 1},
            2: {"id": 2, "kind": "ARRAY", "type_id": 1, "nr_elems": 4, "index_type_id": 1},
            3: {
                "id": 3,
                "kind": "STRUCT",
                "name": "arr_struct",
                "size": 4,
                "members": [{"name": "buf", "type_id": 2, "bits_offset": 0}],
            },
        }

        res = get_shallow(types, "arr_struct", 4, types[3]["members"][0], "arr_struct")
        self.assertEqual(len(res), 4)
        self.assertEqual(res[0]["name"], "buf[0]")
        self.assertEqual(res[3]["name"], "buf[3]")

    def test_enums_32_and_64(self):
        """Test ENUM and ENUM64 handling."""
        types = {
            1: {"id": 1, "kind": "ENUM", "name": "my_enum", "size": 4, "vlen": 1},
            2: {"id": 2, "kind": "ENUM64", "name": "my_enum64", "size": 8, "vlen": 1},
            3: {
                "id": 3,
                "kind": "STRUCT",
                "name": "enum_struct",
                "size": 12,
                "members": [
                    {"name": "e32", "type_id": 1, "bits_offset": 0},
                    {"name": "e64", "type_id": 2, "bits_offset": 32},
                ],
            },
        }

        res_e32 = get_shallow(types, "enum_struct", 12, types[3]["members"][0], "enum_struct")
        self.assertEqual(res_e32[0]["nr_bits"], 32)

        res_e64 = get_shallow(types, "enum_struct", 12, types[3]["members"][1], "enum_struct")
        self.assertEqual(res_e64[0]["nr_bits"], 64)

    def test_bitfields(self):
        """Test bitfield size and offset calculations."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "int", "nr_bits": 32, "size": 4},
            2: {
                "id": 2,
                "kind": "STRUCT",
                "name": "bf_struct",
                "size": 4,
                "members": [
                    {"name": "f1", "type_id": 1, "bits_offset": 0, "bitfield_size": 6},
                    {"name": "f2", "type_id": 1, "bits_offset": 6, "bitfield_size": 8},
                ],
            },
            3: {
                "id": 3,
                "kind": "STRUCT",
                "name": "container",
                "size": 4,
                "members": [{"name": "bf", "type_id": 2, "bits_offset": 0}],
            },
        }

        res = get_shallow(types, "container", 4, types[3]["members"][0], "container")
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]["name"], "bf.f1:6")
        self.assertEqual(res[1]["name"], "bf.f2:8")

    def test_func_proto(self):
        """Test function pointer prototypes."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "int", "nr_bits": 32, "size": 4},
            2: {
                "id": 2,
                "kind": "FUNC_PROTO",
                "name": "(anon)",
                "ret_type_id": 1,
                "params": [{"name": "arg1", "type_id": 1}],
            },
            3: {"id": 3, "kind": "PTR", "name": "", "type_id": 2},
            4: {
                "id": 4,
                "kind": "STRUCT",
                "name": "cb_struct",
                "size": 8,
                "members": [{"name": "callback", "type_id": 3, "bits_offset": 0}],
            },
        }

        res = get_shallow(types, "cb_struct", 8, types[4]["members"][0], "cb_struct")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["kind"], "PTR")
        self.assertIn("int (*<name>) (int arg1)", res[0]["type"])

    def test_sqlite_db_creation(self):
        """Test full SQLite database table creation and insertion."""
        json_data = {
            "types": [
                {"id": 1, "kind": "INT", "name": "int", "nr_bits": 32, "size": 4},
                {
                    "id": 2,
                    "kind": "STRUCT",
                    "name": "sample_struct",
                    "size": 4,
                    "members": [{"name": "field_a", "type_id": 1, "bits_offset": 0}],
                },
            ]
        }

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            db_path = tmp_db.name

        try:
            create_sql_db(db_path, json_data)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM types;")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 1)

            cursor.execute("SELECT struct_name, name, type, kind FROM types;")
            row = cursor.fetchone()
            self.assertEqual(row, ("sample_struct", "field_a", "int", "INT"))
            conn.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_existing_btf_db_integrity(self):
        """Integration test verifying integrity of generated btf_6.18.db or btf.db if present."""
        db_candidates = [
            os.path.join(parent_dir, "btf_6.18.db"),
            os.path.join(parent_dir, "btf.db"),
        ]
        target_db = next((f for f in db_candidates if os.path.exists(f)), None)
        if not target_db:
            self.skipTest("No btf.db database file found on disk for integration testing.")

        conn = sqlite3.connect(target_db)
        cursor = conn.cursor()

        # Verify row count
        cursor.execute("SELECT count(*) FROM types;")
        total_rows = cursor.fetchone()[0]
        self.assertGreater(total_rows, 0, f"Database {target_db} has 0 rows.")

        # Verify no nulls in required columns
        cursor.execute("""
            SELECT count(*) FROM types 
            WHERE struct_name IS NULL OR kind IS NULL OR type IS NULL OR name IS NULL;
        """)
        null_count = cursor.fetchone()[0]
        self.assertEqual(null_count, 0, f"Database {target_db} contains NULL in required fields.")

        # Verify bits offset logic (bits_end >= bits_offset)
        cursor.execute("SELECT count(*) FROM types WHERE bits_end < bits_offset;")
        invalid_offsets = cursor.fetchone()[0]
        self.assertEqual(invalid_offsets, 0, f"Database {target_db} has invalid bit ranges.")

        conn.close()

    def test_vmlinux_binary_validation(self):
        """Test vmlinux CLI argument validation function."""
        # Non-existent file should raise ValueError
        with self.assertRaises(ValueError):
            extract_btf.vmlinux("/nonexistent/path/to/vmlinux")

        # Test against existing vmlinux if present
        vmlinux_path = "/usr/local/google/home/ametla/prodkernel_vmlinux/vmlinux-6.18.20-smp-DEV"
        if os.path.exists(vmlinux_path):
            validated_path = extract_btf.vmlinux(vmlinux_path)
            self.assertEqual(validated_path, os.path.abspath(vmlinux_path))

    def test_check_tools(self):
        """Test check_tools helper function to verify system Pahole, Bpftool, Readelf binaries."""
        try:
            extract_btf.check_tools()
        except subprocess.CalledProcessError:
            self.fail("check_tools() failed unexpectedly; system tools (pahole, bpftool, readelf) should be installed.")

    def test_empty_btf_raises_error(self):
        """Test that create_types_table raises ValueError when given JSON without struct types."""
        json_data = {"types": [{"id": 1, "kind": "INT", "name": "int", "nr_bits": 32, "size": 4}]}
        conn = sqlite3.connect(":memory:")
        with self.assertRaises(ValueError):
            create_types_table(json_data, conn)
        conn.close()

    def test_flexible_array_members(self):
        """Test detection of flexible array members (is_flex flag)."""
        types = {
            1: {"id": 1, "kind": "INT", "name": "char", "nr_bits": 8, "size": 1},
            2: {"id": 2, "kind": "ARRAY", "type_id": 1, "nr_elems": 0, "index_type_id": 1},
            3: {
                "id": 3,
                "kind": "STRUCT",
                "name": "flex_struct",
                "size": 4,
                "members": [{"name": "flex_buf", "type_id": 2, "bits_offset": 32}],
            },
        }

        res = get_shallow(types, "flex_struct", 4, types[3]["members"][0], "flex_struct")
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0]["is_flex"])
        self.assertEqual(res[0]["kind"], "ARRAY<INT>")

    def test_real_vmlinux_well_known_structs(self):
        """Integration test verifying essential Linux kernel structs (task_struct, inode, file) in extracted DB."""
        db_candidates = [
            os.path.join(parent_dir, "btf_6.18.db"),
            os.path.join(parent_dir, "btf.db"),
        ]
        target_db = next((f for f in db_candidates if os.path.exists(f)), None)
        if not target_db:
            self.skipTest("No btf.db database file found on disk for kernel struct verification.")

        conn = sqlite3.connect(target_db)
        cursor = conn.cursor()

        # Check core kernel structs
        well_known_structs = ["task_struct", "mm_struct", "inode", "file", "sock"]
        for s in well_known_structs:
            cursor.execute("SELECT count(*) FROM types WHERE struct_name = ?;", (s,))
            count = cursor.fetchone()[0]
            self.assertGreater(count, 0, f"Expected struct '{s}' not found in {target_db}.")

        # Check task_struct pid field
        cursor.execute("SELECT type, kind, bits_offset FROM types WHERE struct_name = 'task_struct' AND name = 'pid';")
        row = cursor.fetchone()
        self.assertIsNotNone(row, "task_struct.pid field not found in database.")
        self.assertEqual(row[1], "INT", "task_struct.pid field kind should be INT.")

        conn.close()

    def test_elastic_kernel_objects_fixture(self):
        """Test extraction of elastic kernel objects (msg_msg, user_key_payload, pipe_buffer, sk_buff) using JSON fixture."""
        fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "elastic_structs.json")
        if not os.path.exists(fixture_path):
            self.skipTest("elastic_structs.json fixture file not found.")

        import json
        with open(fixture_path, "r") as f:
            json_data = json.load(f)

        types = {t["id"]: t for t in json_data["types"]}

        # 1. Test msg_msg
        msg_msg_type = next((t for t in json_data["types"] if t["kind"] == "STRUCT" and t.get("name") == "msg_msg"), None)
        self.assertIsNotNone(msg_msg_type, "msg_msg struct not found in fixture.")
        self.assertEqual(msg_msg_type["size"], 48, "msg_msg header size should be 48 bytes.")

        msg_fields = []
        for m in msg_msg_type["members"]:
            msg_fields += get_shallow(types, "msg_msg", 48, m, "msg_msg")

        msg_field_names = [f["name"] for f in msg_fields]
        self.assertIn("m_list.next", msg_field_names)
        self.assertIn("m_type", msg_field_names)
        self.assertIn("m_ts", msg_field_names)
        self.assertIn("next", msg_field_names)
        self.assertIn("security", msg_field_names)

        # Check next field type in msg_msg
        next_field = next(f for f in msg_fields if f["name"] == "next")
        self.assertEqual(next_field["kind"], "PTR")
        self.assertIn("msg_msgseg", next_field["type"])

        # 2. Test user_key_payload (flexible array member char data[])
        key_type = next((t for t in json_data["types"] if t["kind"] == "STRUCT" and t.get("name") == "user_key_payload"), None)
        self.assertIsNotNone(key_type, "user_key_payload struct not found in fixture.")

        key_fields = []
        for m in key_type["members"]:
            key_fields += get_shallow(types, "user_key_payload", key_type["size"], m, "user_key_payload")

        key_field_names = [f["name"] for f in key_fields]
        self.assertIn("datalen", key_field_names)

        data_field = next((f for f in key_fields if f["name"] == "data"), None)
        self.assertIsNotNone(data_field, "user_key_payload.data field not found.")
        self.assertTrue(data_field["is_flex"], "user_key_payload.data should be detected as flexible array member.")

        # 3. Test msg_msgseg
        seg_type = next((t for t in json_data["types"] if t["kind"] == "STRUCT" and t.get("name") == "msg_msgseg"), None)
        self.assertIsNotNone(seg_type, "msg_msgseg struct not found in fixture.")
        self.assertEqual(seg_type["size"], 8, "msg_msgseg header size should be 8 bytes.")

        # 4. Test pipe_buffer
        pipe_type = next((t for t in json_data["types"] if t["kind"] == "STRUCT" and t.get("name") == "pipe_buffer"), None)
        self.assertIsNotNone(pipe_type, "pipe_buffer struct not found in fixture.")
        pipe_fields = []
        for m in pipe_type["members"]:
            pipe_fields += get_shallow(types, "pipe_buffer", pipe_type["size"], m, "pipe_buffer")
        pipe_names = [f["name"] for f in pipe_fields]
        self.assertIn("page", pipe_names)
        self.assertIn("offset", pipe_names)
        self.assertIn("len", pipe_names)
        self.assertIn("flags", pipe_names)


if __name__ == "__main__":
    unittest.main()
