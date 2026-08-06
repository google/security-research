#!/usr/bin/env python3

import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

# Add parent directory to sys.path
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import import_allocations
import import_conditions
import import_conditions_reachable
import import_configs
import import_field_access
import import_functions
import import_macro_invocations
import import_macros
import import_ops_targets
import import_syscall_reachable
from utils import detect_prefix, trim_filename


class TestDetectPrefixAndTrim(unittest.TestCase):
    def test_detect_prefix_and_trim(self):
        sample_paths = [
            "/build/workspace/custom_repo/arch/x86/kernel/main.c",
            "/build/workspace/custom_repo/mm/page_alloc.c",
            "/build/workspace/custom_repo/net/core/dev.c",
        ]
        prefix = detect_prefix(sample_paths)
        self.assertEqual(prefix, "/build/workspace/custom_repo/")

        self.assertEqual(
            trim_filename("/build/workspace/custom_repo/arch/x86/kernel/main.c", prefix),
            "arch/x86/kernel/main.c",
        )
        self.assertEqual(
            trim_filename("/build/workspace/custom_repo/my_custom_driver/foo.c", prefix),
            "my_custom_driver/foo.c",
        )

    def test_detect_prefix_with_leading_unknown_dirs(self):
        sample_paths = [
            "/home/user/repo/linux_tree/vendor_subsystem/driver1.c",
            "/home/user/repo/linux_tree/vendor_subsystem/driver2.c",
            "/home/user/repo/linux_tree/custom_module/mod.c",
            "/home/user/repo/linux_tree/arch/x86/boot/main.c",
            "/home/user/repo/linux_tree/mm/slab.c",
            "/home/user/repo/linux_tree/net/socket.c",
        ]
        prefix = detect_prefix(sample_paths)
        self.assertEqual(prefix, "/home/user/repo/linux_tree/")

        self.assertEqual(
            trim_filename("/home/user/repo/linux_tree/vendor_subsystem/driver1.c", prefix),
            "vendor_subsystem/driver1.c",
        )

    def test_detect_prefix_empty(self):
        self.assertEqual(detect_prefix([]), "")
        self.assertEqual(trim_filename(""), "")


class BaseImporterTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_codeql.db")
        self.csv_path = os.path.join(self.tmp_dir.name, "test.csv")

    def tearDown(self):
        self.tmp_dir.cleanup()


class TestImportAllocations(BaseImporterTest):
    def test_import_allocations(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(
                'call_site,call_expr,struct_type,struct_def,struct_size,flags,alloc_size,sizeof_expr,is_flexible\n'
                '"linux/mm/slab.c:100","kmalloc()","struct foo","linux/include/foo.h",64,"GFP_KERNEL",64,"sizeof(struct foo)","false"\n'
                '"invalid_row"\n'
            )

        count = import_allocations.import_allocations_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT call_site, struct_def FROM kmalloc_calls")
        row = cursor.fetchone()
        self.assertEqual(row[0], "mm/slab.c:100")
        self.assertEqual(row[1], "include/foo.h")
        conn.close()

    def test_import_allocations_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write('h1,h2,h3,h4,h5,h6,h7,h8,h9\n"site","expr","type","def",32,"flag",32,"sof","false"\n')

        with patch("sys.argv", ["import_allocations.py", self.csv_path, self.db_path]):
            import_allocations.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM kmalloc_calls")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_allocations.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_allocations.main()


class TestImportFunctions(BaseImporterTest):
    def test_import_functions(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(
                "function_name,file_path,start_line,end_line\n"
                'sock_create,"linux/net/socket.c",100,200\n'
                'bad_lines,"linux/net/socket.c",invalid,bad\n'
                'short_row\n'
            )

        count = import_functions.import_functions_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT function_name, file_path FROM function_locations")
        row = cursor.fetchone()
        self.assertEqual(row, ("sock_create", "net/socket.c"))
        conn.close()

    def test_import_functions_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("fn,path,start,end\nfn1,path1,10,20\n")

        with patch("sys.argv", ["import_functions.py", self.csv_path, self.db_path]):
            import_functions.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM function_locations")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_functions.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_functions.main()


class TestImportConfigs(BaseImporterTest):
    def test_import_configs(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("function_name,config\nsock_create,CONFIG_NET\nshort\n")

        count = import_configs.import_configs_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT function_name, config FROM configs")
        self.assertEqual(cursor.fetchone(), ("sock_create", "CONFIG_NET"))
        conn.close()

    def test_import_configs_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("fn,config\nfn1,CONFIG_FOO\n")

        with patch("sys.argv", ["import_configs.py", self.csv_path, self.db_path]):
            import_configs.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM configs")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_configs.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_configs.main()


class TestImportMacroInvocations(BaseImporterTest):
    def test_import_macro_invocations(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(
                "macroinvocation_name,file_path,start_line,end_line\n"
                'MY_MACRO,"linux/net/socket.c",10,20\n'
                'bad_macro,"linux/net/socket.c",x,y\n'
            )

        count = import_macro_invocations.import_macroinvocations_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT macroinvocation_name, file_path FROM macroinvocation_locations")
        self.assertEqual(cursor.fetchone(), ("MY_MACRO", "net/socket.c"))
        conn.close()

    def test_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("m,p,s,e\nm1,p1,1,2\n")

        with patch("sys.argv", ["import_macro_invocations.py", self.csv_path, self.db_path]):
            import_macro_invocations.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM macroinvocation_locations")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_macro_invocations.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_macro_invocations.main()


class TestImportMacros(BaseImporterTest):
    def test_import_macros(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(
                "macro_name,file_path,start_line,end_line\n"
                'MY_MACRO,"linux/include/net.h",5,15\n'
                'bad_row,"linux/include/net.h",bad,bad\n'
            )

        count = import_macros.import_macros_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT macro_name, file_path FROM macro_locations")
        self.assertEqual(cursor.fetchone(), ("MY_MACRO", "include/net.h"))
        conn.close()

    def test_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("m,p,s,e\nm1,p1,1,2\n")

        with patch("sys.argv", ["import_macros.py", self.csv_path, self.db_path]):
            import_macros.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM macro_locations")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_macros.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_macros.main()


class TestImportConditions(BaseImporterTest):
    def test_import_conditions(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("type,def,cond,arg,call,call_loc\n\"if\",\"linux/net/foo.c\",\"x > 0\",\"x\",\"bar\",\"linux/net/bar.c\"\nshort\n")

        count = import_conditions.import_conditions_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT definition, call_location FROM conditions")
        self.assertEqual(cursor.fetchone(), ("net/foo.c", "net/bar.c"))
        conn.close()

    def test_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("t,d,c,a,cl,loc\n1,2,3,4,5,6\n")

        with patch("sys.argv", ["import_conditions.py", self.csv_path, self.db_path]):
            import_conditions.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM conditions")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_conditions.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_conditions.main()


class TestImportSyscallReachable(BaseImporterTest):
    def test_import_syscall_reachable(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("syscall,fn,sys_loc,fn_loc\n\"sys_bind\",\"sock_create\",\"linux/arch/x86/sys.c\",\"linux/net/sock.c\"\nshort\n")

        count = import_syscall_reachable.import_syscall_reachable_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT syscall_location, function_location FROM syscall_node")
        self.assertEqual(cursor.fetchone(), ("arch/x86/sys.c", "net/sock.c"))
        conn.close()

    def test_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("s,f,sl,fl\ns,f,sl,fl\n")

        with patch("sys.argv", ["import_syscall_reachable.py", self.csv_path, self.db_path]):
            import_syscall_reachable.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM syscall_node")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_syscall_reachable.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_syscall_reachable.main()


class TestImportConditionsReachable(BaseImporterTest):
    def test_import_conditions_reachable(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("cond,fn,cond_loc,fn_loc\n\"IS_ERR\",\"sock_create\",\"linux/include/err.h\",\"linux/net/sock.c\"\nshort\n")

        count = import_conditions_reachable.import_conditions_reachable_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT conditions_location, function_location FROM conditions_node")
        self.assertEqual(cursor.fetchone(), ("include/err.h", "net/sock.c"))
        conn.close()

    def test_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("c,f,cl,fl\nc,f,cl,fl\n")

        with patch("sys.argv", ["import_conditions_reachable.py", self.csv_path, self.db_path]):
            import_conditions_reachable.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM conditions_node")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_conditions_reachable.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_conditions_reachable.main()


class TestImportFieldAccess(BaseImporterTest):
    def test_import_field_access(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(
                "type,field,parent,loc\n"
                '"struct foo","bar","parent_fn","linux/net/foo.c"\n'
                '"unknown","bar","parent_fn","linux/net/foo.c"\n'  # should be skipped
                'short\n'
            )

        count = import_field_access.import_field_access_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT location FROM field_access")
        self.assertEqual(cursor.fetchone()[0], "net/foo.c")
        conn.close()

    def test_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("t,f,p,l\nt,f,p,l\n")

        with patch("sys.argv", ["import_field_access.py", self.csv_path, self.db_path]):
            import_field_access.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM field_access")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_field_access.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_field_access.main()


class TestImportOpsTargets(BaseImporterTest):
    def test_import_ops_targets(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(
                "def,parent,field,target,target_file,target_start,target_end,exprcall_file,exprcall_line,exprcall_pstart,exprcall_pend\n"
                '"linux/net/def.c","struct proto","bind","sys_bind","linux/arch/x86/sys.c",10,20,"linux/kernel/expr.c",15,10,30\n'
                '"unknown","p","f","t","tf",1,2,"ef",1,1,1\n'  # should be skipped
                'short\n'
            )

        count = import_ops_targets.import_ops_targets_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT definition, target_file, exprcall_file FROM ops_targets")
        self.assertEqual(cursor.fetchone(), ("net/def.c", "arch/x86/sys.c", "kernel/expr.c"))
        conn.close()

    def test_cli_main(self):
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("d,p,f,t,tf,ts,te,ef,el,eps,epe\nd,p,f,t,tf,1,2,ef,1,1,1\n")

        with patch("sys.argv", ["import_ops_targets.py", self.csv_path, self.db_path]):
            import_ops_targets.main()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM ops_targets")
        self.assertEqual(cursor.fetchone()[0], 1)
        conn.close()

    def test_cli_missing_csv(self):
        missing_csv = os.path.join(self.tmp_dir.name, "nonexistent.csv")
        with patch("sys.argv", ["import_ops_targets.py", missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                import_ops_targets.main()


if __name__ == "__main__":
    unittest.main()
