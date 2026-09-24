#!/usr/bin/env python3
"""Unit tests for CodeQL CSV and SARIF SQLite database importers."""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from typing import Any, Callable
import unittest
from unittest.mock import patch

# Add parent directory to sys.path before importing local modules.
PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# pylint: disable=wrong-import-position
import import_all_calls
import import_allocations
import import_allocs
import import_conditions
import import_conditions_reachable
import import_configs
import import_field_access
import import_functions
import import_macro_invocations
import import_macros
import import_ops_targets
import import_syscall_node
from utils import detect_prefix, trim_filename
# pylint: enable=wrong-import-position


class TestDetectPrefixAndTrim(unittest.TestCase):
    """Tests for kernel root prefix detection and file path trimming."""

    def test_detect_prefix_and_trim(self):
        """Verifies root prefix detection and trimming on standard paths."""
        sample_paths = [
            "/build/workspace/custom_repo/arch/x86/kernel/main.c",
            "/build/workspace/custom_repo/mm/page_alloc.c",
            "/build/workspace/custom_repo/net/core/dev.c",
        ]
        prefix = detect_prefix(sample_paths)
        self.assertEqual(prefix, "/build/workspace/custom_repo/")

        self.assertEqual(
            trim_filename(
                "/build/workspace/custom_repo/arch/x86/kernel/main.c", prefix
            ),
            "arch/x86/kernel/main.c",
        )
        self.assertEqual(
            trim_filename(
                "/build/workspace/custom_repo/my_custom_driver/foo.c", prefix
            ),
            "my_custom_driver/foo.c",
        )

    def test_detect_prefix_with_leading_unknown_dirs(self):
        """Verifies majority prefix detection when custom directories exist."""
        sample_paths = [
            "/workspace/repo/linux_tree/vendor_subsystem/driver1.c",
            "/workspace/repo/linux_tree/vendor_subsystem/driver2.c",
            "/workspace/repo/linux_tree/custom_module/mod.c",
            "/workspace/repo/linux_tree/arch/x86/boot/main.c",
            "/workspace/repo/linux_tree/mm/slab.c",
            "/workspace/repo/linux_tree/net/socket.c",
        ]
        prefix = detect_prefix(sample_paths)
        self.assertEqual(prefix, "/workspace/repo/linux_tree/")

        self.assertEqual(
            trim_filename(
                "/workspace/repo/linux_tree/vendor_subsystem/driver1.c", prefix
            ),
            "vendor_subsystem/driver1.c",
        )

    def test_detect_prefix_empty(self):
        """Verifies empty inputs return empty strings."""
        self.assertEqual(detect_prefix([]), "")
        self.assertEqual(trim_filename(""), "")

    def test_detect_prefix_and_trim_file_scheme(self):
        """Verifies file:// URI scheme stripping during prefix trimming."""
        sample_paths = [
            "file:///build/workspace/linux_tree/net/socket.c:100:5:100:20",
            "file:///build/workspace/linux_tree/mm/slab.c:50:1:50:10",
        ]
        prefix = detect_prefix(sample_paths)
        self.assertEqual(prefix, "/build/workspace/linux_tree/")
        self.assertEqual(
            trim_filename(
                "file:///build/workspace/linux_tree/net/socket.c:100:5:100:20",
                prefix,
            ),
            "net/socket.c:100:5:100:20",
        )


class BaseImporterTest(unittest.TestCase):
    """Base test case managing temporary SQLite DB and CSV paths."""

    def setUp(self):
        """Creates a temporary directory for test CSV and DB artifacts."""
        super().setUp()
        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp_dir)
        self.db_path = os.path.join(self.tmp_dir, "test_codeql.db")
        self.csv_path = os.path.join(self.tmp_dir, "test.csv")

    def write_test_csv(self, content: str) -> None:
        """Writes `content` to `self.csv_path` using UTF-8 encoding."""
        with open(self.csv_path, "w", encoding="utf-8") as csv_file:
            csv_file.write(content)

    def fetch_one(self, query: str) -> Any:
        """Executes `query` against `self.db_path` and returns `fetchone()`."""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query).fetchone()

    def fetch_all(self, query: str) -> list[Any]:
        """Executes `query` against `self.db_path` and returns `fetchall()`."""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(query).fetchall()

    def assert_cli_main_imports_row(
        self,
        script_name: str,
        csv_content: str,
        main_fn: Callable[[], None],
        table_name: str,
    ) -> None:
        """Runs `main_fn` with patched argv and verifies 1 row was imported."""
        self.write_test_csv(csv_content)
        with patch("sys.argv", [script_name, self.csv_path, self.db_path]):
            main_fn()
        row = self.fetch_one(f"SELECT count(*) FROM {table_name}")
        self.assertEqual(row[0], 1)

    def assert_missing_csv_exits(
        self, script_name: str, main_fn: Callable[[], None]
    ) -> None:
        """Verifies `main_fn` exits when given a nonexistent CSV file path."""
        missing_csv = os.path.join(self.tmp_dir, "nonexistent.csv")
        with patch("sys.argv", [script_name, missing_csv, self.db_path]):
            with self.assertRaises(SystemExit):
                main_fn()


class TestImportAllocations(BaseImporterTest):
    """Tests for `import_allocations.py`."""

    def test_import_allocations(self):
        """Verifies importing valid and malformed allocation CSV rows."""
        self.write_test_csv(
            "call_site,call_expr,struct_type,struct_def,struct_size,"
            "flags,alloc_size,sizeof_expr,is_flexible\n"
            '"linux/mm/slab.c:100","kmalloc()","struct foo",'
            '"linux/include/foo.h",64,"GFP_KERNEL",64,'
            '"sizeof(struct foo)","false"\n'
            '"invalid_row"\n'
        )

        count = import_allocations.import_allocations_to_db(
            self.csv_path, self.db_path
        )
        self.assertEqual(count, 1)

        row = self.fetch_one("SELECT call_site, struct_def FROM kmalloc_calls")
        self.assertEqual(row[0], "mm/slab.c:100")
        self.assertEqual(row[1], "include/foo.h")

    def test_import_allocations_cli_main(self):
        """Verifies CLI entry point for `import_allocations`."""
        self.assert_cli_main_imports_row(
            "import_allocations.py",
            'h1,h2,h3,h4,h5,h6,h7,h8,h9\n'
            '"site","expr","type","def",32,"flag",32,"sof","false"\n',
            import_allocations.main,
            "kmalloc_calls",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_allocations`."""
        self.assert_missing_csv_exits(
            "import_allocations.py", import_allocations.main
        )


class TestImportFunctions(BaseImporterTest):
    """Tests for `import_functions.py`."""

    def test_import_functions(self):
        """Verifies importing function location CSV records."""
        self.write_test_csv(
            "function_name,file_path,start_line,end_line\n"
            'sock_create,"linux/net/socket.c",100,200\n'
            'bad_lines,"linux/net/socket.c",invalid,bad\n'
            "short_row\n"
        )

        count = import_functions.import_functions_to_db(
            self.csv_path, self.db_path
        )
        self.assertEqual(count, 1)

        row = self.fetch_one(
            "SELECT function_name, file_path FROM function_locations"
        )
        self.assertEqual(row, ("sock_create", "net/socket.c"))

    def test_import_functions_cli_main(self):
        """Verifies CLI entry point for `import_functions`."""
        self.assert_cli_main_imports_row(
            "import_functions.py",
            "fn,path,start,end\nfn1,path1,10,20\n",
            import_functions.main,
            "function_locations",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_functions`."""
        self.assert_missing_csv_exits(
            "import_functions.py", import_functions.main
        )


class TestImportConfigs(BaseImporterTest):
    """Tests for `import_configs.py`."""

    def test_import_configs(self):
        """Verifies importing kernel config guard CSV records."""
        self.write_test_csv(
            "config,path,ifdef,endif,else_\n"
            "CONFIG_INTEL_TDX_GUEST,"
            "/build/linux/arch/x86/include/asm/disabled-features.h,84,88,86\n"
            "CONFIG_64BIT,/build/linux/include/linux/mm_types.h,145,148,0\n"
            "short\n"
        )

        count = import_configs.import_configs_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 2)

        rows = self.fetch_all(
            "SELECT config, path, ifdef, endif, else_ "
            "FROM configs ORDER BY ifdef"
        )
        self.assertEqual(
            rows,
            [
                (
                    "CONFIG_INTEL_TDX_GUEST",
                    "arch/x86/include/asm/disabled-features.h",
                    84,
                    88,
                    86,
                ),
                ("CONFIG_64BIT", "include/linux/mm_types.h", 145, 148, 0),
            ],
        )

    def test_import_configs_cli_main(self):
        """Verifies CLI entry point for `import_configs`."""
        self.assert_cli_main_imports_row(
            "import_configs.py",
            "config,path,ifdef,endif,else_\nCONFIG_FOO,net/socket.c,10,20,15\n",
            import_configs.main,
            "configs",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_configs`."""
        self.assert_missing_csv_exits("import_configs.py", import_configs.main)


class TestImportMacroInvocations(BaseImporterTest):
    """Tests for `import_macro_invocations.py`."""

    def test_import_macro_invocations(self):
        """Verifies importing macro invocation location CSV records."""
        self.write_test_csv(
            "macroinvocation_name,file_path,start_line,end_line\n"
            'MY_MACRO,"linux/net/socket.c",10,20\n'
            'bad_macro,"linux/net/socket.c",x,y\n'
        )

        count = import_macro_invocations.import_macroinvocations_to_db(
            self.csv_path, self.db_path
        )
        self.assertEqual(count, 1)

        row = self.fetch_one(
            "SELECT macroinvocation_name, file_path "
            "FROM macroinvocation_locations"
        )
        self.assertEqual(row, ("MY_MACRO", "net/socket.c"))

    def test_cli_main(self):
        """Verifies CLI entry point for `import_macro_invocations`."""
        self.assert_cli_main_imports_row(
            "import_macro_invocations.py",
            "m,p,s,e\nm1,p1,1,2\n",
            import_macro_invocations.main,
            "macroinvocation_locations",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_macro_invocations`."""
        self.assert_missing_csv_exits(
            "import_macro_invocations.py", import_macro_invocations.main
        )


class TestImportMacros(BaseImporterTest):
    """Tests for `import_macros.py`."""

    def test_import_macros(self):
        """Verifies importing macro definition CSV records."""
        self.write_test_csv(
            "macro_name,file_path,start_line,end_line\n"
            'MY_MACRO,"linux/include/net.h",5,15\n'
            'bad_row,"linux/include/net.h",bad,bad\n'
        )

        count = import_macros.import_macros_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        row = self.fetch_one(
            "SELECT macro_name, file_path FROM macro_locations"
        )
        self.assertEqual(row, ("MY_MACRO", "include/net.h"))

    def test_cli_main(self):
        """Verifies CLI entry point for `import_macros`."""
        self.assert_cli_main_imports_row(
            "import_macros.py",
            "m,p,s,e\nm1,p1,1,2\n",
            import_macros.main,
            "macro_locations",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_macros`."""
        self.assert_missing_csv_exits("import_macros.py", import_macros.main)


class TestImportConditions(BaseImporterTest):
    """Tests for `import_conditions.py`."""

    def test_import_conditions(self):
        """Verifies importing condition statement CSV records."""
        self.write_test_csv(
            "type,def,cond,arg,call,call_loc\n"
            '"if","linux/net/foo.c","x > 0","x","bar","linux/net/bar.c"\n'
            "short\n"
        )

        count = import_conditions.import_conditions_to_db(
            self.csv_path, self.db_path
        )
        self.assertEqual(count, 1)

        row = self.fetch_one("SELECT definition, call_location FROM conditions")
        self.assertEqual(row, ("net/foo.c", "net/bar.c"))

    def test_cli_main(self):
        """Verifies CLI entry point for `import_conditions`."""
        self.assert_cli_main_imports_row(
            "import_conditions.py",
            "t,d,c,a,cl,loc\n1,2,3,4,5,6\n",
            import_conditions.main,
            "conditions",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_conditions`."""
        self.assert_missing_csv_exits(
            "import_conditions.py", import_conditions.main
        )


class TestImportConditionsReachable(BaseImporterTest):
    """Tests for `import_conditions_reachable.py`."""

    def test_import_conditions_reachable(self):
        """Verifies importing condition reachability CSV records."""
        self.write_test_csv(
            "cond,fn,cond_loc,fn_loc\n"
            '"IS_ERR","sock_create","linux/include/err.h","linux/net/sock.c"\n'
            "short\n"
        )

        count = import_conditions_reachable.import_conditions_reachable_to_db(
            self.csv_path, self.db_path
        )
        self.assertEqual(count, 1)

        row = self.fetch_one(
            "SELECT conditions_location, function_location "
            "FROM conditions_node"
        )
        self.assertEqual(row, ("include/err.h", "net/sock.c"))

    def test_cli_main(self):
        """Verifies CLI entry point for `import_conditions_reachable`."""
        self.assert_cli_main_imports_row(
            "import_conditions_reachable.py",
            "c,f,cl,fl\nc,f,cl,fl\n",
            import_conditions_reachable.main,
            "conditions_node",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_conditions_reachable`."""
        self.assert_missing_csv_exits(
            "import_conditions_reachable.py", import_conditions_reachable.main
        )


class TestImportFieldAccess(BaseImporterTest):
    """Tests for `import_field_access.py`."""

    def test_import_field_access(self):
        """Verifies importing struct field access CSV records."""
        self.write_test_csv(
            "type,field,parent,loc\n"
            '"struct foo","bar","parent_fn","linux/net/foo.c"\n'
            '"unknown","bar","parent_fn","linux/net/foo.c"\n'
            "short\n"
        )

        count = import_field_access.import_field_access_to_db(
            self.csv_path, self.db_path
        )
        self.assertEqual(count, 1)

        row = self.fetch_one("SELECT location FROM field_access")
        self.assertEqual(row[0], "net/foo.c")

    def test_cli_main(self):
        """Verifies CLI entry point for `import_field_access`."""
        self.assert_cli_main_imports_row(
            "import_field_access.py",
            "t,f,p,l\nt,f,p,l\n",
            import_field_access.main,
            "field_access",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_field_access`."""
        self.assert_missing_csv_exits(
            "import_field_access.py", import_field_access.main
        )


class TestImportOpsTargets(BaseImporterTest):
    """Tests for `import_ops_targets.py`."""

    def test_import_ops_targets(self):
        """Verifies importing ops target call CSV records."""
        self.write_test_csv(
            "def,parent,field,target,target_file,target_start,target_end,"
            "exprcall_file,exprcall_line,exprcall_pstart,exprcall_pend\n"
            '"linux/net/def.c","struct proto","bind","sys_bind",'
            '"linux/arch/x86/sys.c",10,20,"linux/kernel/expr.c",15,10,30\n'
            '"unknown","p","f","t","tf",1,2,"ef",1,1,1\n'
            "short\n"
        )

        count = import_ops_targets.import_ops_targets_to_db(
            self.csv_path, self.db_path
        )
        self.assertEqual(count, 1)

        row = self.fetch_one(
            "SELECT definition, target_file, exprcall_file FROM ops_targets"
        )
        self.assertEqual(row, ("net/def.c", "arch/x86/sys.c", "kernel/expr.c"))

    def test_cli_main(self):
        """Verifies CLI entry point for `import_ops_targets`."""
        self.assert_cli_main_imports_row(
            "import_ops_targets.py",
            "d,p,f,t,tf,ts,te,ef,el,eps,epe\nd,p,f,t,tf,1,2,ef,1,1,1\n",
            import_ops_targets.main,
            "ops_targets",
        )

    def test_cli_missing_csv(self):
        """Verifies missing CSV handling for `import_ops_targets`."""
        self.assert_missing_csv_exits(
            "import_ops_targets.py", import_ops_targets.main
        )


class TestImportSyscallNode(BaseImporterTest):
    """Tests for `import_syscall_node.py`."""

    def setUp(self):
        """Sets up locs.csv and pairs.csv test file paths."""
        super().setUp()
        self.locs_path = os.path.join(self.tmp_dir, "locs.csv")
        self.pairs_path = os.path.join(self.tmp_dir, "pairs.csv")
        self.out_csv = os.path.join(self.tmp_dir, "syscall_node.csv")

    def _write_sample_locs(self) -> None:
        """Writes a 3-row locs.csv with duplicate `hash` function names."""
        with open(self.locs_path, "w", encoding="utf-8") as locs_file:
            locs_file.write(
                '"__do_sys_openat","linux/fs/open.c",100,1,120,20\n'
                '"hash","linux/fs/inode.c",50,1,60,20\n'
                '"hash","linux/kernel/bpf/bloom_filter.c",70,1,80,20\n'
            )

    def test_import_3col_exact_join(self):
        """Verifies 3-column (syscall, function, file) disambiguated join."""
        self._write_sample_locs()
        with open(self.pairs_path, "w", encoding="utf-8") as pairs_file:
            pairs_file.write('"__do_sys_openat","hash","linux/fs/inode.c"\n')

        by_fn_file, by_name, prefix = import_syscall_node.load_locs(
            self.locs_path
        )
        sysloc = import_syscall_node.syscall_locations(by_name)
        rows = list(
            import_syscall_node.gen_rows(
                self.pairs_path, by_fn_file, by_name, sysloc, prefix
            )
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0],
            (
                "__do_sys_openat",
                "hash",
                "fs/open.c:100:1:120:20",
                "fs/inode.c:50:1:60:20",
            ),
        )

        import_syscall_node.write_db(self.db_path, rows)
        row = self.fetch_one("SELECT count(*) FROM syscall_node")
        self.assertEqual(row[0], 1)

    def test_import_2col_fallback(self):
        """Verifies 2-column fallback joins across all matching functions."""
        self._write_sample_locs()
        with open(self.pairs_path, "w", encoding="utf-8") as pairs_file:
            pairs_file.write('"__do_sys_openat","hash"\n')

        by_fn_file, by_name, prefix = import_syscall_node.load_locs(
            self.locs_path
        )
        sysloc = import_syscall_node.syscall_locations(by_name)
        rows = list(
            import_syscall_node.gen_rows(
                self.pairs_path, by_fn_file, by_name, sysloc, prefix
            )
        )

        self.assertEqual(len(rows), 2)

    def test_cli_main(self):
        """Verifies CLI entry point for `import_syscall_node`."""
        with open(self.locs_path, "w", encoding="utf-8") as locs_file:
            locs_file.write(
                '"__do_sys_openat","linux/fs/open.c",100,1,120,20\n'
                '"vfs_read","linux/fs/read_write.c",200,1,220,20\n'
            )

        with open(self.pairs_path, "w", encoding="utf-8") as pairs_file:
            pairs_file.write(
                '"__do_sys_openat","vfs_read","linux/fs/read_write.c"\n'
            )

        argv = [
            "import_syscall_node.py",
            "--pairs",
            self.pairs_path,
            "--locs",
            self.locs_path,
            "--db",
            self.db_path,
        ]
        with patch("sys.argv", argv):
            import_syscall_node.main()

        row = self.fetch_one("SELECT count(*) FROM syscall_node")
        self.assertEqual(row[0], 1)


class TestImportAllocs(BaseImporterTest):
    """Tests for `import_allocs.py`."""

    def test_import_allocs_17col(self):
        """Verifies importing 17-column allocs CSV records."""
        self.write_test_csv(
            "call_value,type_value,objectSize,sizeMin,sizeMax,sizeVal,"
            "flagsMin,flagsMax,flagsVal,file,line,col,isFlexible,depth,"
            "typeUri,typeLine,typeCol\n"
            '"kmalloc","struct foo","64","64","64","64","3264","3264",'
            '"3264","linux/mm/slab.c","100","12","false","1",'
            '"linux/include/foo.h","20","8"\n'
            '"short"\n'
        )

        count = import_allocs.import_allocs_to_db(self.csv_path, self.db_path)
        self.assertEqual(count, 1)

        row = self.fetch_one(
            "SELECT call_value, type_value, call_uri, call_startLine, "
            "depth_value, type_uri FROM allocs"
        )
        self.assertEqual(
            row,
            (
                "call to kmalloc",
                "struct foo",
                "mm/slab.c",
                100,
                "1",
                "include/foo.h",
            ),
        )


def _make_sarif_location(
    msg: str, uri: str, line: int, col: int, end_col: int
) -> dict[str, Any]:
    """Builds a minimal SARIF threadFlow location object."""
    return {
        "location": {
            "message": {"text": msg},
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {
                    "startLine": line,
                    "startColumn": col,
                    "endLine": line,
                    "endColumn": end_col,
                },
            },
        }
    }


class TestImportAllCalls(BaseImporterTest):
    """Tests for `import_all_calls.py`."""

    def test_import_all_calls_to_db(self):
        """Verifies importing a SARIF v2.1.0 callgraph file into SQLite."""
        sarif_path = os.path.join(self.tmp_dir, "test.sarif")
        locs = [
            _make_sarif_location("caller_fn", "linux/net/socket.c", 100, 5, 15),
            _make_sarif_location(
                "call to callee_fn", "linux/net/socket.c", 105, 10, 20
            ),
        ]
        sarif_content = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "callgraph-all",
                            "message": {"text": "callgraph-all"},
                            "codeFlows": [
                                {"threadFlows": [{"locations": locs}]}
                            ],
                        }
                    ]
                }
            ]
        }

        with open(sarif_path, "w", encoding="utf-8") as sarif_file:
            json.dump(sarif_content, sarif_file)

        edge_cnt = import_all_calls.import_all_calls_to_db(
            sarif_path, self.db_path
        )
        self.assertEqual(edge_cnt, 1)

        db_locs = self.fetch_all(
            "SELECT uri, message FROM locations ORDER BY id ASC"
        )
        self.assertEqual(db_locs[0], ("net/socket.c", "caller_fn"))
        self.assertEqual(db_locs[1], ("net/socket.c", "call to callee_fn"))
        rule_row = self.fetch_one("SELECT rule_id FROM edges")
        self.assertEqual(rule_row[0], "callgraph-all")


if __name__ == "__main__":
    unittest.main()
