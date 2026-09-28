#!/usr/bin/env python3
"""Unit tests for kconfig_dump.py Makefile/Kbuild and Kconfig extraction."""

import os
import sqlite3
import sys
import tempfile
import unittest

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import kconfig_dump  # pylint: disable=wrong-import-position


class TestValidationHelpers(unittest.TestCase):
    """Test directory and file path validation helper functions."""

    def test_can_read_dir_valid_and_invalid(self):
        """Verify can_read_dir accepts valid dirs and rejects missing ones."""
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(
                kconfig_dump.can_read_dir(tmpdir), os.path.abspath(tmpdir)
            )
        with self.assertRaises(ValueError):
            kconfig_dump.can_read_dir("/nonexistent_dir_kconfig_xyz")

    def test_can_create_file_valid_and_invalid(self):
        """Verify can_create_file accepts valid parent dirs and rejects bad."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "out.db")
            self.assertEqual(kconfig_dump.can_create_file(target), target)
        with self.assertRaises(ValueError):
            kconfig_dump.can_create_file("/nonexistent_dir_kconfig_xyz/out.db")


class TestMakefileParsing(unittest.TestCase):
    """Test Makefile/Kbuild parsing, composite modules, and subdir rules."""

    def test_join_continuation_lines(self):
        """Verify backslash line continuations and comments are normalized."""
        raw = [
            "# Top comment\n",
            "obj-$(CONFIG_FOO) += a.o \\\n",
            "                     b.o # inline comment\n",
            "obj-$(CONFIG_BAR) += c.o\n",
        ]
        joined = kconfig_dump.join_continuation_lines(raw)
        self.assertEqual(len(joined), 2)
        self.assertEqual(joined[0][1], "obj-$(CONFIG_FOO) += a.o b.o")
        self.assertEqual(joined[1][1], "obj-$(CONFIG_BAR) += c.o")

    def test_parse_single_makefile_direct_and_composite(self):
        """Verify direct obj-$(CONFIG_*), composites, and conditionals."""
        content = """
obj-$(CONFIG_NETFILTER) += netfilter/
obj-$(CONFIG_NF_TABLES) += nf_tables_api.o

obj-$(CONFIG_KVM) += kvm.o
kvm-y := kvm_main.o coalesced_mmio.o
kvm-$(CONFIG_KVM_VFIO) += vfio.o

ifdef CONFIG_DEBUG_FS
obj-y += debugfs_helper.o
else
obj-y += fallback_helper.o
endif

ifeq ($(CONFIG_FOO),m)
obj-y += foo_mod.o
else ifeq ($(CONFIG_BAR),y)
obj-y += bar_builtin.o
endif
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix="Makefile", delete=False
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            file_cfgs, subdir_cfgs = kconfig_dump.parse_single_makefile(
                tmp_path
            )
            self.assertEqual(subdir_cfgs.get("netfilter"), {"CONFIG_NETFILTER"})
            self.assertEqual(
                file_cfgs.get("nf_tables_api.c"), {"CONFIG_NF_TABLES"}
            )
            self.assertEqual(file_cfgs.get("kvm_main.c"), {"CONFIG_KVM"})
            self.assertEqual(file_cfgs.get("coalesced_mmio.c"), {"CONFIG_KVM"})
            self.assertEqual(
                file_cfgs.get("vfio.c"), {"CONFIG_KVM", "CONFIG_KVM_VFIO"}
            )
            self.assertEqual(
                file_cfgs.get("debugfs_helper.c"), {"CONFIG_DEBUG_FS"}
            )
            self.assertEqual(
                file_cfgs.get("fallback_helper.c"), {"!CONFIG_DEBUG_FS"}
            )
            self.assertEqual(file_cfgs.get("foo_mod.c"), {"CONFIG_FOO"})
            self.assertEqual(file_cfgs.get("bar_builtin.c"), {"CONFIG_BAR"})
        finally:
            os.remove(tmp_path)

    def test_collect_makefile_configs_recursive_inheritance(self):
        """Verify subdirectory CONFIG_* guards propagate to child .c files."""
        with tempfile.TemporaryDirectory() as repo:
            os.makedirs(os.path.join(repo, "net", "netfilter"), exist_ok=True)
            with open(
                os.path.join(repo, "net", "Makefile"), "w", encoding="utf-8"
            ) as fh:
                fh.write("obj-$(CONFIG_NETFILTER) += netfilter/\n")

            with open(
                os.path.join(repo, "net", "netfilter", "Makefile"),
                "w",
                encoding="utf-8",
            ) as fh:
                fh.write("obj-$(CONFIG_NF_TABLES) += nf_tables_api.o\n")

            c_file = os.path.join(repo, "net", "netfilter", "nf_tables_api.c")
            with open(c_file, "w", encoding="utf-8") as fh:
                fh.write("int a = 1;\nint b = 2;\nint c = 3;\n")

            rows = kconfig_dump.collect_makefile_configs(repo)
            rel_c = "net/netfilter/nf_tables_api.c"
            self.assertEqual(
                rows,
                [
                    ("CONFIG_NETFILTER", rel_c, 1, 3, 0),
                    ("CONFIG_NF_TABLES", rel_c, 1, 3, 0),
                ],
            )


class TestKconfigAndStorage(unittest.TestCase):
    """Test Kconfig symbol extraction, .config parsing, and SQLite storage."""

    def test_parse_kconfig_and_dot_config_and_store(self):
        """Verify Kconfig symbols, .config values, and SQLite tables."""
        with tempfile.TemporaryDirectory() as repo:
            with open(
                os.path.join(repo, ".config"), "w", encoding="utf-8"
            ) as fh:
                fh.write("CONFIG_NF_TABLES=y\n# CONFIG_KVM_VFIO is not set\n")

            with open(
                os.path.join(repo, "Kconfig"), "w", encoding="utf-8"
            ) as fh:
                fh.write(
                    """
config NF_TABLES
\ttristate "Netfilter nf_tables support"
\tdepends on NET && \\
\t\tINET
\tselect NETFILTER_NETLINK if NET
\tdefault m if EXPERIMENTAL
\tdefault n
\thelp
\t  This help text mentions default y and select BOGUS_SYM
\t  which must be ignored by the Kconfig parser.

menuconfig KVM_VFIO
\tdef_bool y
\tdepends on KVM
"""
                )

            syms = kconfig_dump.collect_kconfig_symbols(repo)
            self.assertEqual(len(syms), 2)
            by_name = {s[0]: s for s in syms}

            nft = by_name["CONFIG_NF_TABLES"]
            self.assertEqual(nft[1], "tristate")
            self.assertEqual(nft[2], "Netfilter nf_tables support")
            self.assertEqual(nft[3], "NET && INET")
            self.assertEqual(nft[4], "NETFILTER_NETLINK if NET")
            self.assertEqual(nft[5], "m if EXPERIMENTAL; n")
            self.assertEqual(nft[6], "y")

            vfio = by_name["CONFIG_KVM_VFIO"]
            self.assertEqual(vfio[1], "bool")
            self.assertEqual(vfio[5], "y")
            self.assertEqual(vfio[6], "n")

            db_path = os.path.join(repo, "test_kconfig.db")
            mf_rows = [
                ("CONFIG_NF_TABLES", "net/netfilter/nf_tables_api.c", 1, 50, 0)
            ]
            ins_mf, ins_sym = kconfig_dump.store_kconfig_data(
                db_path, mf_rows, syms
            )
            self.assertEqual(ins_mf, 1)
            self.assertEqual(ins_sym, 2)

            # Second run should deduplicate existing configs rows
            ins_mf_dup, _ = kconfig_dump.store_kconfig_data(
                db_path, mf_rows, syms
            )
            self.assertEqual(ins_mf_dup, 0)

            conn = sqlite3.connect(db_path)
            cfg_count = conn.execute("SELECT count(*) FROM configs").fetchone()[
                0
            ]
            sym_count = conn.execute(
                "SELECT count(*) FROM kconfig_symbols"
            ).fetchone()[0]
            conn.close()
            self.assertEqual(cfg_count, 1)
            self.assertEqual(sym_count, 2)


if __name__ == "__main__":
    unittest.main()
