#!/usr/bin/env python3
# pylint: disable=duplicate-code
"""Extracts Linux kernel Makefile/Kbuild and Kconfig dependencies into SQLite.

Parses two complementary sources from a Linux kernel source tree (--repo_dir):
1. Makefile / Kbuild rules (obj-$(CONFIG_*), composite modules, directory
   descent, and Makefile ifdef/ifeq blocks) to map each .c source file to its
   file-level CONFIG_* requirements in the `configs` table (ifdef=1,
   endif=<file_line_count>, else_=0).
2. Kconfig* symbol definitions and optional .config build values into the
   `kconfig_symbols` table (config, type, prompt, depends_on, select_list,
   default_val, build_val, kconfig_file, line_no).
"""

import argparse
from contextlib import closing
import logging
import os
import re
import sqlite3
from typing import Dict, List, Optional, Set, Tuple

CONFIG_TOKEN_RE = re.compile(r"\b(CONFIG_[A-Za-z0-9_]+)\b")
OBJ_ASSIGN_RE = re.compile(
    r"^([A-Za-z0-9_$()-]+)\s*(?:\+=|:=|=)\s*(.*)$"
)
MAKEFILE_IFDEF_RE = re.compile(
    r"^\s*(ifdef|ifndef)\s+(CONFIG_[A-Za-z0-9_]+)\b"
)
MAKEFILE_IFEQ_RE = re.compile(
    r"^\s*(ifeq|ifneq)\s*\(\s*\$\((CONFIG_[A-Za-z0-9_]+)\)\s*,\s*([^)]*)\)"
)
KCONFIG_ENTRY_RE = re.compile(
    r"^(?:menu)?config\s+([A-Za-z0-9_]+)\s*$"
)
KCONFIG_TYPE_RE = re.compile(
    r"^\s*(bool|tristate|string|hex|int)(?:\s+\"(.*)\")?"
)


def can_read_dir(dirname: str) -> str:
    """Validates that a path is an existing readable directory."""
    if os.path.isdir(dirname) and os.access(dirname, os.R_OK):
        return os.path.abspath(dirname)
    logging.critical("Directory not found or unreadable: %s", dirname)
    raise ValueError(f"Directory not found or unreadable: {dirname}")


def can_create_file(filename: str) -> str:
    """Validates that a file path can be created in its target directory."""
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()
    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)
    logging.critical("Wrong path provided: %s", filename)
    raise ValueError(f"Wrong path provided: {filename}")


def join_continuation_lines(lines: List[str]) -> List[Tuple[int, str]]:
    """Joins backslash-continued lines in a Makefile, returning (line_no, text)."""
    joined: List[Tuple[int, str]] = []
    buf = ""
    start_line = 1
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        # Strip inline comments unless inside quotes
        if "#" in line:
            line = line.split("#", 1)[0]
        if not buf:
            start_line = idx
        if line.endswith("\\"):
            buf += line[:-1] + " "
        else:
            buf += line
            normalized = " ".join(buf.split())
            if normalized:
                joined.append((start_line, normalized))
            buf = ""
    if buf.strip():
        joined.append((start_line, " ".join(buf.split())))
    return joined


def _parse_makefile_condition(line: str) -> Optional[str]:
    """Parses a Makefile ifdef/ifndef/ifeq/ifneq line for CONFIG_* guards."""
    m_ifdef = MAKEFILE_IFDEF_RE.match(line)
    if m_ifdef:
        directive, cfg = m_ifdef.group(1), m_ifdef.group(2)
        return f"!{cfg}" if directive == "ifndef" else cfg

    m_ifeq = MAKEFILE_IFEQ_RE.match(line)
    if m_ifeq:
        directive, cfg, val = (
            m_ifeq.group(1),
            m_ifeq.group(2),
            m_ifeq.group(3).strip(),
        )
        is_neg = (directive == "ifneq" and val in ("y", "m")) or (
            directive == "ifeq" and val in ("", "n")
        )
        return f"!{cfg}" if is_neg else cfg
    return None


def _invert_config(cfg: str) -> str:
    """Inverts a CONFIG_* or !CONFIG_* guard string."""
    return cfg[1:] if cfg.startswith("!") else f"!{cfg}"


def parse_single_makefile(  # pylint: disable=too-many-locals,too-many-branches
    makefile_path: str,
) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """Parses a single Makefile or Kbuild file.

    Returns:
      - file_configs: mapping of local `.c` filename -> set of CONFIG_* guards
      - subdir_configs: mapping of local subdirectory name -> set of CONFIG_* guards
    """
    try:
        with open(makefile_path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()
    except OSError:
        return {}, {}

    joined_lines = join_continuation_lines(raw_lines)

    # Track direct and composite rules:
    # target_configs[stem] = set of CONFIG_* gating `obj-$(CONFIG_X) += stem.o`
    target_configs: Dict[str, Set[str]] = {}
    # composite_members[stem] = list of (member_stem, extra_configs_set)
    composite_members: Dict[str, List[Tuple[str, Set[str]]]] = {}
    subdir_configs: Dict[str, Set[str]] = {}

    cond_stack: List[Optional[str]] = []

    for _line_no, line in joined_lines:
        if line.startswith(("ifdef ", "ifndef ", "ifeq", "ifneq")):
            cond_stack.append(_parse_makefile_condition(line))
            continue
        if line == "else" or line.startswith("else "):
            if cond_stack and cond_stack[-1] is not None:
                cond_stack[-1] = _invert_config(cond_stack[-1])
            continue
        if line.startswith("endif"):
            if cond_stack:
                cond_stack.pop()
            continue

        m_assign = OBJ_ASSIGN_RE.match(line)
        if not m_assign:
            continue

        lhs, rhs = m_assign.group(1), m_assign.group(2)
        active_conds = {c for c in cond_stack if c is not None}
        lhs_configs = set(CONFIG_TOKEN_RE.findall(lhs)) | active_conds

        # Determine if LHS is top-level (obj-*, lib-*, hostprogs-*, core-*, etc.)
        # or a composite module definition (<mod>-y, <mod>-objs, <mod>-$(CONFIG_*))
        lhs_prefix = lhs.split("-", 1)[0] if "-" in lhs else lhs
        is_top_level = lhs_prefix in (
            "obj",
            "lib",
            "core",
            "drivers",
            "net",
            "fs",
            "virt",
            "sound",
            "arch",
        )

        for token in rhs.split():
            if token.startswith(("$", "-", "+")):
                continue
            if token.endswith("/"):
                subdir = token.rstrip("/")
                if subdir and "/" not in subdir:
                    subdir_configs.setdefault(subdir, set()).update(lhs_configs)
                continue
            if token.endswith(".o"):
                obj_stem = token[:-2]
                if is_top_level:
                    target_configs.setdefault(obj_stem, set()).update(
                        lhs_configs
                    )
                else:
                    composite_members.setdefault(lhs_prefix, []).append(
                        (obj_stem, set(lhs_configs))
                    )

    file_configs: Dict[str, Set[str]] = {}
    # 1. Direct .o -> .c mappings
    for stem, cfgs in target_configs.items():
        if stem not in composite_members:
            file_configs.setdefault(f"{stem}.c", set()).update(cfgs)

    # 2. Composite module mappings (e.g., kvm.o -> kvm_main.o, vfio.o)
    for mod_stem, members in composite_members.items():
        parent_cfgs = target_configs.get(mod_stem, set())
        for member_stem, member_cfgs in members:
            combined = set(parent_cfgs) | set(member_cfgs)
            file_configs.setdefault(f"{member_stem}.c", set()).update(combined)

    return file_configs, subdir_configs


def count_file_lines(filepath: str) -> int:
    """Returns total line count of a file (at least 2 for valid ifdef < endif)."""
    try:
        with open(filepath, "rb") as fh:
            count = sum(1 for _ in fh)
        return max(count, 2)
    except OSError:
        return 2


def collect_makefile_configs(
    repo_dir: str,
) -> List[Tuple[str, str, int, int, int]]:
    """Walks repo_dir top-down to extract file-level Makefile CONFIG_* guards.

    Returns list of 5-tuples matching the `configs` table schema:
      (config, relative_file_path, ifdef=1, endif=file_lines, else_=0)
    """
    repo_root = os.path.abspath(repo_dir)
    # dir_inherited_configs[rel_dir] = set of CONFIG_* inherited from parent dirs
    dir_inherited: Dict[str, Set[str]] = {"": set()}
    records: Set[Tuple[str, str, int, int, int]] = set()

    for root, dirs, files in os.walk(repo_root):
        # Skip hidden directories (.git) and Documentation/scripts/tools/samples
        dirs[:] = sorted(
            d
            for d in dirs
            if not d.startswith(".")
            and d not in ("Documentation", "scripts", "samples")
        )
        rel_dir = os.path.relpath(root, repo_root)
        if rel_dir == ".":
            rel_dir = ""

        inherited = set(dir_inherited.get(rel_dir, set()))

        makefile_name = (
            "Kbuild"
            if "Kbuild" in files
            else ("Makefile" if "Makefile" in files else None)
        )
        local_file_cfgs: Dict[str, Set[str]] = {}
        local_subdir_cfgs: Dict[str, Set[str]] = {}

        if makefile_name:
            mf_path = os.path.join(root, makefile_name)
            local_file_cfgs, local_subdir_cfgs = parse_single_makefile(mf_path)

        # Propagate directory configs to child directories
        for d in dirs:
            child_rel = os.path.join(rel_dir, d) if rel_dir else d
            child_cfgs = set(inherited) | local_subdir_cfgs.get(d, set())
            dir_inherited[child_rel] = child_cfgs

        # Assign configs to existing .c files in this directory
        c_files = [f for f in files if f.endswith(".c")]
        for c_file in c_files:
            all_cfgs = set(inherited) | local_file_cfgs.get(c_file, set())
            if not all_cfgs:
                continue
            full_c_path = os.path.join(root, c_file)
            rel_c_path = (
                os.path.join(rel_dir, c_file) if rel_dir else c_file
            ).replace("\\", "/")
            end_line = count_file_lines(full_c_path)
            for cfg in sorted(all_cfgs):
                records.add((cfg, rel_c_path, 1, end_line, 0))

    return sorted(records, key=lambda r: (r[1], r[0]))


def parse_dot_config(dot_config_path: str) -> Dict[str, str]:
    """Parses a Linux `.config` file into a dict of CONFIG_FOO -> value."""
    build_vals: Dict[str, str] = {}
    if not dot_config_path or not os.path.isfile(dot_config_path):
        return build_vals

    not_set_re = re.compile(r"^#\s*(CONFIG_[A-Z0-9_]+)\s+is not set\b")
    assign_re = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.*)$")

    try:
        with open(
            dot_config_path, "r", encoding="utf-8", errors="replace"
        ) as fh:
            for raw_line in fh:
                line = raw_line.strip()
                m_unset = not_set_re.match(line)
                if m_unset:
                    build_vals[m_unset.group(1)] = "n"
                    continue
                m_set = assign_re.match(line)
                if m_set:
                    build_vals[m_set.group(1)] = m_set.group(2).strip()
    except OSError:
        pass
    return build_vals


def _join_kconfig_lines(raw_lines: List[str]) -> List[Tuple[int, str]]:
    """Joins backslash-continued lines in a Kconfig file, preserving leading indent."""
    joined: List[Tuple[int, str]] = []
    buf = ""
    start_line = 1
    for idx, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.rstrip("\r\n")
        if not buf:
            start_line = idx
            if line.endswith("\\"):
                buf = line[:-1].rstrip() + " "
            else:
                joined.append((start_line, line))
        else:
            cont = line.strip()
            if cont.endswith("\\"):
                buf += cont[:-1].rstrip() + " "
            else:
                buf += cont
                joined.append((start_line, buf))
                buf = ""
    if buf:
        joined.append((start_line, buf.rstrip()))
    return joined


def _indent_width(line: str) -> int:
    """Computes effective leading indentation width (tabs = 8 spaces)."""
    width = 0
    for ch in line:
        if ch == "\t":
            width = (width // 8 + 1) * 8
        elif ch == " ":
            width += 1
        else:
            break
    return width


def parse_kconfig_file(  # pylint: disable=too-many-locals,too-many-branches
    kconfig_path: str, rel_path: str, build_vals: Dict[str, str]
) -> List[Tuple[str, str, str, str, str, str, str, str, int]]:
    """Parses a single Kconfig file into symbol metadata tuples."""
    try:
        with open(kconfig_path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()
    except OSError:
        return []

    symbols: List[Tuple[str, str, str, str, str, str, str, str, int]] = []
    curr_sym: Optional[Dict[str, object]] = None
    help_indent: Optional[int] = None

    def _flush_current() -> None:
        if not curr_sym:
            return
        cfg_name = str(curr_sym["config"])
        symbols.append((
            cfg_name,
            str(curr_sym["type"]),
            str(curr_sym["prompt"]),
            " && ".join(curr_sym["depends"]),  # type: ignore[arg-type]
            ", ".join(curr_sym["selects"]),  # type: ignore[arg-type]
            str(curr_sym["default"]),
            build_vals.get(cfg_name, ""),
            rel_path,
            int(curr_sym["line_no"]),  # type: ignore[arg-type]
        ))

    for idx, line in _join_kconfig_lines(raw_lines):
        m_entry = KCONFIG_ENTRY_RE.match(line)
        if m_entry:
            _flush_current()
            help_indent = None
            curr_sym = {
                "config": f"CONFIG_{m_entry.group(1)}",
                "type": "",
                "prompt": "",
                "depends": [],
                "selects": [],
                "default": "",
                "line_no": idx,
            }
            continue

        if curr_sym is None:
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        cur_indent = _indent_width(line)
        if help_indent is not None:
            if cur_indent > help_indent:
                continue
            help_indent = None

        # End of config block when hitting a new top-level keyword
        if cur_indent == 0:
            _flush_current()
            curr_sym = None
            continue

        if stripped in ("help", "---help---"):
            help_indent = cur_indent
            continue

        m_type = KCONFIG_TYPE_RE.match(line)
        if m_type and not curr_sym["type"]:
            curr_sym["type"] = m_type.group(1)
            if m_type.group(2):
                curr_sym["prompt"] = m_type.group(2)
        elif stripped.startswith("prompt ") and not curr_sym["prompt"]:
            curr_sym["prompt"] = stripped[7:].strip().strip('"')
        elif stripped.startswith("depends on "):
            dep = stripped[len("depends on ") :].strip()
            curr_sym["depends"].append(dep)  # type: ignore[attr-defined]
        elif stripped.startswith("select "):
            sel = stripped[len("select ") :].split()[0].strip()
            curr_sym["selects"].append(sel)  # type: ignore[attr-defined]
        elif stripped.startswith(("default ", "def_bool ", "def_tristate ")):
            parts = stripped.split(None, 1)
            if len(parts) == 2 and not curr_sym["default"]:
                curr_sym["default"] = parts[1].strip()
                if parts[0] == "def_bool" and not curr_sym["type"]:
                    curr_sym["type"] = "bool"
                elif parts[0] == "def_tristate" and not curr_sym["type"]:
                    curr_sym["type"] = "tristate"

    _flush_current()
    return symbols


def collect_kconfig_symbols(
    repo_dir: str, dot_config_path: Optional[str] = None
) -> List[Tuple[str, str, str, str, str, str, str, str, int]]:
    """Walks repo_dir to parse all Kconfig* files and optional .config values."""
    repo_root = os.path.abspath(repo_dir)
    if not dot_config_path:
        candidate = os.path.join(repo_root, ".config")
        if os.path.isfile(candidate):
            dot_config_path = candidate
    build_vals = parse_dot_config(dot_config_path or "")

    all_symbols: List[Tuple[str, str, str, str, str, str, str, str, int]] = []
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        rel_dir = os.path.relpath(root, repo_root)
        if rel_dir == ".":
            rel_dir = ""
        for fname in sorted(files):
            if fname == "Kconfig" or fname.startswith("Kconfig."):
                full_p = os.path.join(root, fname)
                rel_p = (
                    os.path.join(rel_dir, fname) if rel_dir else fname
                ).replace("\\", "/")
                all_symbols.extend(
                    parse_kconfig_file(full_p, rel_p, build_vals)
                )
    return all_symbols


def store_kconfig_data(
    db_file: str,
    makefile_rows: List[Tuple[str, str, int, int, int]],
    kconfig_symbols: List[Tuple[str, str, str, str, str, str, str, str, int]],
) -> Tuple[int, int]:
    """Writes Makefile config rows into `configs` and symbols into `kconfig_symbols`."""
    with closing(sqlite3.connect(db_file)) as conn:
        conn.execute("PRAGMA synchronous = OFF;")
        conn.execute("PRAGMA journal_mode = MEMORY;")
        with conn as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS configs (
                    config TEXT,
                    path TEXT,
                    ifdef INTEGER,
                    endif INTEGER,
                    else_ INTEGER
                )
            """)
            # Avoid duplicate insertion if run multiple times on the same DB
            existing_rows = set(
                cur.execute(
                    "SELECT config, path, ifdef, endif, else_ FROM configs"
                ).fetchall()
            )
            new_makefile_rows = [
                r for r in makefile_rows if r not in existing_rows
            ]
            if new_makefile_rows:
                cur.executemany(
                    "INSERT INTO configs (config, path, ifdef, endif, else_)"
                    " VALUES (?, ?, ?, ?, ?)",
                    new_makefile_rows,
                )

            cur.execute("DROP TABLE IF EXISTS kconfig_symbols;")
            cur.execute("""
                CREATE TABLE kconfig_symbols (
                    config TEXT NOT NULL,
                    type TEXT,
                    prompt TEXT,
                    depends_on TEXT,
                    select_list TEXT,
                    default_val TEXT,
                    build_val TEXT,
                    kconfig_file TEXT NOT NULL,
                    line_no INTEGER NOT NULL
                )
            """)
            if kconfig_symbols:
                cur.executemany(
                    "INSERT INTO kconfig_symbols VALUES"
                    " (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    kconfig_symbols,
                )

    logging.info(
        "Inserted %d Makefile config rows into 'configs' and %d symbols into"
        " 'kconfig_symbols' in '%s'.",
        len(new_makefile_rows),
        len(kconfig_symbols),
        db_file,
    )
    return len(new_makefile_rows), len(kconfig_symbols)


def main() -> None:
    """CLI entry point for extracting Makefile and Kconfig data into SQLite."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
    parser = argparse.ArgumentParser(
        description=(
            "Extract Linux kernel Makefile/Kbuild file-level CONFIG_* guards"
            " and Kconfig symbol metadata into SQLite."
        )
    )
    parser.add_argument(
        "--repo_dir",
        required=True,
        type=can_read_dir,
        help="Path to local Linux kernel source repository.",
    )
    parser.add_argument(
        "--db_file",
        required=True,
        type=can_create_file,
        help="Path to target SQLite database file.",
    )
    parser.add_argument(
        "--dot_config",
        default=None,
        help="Optional path to .config build file (defaults to <repo_dir>/.config).",
    )
    args = parser.parse_args()

    makefile_rows = collect_makefile_configs(args.repo_dir)
    kconfig_syms = collect_kconfig_symbols(args.repo_dir, args.dot_config)
    store_kconfig_data(args.db_file, makefile_rows, kconfig_syms)


if __name__ == "__main__":
    main()
