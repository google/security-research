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
from typing import Any, Dict, List, Optional, Set, Tuple

CONFIG_TOKEN_RE = re.compile(r"\b(CONFIG_[A-Za-z0-9_]+)\b")
OBJ_ASSIGN_RE = re.compile(r"^([A-Za-z0-9_$()-]+)\s*(?:\+=|:=|=)\s*(.*)$")
MAKEFILE_IFDEF_RE = re.compile(
    r"^\s*(ifdef|ifndef)\s+(CONFIG_[A-Za-z0-9_]+)\b"
)
MAKEFILE_IFEQ_RE = re.compile(
    r"^\s*(ifeq|ifneq)\s*\(\s*\$\((CONFIG_[A-Za-z0-9_]+)\)\s*,\s*([^)]*)\)"
)
KCONFIG_ENTRY_RE = re.compile(r"^(?:menu)?config\s+([A-Za-z0-9_]+)\s*$")
KCONFIG_TYPE_RE = re.compile(
    r"^\s*(bool|tristate|string|hex|int)(?:\s+\"(.*)\")?"
)
DOT_CONFIG_UNSET_RE = re.compile(
    r"^#\s*(CONFIG_[A-Za-z0-9_]+)\s+is not set\b"
)
DOT_CONFIG_ASSIGN_RE = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")

SKIP_DIRS = {"Documentation", "scripts", "samples", "tools"}

KconfigRow = Tuple[str, str, str, str, str, str, str, str, int]
MakefileRow = Tuple[str, str, int, int, int]


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
    """Joins backslash-continued Makefile lines into (line_no, text) pairs."""
    joined: List[Tuple[int, str]] = []
    buf = ""
    start_line = 1
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        # Strip inline Make comments
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


def _update_cond_stack(line: str, cond_stack: List[Optional[str]]) -> bool:
    """Updates `cond_stack` if `line` is a Makefile conditional directive."""
    if line.startswith(("ifdef ", "ifndef ", "ifeq", "ifneq")):
        cond_stack.append(_parse_makefile_condition(line))
        return True
    if line == "else":
        if cond_stack and cond_stack[-1] is not None:
            cond_stack[-1] = _invert_config(cond_stack[-1])
        return True
    if line.startswith("else "):
        if cond_stack:
            cond_stack[-1] = _parse_makefile_condition(line[5:].strip())
        return True
    if line.startswith("endif"):
        if cond_stack:
            cond_stack.pop()
        return True
    return False


def parse_single_makefile(
    makefile_path: str,
) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """Parses a single Makefile or Kbuild file.

    Returns:
      - file_configs: mapping of local `.c` filename -> set of CONFIG_* guards
      - subdir_configs: mapping of local subdir name -> set of CONFIG_* guards
    """
    try:
        with open(makefile_path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()
    except OSError:
        return {}, {}

    edges: List[Tuple[str, str]] = []
    stem_configs: Dict[str, Set[str]] = {}
    subdir_configs: Dict[str, Set[str]] = {}
    cond_stack: List[Optional[str]] = []

    for _line_no, line in join_continuation_lines(raw_lines):
        if _update_cond_stack(line, cond_stack):
            continue

        m_assign = OBJ_ASSIGN_RE.match(line)
        if not m_assign:
            continue

        lhs, rhs = m_assign.group(1), m_assign.group(2)
        active_conds = {c for c in cond_stack if c is not None}
        lhs_configs = set(CONFIG_TOKEN_RE.findall(lhs)) | active_conds
        lhs_prefix = lhs.split("-", 1)[0] if "-" in lhs else lhs

        for token in rhs.split():
            if token.startswith(("$", "-", "+")):
                continue
            if token.endswith("/"):
                subdir = token.rstrip("/")
                if subdir and "/" not in subdir:
                    subdir_configs.setdefault(subdir, set()).update(lhs_configs)
            elif token.endswith(".o"):
                obj_stem = token[:-2]
                stem_configs.setdefault(obj_stem, set()).update(lhs_configs)
                edges.append((lhs_prefix, obj_stem))

    composite_parents = {lhs for lhs, rhs in edges if lhs != rhs}
    self_included = {lhs for lhs, rhs in edges if lhs == rhs}
    for lhs_prefix, obj_stem in edges:
        if lhs_prefix in stem_configs:
            stem_configs[obj_stem].update(stem_configs[lhs_prefix])

    file_configs = {
        f"{stem}.c": cfgs
        for stem, cfgs in stem_configs.items()
        if stem not in composite_parents or stem in self_included
    }
    return file_configs, subdir_configs


def count_file_lines(filepath: str) -> int:
    """Returns total line count of a file (minimum 2 for ifdef < endif)."""
    try:
        with open(filepath, "rb") as fh:
            return max(sum(1 for _ in fh), 2)
    except OSError:
        return 2


def collect_makefile_configs(repo_dir: str) -> List[MakefileRow]:
    """Walks repo_dir top-down to extract file-level Makefile CONFIG_* guards.

    Returns list of 5-tuples matching the `configs` table schema:
      (config, relative_file_path, ifdef=1, endif=file_lines, else_=0)
    """
    repo_root = os.path.abspath(repo_dir)
    dir_inherited: Dict[str, Set[str]] = {"": set()}
    records: Set[MakefileRow] = set()

    for root, dirs, files in os.walk(repo_root):
        dirs[:] = sorted(
            d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS
        )
        rel_dir = os.path.relpath(root, repo_root)
        rel_dir = "" if rel_dir == "." else rel_dir
        inherited = dir_inherited.get(rel_dir, set())

        makefile_name = (
            "Kbuild"
            if "Kbuild" in files
            else ("Makefile" if "Makefile" in files else None)
        )
        local_file_cfgs: Dict[str, Set[str]] = {}
        local_subdir_cfgs: Dict[str, Set[str]] = {}
        if makefile_name:
            local_file_cfgs, local_subdir_cfgs = parse_single_makefile(
                os.path.join(root, makefile_name)
            )

        for d in dirs:
            child_rel = os.path.join(rel_dir, d) if rel_dir else d
            dir_inherited[child_rel] = inherited | local_subdir_cfgs.get(
                d, set()
            )

        for c_file in (f for f in files if f.endswith(".c")):
            all_cfgs = inherited | local_file_cfgs.get(c_file, set())
            if not all_cfgs:
                continue
            rel_c_path = (
                os.path.join(rel_dir, c_file) if rel_dir else c_file
            ).replace("\\", "/")
            end_line = count_file_lines(os.path.join(root, c_file))
            for cfg in sorted(all_cfgs):
                records.add((cfg, rel_c_path, 1, end_line, 0))

    return sorted(records, key=lambda r: (r[1], r[0]))


def parse_dot_config(dot_config_path: str) -> Dict[str, str]:
    """Parses a Linux `.config` file into a dict of CONFIG_FOO -> value."""
    build_vals: Dict[str, str] = {}
    if not dot_config_path or not os.path.isfile(dot_config_path):
        return build_vals

    try:
        with open(
            dot_config_path, "r", encoding="utf-8", errors="replace"
        ) as fh:
            for raw_line in fh:
                line = raw_line.strip()
                m_unset = DOT_CONFIG_UNSET_RE.match(line)
                if m_unset:
                    build_vals[m_unset.group(1)] = "n"
                    continue
                m_set = DOT_CONFIG_ASSIGN_RE.match(line)
                if m_set:
                    build_vals[m_set.group(1)] = m_set.group(2).strip()
    except OSError:
        pass
    return build_vals


def _join_kconfig_lines(raw_lines: List[str]) -> List[Tuple[int, str]]:
    """Joins backslash-continued Kconfig lines, preserving leading indent."""
    joined: List[Tuple[int, str]] = []
    buf = ""
    start_line = 1
    for idx, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.rstrip("\r\n")
        part = line.strip() if buf else line
        if not buf:
            start_line = idx
        if part.endswith("\\"):
            buf += part[:-1].rstrip() + " "
        else:
            joined.append((start_line, buf + part))
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


def _apply_kconfig_attribute(
    entry: Dict[str, Any], line: str, stripped: str
) -> None:
    """Updates `entry` dict with a single indented Kconfig attribute line."""
    m_type = KCONFIG_TYPE_RE.match(line)
    if m_type and not entry["type"]:
        entry["type"] = m_type.group(1)
        if m_type.group(2):
            entry["prompt"] = m_type.group(2)
    elif stripped.startswith("prompt ") and not entry["prompt"]:
        entry["prompt"] = stripped[7:].strip().strip('"')
    elif stripped.startswith("depends on "):
        entry["depends"].append(stripped[len("depends on ") :].strip())
    elif stripped.startswith("select "):
        entry["selects"].append(stripped[len("select ") :].strip())
    elif stripped.startswith(("default ", "def_bool ", "def_tristate ")):
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            entry["defaults"].append(parts[1].strip())
            if parts[0] == "def_bool" and not entry["type"]:
                entry["type"] = "bool"
            elif parts[0] == "def_tristate" and not entry["type"]:
                entry["type"] = "tristate"


def parse_kconfig_file(
    kconfig_path: str, rel_path: str, build_vals: Dict[str, str]
) -> List[KconfigRow]:
    """Parses a single Kconfig file into symbol metadata tuples."""
    try:
        with open(kconfig_path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()
    except OSError:
        return []

    entries: List[Dict[str, Any]] = []
    curr: Optional[Dict[str, Any]] = None
    help_indent: Optional[int] = None

    for idx, line in _join_kconfig_lines(raw_lines):
        m_entry = KCONFIG_ENTRY_RE.match(line)
        if m_entry:
            help_indent = None
            curr = {
                "config": f"CONFIG_{m_entry.group(1)}",
                "type": "",
                "prompt": "",
                "depends": [],
                "selects": [],
                "defaults": [],
                "line_no": idx,
            }
            entries.append(curr)
            continue

        if curr is None:
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        cur_indent = _indent_width(line)
        if help_indent is not None:
            if cur_indent > help_indent:
                continue
            help_indent = None

        if cur_indent == 0:
            curr = None
            continue

        if stripped in ("help", "---help---"):
            help_indent = cur_indent
            continue

        _apply_kconfig_attribute(curr, line, stripped)

    return [
        (
            e["config"],
            e["type"],
            e["prompt"],
            " && ".join(e["depends"]),
            ", ".join(e["selects"]),
            "; ".join(e["defaults"]),
            build_vals.get(e["config"], ""),
            rel_path,
            e["line_no"],
        )
        for e in entries
    ]


def collect_kconfig_symbols(
    repo_dir: str, dot_config_path: Optional[str] = None
) -> List[KconfigRow]:
    """Walks repo_dir to parse all Kconfig* files and .config build values."""
    repo_root = os.path.abspath(repo_dir)
    if not dot_config_path:
        candidate = os.path.join(repo_root, ".config")
        if os.path.isfile(candidate):
            dot_config_path = candidate
    build_vals = parse_dot_config(dot_config_path or "")

    all_symbols: List[KconfigRow] = []
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        rel_dir = os.path.relpath(root, repo_root)
        rel_dir = "" if rel_dir == "." else rel_dir
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
    makefile_rows: List[MakefileRow],
    kconfig_symbols: List[KconfigRow],
) -> Tuple[int, int]:
    """Stores Makefile rows in `configs` and symbols in `kconfig_symbols`."""
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
        help=(
            "Optional path to .config build file (defaults to"
            " <repo_dir>/.config)."
        ),
    )
    args = parser.parse_args()

    makefile_rows = collect_makefile_configs(args.repo_dir)
    kconfig_syms = collect_kconfig_symbols(args.repo_dir, args.dot_config)
    store_kconfig_data(args.db_file, makefile_rows, kconfig_syms)


if __name__ == "__main__":
    main()
