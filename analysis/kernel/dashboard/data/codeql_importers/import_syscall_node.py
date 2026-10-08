#!/usr/bin/env python3
"""Build the syscall_node table from the two split CodeQL query outputs."""

from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Optional

from data.codeql_importers.lib.reachability_node import (
    LocIndex,
    ReachabilityNodeSpec,
    iter_joined_reachability_rows,
    load_locs,
    loc_string,
    run_reachability_cli,
    select_root_locations,
    write_csv,
    write_node_db,
)

__all__ = [
    "gen_rows",
    "load_locs",
    "loc_string",
    "main",
    "syscall_locations",
    "write_csv",
    "write_db",
]

_SYSCALL_NODE_SPEC = ReachabilityNodeSpec(
    table_name="syscall_node",
    create_sql=(
        "CREATE TABLE syscall_node ("
        "syscall TEXT, function TEXT, "
        "syscall_location TEXT, function_location TEXT)"
    ),
    insert_sql="INSERT INTO syscall_node VALUES (?, ?, ?, ?)",
    indexes=(
        "CREATE INDEX idx_syscall_node_function ON syscall_node(function)",
        "CREATE INDEX idx_syscall_node_syscall ON syscall_node(syscall)",
    ),
    description=(
        "Assemble syscall_node table/CSV from split CodeQL query outputs."
    ),
    pairs_help="syscall-node-pairs.ql output (syscall, function[, file])",
)


def syscall_locations(
    by_name: Mapping[str, Sequence[tuple[str, str]]],
) -> dict[str, str]:
    """Maps each `__do_sys_*` entry to its `.c` definition location."""
    return select_root_locations(by_name, name_prefix="__do_sys_")


def _extract_syscall_pair(
    row: Sequence[str],
) -> Optional[tuple[tuple[str, ...], str, str, int]]:
    """Extracts `((syscall, function), syscall, function, 2)` from a row."""
    if len(row) < 2:
        return None
    syscall = row[0].strip().strip('"')
    function = row[1].strip().strip('"')
    if syscall == "syscall" and function == "function":
        return None
    return (syscall, function), syscall, function, 2


def gen_rows(
    pairs_path: str,
    by_fn_file: Mapping[tuple[str, str], Sequence[str]],
    by_name: Mapping[str, Sequence[tuple[str, str]]],
    sysloc: Mapping[str, str],
    prefix: str = "",
) -> Iterator[tuple[str, ...]]:
    """Yields `(syscall, function, syscall_location, function_location)`."""
    loc_index = LocIndex(by_fn_file=by_fn_file, by_name=by_name, prefix=prefix)
    return iter_joined_reachability_rows(
        pairs_path, loc_index, sysloc, _extract_syscall_pair
    )


def write_db(db_path: str, rows: Iterable[Sequence[object]]) -> int:
    """Drops, recreates, indexes, and populates the `syscall_node` table."""
    return write_node_db(db_path, _SYSCALL_NODE_SPEC, rows)


def main() -> None:
    """Parses CLI arguments and builds the `syscall_node` table or CSV."""
    run_reachability_cli(_SYSCALL_NODE_SPEC, syscall_locations, gen_rows)


if __name__ == "__main__":
    main()
