#!/usr/bin/env python3
"""Build entry_node table from entry-node-pairs.ql and syscall-node-locs.ql."""

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
    "entry_locations",
    "gen_rows",
    "load_locs",
    "loc_string",
    "main",
    "write_csv",
    "write_db",
]

_ENTRY_NODE_SPEC = ReachabilityNodeSpec(
    table_name="entry_node",
    create_sql=(
        "CREATE TABLE entry_node ("
        "entry_kind TEXT, entry TEXT, function TEXT, "
        "entry_location TEXT, function_location TEXT)"
    ),
    insert_sql="INSERT INTO entry_node VALUES (?, ?, ?, ?, ?)",
    indexes=(
        "CREATE INDEX idx_entry_node_function ON entry_node(function)",
        "CREATE INDEX idx_entry_node_entry ON entry_node(entry)",
        "CREATE INDEX idx_entry_node_kind ON entry_node(entry_kind)",
    ),
    description=(
        "Assemble entry_node table/CSV from entry-node-pairs.ql and "
        "syscall-node-locs.ql outputs."
    ),
    pairs_help=(
        "entry-node-pairs.ql output (entry_kind, entry, function[, file])"
    ),
)


def entry_locations(
    by_name: Mapping[str, Sequence[tuple[str, str]]],
) -> dict[str, str]:
    """Maps each function name to its definition location (`.c` preferred)."""
    return select_root_locations(by_name)


def _extract_entry_pair(
    row: Sequence[str],
) -> Optional[tuple[tuple[str, ...], str, str, int]]:
    """Extracts `((entry_kind, entry, function), entry, function, 3)`."""
    if len(row) < 3:
        return None
    entry_kind = row[0].strip().strip('"')
    entry = row[1].strip().strip('"')
    function = row[2].strip().strip('"')
    if entry_kind == "entry_kind" and entry == "entry":
        return None
    return (entry_kind, entry, function), entry, function, 3


def gen_rows(
    pairs_path: str,
    by_fn_file: Mapping[tuple[str, str], Sequence[str]],
    by_name: Mapping[str, Sequence[tuple[str, str]]],
    entloc: Mapping[str, str],
    prefix: str = "",
) -> Iterator[tuple[str, ...]]:
    """Yields `(entry_kind, entry, function, entry_loc, function_loc)`."""
    loc_index = LocIndex(by_fn_file=by_fn_file, by_name=by_name, prefix=prefix)
    return iter_joined_reachability_rows(
        pairs_path, loc_index, entloc, _extract_entry_pair
    )


def write_db(db_path: str, rows: Iterable[Sequence[object]]) -> int:
    """Drops, recreates, indexes, and populates the `entry_node` table."""
    return write_node_db(db_path, _ENTRY_NODE_SPEC, rows)


def main() -> None:
    """Parses CLI arguments and builds the `entry_node` table or CSV."""
    run_reachability_cli(_ENTRY_NODE_SPEC, entry_locations, gen_rows)


if __name__ == "__main__":
    main()
