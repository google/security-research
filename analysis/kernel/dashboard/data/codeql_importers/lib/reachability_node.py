#!/usr/bin/env python3
"""Shared location-join and SQLite/CSV output helpers for reachability nodes."""

import argparse
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
import csv
from dataclasses import dataclass
import logging
import os
import sys
from typing import Optional

from data.codeql_importers.lib.utils import detect_prefix, trim_filename
from data.lib.db import open_sqlite_db

LocByFnFile = dict[tuple[str, str], list[str]]
LocByName = dict[str, list[tuple[str, str]]]


@dataclass(frozen=True)
class LocIndex:
    """In-memory index of function locations from `syscall-node-locs.ql`."""

    by_fn_file: Mapping[tuple[str, str], Sequence[str]]
    by_name: Mapping[str, Sequence[tuple[str, str]]]
    prefix: str = ""


@dataclass(frozen=True)
class ReachabilityNodeSpec:
    """Table schema and CLI metadata for a reachability node importer."""

    table_name: str
    create_sql: str
    insert_sql: str
    indexes: tuple[str, ...]
    description: str
    pairs_help: str


def loc_string(file_path: str, sl: str, sc: str, el: str, ec: str) -> str:
    """Assembles a `file:startLine:startCol:endLine:endCol` location string."""
    return f"{file_path}:{sl}:{sc}:{el}:{ec}"


def _is_valid_loc_row(row: Sequence[str]) -> bool:
    """Returns True if `row` has 6+ columns with integer line/column bounds."""
    if len(row) < 6:
        return False
    try:
        int(row[2])
        int(row[3])
        int(row[4])
        int(row[5])
    except (ValueError, TypeError):
        return False
    return True


def _sample_loc_files(path: str, limit: int = 1000) -> list[str]:
    """Collects up to `limit` sample file paths from a locs CSV file."""
    sample_files: list[str] = []
    with open(path, newline="", encoding="utf-8", errors="ignore") as loc_file:
        for row in csv.reader(loc_file):
            if _is_valid_loc_row(row) and row[1]:
                sample_files.append(row[1].strip().strip('"'))
                if len(sample_files) >= limit:
                    break
    return sample_files


def load_locs(path: str) -> tuple[LocByFnFile, LocByName, str]:
    """Loads function locations from `syscall-node-locs.ql` CSV output."""
    prefix = detect_prefix(_sample_loc_files(path))
    by_fn_file: LocByFnFile = defaultdict(list)
    by_name: LocByName = defaultdict(list)

    with open(path, newline="", encoding="utf-8", errors="ignore") as loc_file:
        for row in csv.reader(loc_file):
            if not _is_valid_loc_row(row):
                continue
            name = row[0].strip().strip('"')
            file_path = trim_filename(row[1].strip().strip('"'), prefix)
            loc = loc_string(file_path, row[2], row[3], row[4], row[5])
            by_fn_file[(name, file_path)].append(loc)
            by_name[name].append((file_path, loc))

    return by_fn_file, by_name, prefix


def select_root_locations(
    by_name: Mapping[str, Sequence[tuple[str, str]]],
    name_prefix: str = "",
) -> dict[str, str]:
    """Maps each root function name to its definition location (`.c` first)."""
    out: dict[str, str] = {}
    for name, file_loc_pairs in by_name.items():
        if name_prefix and not name.startswith(name_prefix):
            continue
        c_locs = [
            loc for f_path, loc in file_loc_pairs if f_path.endswith(".c")
        ]
        if c_locs:
            out[name] = c_locs[0]
        elif file_loc_pairs:
            out[name] = file_loc_pairs[0][1]
    return out


def resolve_function_locations(
    row: Sequence[str],
    function: str,
    file_col_idx: int,
    loc_index: LocIndex,
) -> list[str]:
    """Resolves function location strings for a pairs CSV row."""
    if len(row) > file_col_idx and row[file_col_idx].strip().strip('"'):
        file_path = trim_filename(
            row[file_col_idx].strip().strip('"'), loc_index.prefix
        )
        flocs = loc_index.by_fn_file.get((function, file_path))
        if flocs:
            return list(flocs)
    return [loc for _, loc in loc_index.by_name.get(function, [])]


def iter_joined_reachability_rows(
    pairs_path: str,
    loc_index: LocIndex,
    root_locs: Mapping[str, str],
    row_extractor: Callable[
        [Sequence[str]], Optional[tuple[tuple[str, ...], str, str, int]]
    ],
) -> Iterator[tuple[str, ...]]:
    """Yields deduplicated reachability rows joined against `loc_index`."""
    misses = [0, 0]
    seen: set[tuple[str, ...]] = set()

    with open(
        pairs_path, newline="", encoding="utf-8", errors="ignore"
    ) as pairs_file:
        for row in csv.reader(pairs_file):
            extracted = row_extractor(row)
            if extracted is None:
                continue
            root_loc = root_locs.get(extracted[1])
            if root_loc is None:
                misses[0] += 1
                continue

            flocs = resolve_function_locations(
                row, extracted[2], extracted[3], loc_index
            )
            if not flocs:
                misses[1] += 1
                continue

            for floc in flocs:
                record = (*extracted[0], root_loc, floc)
                if record not in seen:
                    seen.add(record)
                    yield record

    if misses[1]:
        logging.warning("%d pairs had a function with no location.", misses[1])
    if misses[0]:
        logging.warning("%d pairs had a root with no location.", misses[0])


def write_node_db(
    db_path: str,
    spec: ReachabilityNodeSpec,
    rows: Iterable[Sequence[object]],
) -> int:
    """Drops, recreates, populates, and indexes a reachability node table."""
    with open_sqlite_db(db_path, fast_pragmas=True) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {spec.table_name}")
        conn.execute(spec.create_sql)
        conn.executemany(spec.insert_sql, rows)
        for index_sql in spec.indexes:
            conn.execute(index_sql)
        row_count = int(
            conn.execute(f"SELECT count(*) FROM {spec.table_name}").fetchone()[
                0
            ]
        )
    logging.info(
        "Built %s: %s has %d rows.", db_path, spec.table_name, row_count
    )
    return row_count


def write_csv(out_path: str, rows: Iterable[Sequence[object]]) -> int:
    """Writes all rows to a CSV file and returns the number of rows written."""
    with open(out_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        count = sum(1 for _ in map(writer.writerow, rows))
    logging.info("Wrote %d rows to %s.", count, out_path)
    return count


def run_reachability_cli(
    spec: ReachabilityNodeSpec,
    root_locs_fn: Callable[
        [Mapping[str, Sequence[tuple[str, str]]]], dict[str, str]
    ],
    gen_rows_fn: Callable[
        [
            str,
            Mapping[tuple[str, str], Sequence[str]],
            Mapping[str, Sequence[tuple[str, str]]],
            Mapping[str, str],
            str,
        ],
        Iterator[tuple[str, ...]],
    ],
) -> None:
    """Parses CLI arguments and builds a reachability node SQLite table/CSV."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description=spec.description)
    parser.add_argument("--pairs", required=True, help=spec.pairs_help)
    parser.add_argument(
        "--locs",
        required=True,
        help="syscall-node-locs.ql output (name, file, sl, sc, el, ec)",
    )
    parser.add_argument(
        "--db",
        help=(
            f"build/refresh {spec.table_name} in this SQLite DB (primary mode)"
        ),
    )
    parser.add_argument(
        "--out", help="alternatively, write the rows to a CSV file"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.pairs):
        sys.exit(f"Error: pairs file not found: {args.pairs}")
    if not os.path.isfile(args.locs):
        sys.exit(f"Error: locs file not found: {args.locs}")
    if not args.db and not args.out:
        sys.exit("need --out or --db")

    by_fn_file, by_name, prefix = load_locs(args.locs)
    root_locs = root_locs_fn(by_name)
    rows = gen_rows_fn(args.pairs, by_fn_file, by_name, root_locs, prefix)

    if args.db:
        write_node_db(args.db, spec, rows)
    elif args.out:
        write_csv(args.out, rows)
