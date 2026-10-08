#!/usr/bin/env python3
"""Path trimming and shared CLI/CSV utilities for CodeQL CSV importers."""

import argparse
from collections import Counter
from collections.abc import Callable, Sequence
import csv
from dataclasses import dataclass
import logging
import os
import sys
from typing import Optional

from data.lib.db import execute_sqlite_batch, open_sqlite_db

KERNEL_TOP_DIRS = (
    "arch/",
    "block/",
    "certs/",
    "crypto/",
    "drivers/",
    "fs/",
    "include/",
    "init/",
    "io_uring/",
    "ipc/",
    "kernel/",
    "lib/",
    "mm/",
    "net/",
    "rust/",
    "samples/",
    "scripts/",
    "security/",
    "sound/",
    "tools/",
    "usr/",
    "virt/",
)


@dataclass(frozen=True)
class CsvTableSpec:
    """Declarative specification for importing a CodeQL CSV into SQLite."""

    table_name: str
    create_sql: str
    insert_sql: str
    min_cols: int
    path_cols: tuple[int, ...]
    row_parser: Callable[[Sequence[str], str], Optional[tuple[object, ...]]]
    indexes: tuple[str, ...] = ()


def _strip_file_scheme(path: str) -> str:
    """Strips leading file:// scheme while preserving the absolute slash."""
    if not path:
        return ""
    if path.startswith("file:///"):
        return path[len("file://") :]
    if path.startswith("file://"):
        return path[len("file://") :]
    return path


def detect_prefix(paths: Sequence[str]) -> str:
    """Scans paths in a dataset to find the most common kernel root prefix."""
    prefixes = []
    for raw_path in paths:
        path = _strip_file_scheme(raw_path)
        if not path or not path.startswith("/"):
            continue
        for top_dir in KERNEL_TOP_DIRS:
            idx = path.find("/" + top_dir)
            if idx != -1:
                prefixes.append(path[: idx + 1])
                break

    if prefixes:
        return Counter(prefixes).most_common(1)[0][0]
    return ""


def detect_csv_prefix(
    rows: Sequence[Sequence[str]],
    path_cols: Sequence[int],
    min_cols: int,
    limit: int = 1000,
) -> str:
    """Samples up to `limit` paths from `path_cols` in a single pass."""
    sample_paths: list[str] = []
    for row in rows:
        if len(row) < min_cols:
            continue
        for col_idx in path_cols:
            if col_idx < len(row) and row[col_idx]:
                sample_paths.append(row[col_idx])
                if len(sample_paths) >= limit:
                    return detect_prefix(sample_paths)
    return detect_prefix(sample_paths)


def trim_filename(path: str, prefix: str = "") -> str:
    """Strips the detected root directory prefix from a file path."""
    if not path:
        return ""

    path = _strip_file_scheme(path)
    clean_prefix = _strip_file_scheme(prefix) if prefix else ""

    if clean_prefix and path.startswith(clean_prefix):
        return path[len(clean_prefix) :]

    if path.startswith(KERNEL_TOP_DIRS):
        return path

    earliest_idx = -1
    for top_dir in KERNEL_TOP_DIRS:
        idx = path.find("/" + top_dir)
        if idx != -1 and (earliest_idx == -1 or idx < earliest_idx):
            earliest_idx = idx

    if earliest_idx != -1:
        return path[earliest_idx + 1 :]

    return path


def has_unknown_token(row: Sequence[str]) -> bool:
    """Returns True if `row` contains an `'unknown'` or `'unnamed'` cell."""
    return "unknown" in row or "unnamed" in row


def parse_optional_int(value: str) -> Optional[int]:
    """Converts a string to int, returning None on ValueError or TypeError."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def parse_float_int(value: str) -> Optional[int]:
    """Parses a numeric string (possibly float-formatted) into an int."""
    try:
        return int(float(value.strip()))
    except (ValueError, TypeError):
        return None


def read_csv_rows(
    csv_filename: str,
    *,
    skip_header: bool = True,
    header_tokens: Sequence[str] = (),
) -> list[list[str]]:
    """Reads all data rows from a CSV file, optionally skipping its header."""
    rows: list[list[str]] = []
    with open(csv_filename, "r", encoding="utf-8", errors="ignore") as csv_file:
        reader = csv.reader(csv_file, delimiter=",", quotechar='"')
        try:
            first_row = next(reader)
        except StopIteration:
            return []

        if header_tokens:
            first_token = first_row[0].strip().lower() if first_row else ""
            if first_token not in header_tokens:
                rows.append(first_row)
        elif not skip_header:
            rows.append(first_row)

        rows.extend(reader)
    return rows


def execute_bulk_insert(
    db_name: str,
    create_sql: str,
    insert_sql: str,
    data: Sequence[Sequence[object]],
    drop_table: Optional[str] = None,
) -> None:
    """Creates a table if needed and bulk-inserts `data` into `db_name`."""
    execute_sqlite_batch(
        db_name,
        create_sql,
        insert_sql,
        data,
        drop_table=drop_table,
    )


def import_csv_table(
    csv_filename: str,
    db_name: str,
    spec: CsvTableSpec,
    *,
    clear_sql: Optional[str] = None,
) -> int:
    """Imports a CodeQL CSV file into SQLite according to `spec`."""
    rows = read_csv_rows(csv_filename)
    prefix = detect_csv_prefix(rows, spec.path_cols, spec.min_cols)

    data: list[tuple[object, ...]] = []
    for row in rows:
        if len(row) < spec.min_cols:
            logging.warning("Skipping invalid row: %s", row)
            continue
        try:
            parsed = spec.row_parser(row, prefix)
        except (ValueError, TypeError):
            logging.warning("Skipping row with invalid values: %s", row)
            continue
        if parsed is not None:
            data.append(parsed)

    with open_sqlite_db(db_name, fast_pragmas=True) as conn:
        cursor = conn.cursor()
        if clear_sql is None:
            cursor.execute(f"DROP TABLE IF EXISTS {spec.table_name}")
        cursor.execute(spec.create_sql)
        if clear_sql is not None:
            cursor.execute(clear_sql)
        cursor.executemany(spec.insert_sql, data)
        for index_sql in spec.indexes:
            cursor.execute(index_sql)

    logging.info(
        "Successfully imported %d rows into '%s' (table '%s').",
        len(data),
        db_name,
        spec.table_name,
    )
    return len(data)


def run_importer_cli(
    description: str,
    csv_help: str,
    importer_fn: Callable[[str, str], int],
) -> None:
    """Parses standard (csv_file, db_file) arguments and runs an importer."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("csv_file", help=csv_help, type=str)
    parser.add_argument(
        "db_file",
        help="Path to target SQLite database file.",
        type=str,
    )
    args = parser.parse_args()

    if not os.path.isfile(args.csv_file):
        logging.critical("CSV file not found or unreadable: %s", args.csv_file)
        sys.exit(1)

    importer_fn(args.csv_file, args.db_file)


def parse_location_rows(
    rows: Sequence[Sequence[str]], prefix: str
) -> list[tuple[str, str, int, int]]:
    """Parses 4-column (name, file_path, start_line, end_line) CSV rows."""
    data = []
    for row in rows:
        if len(row) >= 4:
            name = row[0]
            file_path = trim_filename(row[1], prefix)
            try:
                start_line = int(row[2])
                end_line = int(row[3])
            except (ValueError, TypeError):
                logging.warning(
                    "Skipping row with invalid line numbers: %s", row
                )
                continue
            data.append((name, file_path, start_line, end_line))
        else:
            logging.warning("Skipping invalid row: %s", row)
    return data


def import_location_table(
    csv_filename: str,
    db_name: str,
    table_name: str,
    name_column: str,
    label: str = "",
) -> int:
    """Imports a 4-column CodeQL location CSV into `table_name`."""
    del label
    spec = CsvTableSpec(
        table_name=table_name,
        create_sql=f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            {name_column} TEXT,
            file_path TEXT,
            start_line INTEGER,
            end_line INTEGER
        )
        """,
        insert_sql=f"""
        INSERT INTO {table_name} (
            {name_column}, file_path, start_line, end_line
        )
        VALUES (?, ?, ?, ?)
        """,
        min_cols=4,
        path_cols=(1,),
        row_parser=lambda row, prefix: (
            row[0],
            trim_filename(row[1], prefix),
            int(row[2]),
            int(row[3]),
        ),
        indexes=(
            (
                f"CREATE INDEX IF NOT EXISTS idx_{table_name}_{name_column} "
                f"ON {table_name}({name_column})"
            ),
            (
                f"CREATE INDEX IF NOT EXISTS idx_{table_name}_loc "
                f"ON {table_name}(file_path, start_line, end_line)"
            ),
        ),
    )
    return import_csv_table(csv_filename, db_name, spec)
