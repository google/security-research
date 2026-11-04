#!/usr/bin/env python3
"""Path trimming and shared CLI/CSV utilities for CodeQL CSV importers."""

import argparse
from collections.abc import Callable, Iterator, Sequence
import csv
from dataclasses import dataclass
import logging
import os
import sys
from typing import Optional

from data.lib.db import execute_sqlite_batch, open_sqlite_db


@dataclass(frozen=True)
class CsvTableSpec:
    """Declarative specification for importing a CodeQL CSV into SQLite."""

    table_name: str
    create_sql: str
    insert_sql: str
    min_cols: int
    row_parser: Callable[[Sequence[str]], Optional[tuple[object, ...]]]
    indexes: tuple[str, ...] = ()


def trim_filename(path: str) -> str:
    """Normalizes a relative file path or file:// URI from CodeQL."""
    if not path:
        return ""
    return path.removeprefix("file://").lstrip("/")


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


def iter_csv_rows(
    csv_filename: str,
    *,
    skip_header: bool = True,
    header_tokens: Sequence[str] = (),
) -> Iterator[list[str]]:
    """Streams data rows from a CSV file, optionally skipping its header."""
    with open(csv_filename, "r", encoding="utf-8", errors="ignore") as csv_file:
        reader = csv.reader(csv_file, delimiter=",", quotechar='"')
        try:
            first_row = next(reader)
        except StopIteration:
            return

        if header_tokens:
            first_token = first_row[0].strip().lower() if first_row else ""
            if first_token not in header_tokens:
                yield first_row
        elif not skip_header:
            yield first_row

        yield from reader


def read_csv_rows(
    csv_filename: str,
    *,
    skip_header: bool = True,
    header_tokens: Sequence[str] = (),
) -> list[list[str]]:
    """Reads all data rows from a CSV file, optionally skipping its header."""
    return list(
        iter_csv_rows(
            csv_filename,
            skip_header=skip_header,
            header_tokens=header_tokens,
        )
    )


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
    row_count = 0

    def _iter_parsed() -> Iterator[tuple[object, ...]]:
        nonlocal row_count
        for row in iter_csv_rows(csv_filename):
            if len(row) < spec.min_cols:
                logging.warning("Skipping invalid row: %s", row)
                continue
            try:
                parsed = spec.row_parser(row)
            except (ValueError, TypeError):
                logging.warning("Skipping row with invalid values: %s", row)
                continue
            if parsed is not None:
                row_count += 1
                yield parsed

    with open_sqlite_db(db_name, fast_pragmas=True) as conn:
        cursor = conn.cursor()
        if clear_sql is None:
            cursor.execute(f"DROP TABLE IF EXISTS {spec.table_name}")
        cursor.execute(spec.create_sql)
        if clear_sql is not None:
            cursor.execute(clear_sql)
        cursor.executemany(spec.insert_sql, _iter_parsed())
        for index_sql in spec.indexes:
            cursor.execute(index_sql)

    logging.info(
        "Successfully imported %d rows into '%s' (table '%s').",
        row_count,
        db_name,
        spec.table_name,
    )
    return row_count


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
        row_parser=lambda row: (
            row[0],
            trim_filename(row[1]),
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
