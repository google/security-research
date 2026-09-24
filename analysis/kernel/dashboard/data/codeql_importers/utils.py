#!/usr/bin/env python3
"""Path trimming and shared CLI/CSV utilities for CodeQL CSV importers."""

import argparse
from collections import Counter
from contextlib import closing
import csv
import logging
import os
import sqlite3
import sys
from typing import Callable, Optional, Sequence

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
        # Return the statistical majority root prefix across all dataset paths
        return Counter(prefixes).most_common(1)[0][0]
    return ""


def trim_filename(path: str, prefix: str = "") -> str:
    """Strips the detected root directory prefix from a file path."""
    if not path:
        return ""

    path = _strip_file_scheme(path)
    clean_prefix = _strip_file_scheme(prefix) if prefix else ""

    if clean_prefix and path.startswith(clean_prefix):
        return path[len(clean_prefix) :]

    # Fallback for individual paths that did not match the detected root prefix
    for top_dir in KERNEL_TOP_DIRS:
        idx = path.find("/" + top_dir)
        if idx != -1:
            return path[idx + 1 :]
        if path.startswith(top_dir):
            return path

    return path


def read_csv_rows(csv_filename: str) -> list[list[str]]:
    """Reads all data rows from a CSV file after skipping its header row."""
    with open(
        csv_filename, "r", encoding="utf-8", errors="ignore"
    ) as csv_file:
        reader = csv.reader(csv_file, delimiter=",", quotechar='"')
        try:
            next(reader)  # Skip header
        except StopIteration:
            return []
        return list(reader)


def execute_bulk_insert(
    db_name: str,
    create_sql: str,
    insert_sql: str,
    data: Sequence[Sequence[object]],
    drop_table: Optional[str] = None,
) -> None:
    """Creates a table if needed and bulk-inserts `data` into `db_name`."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        if drop_table:
            cursor.execute(f"DROP TABLE IF EXISTS {drop_table}")
        cursor.execute(create_sql)
        cursor.executemany(insert_sql, data)
        conn.commit()


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
    label: str,
) -> int:
    """Imports a 4-column CodeQL location CSV into `table_name`."""
    rows = read_csv_rows(csv_filename)
    prefix = detect_prefix([r[1] for r in rows if len(r) >= 4])
    data = parse_location_rows(rows, prefix)

    execute_bulk_insert(
        db_name,
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            {name_column} TEXT,
            file_path TEXT,
            start_line INTEGER,
            end_line INTEGER
        )
        """,
        f"""
        INSERT INTO {table_name} (
            {name_column}, file_path, start_line, end_line
        )
        VALUES (?, ?, ?, ?)
        """,
        data,
    )
    logging.info(
        "Successfully imported %d %s into '%s' (table '%s').",
        len(data),
        label,
        db_name,
        table_name,
    )
    return len(data)
