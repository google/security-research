#!/usr/bin/env python3
"""Imports CodeQL syscall reachability CSV records into an SQLite database.

Reads syscall reachability nodes from a CSV file and populates the syscall_node table.
"""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_syscall_reachable_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL syscall reachability CSV records into the SQLite syscall_node table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS syscall_node (
                syscall TEXT,
                function TEXT,
                syscall_location TEXT,
                function_location TEXT
            )
            """
        )

        rows = []
        with open(csv_filename, "r", encoding="utf-8", errors="ignore") as file:
            reader = csv.reader(file)
            try:
                next(reader)  # Skip header
            except StopIteration:
                pass
            rows = list(reader)

        sample_paths = [r[2] for r in rows if len(r) >= 4] + [r[3] for r in rows if len(r) >= 4]
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if len(row) >= 4:
                data.append(
                    (row[0], row[1], trim_filename(row[2], prefix), trim_filename(row[3], prefix))
                )
            else:
                logging.warning(f"Skipping invalid row: {row}")

        cursor.executemany(
            """
            INSERT INTO syscall_node (syscall, function, syscall_location, function_location)
            VALUES (?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} syscall nodes into '{db_name}' (table 'syscall_node')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs syscall reachability CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL syscall reachable CSV into SQLite database (syscall_node table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to syscall reachable CSV file.",
        type=str,
    )
    parser.add_argument(
        "db_file",
        help="Path to target SQLite database file.",
        type=str,
    )
    args = parser.parse_args()

    if not os.path.isfile(args.csv_file):
        logging.critical(f"CSV file not found or unreadable: {args.csv_file}")
        sys.exit(1)

    import_syscall_reachable_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
