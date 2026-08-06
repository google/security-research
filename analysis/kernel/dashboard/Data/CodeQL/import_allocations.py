#!/usr/bin/env python3
"""Imports CodeQL heap allocation CSV records into an SQLite database.

Reads allocation sites from a CSV file and populates the kmalloc_calls table.
"""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_allocations_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL heap allocation CSV records into the SQLite kmalloc_calls table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS kmalloc_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_site TEXT,
                call_expr TEXT,
                struct_type TEXT,
                struct_def TEXT,
                struct_size INTEGER,
                flags TEXT,
                alloc_size INTEGER,
                sizeof_expr TEXT,
                is_flexible TEXT
            )
            """
        )

        rows = []
        with open(csv_filename, "r", encoding="utf-8", errors="ignore") as csvfile:
            reader = csv.reader(csvfile, delimiter=",", quotechar='"')
            try:
                next(reader)  # Skip header
            except StopIteration:
                pass
            rows = list(reader)

        sample_paths = [r[0] for r in rows if len(r) >= 9] + [r[3] for r in rows if len(r) >= 9]
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if len(row) >= 9:
                call_site = trim_filename(row[0], prefix)
                call_expr = row[1]
                struct_type = row[2]
                struct_def = trim_filename(row[3], prefix)
                try:
                    struct_size = int(row[4])
                except (ValueError, TypeError):
                    struct_size = None
                flags = row[5]

                try:
                    alloc_size = int(row[6])
                except (ValueError, TypeError):
                    alloc_size = None

                sizeof_expr = row[7]
                is_flexible = row[8]

                data.append(
                    (
                        call_site,
                        call_expr,
                        struct_type,
                        struct_def,
                        struct_size,
                        flags,
                        alloc_size,
                        sizeof_expr,
                        is_flexible,
                    )
                )
            else:
                logging.warning(f"Skipping invalid row with insufficient columns: {row}")

        cursor.executemany(
            """
            INSERT INTO kmalloc_calls (
                call_site, call_expr, struct_type, struct_def, struct_size,
                flags, alloc_size, sizeof_expr, is_flexible
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} allocations into '{db_name}' (table 'kmalloc_calls')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs allocations CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL allocations CSV into SQLite database (kmalloc_calls table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to allocations CSV file.",
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

    import_allocations_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
