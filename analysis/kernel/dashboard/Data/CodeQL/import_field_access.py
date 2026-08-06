#!/usr/bin/env python3
"""Imports CodeQL struct field access CSV records into an SQLite database.

Reads struct field access locations from a CSV file and populates the field_access table.
"""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_field_access_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL struct field access CSV records into the SQLite field_access table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS field_access (
                type TEXT,
                field TEXT,
                parent TEXT,
                location TEXT
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

        sample_paths = [r[3] for r in rows if len(r) >= 4]
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if "unknown" in row or "unnamed" in row:
                continue
            if len(row) >= 4:
                data.append((row[0], row[1], row[2], trim_filename(row[3], prefix)))
            else:
                logging.warning(f"Skipping invalid row: {row}")

        cursor.executemany(
            """
            INSERT INTO field_access (type, field, parent, location)
            VALUES (?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} field accesses into '{db_name}' (table 'field_access')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs field access CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL field access CSV into SQLite database (field_access table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to field_access CSV file.",
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

    import_field_access_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
