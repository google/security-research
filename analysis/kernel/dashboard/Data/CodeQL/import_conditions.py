#!/usr/bin/env python3
"""Imports CodeQL condition statement CSV records into SQLite database."""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_conditions_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL condition statement CSV records into the SQLite conditions table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS conditions (
                type TEXT,
                definition TEXT,
                condition TEXT,
                argument TEXT,
                call TEXT,
                call_location TEXT
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

        sample_paths = (
            [r[1] for r in rows if len(r) >= 6]
            + [r[2] for r in rows if len(r) >= 6]
            + [r[5] for r in rows if len(r) >= 6]
        )
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if len(row) >= 6:
                data.append(
                    (
                        row[0],
                        trim_filename(row[1], prefix),
                        trim_filename(row[2], prefix),
                        row[3],
                        row[4],
                        trim_filename(row[5], prefix),
                    )
                )
            else:
                logging.warning(f"Skipping invalid row: {row}")

        cursor.executemany(
            """
            INSERT INTO conditions (type, definition, condition, argument, call, call_location)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} conditions into '{db_name}' (table 'conditions')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs conditions CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL conditions CSV into SQLite database (conditions table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to conditions CSV file.",
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

    import_conditions_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
