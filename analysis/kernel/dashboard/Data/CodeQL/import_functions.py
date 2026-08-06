#!/usr/bin/env python3
"""Imports CodeQL function location CSV records into an SQLite database.

Reads function boundary locations from a CSV file and populates the function_locations table.
"""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_functions_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL function location CSV records into the SQLite function_locations table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS function_locations (
                function_name TEXT,
                file_path TEXT,
                start_line INTEGER,
                end_line INTEGER
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

        sample_paths = [r[1] for r in rows if len(r) >= 4]
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if len(row) >= 4:
                function_name = row[0]
                file_path = trim_filename(row[1], prefix)
                try:
                    start_line = int(row[2])
                    end_line = int(row[3])
                except (ValueError, TypeError):
                    logging.warning(f"Skipping row with invalid line numbers: {row}")
                    continue
                data.append((function_name, file_path, start_line, end_line))
            else:
                logging.warning(f"Skipping invalid row: {row}")

        cursor.executemany(
            """
            INSERT INTO function_locations (function_name, file_path, start_line, end_line)
            VALUES (?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} functions into '{db_name}' (table 'function_locations')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs functions CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL functions CSV into SQLite database (function_locations table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to functions CSV file.",
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

    import_functions_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
