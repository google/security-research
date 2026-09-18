#!/usr/bin/env python3
"""Imports CodeQL kernel config CSV records into SQLite database."""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_configs_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL kernel config guard CSV records into the SQLite configs table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS configs (
                config TEXT,
                path TEXT,
                ifdef INTEGER,
                endif INTEGER,
                else_ INTEGER
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

        sample_paths = [r[1] for r in rows if len(r) >= 5]
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if len(row) >= 5:
                try:
                    data.append(
                        (
                            row[0],
                            trim_filename(row[1], prefix),
                            int(row[2]),
                            int(row[3]),
                            int(row[4]),
                        )
                    )
                except ValueError:
                    logging.warning(f"Skipping row with non-integer line numbers: {row}")
            else:
                logging.warning(f"Skipping invalid row: {row}")

        cursor.executemany(
            """
            INSERT INTO configs (config, path, ifdef, endif, else_)
            VALUES (?, ?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} configs into '{db_name}' (table 'configs')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs configs CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL kernel configs CSV into SQLite database (configs table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to configs CSV file.",
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

    import_configs_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
