#!/usr/bin/env python3
"""Imports CodeQL ops target calls CSV records into an SQLite database.

Reads ops target function call locations from a CSV file and populates the ops_targets table.
"""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_ops_targets_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL ops target calls CSV records into the SQLite ops_targets table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ops_targets (
                definition TEXT,
                parent TEXT,
                field TEXT,
                target TEXT,
                target_file TEXT,
                target_start INTEGER,
                target_end INTEGER,
                exprcall_file TEXT,
                exprcall_line INTEGER,
                exprcall_parent_start INTEGER,
                exprcall_parent_end INTEGER
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
            [r[0] for r in rows if len(r) >= 11]
            + [r[4] for r in rows if len(r) >= 11]
            + [r[7] for r in rows if len(r) >= 11]
        )
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if "unknown" in row or "unnamed" in row:
                continue
            if len(row) >= 11:
                data.append(
                    (
                        trim_filename(row[0], prefix),
                        row[1],
                        row[2],
                        row[3],
                        trim_filename(row[4], prefix),
                        int(row[5]),
                        int(row[6]),
                        trim_filename(row[7], prefix),
                        int(row[8]),
                        int(row[9]),
                        int(row[10]),
                    )
                )
            else:
                logging.warning(f"Skipping invalid row: {row}")

        cursor.executemany(
            """
            INSERT INTO ops_targets (
                definition, parent, field, target, target_file,
                target_start, target_end, exprcall_file, exprcall_line,
                exprcall_parent_start, exprcall_parent_end
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} ops targets into '{db_name}' (table 'ops_targets')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs ops targets CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL ops targets CSV into SQLite database (ops_targets table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to ops_targets CSV file.",
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

    import_ops_targets_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
