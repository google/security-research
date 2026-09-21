#!/usr/bin/env python3
"""Imports CodeQL allocs (allocation size/flag ranges) CSV records into SQLite database."""

import argparse
import csv
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_allocs_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL allocs CSV records into the SQLite allocs table."""
    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS allocs")
        cursor.execute(
            """
            CREATE TABLE allocs (
                call_value TEXT,
                type_value TEXT,
                objectSize_value TEXT,
                allocSizeMin_value TEXT,
                allocSizeMax_value TEXT,
                allocSize_value TEXT,
                flagsMin_value TEXT,
                flagsMax_value TEXT,
                flags_value TEXT,
                call_uri TEXT,
                call_startLine INTEGER,
                call_startColumn INTEGER,
                depth_value TEXT,
                type_uri TEXT,
                type_startLine TEXT,
                type_startColumn TEXT,
                is_flexible TEXT
            )
            """
        )

        rows = []
        with open(csv_filename, "r", encoding="utf-8", errors="ignore") as csvfile:
            reader = csv.reader(csvfile, delimiter=",", quotechar='"')
            try:
                first_row = next(reader)
                # Check if first row is a header
                if first_row and first_row[0].strip().lower() not in ("call_value", "col0", "call"):
                    rows.append(first_row)
            except StopIteration:
                pass
            rows.extend(reader)

        sample_paths = [r[9] for r in rows if len(r) >= 13]
        prefix = detect_prefix(sample_paths)

        data = []
        for row in rows:
            if len(row) >= 13:
                raw_call = row[0].strip()
                call_value = raw_call if raw_call.startswith("call to ") else f"call to {raw_call}"
                type_value = row[1].strip()
                object_size = row[2].strip()
                size_min = row[3].strip()
                size_max = row[4].strip()
                size_val = row[5].strip()
                flags_min = row[6].strip()
                flags_max = row[7].strip()
                flags_val = row[8].strip()
                call_uri = trim_filename(row[9].strip(), prefix)

                try:
                    call_start_line = int(float(row[10].strip()))
                except (ValueError, TypeError):
                    call_start_line = None

                try:
                    call_start_col = int(float(row[11].strip()))
                except (ValueError, TypeError):
                    call_start_col = None

                is_flexible = row[12].strip()

                if len(row) >= 17:
                    depth_val = row[13].strip()
                    raw_type_uri = row[14].strip()
                    type_uri = (
                        trim_filename(raw_type_uri, prefix)
                        if raw_type_uri and raw_type_uri != "file:/"
                        else "file:/"
                    )
                    type_start_line = row[15].strip()
                    type_start_col = row[16].strip()
                else:
                    depth_val = "1"
                    type_uri = "file:/"
                    type_start_line = ""
                    type_start_col = ""

                data.append(
                    (
                        call_value,
                        type_value,
                        object_size,
                        size_min,
                        size_max,
                        size_val,
                        flags_min,
                        flags_max,
                        flags_val,
                        call_uri,
                        call_start_line,
                        call_start_col,
                        depth_val,
                        type_uri,
                        type_start_line,
                        type_start_col,
                        is_flexible,
                    )
                )
            else:
                logging.warning(f"Skipping invalid row with insufficient columns: {row}")

        cursor.executemany(
            """
            INSERT INTO allocs (
                call_value, type_value, objectSize_value,
                allocSizeMin_value, allocSizeMax_value, allocSize_value,
                flagsMin_value, flagsMax_value, flags_value,
                call_uri, call_startLine, call_startColumn,
                depth_value, type_uri, type_startLine, type_startColumn,
                is_flexible
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data,
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_allocs_type ON allocs(type_value, objectSize_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_allocs_loc ON allocs(call_uri, call_startLine)")
        conn.commit()
        logging.info(
            f"Successfully imported {len(data)} allocs records into '{db_name}' (table 'allocs')."
        )
        return len(data)


def main():
    """Parses command-line arguments and runs allocs CSV import."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL allocs CSV into SQLite database (allocs table)."
    )
    parser.add_argument(
        "csv_file",
        help="Path to allocs CSV file.",
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

    import_allocs_to_db(args.csv_file, args.db_file)


if __name__ == "__main__":
    main()
