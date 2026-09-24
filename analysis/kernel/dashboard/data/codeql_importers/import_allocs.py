#!/usr/bin/env python3
"""Imports CodeQL allocs (size/flag ranges) CSV records into SQLite database."""

from contextlib import closing
import csv
import logging
import sqlite3
from typing import Optional

from utils import detect_prefix, run_importer_cli, trim_filename


def _parse_float_int(value: str) -> Optional[int]:
    """Parses a numeric string (possibly float-formatted) into an int."""
    try:
        return int(float(value.strip()))
    except (ValueError, TypeError):
        return None


def _read_allocs_rows(csv_filename: str) -> list[list[str]]:
    """Reads rows from allocs CSV, skipping the header row if present."""
    rows = []
    with open(csv_filename, "r", encoding="utf-8", errors="ignore") as csvfile:
        reader = csv.reader(csvfile, delimiter=",", quotechar='"')
        try:
            first_row = next(reader)
            if first_row and first_row[0].strip().lower() not in (
                "call_value",
                "col0",
                "call",
            ):
                rows.append(first_row)
        except StopIteration:
            pass
        rows.extend(reader)
    return rows


def _parse_alloc_row(row: list[str], prefix: str) -> tuple[object, ...]:
    """Parses a 13+ column allocs CSV row into a 17-column database tuple."""
    raw_call = row[0].strip()
    call_value = (
        raw_call if raw_call.startswith("call to ") else f"call to {raw_call}"
    )
    if len(row) >= 17:
        raw_type_uri = row[14].strip()
        type_uri = (
            trim_filename(raw_type_uri, prefix)
            if raw_type_uri and raw_type_uri != "file:/"
            else "file:/"
        )
        extra = (
            row[13].strip(),
            type_uri,
            row[15].strip(),
            row[16].strip(),
        )
    else:
        extra = ("1", "file:/", "", "")

    return (
        call_value,
        row[1].strip(),
        row[2].strip(),
        row[3].strip(),
        row[4].strip(),
        row[5].strip(),
        row[6].strip(),
        row[7].strip(),
        row[8].strip(),
        trim_filename(row[9].strip(), prefix),
        _parse_float_int(row[10]),
        _parse_float_int(row[11]),
        extra[0],
        extra[1],
        extra[2],
        extra[3],
        row[12].strip(),
    )


def import_allocs_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL allocs CSV records into the SQLite allocs table."""
    rows = _read_allocs_rows(csv_filename)
    prefix = detect_prefix([r[9] for r in rows if len(r) >= 13])

    data = []
    for row in rows:
        if len(row) >= 13:
            data.append(_parse_alloc_row(row, prefix))
        else:
            logging.warning(
                "Skipping invalid row with insufficient columns: %s", row
            )

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
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_allocs_type "
            "ON allocs(type_value, objectSize_value)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_allocs_loc "
            "ON allocs(call_uri, call_startLine)"
        )
        conn.commit()

    logging.info(
        "Successfully imported %d allocs records into '%s' (table 'allocs').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs allocs CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL allocs CSV into SQLite database (allocs table)."
        ),
        csv_help="Path to allocs CSV file.",
        importer_fn=import_allocs_to_db,
    )


if __name__ == "__main__":
    main()
