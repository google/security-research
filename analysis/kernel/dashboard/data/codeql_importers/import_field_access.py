#!/usr/bin/env python3
"""Imports CodeQL struct field access CSV records into SQLite database."""

import logging

from utils import (
    detect_prefix,
    execute_bulk_insert,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)


def import_field_access_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL struct field access CSV into the field_access table."""
    rows = read_csv_rows(csv_filename)
    prefix = detect_prefix([r[3] for r in rows if len(r) >= 4])

    data = []
    for row in rows:
        if "unknown" in row or "unnamed" in row:
            continue
        if len(row) >= 4:
            data.append((row[0], row[1], row[2], trim_filename(row[3], prefix)))
        else:
            logging.warning("Skipping invalid row: %s", row)

    execute_bulk_insert(
        db_name,
        """
        CREATE TABLE IF NOT EXISTS field_access (
            type TEXT,
            field TEXT,
            parent TEXT,
            location TEXT
        )
        """,
        """
        INSERT INTO field_access (type, field, parent, location)
        VALUES (?, ?, ?, ?)
        """,
        data,
    )
    logging.info(
        "Successfully imported %d field accesses into '%s' "
        "(table 'field_access').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs field access CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL field access CSV into SQLite database "
            "(field_access table)."
        ),
        csv_help="Path to field_access CSV file.",
        importer_fn=import_field_access_to_db,
    )


if __name__ == "__main__":
    main()
