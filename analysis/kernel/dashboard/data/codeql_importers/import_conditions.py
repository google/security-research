#!/usr/bin/env python3
"""Imports CodeQL condition statement CSV records into SQLite database."""

import logging

from utils import (
    detect_prefix,
    execute_bulk_insert,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)


def import_conditions_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL condition CSV records into the SQLite conditions table."""
    rows = read_csv_rows(csv_filename)
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
            logging.warning("Skipping invalid row: %s", row)

    execute_bulk_insert(
        db_name,
        """
        CREATE TABLE IF NOT EXISTS conditions (
            type TEXT,
            definition TEXT,
            condition TEXT,
            argument TEXT,
            call TEXT,
            call_location TEXT
        )
        """,
        """
        INSERT INTO conditions (
            type, definition, condition, argument, call, call_location
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        data,
    )
    logging.info(
        "Successfully imported %d conditions into '%s' (table 'conditions').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs conditions CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL conditions CSV into SQLite database "
            "(conditions table)."
        ),
        csv_help="Path to conditions CSV file.",
        importer_fn=import_conditions_to_db,
    )


if __name__ == "__main__":
    main()
