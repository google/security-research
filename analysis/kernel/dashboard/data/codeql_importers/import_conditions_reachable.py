#!/usr/bin/env python3
"""Imports CodeQL condition reachability CSV records into SQLite database."""

import logging

from utils import (
    detect_prefix,
    execute_bulk_insert,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)


def import_conditions_reachable_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL condition reachability CSV into conditions_node table."""
    rows = read_csv_rows(csv_filename)
    sample_paths = [r[2] for r in rows if len(r) >= 4] + [
        r[3] for r in rows if len(r) >= 4
    ]
    prefix = detect_prefix(sample_paths)

    data = []
    for row in rows:
        if len(row) >= 4:
            data.append(
                (
                    row[0],
                    row[1],
                    trim_filename(row[2], prefix),
                    trim_filename(row[3], prefix),
                )
            )
        else:
            logging.warning("Skipping invalid row: %s", row)

    execute_bulk_insert(
        db_name,
        """
        CREATE TABLE IF NOT EXISTS conditions_node (
            conditions TEXT,
            function TEXT,
            conditions_location TEXT,
            function_location TEXT
        )
        """,
        """
        INSERT INTO conditions_node (
            conditions, function, conditions_location, function_location
        )
        VALUES (?, ?, ?, ?)
        """,
        data,
    )
    logging.info(
        "Successfully imported %d condition nodes into '%s' "
        "(table 'conditions_node').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs condition reachability import."""
    run_importer_cli(
        description=(
            "Import CodeQL conditions reachable CSV into SQLite database "
            "(conditions_node table)."
        ),
        csv_help="Path to conditions reachable CSV file.",
        importer_fn=import_conditions_reachable_to_db,
    )


if __name__ == "__main__":
    main()
