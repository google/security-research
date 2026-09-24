#!/usr/bin/env python3
"""Imports CodeQL kernel config CSV records into SQLite database."""

import logging

from utils import (
    detect_prefix,
    execute_bulk_insert,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)


def import_configs_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL kernel config CSV records into the configs table."""
    rows = read_csv_rows(csv_filename)
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
                logging.warning(
                    "Skipping row with non-integer line numbers: %s", row
                )
        else:
            logging.warning("Skipping invalid row: %s", row)

    execute_bulk_insert(
        db_name,
        """
        CREATE TABLE IF NOT EXISTS configs (
            config TEXT,
            path TEXT,
            ifdef INTEGER,
            endif INTEGER,
            else_ INTEGER
        )
        """,
        """
        INSERT INTO configs (config, path, ifdef, endif, else_)
        VALUES (?, ?, ?, ?, ?)
        """,
        data,
    )
    logging.info(
        "Successfully imported %d configs into '%s' (table 'configs').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs configs CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL kernel configs CSV into SQLite database "
            "(configs table)."
        ),
        csv_help="Path to configs CSV file.",
        importer_fn=import_configs_to_db,
    )


if __name__ == "__main__":
    main()
