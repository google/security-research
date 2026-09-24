#!/usr/bin/env python3
"""Imports CodeQL ops target calls CSV records into SQLite database."""

import logging

from utils import (
    detect_prefix,
    execute_bulk_insert,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)


def import_ops_targets_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL ops target calls CSV into the ops_targets table."""
    rows = read_csv_rows(csv_filename)
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
            logging.warning("Skipping invalid row: %s", row)

    execute_bulk_insert(
        db_name,
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
        """,
        """
        INSERT INTO ops_targets (
            definition, parent, field, target, target_file,
            target_start, target_end, exprcall_file, exprcall_line,
            exprcall_parent_start, exprcall_parent_end
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        data,
    )
    logging.info(
        "Successfully imported %d ops targets into '%s' (table 'ops_targets').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs ops targets CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL ops targets CSV into SQLite database "
            "(ops_targets table)."
        ),
        csv_help="Path to ops_targets CSV file.",
        importer_fn=import_ops_targets_to_db,
    )


if __name__ == "__main__":
    main()
