#!/usr/bin/env python3
"""Imports CodeQL heap allocation CSV records into SQLite database."""

import logging
from typing import Optional

from utils import (
    detect_prefix,
    execute_bulk_insert,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)


def _parse_optional_int(value: str) -> Optional[int]:
    """Converts a string to int, returning None on ValueError or TypeError."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _parse_allocation_row(row: list[str], prefix: str) -> tuple[object, ...]:
    """Parses a 9-column allocation CSV row into a database tuple."""
    return (
        trim_filename(row[0], prefix),
        row[1],
        row[2],
        trim_filename(row[3], prefix),
        _parse_optional_int(row[4]),
        row[5],
        _parse_optional_int(row[6]),
        row[7],
        row[8],
    )


def import_allocations_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL heap allocation CSV into the kmalloc_calls table."""
    rows = read_csv_rows(csv_filename)
    sample_paths = [r[0] for r in rows if len(r) >= 9] + [
        r[3] for r in rows if len(r) >= 9
    ]
    prefix = detect_prefix(sample_paths)

    data = []
    for row in rows:
        if len(row) >= 9:
            data.append(_parse_allocation_row(row, prefix))
        else:
            logging.warning(
                "Skipping invalid row with insufficient columns: %s", row
            )

    execute_bulk_insert(
        db_name,
        """
        CREATE TABLE kmalloc_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_site TEXT,
            call_expr TEXT,
            struct_type TEXT,
            struct_def TEXT,
            struct_size INTEGER,
            flags TEXT,
            alloc_size INTEGER,
            sizeof_expr TEXT,
            is_flexible TEXT
        )
        """,
        """
        INSERT INTO kmalloc_calls (
            call_site, call_expr, struct_type, struct_def, struct_size,
            flags, alloc_size, sizeof_expr, is_flexible
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        data,
        drop_table="kmalloc_calls",
    )
    logging.info(
        "Successfully imported %d allocations into '%s' "
        "(table 'kmalloc_calls').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs allocations CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL allocations CSV into SQLite database "
            "(kmalloc_calls table)."
        ),
        csv_help="Path to allocations CSV file.",
        importer_fn=import_allocations_to_db,
    )


if __name__ == "__main__":
    main()
