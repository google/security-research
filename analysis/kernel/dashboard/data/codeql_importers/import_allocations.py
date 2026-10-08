#!/usr/bin/env python3
"""Imports CodeQL heap allocation CSV records into SQLite database."""

from collections.abc import Sequence

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    import_csv_table,
    parse_optional_int,
    run_importer_cli,
    trim_filename,
)


def _parse_allocation_row(
    row: Sequence[str], prefix: str
) -> tuple[object, ...]:
    """Parses a 9-column allocation CSV row into a database tuple."""
    return (
        trim_filename(row[0], prefix),
        row[1],
        row[2],
        trim_filename(row[3], prefix),
        parse_optional_int(row[4]),
        row[5],
        parse_optional_int(row[6]),
        row[7],
        row[8],
    )


_ALLOCATIONS_SPEC = CsvTableSpec(
    table_name="kmalloc_calls",
    create_sql="""
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
    insert_sql="""
    INSERT INTO kmalloc_calls (
        call_site, call_expr, struct_type, struct_def, struct_size,
        flags, alloc_size, sizeof_expr, is_flexible
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    min_cols=9,
    path_cols=(0, 3),
    row_parser=_parse_allocation_row,
    indexes=(
        (
            "CREATE INDEX IF NOT EXISTS idx_kmalloc_calls_struct_type "
            "ON kmalloc_calls(struct_type)"
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_kmalloc_calls_call_site "
            "ON kmalloc_calls(call_site)"
        ),
    ),
)


def import_allocations_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL heap allocation CSV into the `kmalloc_calls` table."""
    return import_csv_table(csv_filename, db_name, _ALLOCATIONS_SPEC)


def main() -> None:
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
