#!/usr/bin/env python3
"""Imports CodeQL struct field access CSV records into SQLite database."""

from collections.abc import Sequence
from typing import Optional

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    has_unknown_token,
    import_csv_table,
    run_importer_cli,
    trim_filename,
)


def _parse_field_access_row(
    row: Sequence[str], prefix: str
) -> Optional[tuple[object, ...]]:
    """Parses a 7-column (or 4-column) field_access CSV row."""
    if has_unknown_token(row):
        return None
    loc = trim_filename(row[3], prefix)
    if len(row) >= 7:
        fn_name = row[4]
        file_path = trim_filename(row[5], prefix)
        line = int(row[6])
    else:
        fn_name = ""
        loc_parts = loc.split(":")
        file_path = loc_parts[0] if loc_parts else ""
        line = (
            int(loc_parts[1])
            if len(loc_parts) > 1 and loc_parts[1].isdigit()
            else 0
        )
    return (row[0], row[1], row[2], loc, fn_name, file_path, line)


_FIELD_ACCESS_SPEC = CsvTableSpec(
    table_name="field_access",
    create_sql="""
    CREATE TABLE IF NOT EXISTS field_access (
        type TEXT,
        field TEXT,
        parent TEXT,
        location TEXT,
        function_name TEXT,
        file_path TEXT,
        line INTEGER
    )
    """,
    insert_sql="""
    INSERT INTO field_access (
        type, field, parent, location, function_name, file_path, line
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
    min_cols=4,
    path_cols=(3, 5),
    row_parser=_parse_field_access_row,
    indexes=(
        (
            "CREATE INDEX IF NOT EXISTS idx_field_access_parent_field "
            "ON field_access(parent, field)"
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_field_access_fn_file "
            "ON field_access(function_name, file_path)"
        ),
    ),
)


def import_field_access_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL struct field access CSV into the `field_access` table."""
    return import_csv_table(csv_filename, db_name, _FIELD_ACCESS_SPEC)


def main() -> None:
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
