#!/usr/bin/env python3
"""Imports CodeQL struct field access CSV records into SQLite database."""

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    has_unknown_token,
    import_csv_table,
    run_importer_cli,
    trim_filename,
)

_FIELD_ACCESS_SPEC = CsvTableSpec(
    table_name="field_access",
    create_sql="""
    CREATE TABLE IF NOT EXISTS field_access (
        type TEXT,
        field TEXT,
        parent TEXT,
        location TEXT
    )
    """,
    insert_sql="""
    INSERT INTO field_access (type, field, parent, location)
    VALUES (?, ?, ?, ?)
    """,
    min_cols=4,
    path_cols=(3,),
    row_parser=lambda row, prefix: (
        None
        if has_unknown_token(row)
        else (
            row[0],
            row[1],
            row[2],
            trim_filename(row[3], prefix),
        )
    ),
    indexes=(
        (
            "CREATE INDEX IF NOT EXISTS idx_field_access_parent_field "
            "ON field_access(parent, field)"
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
