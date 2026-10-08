#!/usr/bin/env python3
"""Imports CodeQL condition statement CSV records into SQLite database."""

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    import_csv_table,
    run_importer_cli,
    trim_filename,
)

_CONDITIONS_SPEC = CsvTableSpec(
    table_name="conditions",
    create_sql="""
    CREATE TABLE IF NOT EXISTS conditions (
        type TEXT,
        definition TEXT,
        condition TEXT,
        argument TEXT,
        call TEXT,
        call_location TEXT
    )
    """,
    insert_sql="""
    INSERT INTO conditions (
        type, definition, condition, argument, call, call_location
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """,
    min_cols=6,
    path_cols=(1, 2, 5),
    row_parser=lambda row, prefix: (
        row[0],
        trim_filename(row[1], prefix),
        trim_filename(row[2], prefix),
        row[3],
        row[4],
        trim_filename(row[5], prefix),
    ),
    indexes=(
        "CREATE INDEX IF NOT EXISTS idx_conditions_call ON conditions(call)",
    ),
)


def import_conditions_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL condition CSV records into the `conditions` table."""
    return import_csv_table(csv_filename, db_name, _CONDITIONS_SPEC)


def main() -> None:
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
