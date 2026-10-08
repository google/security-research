#!/usr/bin/env python3
"""Imports CodeQL kernel config CSV records into SQLite database."""

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    import_csv_table,
    run_importer_cli,
    trim_filename,
)

_CONFIGS_SPEC = CsvTableSpec(
    table_name="configs",
    create_sql="""
    CREATE TABLE IF NOT EXISTS configs (
        config TEXT,
        path TEXT,
        ifdef INTEGER,
        endif INTEGER,
        else_ INTEGER
    )
    """,
    insert_sql="""
    INSERT INTO configs (config, path, ifdef, endif, else_)
    VALUES (?, ?, ?, ?, ?)
    """,
    min_cols=5,
    path_cols=(1,),
    row_parser=lambda row, prefix: (
        row[0],
        trim_filename(row[1], prefix),
        int(row[2]),
        int(row[3]),
        int(row[4]),
    ),
    indexes=(
        (
            "CREATE INDEX IF NOT EXISTS idx_configs_path_span "
            "ON configs(path, ifdef, endif)"
        ),
    ),
)


def import_configs_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL kernel config CSV records into the `configs` table."""
    return import_csv_table(
        csv_filename,
        db_name,
        _CONFIGS_SPEC,
        clear_sql="DELETE FROM configs WHERE NOT (ifdef = 1 AND else_ = 0)",
    )


def main() -> None:
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
