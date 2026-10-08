#!/usr/bin/env python3
"""Imports CodeQL condition reachability CSV records into SQLite database."""

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    import_csv_table,
    run_importer_cli,
    trim_filename,
)

_CONDITIONS_NODE_SPEC = CsvTableSpec(
    table_name="conditions_node",
    create_sql="""
    CREATE TABLE IF NOT EXISTS conditions_node (
        conditions TEXT,
        function TEXT,
        conditions_location TEXT,
        function_location TEXT
    )
    """,
    insert_sql="""
    INSERT INTO conditions_node (
        conditions, function, conditions_location, function_location
    )
    VALUES (?, ?, ?, ?)
    """,
    min_cols=4,
    path_cols=(2, 3),
    row_parser=lambda row, prefix: (
        row[0],
        row[1],
        trim_filename(row[2], prefix),
        trim_filename(row[3], prefix),
    ),
    indexes=(
        (
            "CREATE INDEX IF NOT EXISTS idx_conditions_node_function "
            "ON conditions_node(function)"
        ),
    ),
)


def import_conditions_reachable_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL condition reachability CSV into `conditions_node`."""
    return import_csv_table(csv_filename, db_name, _CONDITIONS_NODE_SPEC)


def main() -> None:
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
