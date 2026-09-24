#!/usr/bin/env python3
"""Imports CodeQL function location CSV records into SQLite database."""

from utils import import_location_table, run_importer_cli


def import_functions_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL function location CSV into function_locations table."""
    return import_location_table(
        csv_filename,
        db_name,
        table_name="function_locations",
        name_column="function_name",
        label="functions",
    )


def main():
    """Parses command-line arguments and runs functions CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL functions CSV into SQLite database "
            "(function_locations table)."
        ),
        csv_help="Path to functions CSV file.",
        importer_fn=import_functions_to_db,
    )


if __name__ == "__main__":
    main()
