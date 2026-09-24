#!/usr/bin/env python3
"""Imports CodeQL macro definition CSV records into SQLite database."""

from utils import import_location_table, run_importer_cli


def import_macros_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL macro definition CSV into the macro_locations table."""
    return import_location_table(
        csv_filename,
        db_name,
        table_name="macro_locations",
        name_column="macro_name",
        label="macros",
    )


def main():
    """Parses command-line arguments and runs macros CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL macros CSV into SQLite database "
            "(macro_locations table)."
        ),
        csv_help="Path to macros CSV file.",
        importer_fn=import_macros_to_db,
    )


if __name__ == "__main__":
    main()
