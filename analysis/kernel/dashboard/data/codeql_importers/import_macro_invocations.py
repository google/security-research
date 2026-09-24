#!/usr/bin/env python3
"""Imports CodeQL macro invocation CSV records into SQLite database."""

from utils import import_location_table, run_importer_cli


def import_macroinvocations_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL macro invocation CSV into macroinvocation_locations."""
    return import_location_table(
        csv_filename,
        db_name,
        table_name="macroinvocation_locations",
        name_column="macroinvocation_name",
        label="macro invocations",
    )


def main():
    """Parses command-line arguments and runs macro invocations CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL macro invocations CSV into SQLite database "
            "(macroinvocation_locations table)."
        ),
        csv_help="Path to macro_invocations CSV file.",
        importer_fn=import_macroinvocations_to_db,
    )


if __name__ == "__main__":
    main()
