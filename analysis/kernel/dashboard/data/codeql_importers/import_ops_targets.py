#!/usr/bin/env python3
"""Imports CodeQL ops target calls CSV records into SQLite database."""

from collections.abc import Sequence
from typing import Optional

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    has_unknown_token,
    import_csv_table,
    run_importer_cli,
    trim_filename,
)


def _parse_ops_target_row(
    row: Sequence[str], prefix: str
) -> Optional[tuple[object, ...]]:
    """Parses an 11-column ops_edges CSV row into a database tuple."""
    if has_unknown_token(row):
        return None
    return (
        trim_filename(row[0], prefix),
        row[1],
        row[2],
        row[3],
        trim_filename(row[4], prefix),
        int(row[5]),
        int(row[6]),
        trim_filename(row[7], prefix),
        int(row[8]),
        int(row[9]),
        int(row[10]),
    )


_OPS_TARGETS_SPEC = CsvTableSpec(
    table_name="ops_targets",
    create_sql="""
    CREATE TABLE IF NOT EXISTS ops_targets (
        definition TEXT,
        parent TEXT,
        field TEXT,
        target TEXT,
        target_file TEXT,
        target_start INTEGER,
        target_end INTEGER,
        exprcall_file TEXT,
        exprcall_line INTEGER,
        exprcall_parent_start INTEGER,
        exprcall_parent_end INTEGER
    )
    """,
    insert_sql="""
    INSERT INTO ops_targets (
        definition, parent, field, target, target_file,
        target_start, target_end, exprcall_file, exprcall_line,
        exprcall_parent_start, exprcall_parent_end
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    min_cols=11,
    path_cols=(0, 4, 7),
    row_parser=_parse_ops_target_row,
    indexes=(
        (
            "CREATE INDEX IF NOT EXISTS idx_ops_targets_target "
            "ON ops_targets(target)"
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_ops_targets_parent_field "
            "ON ops_targets(parent, field)"
        ),
    ),
)


def import_ops_targets_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL ops target calls CSV into the `ops_targets` table."""
    return import_csv_table(csv_filename, db_name, _OPS_TARGETS_SPEC)


def main() -> None:
    """Parses command-line arguments and runs ops targets CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL ops targets CSV into SQLite database "
            "(ops_targets table)."
        ),
        csv_help="Path to ops_targets CSV file.",
        importer_fn=import_ops_targets_to_db,
    )


if __name__ == "__main__":
    main()
