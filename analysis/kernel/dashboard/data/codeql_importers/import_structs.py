#!/usr/bin/env python3
"""Imports CodeQL structs CSV records into SQLite (struct_locations/fields)."""

from collections.abc import Sequence
import logging
from typing import Optional

from data.codeql_importers.lib.utils import (
    detect_csv_prefix,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)
from data.lib.db import open_sqlite_db

_CREATE_STRUCT_LOCATIONS_SQL = """
CREATE TABLE IF NOT EXISTS struct_locations (
    struct_name     TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    start_line      INTEGER NOT NULL,
    end_line        INTEGER NOT NULL,
    byte_size       INTEGER NOT NULL,
    member_count    INTEGER NOT NULL,
    is_anonymous    INTEGER NOT NULL,
    is_typedef      INTEGER NOT NULL,
    has_flex_member INTEGER NOT NULL,
    PRIMARY KEY (struct_name, file_path, start_line)
)
"""

_INSERT_STRUCT_LOCATIONS_SQL = """
INSERT OR REPLACE INTO struct_locations (
    struct_name, file_path, start_line, end_line, byte_size,
    member_count, is_anonymous, is_typedef, has_flex_member
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_CREATE_STRUCT_FIELDS_SQL = """
CREATE TABLE IF NOT EXISTS struct_fields (
    struct_name TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    start_line  INTEGER NOT NULL,
    field_name  TEXT NOT NULL,
    field_path  TEXT NOT NULL,
    field_type  TEXT NOT NULL,
    byte_offset INTEGER NOT NULL,
    bit_offset  INTEGER,
    bit_size    INTEGER,
    is_funcptr  INTEGER NOT NULL,
    is_flex     INTEGER NOT NULL,
    array_len   INTEGER
)
"""

_INSERT_STRUCT_FIELDS_SQL = """
INSERT INTO struct_fields (
    struct_name, file_path, start_line, field_name, field_path,
    field_type, byte_offset, bit_offset, bit_size,
    is_funcptr, is_flex, array_len
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_INDEXES = (
    (
        "CREATE INDEX IF NOT EXISTS idx_struct_locations_name "
        "ON struct_locations(struct_name)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS idx_struct_locations_loc "
        "ON struct_locations(file_path, start_line, end_line)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS idx_struct_fields_struct_key "
        "ON struct_fields(struct_name, file_path, start_line)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS idx_struct_fields_name "
        "ON struct_fields(struct_name, field_name)"
    ),
)


def _nonneg_or_none(value: str) -> Optional[int]:
    """Parses an integer string, returning None if negative (`-1`)."""
    val = int(value)
    return val if val >= 0 else None


def _parse_struct_row(
    row: Sequence[str], prefix: str
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    """Parses an 18-column structs CSV row into location and field tuples."""
    struct_name = row[0]
    file_path = trim_filename(row[1], prefix)
    start_line = int(row[2])
    loc_tuple: tuple[object, ...] = (
        struct_name,
        file_path,
        start_line,
        int(row[3]),
        int(row[4]),
        int(row[5]),
        int(row[6]),
        int(row[7]),
        int(row[8]),
    )
    field_tuple: tuple[object, ...] = (
        struct_name,
        file_path,
        start_line,
        row[9],
        row[10],
        row[11],
        int(row[12]),
        _nonneg_or_none(row[13]),
        _nonneg_or_none(row[14]),
        int(row[15]),
        int(row[16]),
        _nonneg_or_none(row[17]),
    )
    return loc_tuple, field_tuple


def _dedup_struct_rows(
    rows: Sequence[Sequence[str]], prefix: str
) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
    """Deduplicate struct location and field rows by key."""
    locations_by_key: dict[tuple[str, str, int], tuple[object, ...]] = {}
    fields_by_key: dict[tuple[str, str, int, str], tuple[object, ...]] = {}

    for row in rows:
        if len(row) < 18:
            logging.warning("Skipping invalid struct row: %s", row)
            continue
        try:
            loc_tuple, field_tuple = _parse_struct_row(row, prefix)
        except (ValueError, TypeError):
            logging.warning("Skipping struct row with invalid values: %s", row)
            continue

        loc_key = (
            str(loc_tuple[0]),
            str(loc_tuple[1]),
            int(str(loc_tuple[2])),
        )
        prev_loc = locations_by_key.get(loc_key)
        if prev_loc is None or int(str(loc_tuple[4])) >= int(str(prev_loc[4])):
            locations_by_key[loc_key] = loc_tuple

        field_key = (
            str(field_tuple[0]),
            str(field_tuple[1]),
            int(str(field_tuple[2])),
            str(field_tuple[4]),
        )
        prev_field = fields_by_key.get(field_key)
        if prev_field is None or int(str(field_tuple[6])) >= int(
            str(prev_field[6])
        ):
            fields_by_key[field_key] = field_tuple

    return list(locations_by_key.values()), list(fields_by_key.values())


def import_structs_to_db(csv_filename: str, db_name: str) -> int:
    """Imports structs CSV into `struct_locations` and `struct_fields`."""
    rows = read_csv_rows(csv_filename)
    prefix = detect_csv_prefix(rows, (1,), 18)
    locations_data, fields_data = _dedup_struct_rows(rows, prefix)

    with open_sqlite_db(db_name, fast_pragmas=True) as conn:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS struct_locations")
        cursor.execute("DROP TABLE IF EXISTS struct_fields")
        cursor.execute(_CREATE_STRUCT_LOCATIONS_SQL)
        cursor.execute(_CREATE_STRUCT_FIELDS_SQL)
        cursor.executemany(_INSERT_STRUCT_LOCATIONS_SQL, locations_data)
        cursor.executemany(_INSERT_STRUCT_FIELDS_SQL, fields_data)
        for index_sql in _INDEXES:
            cursor.execute(index_sql)

    logging.info(
        "Successfully imported %d struct_locations and %d struct_fields "
        "into '%s'.",
        len(locations_data),
        len(fields_data),
        db_name,
    )
    return len(fields_data)


def main() -> None:
    """Parses command-line arguments and runs structs CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL structs CSV into SQLite database "
            "(struct_locations and struct_fields tables)."
        ),
        csv_help="Path to structs CSV file.",
        importer_fn=import_structs_to_db,
    )


if __name__ == "__main__":
    main()
