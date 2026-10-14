#!/usr/bin/env python3
"""Imports CodeQL all-calls CSV outputs into SQLite (locations and edges)."""

import csv
import logging
import sqlite3
from typing import Any

from data.codeql_importers.lib.utils import (
    detect_prefix,
    run_importer_cli,
    trim_filename,
)
from data.lib.db import open_sqlite_db

RULE_ID = "callgraph-all"


def parse_codeql_url(url: str) -> tuple[str, int, int, int, int]:
    """Parses a CodeQL `file://path:startLine:startCol:endLine:endCol` URL."""
    if url.startswith("file://"):
        url = url[7:]
    parts = url.rsplit(":", 4)
    if len(parts) == 5 and parts[1].isdigit():
        return (
            parts[0],
            int(parts[1]),
            int(parts[2]),
            int(parts[3]),
            int(parts[4]),
        )
    return url, 0, 0, 0, 0


def _is_header_row(row: list[str]) -> bool:
    """Returns True if `row` is a CSV header line."""
    if not row:
        return True
    if row[0] in ("src_label", "a", "nodeFrom"):
        return True
    if len(row) >= 12:
        try:
            int(row[2])
            return False
        except ValueError:
            return True
    return False


def _parse_edge_endpoints(
    row: list[str],
) -> tuple[
    tuple[str, str, int, int, int, int],
    tuple[str, str, int, int, int, int],
] | None:
    """Parses a 12-column explicit row (or 4-column URL row) into two endpoints."""
    if len(row) >= 12:
        try:
            src = (
                row[0],
                row[1],
                int(row[2]),
                int(row[3]),
                int(row[4]),
                int(row[5]),
            )
            dst = (
                row[6],
                row[7],
                int(row[8]),
                int(row[9]),
                int(row[10]),
                int(row[11]),
            )
        except ValueError:
            return None
        if not src[0] or not dst[0]:
            return None
        return src, dst

    if len(row) >= 4:
        src_msg, src_url, dst_msg, dst_url = row[0], row[1], row[2], row[3]
        if not src_msg or not dst_msg:
            return None
        s_uri, s_sl, s_sc, s_el, s_ec = parse_codeql_url(src_url)
        d_uri, d_sl, d_sc, d_el, d_ec = parse_codeql_url(dst_url)
        return (
            (src_msg, s_uri, s_sl, s_sc, s_el, s_ec),
            (dst_msg, d_uri, d_sl, d_sc, d_el, d_ec),
        )
    return None


def _extract_sample_uris_from_csv(
    csv_file_path: str, limit: int = 200
) -> list[str]:
    """Collects up to `limit` raw file URIs from an all-calls CSV file."""
    sample_uris: list[str] = []
    with open(
        csv_file_path, "r", newline="", encoding="utf-8", errors="ignore"
    ) as fh:
        reader = csv.reader(fh)
        for idx, row in enumerate(reader):
            if idx == 0 and _is_header_row(row):
                continue
            parsed = _parse_edge_endpoints(row)
            if parsed is None:
                continue
            for endpoint in parsed:
                if endpoint[1]:
                    sample_uris.append(endpoint[1])
                    if len(sample_uris) >= limit:
                        return sample_uris
    return sample_uris


def _init_all_calls_tables(
    cursor: sqlite3.Cursor, *, replace_existing: bool = True
) -> None:
    """Creates the `locations` and `edges` tables in SQLite."""
    if replace_existing:
        for table in (
            "edges",
            "locations",
            "threadFlows",
            "codeFlows",
            "results",
            "runs",
        ):
            cursor.execute(f"DROP TABLE IF EXISTS {table}")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threadFlow_id INTEGER,
            message TEXT NOT NULL,
            uri TEXT,
            startLine INTEGER,
            startColumn INTEGER,
            endLine INTEGER,
            endColumn INTEGER
        )
        """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_location_id INTEGER NOT NULL,
            target_location_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            FOREIGN KEY (source_location_id) REFERENCES locations (id),
            FOREIGN KEY (target_location_id) REFERENCES locations (id)
        )
        """)


def _create_all_calls_indexes(cursor: sqlite3.Cursor) -> None:
    """Creates lookup indexes on `edges` and `locations`."""
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_edges_source "
        "ON edges(source_location_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_edges_target "
        "ON edges(target_location_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_locations_message ON locations(message)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_locations_uri_line "
        "ON locations(uri, startLine)"
    )


def _get_max_id(cursor: sqlite3.Cursor, table: str) -> int:
    """Returns the current maximum integer ID in `table`, or 0 if empty."""
    row = cursor.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()
    return int(row[0] or 0)


def _collect_csv_rows(
    csv_file_path: str,
    prefix: str,
    base_loc_id: int,
) -> tuple[list[tuple[Any, ...]], list[tuple[int, int, str]]]:
    """Reads `all-calls.csv` into deduplicated `locations` and `edges` batches."""
    loc_id_by_key: dict[tuple[str, str, int, int, int, int], int] = {}
    locations_batch: list[tuple[Any, ...]] = []
    edges_batch: list[tuple[int, int, str]] = []
    next_loc_id = base_loc_id

    def intern_location(
        endpoint: tuple[str, str, int, int, int, int],
    ) -> int:
        nonlocal next_loc_id
        msg, raw_uri, sl, sc, el, ec = endpoint
        clean_uri = trim_filename(raw_uri, prefix)
        key = (msg, clean_uri, sl, sc, el, ec)
        existing_id = loc_id_by_key.get(key)
        if existing_id is not None:
            return existing_id
        next_loc_id += 1
        loc_id_by_key[key] = next_loc_id
        locations_batch.append(
            (next_loc_id, 0, msg, clean_uri, sl, sc, el, ec)
        )
        return next_loc_id

    with open(
        csv_file_path, "r", newline="", encoding="utf-8", errors="ignore"
    ) as fh:
        reader = csv.reader(fh)
        for idx, row in enumerate(reader):
            if idx == 0 and _is_header_row(row):
                continue
            parsed = _parse_edge_endpoints(row)
            if parsed is None:
                continue
            src_id = intern_location(parsed[0])
            dst_id = intern_location(parsed[1])
            edges_batch.append((src_id, dst_id, RULE_ID))

    return locations_batch, edges_batch


def import_all_calls_to_db(
    csv_file_path: str,
    db_name: str = "kernel_dashboard.db",
    *,
    replace_existing: bool = True,
) -> int:
    """Loads an `all-calls.csv` file into `locations` and `edges` in SQLite."""
    try:
        sample_uris = _extract_sample_uris_from_csv(csv_file_path)
    except OSError as exc:
        logging.critical(
            "Error reading all-calls CSV file '%s': %s", csv_file_path, exc
        )
        return 0

    if not sample_uris:
        logging.warning("No valid edge rows found in '%s'.", csv_file_path)
        return 0

    prefix = detect_prefix(sample_uris)

    with open_sqlite_db(db_name, fast_pragmas=True) as conn:
        cursor = conn.cursor()
        _init_all_calls_tables(cursor, replace_existing=replace_existing)
        base_loc_id = _get_max_id(cursor, "locations")
        locations_batch, edges_batch = _collect_csv_rows(
            csv_file_path, prefix, base_loc_id
        )

        cursor.executemany(
            """
            INSERT INTO locations (
                id, threadFlow_id, message, uri,
                startLine, startColumn, endLine, endColumn
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            locations_batch,
        )
        cursor.executemany(
            "INSERT INTO edges "
            "(source_location_id, target_location_id, rule_id) "
            "VALUES (?, ?, ?)",
            edges_batch,
        )
        _create_all_calls_indexes(cursor)

    total_edges = len(edges_batch)
    logging.info(
        "Successfully imported all-calls CSV '%s' into '%s' "
        "(%d locations, %d edges).",
        csv_file_path,
        db_name,
        len(locations_batch),
        total_edges,
    )
    return total_edges


def main() -> None:
    """Parses CLI arguments and imports all-calls CSV into SQLite DB."""
    run_importer_cli(
        description=(
            "Import CodeQL all-calls CSV file into SQLite database "
            "(locations and edges tables)."
        ),
        csv_help="Path to input all-calls CSV file.",
        importer_fn=import_all_calls_to_db,
    )


if __name__ == "__main__":
    main()
