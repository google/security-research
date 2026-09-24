#!/usr/bin/env python3
"""Imports CodeQL all-calls SARIF outputs into SQLite database."""

from contextlib import closing
import json
import logging
import sqlite3
from typing import Any

from utils import detect_prefix, run_importer_cli, trim_filename


def _iter_thread_flows(runs: list[dict[str, Any]]):
    """Yields (run, result, code_flow, thread_flow) tuples across SARIF runs."""
    for run in runs:
        for result in run.get("results", []):
            for code_flow in result.get("codeFlows", []):
                for thread_flow in code_flow.get("threadFlows", []):
                    yield run, result, code_flow, thread_flow


def _extract_sample_uris(runs: list[dict[str, Any]], limit: int = 200):
    """Collects up to `limit` artifact URIs from SARIF runs."""
    sample_uris = []
    for _, _, _, tf in _iter_thread_flows(runs):
        for loc in tf.get("locations", []):
            uri = (
                loc.get("location", {})
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "")
            )
            if uri:
                sample_uris.append(uri)
                if len(sample_uris) >= limit:
                    return sample_uris
    return sample_uris


def _init_all_calls_tables(cursor: sqlite3.Cursor) -> None:
    """Creates the runs, results, codeFlows, threadFlows, locations, edges."""
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool TEXT NOT NULL,
            version TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            ruleId TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES runs (id)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS codeFlows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            result_id INTEGER NOT NULL,
            FOREIGN KEY (result_id) REFERENCES results (id)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS threadFlows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codeFlow_id INTEGER NOT NULL,
            FOREIGN KEY (codeFlow_id) REFERENCES codeFlows (id)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threadFlow_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            uri TEXT,
            startLine INTEGER,
            startColumn INTEGER,
            endLine INTEGER,
            endColumn INTEGER,
            FOREIGN KEY (threadFlow_id) REFERENCES threadFlows (id)
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_location_id INTEGER NOT NULL,
            target_location_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            FOREIGN KEY (source_location_id) REFERENCES locations (id),
            FOREIGN KEY (target_location_id) REFERENCES locations (id)
        )
        """
    )
    cursor.execute("PRAGMA synchronous = OFF")
    cursor.execute("PRAGMA journal_mode = MEMORY")


def _get_max_id(cursor: sqlite3.Cursor, table: str) -> int:
    """Returns the current maximum integer ID in `table`, or 0 if empty."""
    row = cursor.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()
    return int(row[0] or 0)


def _parse_location_tuple(
    location: dict[str, Any], loc_id: int, tf_id: int, prefix: str
) -> tuple[Any, ...]:
    """Extracts a row tuple for the locations table from a SARIF location."""
    loc = location.get("location", {})
    phys_loc = loc.get("physicalLocation", {})
    art_loc = phys_loc.get("artifactLocation", {})
    region = phys_loc.get("region", {})
    loc_msg = loc.get("message", {}).get("text", "")
    raw_uri = art_loc.get("uri", "")
    if raw_uri.startswith("file://"):
        raw_uri = raw_uri[7:]
    clean_uri = trim_filename(raw_uri, prefix)
    return (
        loc_id,
        tf_id,
        loc_msg,
        clean_uri,
        region.get("startLine"),
        region.get("startColumn"),
        region.get("endLine"),
        region.get("endColumn"),
    )


def _collect_sarif_rows(
    runs: list[dict[str, Any]],
    prefix: str,
    base_ids: dict[str, int],
) -> dict[str, list[tuple[Any, ...]]]:
    """Processes SARIF runs into bulk-insert row lists for each table."""
    ids = dict(base_ids)
    batches: dict[str, list[tuple[Any, ...]]] = {
        "runs": [],
        "results": [],
        "codeFlows": [],
        "threadFlows": [],
        "locations": [],
        "edges": [],
    }

    for run in runs:
        ids["run"] += 1
        batches["runs"].append((ids["run"], "dashboard", "1.0"))
        for result in run.get("results", []):
            ids["res"] += 1
            rule_id = result.get("ruleId", "callgraph-all")
            msg_text = result.get("message", {}).get("text", "")
            batches["results"].append(
                (ids["res"], ids["run"], rule_id, msg_text)
            )
            for code_flow in result.get("codeFlows", []):
                ids["cf"] += 1
                batches["codeFlows"].append((ids["cf"], ids["res"]))
                for thread_flow in code_flow.get("threadFlows", []):
                    ids["tf"] += 1
                    batches["threadFlows"].append((ids["tf"], ids["cf"]))
                    loc_ids = []
                    for location in thread_flow.get("locations", []):
                        ids["loc"] += 1
                        batches["locations"].append(
                            _parse_location_tuple(
                                location, ids["loc"], ids["tf"], prefix
                            )
                        )
                        loc_ids.append(ids["loc"])
                    for i in range(len(loc_ids) - 1):
                        batches["edges"].append(
                            (loc_ids[i], loc_ids[i + 1], rule_id)
                        )
    return batches


def import_all_calls_to_db(
    sarif_file_path: str, db_name: str = "codeql_data.db"
) -> int:
    """Loads an all-calls SARIF v2.1.0 file into the SQLite database."""
    try:
        with open(
            sarif_file_path, "r", encoding="utf-8", errors="ignore"
        ) as sarif_file:
            sarif_data = json.load(sarif_file)
    except (OSError, ValueError) as exc:
        logging.critical(
            "Error loading SARIF file '%s': %s", sarif_file_path, exc
        )
        return 0

    runs = sarif_data.get("runs", [])
    if not runs:
        logging.warning("No runs found in SARIF file '%s'.", sarif_file_path)
        return 0

    prefix = detect_prefix(_extract_sample_uris(runs))

    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()
        _init_all_calls_tables(cursor)
        base_ids = {
            "run": _get_max_id(cursor, "runs"),
            "res": _get_max_id(cursor, "results"),
            "cf": _get_max_id(cursor, "codeFlows"),
            "tf": _get_max_id(cursor, "threadFlows"),
            "loc": _get_max_id(cursor, "locations"),
        }
        batches = _collect_sarif_rows(runs, prefix, base_ids)

        cursor.executemany(
            "INSERT INTO runs (id, tool, version) VALUES (?, ?, ?)",
            batches["runs"],
        )
        cursor.executemany(
            "INSERT INTO results (id, run_id, ruleId, message) "
            "VALUES (?, ?, ?, ?)",
            batches["results"],
        )
        cursor.executemany(
            "INSERT INTO codeFlows (id, result_id) VALUES (?, ?)",
            batches["codeFlows"],
        )
        cursor.executemany(
            "INSERT INTO threadFlows (id, codeFlow_id) VALUES (?, ?)",
            batches["threadFlows"],
        )
        cursor.executemany(
            """
            INSERT INTO locations (
                id, threadFlow_id, message, uri,
                startLine, startColumn, endLine, endColumn
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            batches["locations"],
        )
        cursor.executemany(
            "INSERT INTO edges "
            "(source_location_id, target_location_id, rule_id) "
            "VALUES (?, ?, ?)",
            batches["edges"],
        )
        conn.commit()

    total_edges = len(batches["edges"])
    logging.info(
        "Successfully imported all-calls SARIF '%s' into '%s' (%d edges).",
        sarif_file_path,
        db_name,
        total_edges,
    )
    return total_edges


def import_sarif_to_db(
    sarif_file_path: str, db_name: str = "codeql_data.db"
) -> int:
    """Backwards-compatible alias for import_all_calls_to_db."""
    return import_all_calls_to_db(sarif_file_path, db_name)


def create_sarif_database(
    sarif_file_path: str, db_name: str = "codeql_data.db"
) -> int:
    """Backwards-compatible entry point."""
    return import_all_calls_to_db(sarif_file_path, db_name)


def main():
    """Parses CLI arguments and imports all-calls SARIF into SQLite DB."""
    run_importer_cli(
        description=(
            "Import CodeQL all-calls SARIF file into SQLite database "
            "(edges, locations, results, runs tables)."
        ),
        csv_help="Path to input all-calls SARIF file.",
        importer_fn=import_all_calls_to_db,
    )


if __name__ == "__main__":
    main()
