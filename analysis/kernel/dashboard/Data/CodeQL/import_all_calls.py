#!/usr/bin/env python3
"""Imports CodeQL all-calls SARIF outputs into SQLite database."""

import argparse
import json
import logging
import os
import sqlite3
import sys
from contextlib import closing

from utils import detect_prefix, trim_filename


def import_all_calls_to_db(sarif_file_path: str, db_name: str = "codeql_data.db") -> int:
    """Loads an all-calls SARIF v2.1.0 file and populates runs, results, codeFlows, threadFlows, locations, and edges."""
    try:
        with open(sarif_file_path, "r", encoding="utf-8", errors="ignore") as f:
            sarif_data = json.load(f)
    except Exception as e:
        logging.critical(f"Error loading SARIF file '{sarif_file_path}': {e}")
        return 0

    runs = sarif_data.get("runs", [])
    if not runs:
        logging.warning(f"No runs found in SARIF file '{sarif_file_path}'.")
        return 0

    # Collect sample URIs to detect any absolute build prefix
    sample_uris = []
    for run in runs:
        for result in run.get("results", []):
            for cf in result.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        uri = (
                            loc.get("location", {})
                            .get("physicalLocation", {})
                            .get("artifactLocation", {})
                            .get("uri", "")
                        )
                        if uri:
                            sample_uris.append(uri)
                            if len(sample_uris) >= 200:
                                break
                    if len(sample_uris) >= 200:
                        break
                if len(sample_uris) >= 200:
                    break
            if len(sample_uris) >= 200:
                break

    prefix = detect_prefix(sample_uris)

    with closing(sqlite3.connect(db_name)) as conn:
        cursor = conn.cursor()

        # Create tables for runs, results, codeFlows, threadFlows, locations, and edges
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

        # Speed up bulk insertion
        cursor.execute("PRAGMA synchronous = OFF")
        cursor.execute("PRAGMA journal_mode = MEMORY")

        total_edges = 0
        for run in runs:
            cursor.execute(
                "INSERT INTO runs (tool, version) VALUES (?, ?)",
                ("dashboard", "1.0"),
            )
            run_id = cursor.lastrowid

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "callgraph-all")
                msg_text = result.get("message", {}).get("text", "")
                cursor.execute(
                    "INSERT INTO results (run_id, ruleId, message) VALUES (?, ?, ?)",
                    (run_id, rule_id, msg_text),
                )
                result_id = cursor.lastrowid

                for code_flow in result.get("codeFlows", []):
                    cursor.execute(
                        "INSERT INTO codeFlows (result_id) VALUES (?)",
                        (result_id,),
                    )
                    code_flow_id = cursor.lastrowid

                    for thread_flow in code_flow.get("threadFlows", []):
                        cursor.execute(
                            "INSERT INTO threadFlows (codeFlow_id) VALUES (?)",
                            (code_flow_id,),
                        )
                        thread_flow_id = cursor.lastrowid

                        location_ids = []
                        for location in thread_flow.get("locations", []):
                            loc = location.get("location", {})
                            phys_loc = loc.get("physicalLocation", {})
                            art_loc = phys_loc.get("artifactLocation", {})
                            region = phys_loc.get("region", {})
                            loc_msg = loc.get("message", {}).get("text", "")
                            raw_uri = art_loc.get("uri", "")
                            if raw_uri.startswith("file://"):
                                raw_uri = raw_uri[7:]
                            clean_uri = trim_filename(raw_uri, prefix)

                            cursor.execute(
                                """
                                INSERT INTO locations (
                                    threadFlow_id, message, uri, startLine, startColumn, endLine, endColumn
                                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    thread_flow_id,
                                    loc_msg,
                                    clean_uri,
                                    region.get("startLine"),
                                    region.get("startColumn"),
                                    region.get("endLine"),
                                    region.get("endColumn"),
                                ),
                            )
                            location_ids.append(cursor.lastrowid)

                        if len(location_ids) >= 2:
                            edge_rows = [
                                (location_ids[i], location_ids[i + 1], rule_id)
                                for i in range(len(location_ids) - 1)
                            ]
                            cursor.executemany(
                                """
                                INSERT INTO edges (source_location_id, target_location_id, rule_id)
                                VALUES (?, ?, ?)
                                """,
                                edge_rows,
                            )
                            total_edges += len(edge_rows)

        conn.commit()
        logging.info(
            f"Successfully imported all-calls SARIF '{sarif_file_path}' into '{db_name}' ({total_edges} edges)."
        )
        return total_edges


def import_sarif_to_db(sarif_file_path: str, db_name: str = "codeql_data.db") -> int:
    """Backwards-compatible alias for import_all_calls_to_db."""
    return import_all_calls_to_db(sarif_file_path, db_name)


def create_sarif_database(sarif_file_path: str, db_name: str = "codeql_data.db") -> int:
    """Backwards-compatible entry point."""
    return import_all_calls_to_db(sarif_file_path, db_name)


def main():
    """Parses command-line arguments and imports all-calls SARIF file into SQLite database."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Import CodeQL all-calls SARIF file into SQLite database (edges, locations, results, runs tables)."
    )
    parser.add_argument(
        "sarif_file",
        help="Path to input all-calls SARIF file.",
        type=str,
    )
    parser.add_argument(
        "db_file",
        help="Path to target SQLite database file.",
        type=str,
    )
    args = parser.parse_args()

    if not os.path.isfile(args.sarif_file):
        logging.critical(f"SARIF file not found or unreadable: {args.sarif_file}")
        sys.exit(1)

    import_all_calls_to_db(args.sarif_file, args.db_file)


if __name__ == "__main__":
    main()
