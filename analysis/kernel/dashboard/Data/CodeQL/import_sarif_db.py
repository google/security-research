from sarif_om import SarifLog
from sarif.loader import load_sarif_file
import sqlite3


def create_sarif_database(sarif_file_path, db_name="codeql_data.db"):
    try:
        sarif_log: SarifLog = load_sarif_file(sarif_file_path)
    except Exception as e:
        print(f"Error loading SARIF file: {e}")
        return None

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create tables for runs, results, codeFlows, threadFlows, and locations
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

    for run in sarif_log.runs:
        cursor.execute(
            "INSERT INTO runs (tool, version) VALUES (?, ?)",
            ("dashboard", "1.0"),
        )
        run_id = cursor.lastrowid

        for result in run.get_results():
            cursor.execute(
                "INSERT INTO results (run_id, ruleId, message) VALUES (?, ?, ?)",
                (run_id, result["ruleId"], result["message"]["text"]),
            )
            result_id = cursor.lastrowid

            for code_flow in result.get("codeFlows", []):
                cursor.execute(
                    "INSERT INTO codeFlows (result_id) VALUES (?)", (result_id,)
                )
                code_flow_id = cursor.lastrowid

                for thread_flow in code_flow.get("threadFlows", []):
                    cursor.execute(
                        "INSERT INTO threadFlows (codeFlow_id) VALUES (?)",
                        (code_flow_id,),
                    )
                    thread_flow_id = cursor.lastrowid

                    # Store location data in a list of dictionaries
                    location_ids = []

                    for location in thread_flow.get("locations", []):
                        loc = location.get("location", {})
                        phys_loc = loc.get("physicalLocation", {})
                        art_loc = phys_loc.get("artifactLocation", {})
                        region = phys_loc.get("region", {})
                        cursor.execute(
                            """
                        INSERT INTO locations (
                          threadFlow_id, message, uri, startLine, startColumn, endLine, endColumn
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                      """,
                            (
                                thread_flow_id,
                                loc["message"]["text"],
                                art_loc.get("uri", ""),
                                region.get("startLine"),
                                region.get("startColumn"),
                                region.get("endLine"),
                                region.get("endColumn"),
                            ),
                        )
                        location_ids.append(cursor.lastrowid)

                    for i in range(len(location_ids) - 1):
                        cursor.execute(
                            """
                            INSERT INTO edges (source_location_id, target_location_id, rule_id)
                            VALUES (?, ?, ?)
                            """,
                            (
                                location_ids[i],
                                location_ids[i + 1],
                                result["ruleId"],
                            ),
                        )
    conn.commit()
    conn.close()


create_sarif_database("callgraph.sarif")
# create_sarif_database("field-free.sarif")
# create_sarif_database("controlled-field-writes.sarif")
