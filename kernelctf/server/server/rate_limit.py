# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sqlite3
import time
from contextlib import contextmanager

class EvaluationRateLimiter:
    """
    Atomic, multi-process safe rate limiter for kernelCTF evaluations using SQLite with WAL.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("BEGIN IMMEDIATE;")
        try:
            yield conn
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evaluation_quota (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    lts_slot TEXT NOT NULL,
                    researcher_hash TEXT NOT NULL,
                    exploit_hash TEXT NOT NULL,
                    timestamp_ms INTEGER NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_quota_lookup 
                ON evaluation_quota (lts_slot, researcher_hash);
            """)

    def _get_count(self, conn: sqlite3.Connection, lts_slot: str, researcher_hash: str) -> int:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM evaluation_quota WHERE lts_slot = ? AND researcher_hash = ?;",
            (lts_slot, researcher_hash)
        )
        row = cursor.fetchone()
        return row[0] if row else 0

    def get_count(self, lts_slot: str, researcher_hash: str) -> int:
        """
        Gets current count of evaluations used for a given slot and researcher.
        """
        with self._get_conn() as conn:
            return self._get_count(conn, lts_slot, researcher_hash)

    def acquire_slot(self, lts_slot: str, researcher_hash: str, exploit_hash: str, max_evaluations: int) -> tuple[bool, int]:
        """
        Atomically checks remaining quota and records the evaluation attempt.
        Returns (is_allowed: bool, attempts_used: int).
        Uses BEGIN IMMEDIATE to acquire a write lock before checking to prevent race conditions.
        """
        with self._get_conn() as conn:
            current_count = self._get_count(conn, lts_slot, researcher_hash)
            if current_count >= max_evaluations:
                return False, current_count

            now_ms = time.time_ns() // 1_000_000
            conn.execute(
                "INSERT INTO evaluation_quota (lts_slot, researcher_hash, exploit_hash, timestamp_ms) VALUES (?, ?, ?, ?);",
                (lts_slot, researcher_hash, exploit_hash, now_ms)
            )
            return True, current_count + 1
