"""Shared SQLite connection management and bulk-insert helpers."""

from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
from typing import Optional, Union


@contextmanager
def open_sqlite_db(
    db_path: Union[str, Path],
    fast_pragmas: bool = True,
) -> Iterator[sqlite3.Connection]:
    """Opens a SQLite database connection with optional bulk-import pragmas.

    Commits the active transaction on normal exit and guarantees that the
    underlying SQLite connection is closed even if an exception is raised.

    Args:
        db_path: Path to the SQLite database file.
        fast_pragmas: If True, sets `PRAGMA synchronous = OFF` and `PRAGMA
          journal_mode = MEMORY` for faster bulk ingestion.

    Yields:
        An open `sqlite3.Connection` instance.
    """
    with closing(sqlite3.connect(str(db_path))) as conn:
        if fast_pragmas:
            conn.execute("PRAGMA synchronous = OFF")
            conn.execute("PRAGMA journal_mode = MEMORY")
        yield conn
        conn.commit()


def execute_sqlite_batch(
    db_path: Union[str, Path],
    create_sql: str,
    insert_sql: str,
    data: Sequence[Sequence[object]],
    *,
    drop_table: Optional[str] = None,
) -> None:
    """Creates a table, optionally drops it first, and bulk-inserts `data`.

    Args:
        db_path: Target SQLite database path.
        create_sql: `CREATE TABLE` DDL statement.
        insert_sql: Parameterized `INSERT INTO` statement.
        data: Sequence of row tuples to insert via `executemany`.
        drop_table: Optional table name to `DROP TABLE IF EXISTS` before
          creating the table.
    """
    with open_sqlite_db(db_path, fast_pragmas=True) as conn:
        cursor = conn.cursor()
        if drop_table:
            cursor.execute(f"DROP TABLE IF EXISTS {drop_table}")
        cursor.execute(create_sql)
        cursor.executemany(insert_sql, data)
