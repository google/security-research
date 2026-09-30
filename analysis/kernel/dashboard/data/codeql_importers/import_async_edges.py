#!/usr/bin/env python3
"""Imports CodeQL asynchronous callback edges CSV into SQLite database."""

from contextlib import closing
import logging
import sqlite3

from utils import (
    detect_prefix,
    execute_bulk_insert,
    read_csv_rows,
    run_importer_cli,
    trim_filename,
)

MECHANISM_CONTEXT = {
    "async": "kthread",
    "block_io": "softirq",
    "cpuhp": "kthread",
    "crypto": "softirq",
    "firmware": "kthread",
    "hrtimer": "hard_irq",
    "io_uring": "process",
    "ipi": "ipi",
    "irq": "hard_irq",
    "kref": "inline",
    "kthread": "kthread",
    "kthread_worker": "kthread",
    "napi": "softirq",
    "netfilter": "softirq",
    "nf_hook_inline": "inline",
    "notifier": "process",
    "poll": "process",
    "rcu": "softirq",
    "rhashtable_destroy": "inline",
    "skb": "softirq",
    "socket": "softirq",
    "softirq": "softirq",
    "task_work": "process",
    "tasklet": "softirq",
    "teardown": "process",
    "timer": "softirq",
    "usb": "hard_irq",
    "waitqueue": "softirq",
    "workqueue": "kthread",
}

_FILE_SCOPE_PREFIX = "<file-scope:"


def _trim_caller(caller: str, prefix: str) -> str:
    """Trims the kernel root prefix inside `<file-scope:PATH>` caller labels."""
    if caller.startswith(_FILE_SCOPE_PREFIX) and caller.endswith(">"):
        inner_path = caller[len(_FILE_SCOPE_PREFIX) : -1]
        return f"{_FILE_SCOPE_PREFIX}{trim_filename(inner_path, prefix)}>"
    return caller


def import_async_edges_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL async-edges CSV records into the async_edges table."""
    rows = read_csv_rows(csv_filename)
    sample_paths = [r[4] for r in rows if len(r) >= 6]
    prefix = detect_prefix(sample_paths)

    data = []
    for row in rows:
        if len(row) >= 6:
            try:
                line = int(row[5])
            except ValueError:
                logging.warning(
                    "Skipping row with non-integer line number: %s", row
                )
                continue
            data.append(
                (
                    _trim_caller(row[0], prefix),
                    row[1],
                    row[2],
                    MECHANISM_CONTEXT.get(row[2], "unknown"),
                    row[3],
                    trim_filename(row[4], prefix),
                    line,
                )
            )
        else:
            logging.warning("Skipping invalid row: %s", row)

    execute_bulk_insert(
        db_name,
        """
        CREATE TABLE IF NOT EXISTS async_edges (
            caller TEXT,
            callee TEXT,
            mechanism TEXT,
            context TEXT,
            form TEXT,
            file TEXT,
            line INTEGER
        )
        """,
        """
        INSERT INTO async_edges (
            caller, callee, mechanism, context, form, file, line
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        data,
        drop_table="async_edges",
    )

    with closing(sqlite3.connect(db_name)) as conn:
        cur = conn.cursor()
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_async_edges_callee "
            "ON async_edges(callee)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_async_edges_caller "
            "ON async_edges(caller)"
        )
        conn.commit()

    logging.info(
        "Successfully imported %d async edges into '%s' (table 'async_edges').",
        len(data),
        db_name,
    )
    return len(data)


def main():
    """Parses command-line arguments and runs async edges CSV import."""
    run_importer_cli(
        description=(
            "Import CodeQL asynchronous callback edges CSV into SQLite "
            "database (async_edges table)."
        ),
        csv_help="Path to async-edges CSV file.",
        importer_fn=import_async_edges_to_db,
    )


if __name__ == "__main__":
    main()
