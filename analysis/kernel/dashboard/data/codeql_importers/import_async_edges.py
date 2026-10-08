#!/usr/bin/env python3
"""Imports CodeQL asynchronous callback edges CSV into SQLite database."""

from data.codeql_importers.lib.utils import (
    CsvTableSpec,
    import_csv_table,
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


_ASYNC_EDGES_SPEC = CsvTableSpec(
    table_name="async_edges",
    create_sql="""
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
    insert_sql="""
    INSERT INTO async_edges (
        caller, callee, mechanism, context, form, file, line
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
    min_cols=6,
    path_cols=(4,),
    row_parser=lambda row, prefix: (
        _trim_caller(row[0], prefix),
        row[1],
        row[2],
        MECHANISM_CONTEXT.get(row[2], "unknown"),
        row[3],
        trim_filename(row[4], prefix),
        int(row[5]),
    ),
    indexes=(
        (
            "CREATE INDEX IF NOT EXISTS idx_async_edges_callee "
            "ON async_edges(callee)"
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_async_edges_caller "
            "ON async_edges(caller)"
        ),
    ),
)


def import_async_edges_to_db(csv_filename: str, db_name: str) -> int:
    """Imports CodeQL async-edges CSV records into the `async_edges` table."""
    return import_csv_table(csv_filename, db_name, _ASYNC_EDGES_SPEC)


def main() -> None:
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
