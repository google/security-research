# Shared Data Ingestion Library (`data/lib/`)

`data/lib/` provides shared SQLite database management and input validation utilities used across all five `data/` ingestion pipelines (`btf_data`, `codeql_importers`, `git_log`, `kconfig`, and `syzkaller_coverage`).

---

## 1. Modules

### 1.1 [`db.py`](db.py) — SQLite Connection & Batch Transaction Helpers
- **`open_sqlite_db(db_path, fast_pragmas=True)`**:
  - Context manager wrapping `sqlite3.connect(db_path)` inside `contextlib.closing()` so database file descriptors are never leaked on exceptions.
  - When `fast_pragmas=True` (default), configures `PRAGMA synchronous = OFF` and `PRAGMA journal_mode = MEMORY` to accelerate bulk table imports.
- **`execute_sqlite_batch(db_path, create_table_sql, insert_sql, data, *, drop_table=None, clear_sql=None, indexes=())`**:
  - Executes an idempotent table load in a single atomic SQLite transaction:
    1. Optionally drops `drop_table` (`DROP TABLE IF EXISTS ...`) or runs `clear_sql` (for shared tables like `configs`).
    2. Executes `create_table_sql`.
    3. Bulk-inserts `data` via `cursor.executemany(insert_sql, data)`.
    4. Creates all requested SQL indexes (`indexes`).

### 1.2 [`validation.py`](validation.py) — Path, CLI Tool & Line Continuation Helpers
- **`can_read_dir(dirname)`**: `argparse` validator verifying `dirname` is an existing readable directory (`os.R_OK`), returning its absolute path or raising `ValueError`.
- **`can_read_file(filename)`**: `argparse` validator verifying `filename` is an existing readable file (`os.R_OK`).
- **`can_create_file(filename)`**: `argparse` validator verifying the parent directory of `filename` exists and is writable (`os.W_OK`), resolving relative filenames against `os.getcwd()`.
- **`verify_cli_tools(tool_commands)`**: Verifies that required external binaries (such as `bpftool`, `pahole`, `git`, `parallel`) execute cleanly (`check=True`).
- **`join_continuation_lines(lines)`**: Strips inline `#` comments and joins backslash-continued (`\`) lines into `(start_line_no, normalized_text)` pairs.

---

## 2. Running Unit Tests

```bash
pytest data/lib/tests -v
```
