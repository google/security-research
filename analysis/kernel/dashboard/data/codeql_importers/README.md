# CodeQL Output Importers (`data/codeql_importers/`)

This package converts the decoded `.csv` and `.sarif` outputs from the 15 core CodeQL queries in `queries/` into indexed relational SQLite tables in `codeql_data.db`.

---

## 1. Package Structure

```text
data/codeql_importers/
├── lib/
│   ├── utils.py               # Path normalization, smart CSV reader, CsvTableSpec & batch importer
│   └── reachability_node.py   # Shared pair + location join engine for syscall_node & entry_node
├── import_*.py                # 14 table importer entry points
└── tests/
    └── test_imports.py        # Unit test suite covering all 14 importers and lib helpers
```

---

## 2. Core Conversion & Normalization Mechanisms

### 2.1 Build Prefix Detection & Path Canonicalization (`lib/utils.py`)
CodeQL outputs absolute paths from the machine where the database was built (often prefixed with `file://`, e.g., `file:///tmp/build/linux-6.12.109/net/core/sock.c`). To make every SQLite table portable and joinable with Git and Syzkaller paths:
1. **`detect_prefix(sample_paths)`**: Strips `file://` URIs, splits each sample path into directory segments, and locates the first top-level Linux kernel directory (`arch`, `block`, `certs`, `crypto`, `drivers`, `fs`, `include`, `init`, `io_uring`, `ipc`, `kernel`, `lib`, `mm`, `net`, `rust`, `samples`, `scripts`, `security`, `sound`, `tools`, `usr`, `virt`). The longest common prefix preceding that directory (e.g. `/tmp/build/linux-6.12.109/`) is returned.
2. **`trim_filename(path, prefix)`**: Strips `file://`, removes `prefix`, and falls back to matching the first top-level kernel directory segment if a path comes from an out-of-tree or symlinked build directory:
   ```text
   "file:///work/linux-6.12/drivers/net/tun.c" ──► "drivers/net/tun.c"
   ```

### 2.2 Declarative CSV Import Engine (`CsvTableSpec` & `import_csv_table`)
Single-CSV importers (`import_configs.py`, `import_ops_targets.py`, `import_conditions.py`, `import_conditions_reachable.py`, `import_field_access.py`, `import_allocs.py`) declare a [`CsvTableSpec`](lib/utils.py):
1. **Smart Header Detection (`read_csv_rows`)**: Automatically detects whether row 0 is a `codeql bqrs decode` header (`col0`, `function_name`, or non-numeric strings in integer columns) and skips it without dropping data rows from headerless CSVs.
2. **Bounded Prefix Sampling (`detect_csv_prefix`)**: Samples up to 1,000 rows from `spec.path_cols` in a single pass to compute `prefix`.
3. **Fault-Tolerant Row Parsing**: Calls `spec.row_parser(row, prefix)` on rows meeting `spec.min_cols`, catching `(ValueError, TypeError)` with a warning log so a single malformed row never aborts an import.
4. **Atomic Idempotent Write (`execute_bulk_insert`)**: Drops or clears the target table (`drop_table` / `clear_sql`), creates the schema, bulk-inserts all parsed tuples, and builds all lookup `indexes` in one transaction.

### 2.3 Compound Location String Unpacking
CodeQL problem/table queries frequently encode source locations as colon-separated strings `file:startLine:startCol:endLine:endCol`. Three importers unpack these into relational columns:
- **`import_allocations.py` (`parse_location`)**: Splits `file:///.../mm/slub.c:120:5:120:30` from the right (`rsplit(":", 4)`) into `("mm/slub.c", 120)` and deduplicates referenced struct definitions into `codeql_structs`.
- **`import_field_access.py` (`_parse_field_access_row`)**: Splits `location` (`rsplit(":", 4)`) to extract `(trimmed_file, start_line)` for each `read`/`write`/`exec` field access.
- **`import_conditions.py` (`_parse_condition_row`)**: Extracts `file:line` from `check_location`, `if_location`, and `guarded_call_location` via `rsplit(":", 4)` so `tools/check_privilege.py` can match capability checks to exact call lines.

### 2.4 Two-Tier Reachability Location Join (`lib/reachability_node.py`)
`syscall-node-pairs.ql` and `entry-node-pairs.ql` emit lightweight `(root_entry, function_name, file_path)` reachability triples, while `syscall-node-locs.ql` emits `(name, file, startLine, startCol, endLine, endCol)` once per function:
1. **`load_locs()`** builds two lookup tables from `syscall-node-locs.csv`:
   - `by_func_file[(func_name, trimmed_file)]` (primary exact lookup for disambiguating static functions with identical names in different `.c` files).
   - `by_func[func_name]` (fallback lookup).
2. **`gen_rows()`** streams the pairs CSV and joins each `(root, func, file)` row against `by_func_file` (or `by_func` for 2-column CSVs), emitting `(root, func, file_path, start_line, start_col, end_line, end_col)` into `syscall_node` or `entry_node`.

### 2.5 SARIF Call-Graph & Async-Edge Extraction
- **`import_all_calls.py` (`all-calls.sarif` $\rightarrow$ `locations`, `edges`)**:
  - Parses SARIF `runs[].results[].codeFlows[].threadFlows[].locations[]`.
  - Deduplicates every physical location `(message, trimmed_uri, startLine, startColumn, endLine, endColumn)` via an in-memory `loc_cache` dictionary to assign compact integer `location_id` keys.
  - Connects consecutive steps `(step[i], step[i+1])` within each `threadFlow` as a directed edge `(source_location_id, target_location_id)` in `edges`.
- **`import_async_edges.py` (`async-edges.sarif` $\rightarrow$ `async_edges`)**:
  - Reads the 2-step `threadFlow` from registration site (`step[0]`) to async handler (`step[1]`).
  - Unpacks the SARIF result message `"<mechanism>:<reg_Primitive>|<queue_key>"` (e.g., `"workqueue:INIT_WORK|struct tls_offload_context_tx.tx_work"`) together with the `step[0]` enclosing function and `step[1]` handler function into the 10-column `async_edges` table.

---

## 3. Running Unit Tests

```bash
pytest data/codeql_importers/tests -v
```
