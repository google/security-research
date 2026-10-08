# Dashboard Data Ingestion Pipelines (`data/`)

This directory contains the **five data ingestion pipelines** and shared library (`data/lib/`) that populate the unified Linux Kernel Security Research Dashboard SQLite database (`codeql_data.db`):

1. **`lib/`** — Shared SQLite connection/batch helpers (`db.py`) and path/CLI/Makefile validation utilities (`validation.py`).
2. **`btf_data/`** — Extracts ground-truth struct and field layout information from `vmlinux` BTF debug info (`types` table).
3. **`codeql_importers/`** — Imports decoded `.csv` and `.sarif` outputs from the 15 core CodeQL queries into relational SQLite tables, backed by `data/codeql_importers/lib/` (`utils.py`, `reachability_node.py`).
4. **`kconfig/`** — Extracts file-level `Makefile`/`Kbuild` `CONFIG_*` guards (`configs` table) and `Kconfig*` symbol definitions + `.config` build values (`kconfig_symbols` table).
5. **`git_log/`** — Extracts per-function source code and latest Git commit metadata (`git_log` table) from the Linux kernel repository.
6. **`syzkaller_coverage/`** — Parses Syzkaller/Syzbot dynamic code coverage reports (HTML, JSON, JSONL, or `.gz`) into SQLite coverage and reproducer tables.

```text
vmlinux (BTF / DWARF) ────────► data/btf_data/           ──┐
CodeQL (*.csv / *.sarif) ─────► data/codeql_importers/   ──┤
Linux Kbuild & Kconfig ───────► data/kconfig/            ──┼──► Unified SQLite DB (codeql_data.db)
Linux Git Repository ─────────► data/git_log/            ──┤
Syzkaller Coverage Exports ───► data/syzkaller_coverage/ ──┘
```

---

## 1. Subdirectory Overview & Target SQLite Tables

| Subdirectory | Detailed Docs | Entry-Point / Library Modules | Input Source | Target SQLite Table(s) | Unit Tests |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`data/lib/`** | [`lib/README.md`](lib/README.md) | `db.py`, `validation.py` | Shared across all `data/` pipelines | — | `data/lib/tests/` |
| **`data/btf_data/`** | [`btf_data/README.md`](btf_data/README.md) | `extract_btf.py` | `vmlinux` ELF64 binary (with `.BTF` or DWARF) | `types` | `data/btf_data/tests/` |
| **`data/codeql_importers/`** | [`codeql_importers/README.md`](codeql_importers/README.md) | `import_*.py` (14 importers), `lib/utils.py`, `lib/reachability_node.py` | Decoded CodeQL `.csv` (13) and `.sarif` (2) files | `function_locations`, `configs`, `ops_targets`, `allocs`, `codeql_allocations`, `codeql_structs`, `field_access`, `macro_locations`, `macroinvocation_locations`, `syscall_node`, `entry_node`, `conditions`, `conditions_reachable`, `locations`, `edges`, `async_edges` | `data/codeql_importers/tests/` |
| **`data/kconfig/`** | [`kconfig/README.md`](kconfig/README.md) | `kconfig_dump.py` | Linux kernel `Makefile`/`Kbuild`, `Kconfig*`, `.config` | `configs`, `kconfig_symbols` | `data/kconfig/tests/` |
| **`data/git_log/`** | [`git_log/README.md`](git_log/README.md) | `git_log_dump.py` | Linux Git repository + `function_locations` table | `git_log` | `data/git_log/tests/` |
| **`data/syzkaller_coverage/`** | [`syzkaller_coverage/README.md`](syzkaller_coverage/README.md) | `syzkaller_coverage.py` | Syzkaller coverage HTML / JSON / JSONL / `.gz` or URL | `file_path`, `syzk_cov`, `syzk_prog`, `syzk_sys`, `syscalls` | `data/syzkaller_coverage/tests/` |

---

## 2. Pipeline 1: BTF Struct & Field Layout Extractor ([`data/btf_data/README.md`](btf_data/README.md))

### How It Works
`extract_btf.py` inspects a compiled `vmlinux` ELF64 image:
- If `vmlinux` contains an embedded `.BTF` section (`CONFIG_DEBUG_INFO_BTF=y`), it dumps the BTF type graph directly via `bpftool btf dump --json file <vmlinux>`.
- Otherwise, it encodes detached BTF from DWARF debug info via `pahole --btf_encode_detached` before dumping with `bpftool`.
- Recursively flattens nested anonymous structs/unions, bitfields, pointers, arrays, and flexible array members (`is_flex`) into the `types` table.
- Also serves as the ground-truth struct size reference for `codeql_db_test` and `data_test` (`--btf-db`).

### SQLite Schema (`types`)
| Column | Type | Description |
| :--- | :--- | :--- |
| `struct_name` | `TEXT` | Enclosing top-level kernel struct name (or `(anon)`). |
| `struct_size` | `UNSIGNED BIG INT` | Total byte size of `struct_name`. |
| `parent_type` | `TEXT` | Immediate parent struct/union path for nested fields. |
| `kind` | `VARCHAR(15)` | BTF kind (`STRUCT`, `UNION`, `PTR`, `ARRAY`, `INT`, `ENUM`, `FWD`, etc.). |
| `type` | `TEXT` | Resolved C type name of the member. |
| `name` | `TEXT` | Qualified field name (e.g., `f_op` or nested `u.rcu_head.func`). |
| `bits_offset` | `UNSIGNED BIG INT` | Bit offset of the member from the start of `struct_name`. |
| `nr_bits` | `UNSIGNED BIG INT` | Width of the member in bits. |
| `bits_end` | `UNSIGNED BIG INT` | Ending bit offset (`bits_offset + nr_bits`). |
| `is_flex` | `BOOLEAN` | `1` if the member is a trailing flexible array (`[0]` or `[]`), else `0`. |

### Usage
```bash
python3 -m data.btf_data.extract_btf /path/to/vmlinux \
  --db_file /path/to/codeql_data.db \
  [--json_file /path/to/btf_dump.json]
```

---

## 3. Pipeline 2: CodeQL Query Output Importers ([`data/codeql_importers/README.md`](codeql_importers/README.md))

### How It Works
Each importer script reads the decoded `.csv` or `.sarif` file produced by its corresponding CodeQL query in `queries/`, normalizes kernel source file paths via `data/codeql_importers/lib/utils.py` (stripping build root prefixes and `file://` URIs), and bulk-inserts records into SQLite:

| Importer Script | Input File(s) | Target SQLite Table(s) | Description |
| :--- | :--- | :--- | :--- |
| **`import_functions.py`** | `functions.csv` | `function_locations` | Function names, relative file paths, and `[start_line, end_line]` spans. |
| **`import_configs.py`** | `kernel-configs-needed.csv` | `configs` | `#ifdef CONFIG_*` preprocessor branches (`config`, `path`, `ifdef`, `endif`, `else_`). |
| **`import_ops_targets.py`** | `ops_edges.csv` | `ops_targets` | Indirect function-pointer call sites (`exprcall_*`) mapped to ops table targets (`parent`, `field`, `target`, `wrapper_context`, `capability`). |
| **`import_allocs.py`** | `allocs.csv` | `allocs` | 17-column range-analyzed heap allocations (`sizeMin`, `sizeMax`, `flagsMin`, `flagsMax`, `isFlexible`, etc.). |
| **`import_allocations.py`** | `allocations.csv` | `codeql_allocations`, `codeql_structs` | Struct-typed heap allocation sites and referenced struct definitions. |
| **`import_field_access.py`** | `field-acces-type.csv` | `field_access` | Struct field accesses classified as `read`, `write`, or `exec`. |
| **`import_macros.py`** | `macro-locations.csv` | `macro_locations` | Macro definition locations (`macro_name`, `file_path`, `start_line`, `end_line`). |
| **`import_macro_invocations.py`** | `macro-invocations.csv` | `macroinvocation_locations` | Macro invocation sites (`macroinvocation_name`, `file_path`, `start_line`, `end_line`). |
| **`import_syscall_node.py`** | `--pairs syscall-node-pairs.csv` `--locs syscall-node-locs.csv` | `syscall_node` | Joins transitive `__do_sys_*` reachability pairs with function locations via `lib/reachability_node.py`. |
| **`import_entry_node.py`** | `--pairs entry-node-pairs.csv` `--locs syscall-node-locs.csv` | `entry_node` | Joins non-syscall kernel entry points (`netlink`, `sysctl`, `sysfs`, `debugfs`, `proc_ops`, `io_uring`, `uring_cmd`, `kthread`) with function locations via `lib/reachability_node.py`. |
| **`import_conditions.py`** | `condition-graph-direct.csv` | `conditions` | Intra-procedural capability/condition checks dominating call sites. |
| **`import_conditions_reachable.py`** | `condition-graph-all.csv` | `conditions_reachable` | Inter-procedural functions transitively reachable from guarded calls. |
| **`import_all_calls.py`** | `all-calls.sarif` | `locations`, `edges` | Full kernel call-graph nodes and directed edges parsed from SARIF threadFlows. |
| **`import_async_edges.py`** | `async-edges.sarif` | `async_edges` | Deferred execution registration sites (`workqueue`, `timer`, `rcu`, `tasklet`, `irq`, `kthread`, `notifier`) linked to handler functions. |

### Usage
```bash
# Single-CSV/SARIF importers (<input_file> <db_file>):
python3 -m data.codeql_importers.import_functions /path/to/results_dir/functions.csv /path/to/codeql_data.db
python3 -m data.codeql_importers.import_ops_targets /path/to/results_dir/ops_edges.csv /path/to/codeql_data.db
python3 -m data.codeql_importers.import_all_calls /path/to/results_dir/all-calls.sarif /path/to/codeql_data.db
python3 -m data.codeql_importers.import_async_edges /path/to/results_dir/async-edges.sarif /path/to/codeql_data.db

# Reachability node importers (--pairs, --locs, --db):
python3 -m data.codeql_importers.import_syscall_node \
  --pairs /path/to/results_dir/syscall-node-pairs.csv \
  --locs /path/to/results_dir/syscall-node-locs.csv \
  --db /path/to/codeql_data.db
```

---

## 4. Pipeline 3: Makefile/Kbuild & Kconfig Extractor ([`data/kconfig/README.md`](kconfig/README.md))

### How It Works
`kconfig_dump.py` parses two complementary sources from `--repo_dir`:
1. **`Makefile` / `Kbuild` rules** (`obj-$(CONFIG_*)`, composite modules, directory descent, and `ifdef`/`ifeq` blocks) to map each `.c` source file to its file-level `CONFIG_*` requirements in the `configs` table (`ifdef=1`, `endif=<file_lines>`, `else_=0`).
2. **`Kconfig*` symbol definitions and optional `.config` build values** into the `kconfig_symbols` table (`config`, `type`, `prompt`, `depends_on`, `select_list`, `default_val`, `build_val`, `kconfig_file`, `line_no`).

### Usage
```bash
python3 -m data.kconfig.kconfig_dump \
  --repo_dir /path/to/linux \
  --db_file /path/to/codeql_data.db \
  [--dot_config /path/to/linux/.config]
```

---

## 5. Pipeline 4: Git Commit & Function Source Dumper ([`data/git_log/README.md`](git_log/README.md))

### How It Works
`git_log_dump.py` enriches the `function_locations` table with Git history and function source code from the Linux kernel repository:
1. Reads all `(function_name, file_path, start_line, end_line)` spans from `function_locations` in `--codeql_db`.
2. Verifies that the files exist in the target Git repository (`git ls-files`) and automatically unshallows (`git fetch --unshallow`) or builds a commit-graph if needed.
3. Uses GNU `parallel` across `--no_cpu` workers to run `git log -n 1 -L <start>,<end>:<file>` and extract the latest commit hash, author timestamp, and source lines into the `git_log` table (`start_line`, `end_line`, `file_path`, `author_date`, `commit`, `data`).

### Usage
```bash
python3 -m data.git_log.git_log_dump \
  --repo_dir /path/to/linux \
  --codeql_db /path/to/codeql_data.db \
  --db_file /path/to/codeql_data.db \
  [--no_cpu 32] [--force]
```

---

## 6. Pipeline 5: Syzkaller Dynamic Coverage Importer ([`data/syzkaller_coverage/README.md`](syzkaller_coverage/README.md))

### How It Works
`syzkaller_coverage.py` ingests dynamic fuzzer coverage from Syzbot/Syzkaller:
- Supports HTML coverage reports, streaming JSON/JSONL coverage exports, gzip-compressed files (`.gz`), and direct Syzbot URLs.
- **Cross-Commit Line Remapping (`--remap_lines`)**: When a Syzkaller coverage report was generated on a slightly different kernel commit (`--cov_commit`) than the analyzed tree (`--target_commit`), uses `git diff -U0` in `--repo_dir` to remap covered line numbers to the target commit.
- Populates five tables: `file_path`, `syzk_cov`, `syzk_prog`, `syzk_sys`, and `syscalls`.

### Usage
```bash
python3 -m data.syzkaller_coverage.syzkaller_coverage \
  /path/to/syzkaller_coverage.jsonl.gz \
  --db_file /path/to/codeql_data.db \
  [--remap_lines --repo_dir /path/to/linux --target_commit HEAD]
```

---

## 7. Running Unit Tests

All `data/` modules and shared libraries include `pytest` unit test suites:

```bash
pytest data/ -v
```
