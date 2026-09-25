# Linux Kernel CodeQL Queries (`queries/`)

This directory contains the **CodeQL query suite** for the Linux Kernel Security Research Dashboard, along with exploratory taint-tracking and call-graph queries.

The **13 core dashboard queries** extract static call graphs, indirect function-pointer dispatch tables, heap allocation sites, struct field accesses, capability/condition dominance graphs, macro definitions/invocations, and `#ifdef CONFIG_*` blocks into decoded `.csv` and `.sarif` tables. These outputs are validated by `data_test/` and imported into the unified SQLite database via `data/codeql_importers/`.

```text
linux_codeql_db_v* ──► codeql query run ──► *.bqrs
                                              │
                                              ▼
      data/codeql_importers/ ◄── *.csv / *.sarif ◄── codeql bqrs decode / interpret
```

---

## 1. Core Dashboard Queries (`13 Queries` $\rightarrow$ `12 SQLite Tables`)

The 13 core queries are ordered from lightweight foundational queries to global graph queries so `data_test/` can validate outputs fail-fast:

| # | Query File | Decoded Format | Importer (`data/codeql_importers/`) | Target SQLite Table(s) | Validation (`data_test/`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **`functions.ql`** | `functions.csv` | `import_functions.py` | `function_locations` | `test_functions.py` |
| 2 | **`kernel-configs-needed.ql`** | `kernel-configs-needed.csv` | `import_configs.py` | `configs` | `test_kernel_configs_needed.py` |
| 3 | **`ops_edges.ql`** | `ops_edges.csv` | `import_ops_targets.py` | `ops_targets` | `test_ops_edges.py` |
| 4 | **`allocs.ql`** | `allocs.csv` | `import_allocs.py` | `allocs` | `test_allocs.py` |
| 5 | **`allocations.ql`** | `allocations.csv` | `import_allocations.py` | `codeql_allocations`, `codeql_structs` | `test_allocations.py` |
| 6 | **`field-acces-type.ql`** | `field-acces-type.csv` | `import_field_access.py` | `field_access` | `test_field_acces_type.py` |
| 7 | **`macro-locations.ql`** | `macro-locations.csv` | `import_macros.py` | `macro_locations` | `test_macro_locations.py` |
| 8 | **`macro-invocations.ql`** | `macro-invocations.csv` | `import_macro_invocations.py` | `macroinvocation_locations` | `test_macro_invocations.py` |
| 9 | **`syscall-node-pairs.ql`** | `syscall-node-pairs.csv` | `import_syscall_node.py` | `syscall_node` | `test_syscall_node_pairs.py` |
| 10 | **`syscall-node-locs.ql`** | `syscall-node-locs.csv` | `import_syscall_node.py` | `syscall_node` | `test_syscall_node_locs.py` |
| 11 | **`condition-graph-direct.ql`** | `condition-graph-direct.csv` | `import_conditions.py` | `conditions` | `test_condition_graph_direct.py` |
| 12 | **`condition-graph-all.ql`** | `condition-graph-all.csv` | `import_conditions_reachable.py` | `conditions_reachable` | `test_condition_graph_all.py` |
| 13 | **`all-calls.ql`** | `all-calls.sarif` | `import_all_calls.py` | `locations`, `edges`, `path_nodes` | `test_all_calls.py` |

---

## 2. Detailed Schema & Semantics of Core Queries

### 2.1 Foundational & Preprocessor Queries
- **`functions.ql`** (`@kind table`):
  - **Purpose**: Extracts all defined kernel functions with non-empty bodies (excluding `*assert*` helpers) to map source lines to enclosing functions and correlate with Syzkaller coverage.
  - **Output Columns (`4`)**: `function_name`, `file`, `startLine`, `endLine`.
- **`kernel-configs-needed.ql`** (`@kind table`):
  - **Purpose**: Extracts `#ifdef` / `#ifndef` / `#if defined(CONFIG_*)` preprocessor branches to identify kernel configuration options required to reach any file and line range.
  - **Output Columns (`5`)**: `config`, `path`, `ifdef`, `endif`, `else_` (`0` when no `#else` branch exists).
- **`macro-locations.ql`** & **`macro-invocations.ql`** (`@kind table`):
  - **Purpose**: Maps macro definitions (`Macro`) and macro expansion sites (`MacroInvocation`) across the kernel tree. Used by `tools/check_privilege.py` to resolve numeric `CAP_*` constants at capability check sites back to symbolic names (e.g., `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`).
  - **Output Columns (`4`)**: `macro_name`, `file`, `startLine`, `endLine`.

### 2.2 Heap Allocation Queries (`allocs.ql` & `allocations.ql`)
- **`allocs.ql`** (`@kind table`):
  - **Purpose**: Range-analysis-backed kernel heap allocation extractor. Matches allocator functions via `__alloc_size` attributes + `gfp_t` parameters, computes `[sizeMin, sizeMax]` and `[flagsMin, flagsMax]` via `SimpleRangeAnalysis`, detects flexible array members (`isFlexible`), and resolves allocated struct types across `6.1`–`6.18+`.
  - **Cross-Kernel Compatibility (`6.1` / `6.12` / `6.18+`)**:
    - Normalizes `_noprof` suffixes (`kmalloc_noprof` $\rightarrow$ `kmalloc`) introduced in Linux `6.10+`.
    - Deduplicates synthetic calls inside `alloc_hooks_tag` statement expressions (`typeof(_do_alloc) _res` in `6.12` and `if (mem_alloc_profiling_enabled())` branches in `6.18+`).
    - Propagates pointer casts from outer `alloc_hooks` / `kmalloc_objs` statement-expression wrappers via `getWrapperExpr()`.
  - **Output Columns (`17`)**: `call_value`, `type_value`, `objectSize`, `sizeMin`, `sizeMax`, `sizeVal`, `flagsMin`, `flagsMax`, `flagsVal`, `file`, `line`, `col`, `isFlexible`, `depth`, `typeUri`, `typeLine`, `typeCol`.
- **`allocations.ql`** (`@kind problem`):
  - **Purpose**: Extracts struct-typed `kmalloc`/`kzalloc`/`kcalloc`/`krealloc`/`kvmalloc` allocation sites, linking each call site to its target `Struct` definition, byte size, GFP flags, size expression, and flexible-array status (`true`/`false`).
  - **Output Columns (`10`)**: `call_location`, `call_expr`, `struct_name`, `struct_location`, `struct_size`, `gfp_flag`, `alloc_size`, `size_arg`, `is_flexible`, `allocator_name`.

### 2.3 Struct Field Access Query
- **`field-acces-type.ql`** (`@kind table`):
  - **Purpose**: Classifies every struct field access (`FieldAccess`) inside `kernel/`, `net/`, `drivers/`, `fs/`, `io_uring/`, `ipc/`, `mm/`, and `security/` into `read` (`isRValue()`), `write` (`isModified()`), or `exec` (indirect call `ExprCall` through a function-pointer field).
  - **Output Columns (`4`)**: `access_type` (`read`|`write`|`exec`), `field_name`, `declaring_type`, `location`.

### 2.4 Call Graph, Indirect Ops Dispatch & Syscall Reachability
- **`ops_edges.ql`** (`@kind table`):
  - **Purpose**: Resolves indirect function-pointer calls (`ExprCall`, e.g., `dir->i_op->link(...)` or `filp->f_op->unlocked_ioctl(...)`) by matching the accessed struct `Field` against static ops table initializers (`ClassAggregateLiteral`, e.g., `struct file_operations`, `struct proto_ops`, `struct inode_operations`).
  - **Output Columns (`11`)**: `definition`, `parent`, `field_name`, `target_name`, `target_file`, `target_start`, `target_end`, `exprcall_file`, `exprcall_line`, `exprcall_parent_start`, `exprcall_parent_end`.
- **`syscall-node-pairs.ql`** & **`syscall-node-locs.ql`** (`@kind table`):
  - **Purpose**: Computes transitive call-graph reachability (`edges+`) from every `__do_sys_*` syscall entry point across direct calls, indirect taint/points-to calls, and `resolveCall` targets. `syscall-node-pairs.ql` emits `(syscall, function, file)` triples; `syscall-node-locs.ql` emits exact `(name, file, startLine, startCol, endLine, endCol)` spans joined by `import_syscall_node.py` into `syscall_node`.
- **`all-calls.ql`** (`@kind path-problem` $\rightarrow$ SARIF):
  - **Purpose**: Exports the full kernel call graph (combining `Function` $\leftrightarrow$ `FunctionCall`, `Function` $\leftrightarrow$ `ExprCall`, and `ExprCall` $\rightarrow$ `Function` edges) as a SARIF graph consumed by `import_all_calls.py` to populate `locations` and `edges`.

### 2.5 Capability & Condition Dominance Queries
- **`condition-graph-direct.ql`** (`@kind table`):
  - **Purpose**: Identifies intra-procedural capability checks (`capable`, `ns_capable`, `netlink_capable`, `sk_capable`, `file_ns_capable`, etc.) and `IfStmt` conditions that control-flow-dominate (`dominates(condition, call)`) downstream `Call` sites within the same function.
  - **Output Columns (`6`)**: `condition_type`, `check_location`, `if_location`, `argument`, `guarded_call`, `guarded_call_location`.
- **`condition-graph-all.ql`** (`@kind table`):
  - **Purpose**: Extends `condition-graph-direct.ql` inter-procedurally by computing all functions transitively reachable (`reachableFunc`) from calls directly guarded by a capability/condition check.
  - **Output Columns (`4`)**: `guarded_call_name`, `reachable_function_name`, `guarded_call_location`, `reachable_function_location`.

---

## 3. Exploratory & Standalone Queries

In addition to the 13 core pipeline queries, this directory includes standalone dataflow and call-graph queries for targeted vulnerability research:

| Query File | Kind | Description |
| :--- | :--- | :--- |
| **`callgraph-direct.ql`** | `path-problem` | Direct `FunctionCall`-only call graph excluding compiler builtins and assertions. |
| **`callgraph-indirect.ql`** | `path-problem` | Taint-tracked indirect `FunctionAccess` $\rightarrow$ `ExprCall` call graph. |
| **`callgraph-cfi-style.ql`** | `path-problem` | Points-to + struct-field-assigned indirect call graph filtered by parameter type compatibility. |
| **`root-leaf-nodes.ql`** | `path-problem` | Identifies root-to-leaf call paths across the combined direct + indirect call graph. |
| **`controlled-expression-calls.ql`** | `path-problem` | Tracks taint flow from `copy_from_user` / `__do_sys_*` parameters into indirect `ExprCall` arguments. |
| **`controlled-field-writes.ql`** | `path-problem` | Tracks dataflow from user-controlled inputs (including across ops table callbacks) into struct field assignments. |
| **`controled-field-writes.ql`** | `path-problem` | Taint-tracking variant of user-controlled input flowing into `FieldAccess` expressions. |
| **`field-free.ql`** | `path-problem` | Tracks taint flow from struct `FieldAccess` reads into `kfree` arguments (candidate UAF / double-free sites). |
| **`field-leaks.ql`** | `path-problem` | Tracks taint flow from struct `FieldAccess` reads into `copy_to_user` / `put_user` (candidate info-leak sites). |

---

## 4. Usage

### 1. Execute a Query (`.ql` $\rightarrow$ `.bqrs`)
```bash
codeql query run queries/allocs.ql \
  --database=/path/to/linux_codeql_db \
  --output=/path/to/results_dir/allocs.bqrs \
  --threads=0
```

### 2. Decode `.bqrs` Output to `.csv` or `.sarif`
```bash
# Decode table/problem queries (12 CSV queries) to CSV:
codeql bqrs decode /path/to/results_dir/allocs.bqrs \
  --format=csv \
  --output=/path/to/results_dir/allocs.csv

# Interpret path-problem queries (e.g. all-calls.ql or field-free.ql) to SARIF:
codeql bqrs interpret /path/to/results_dir/all-calls.bqrs \
  -t=kind=path-problem \
  -t=id=callgraph-all \
  --format=sarif-latest \
  --output=/path/to/results_dir/all-calls.sarif
```

### 3. Validate Decoded Query Output (`data_test/`)
```bash
# Validate a single query output:
pytest data_test -v \
  --query allocs \
  --results-dir /path/to/results_dir \
  --btf-db /path/to/btf.db

# Validate all 13 decoded query outputs in a results directory:
pytest data_test -v \
  --results-dir /path/to/results_dir \
  --btf-db /path/to/btf.db
```

### 4. Import Decoded Outputs into SQLite (`data/codeql_importers/`)
```bash
python3 data/codeql_importers/import_functions.py /path/to/results_dir/functions.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_configs.py /path/to/results_dir/kernel-configs-needed.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_ops_targets.py /path/to/results_dir/ops_edges.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_allocs.py /path/to/results_dir/allocs.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_allocations.py /path/to/results_dir/allocations.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_field_access.py /path/to/results_dir/field-acces-type.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_macros.py /path/to/results_dir/macro-locations.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_macro_invocations.py /path/to/results_dir/macro-invocations.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_syscall_node.py \
  --pairs /path/to/results_dir/syscall-node-pairs.csv \
  --locs /path/to/results_dir/syscall-node-locs.csv \
  --db /path/to/codeql_data.db
python3 data/codeql_importers/import_conditions.py /path/to/results_dir/condition-graph-direct.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_conditions_reachable.py /path/to/results_dir/condition-graph-all.csv /path/to/codeql_data.db
python3 data/codeql_importers/import_all_calls.py /path/to/results_dir/all-calls.sarif /path/to/codeql_data.db
```
