# Linux Kernel CodeQL Queries (`queries/`)

This directory contains the **CodeQL query suite** for the Linux Kernel Security Research Dashboard, along with shared `.qll` libraries (`kernel_common.qll`, `call_graph_edges.qll`, `async_edges.qll`, `condition_graph.qll`, `ops_edges.qll`) and exploratory taint-tracking queries.

The **16 core dashboard queries** extract function definitions, struct definitions and flattened field layouts, static call graphs, indirect function-pointer dispatch tables, deferred asynchronous edges, heap allocation sites, struct field accesses, capability/condition dominance graphs, macro definitions/invocations, and `#ifdef CONFIG_*` blocks into decoded `.csv` and `.sarif` tables. These outputs are validated by `data_test/` and imported into the unified SQLite database via `data/codeql_importers/`.

```text
linux_codeql_db_v* ──► codeql query run ──► *.bqrs
                                              │
                                              ▼
      data/codeql_importers/ ◄── *.csv / *.sarif ◄── codeql bqrs decode / interpret
```

---

## 1. Core Dashboard Queries (`16 Queries` $\rightarrow$ `18 SQLite Tables`)

The 16 core queries are ordered from lightweight foundational queries to global graph queries so `data_test/` can validate outputs fail-fast:

| # | Query File | Decoded Format | Importer (`data/codeql_importers/`) | Target SQLite Table(s) | Validation (`data_test/`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **`functions.ql`** | `functions.csv` | `import_functions.py` | `function_locations` | `test_functions.py` |
| 2 | **`structs.ql`** | `structs.csv` | `import_structs.py` | `struct_locations`, `struct_fields` | `test_structs.py` |
| 3 | **`kernel-configs-needed.ql`** | `kernel-configs-needed.csv` | `import_configs.py` | `configs` | `test_kernel_configs_needed.py` |
| 4 | **`ops_edges.ql`** | `ops_edges.csv` | `import_ops_targets.py` | `ops_targets` | `test_ops_edges.py` |
| 5 | **`allocs.ql`** | `allocs.csv` | `import_allocs.py` | `allocs` | `test_allocs.py` |
| 6 | **`allocations.ql`** | `allocations.csv` | `import_allocations.py` | `codeql_allocations`, `codeql_structs` | `test_allocations.py` |
| 7 | **`field-acces-type.ql`** | `field-acces-type.csv` | `import_field_access.py` | `field_access` | `test_field_acces_type.py` |
| 8 | **`macro-locations.ql`** | `macro-locations.csv` | `import_macros.py` | `macro_locations` | `test_macro_locations.py` |
| 9 | **`macro-invocations.ql`** | `macro-invocations.csv` | `import_macro_invocations.py` | `macroinvocation_locations` | `test_macro_invocations.py` |
| 10 | **`syscall-node-pairs.ql`** | `syscall-node-pairs.csv` | `import_syscall_node.py` | `syscall_node` | `test_syscall_node_pairs.py` |
| 11 | **`syscall-node-locs.ql`** | `syscall-node-locs.csv` | `import_syscall_node.py`, `import_entry_node.py` | `syscall_node`, `entry_node` | `test_syscall_node_locs.py` |
| 12 | **`entry-node-pairs.ql`** | `entry-node-pairs.csv` | `import_entry_node.py` | `entry_node` | `test_entry_node_pairs.py` |
| 13 | **`condition-graph-direct.ql`** | `condition-graph-direct.csv` | `import_conditions.py` | `conditions` | `test_condition_graph_direct.py` |
| 14 | **`condition-graph-all.ql`** | `condition-graph-all.csv` | `import_conditions_reachable.py` | `conditions_reachable` | `test_condition_graph_all.py` |
| 15 | **`all-calls.ql`** | `all-calls.sarif` | `import_all_calls.py` | `locations`, `edges` | `test_all_calls.py` |
| 16 | **`async-edges.ql`** | `async-edges.sarif` | `import_async_edges.py` | `async_edges` | `test_async_edges.py` |

---

## 2. Detailed Schema & Semantics of Core Queries

### 2.1 Foundational, Struct Layout & Preprocessor Queries
- **`kernel_common.qll`** (shared `.qll` module):
  - **`nonRuntimeKernelFile(File f)`**: Excludes standalone pre-boot binaries, EFI libstub, VDSO, kexec purgatory, host tools, and sample programs (`arch/%/boot/%`, `drivers/firmware/efi/libstub/%`, `%/vdso/%`, `%/purgatory/%`, `scripts/%`, `tools/%`, `samples/%`, `usr/%`, `Documentation/%`) across all queries.
  - **`functionSignatureSpan(Function f, File file, int startLine, int endLine)`**: Computes the canonical signature-to-closing-brace span `[startLine, endLine]` for every compiled runtime kernel function, bounding `f.getLocation().getStartLine()` to within 12 lines above `block.getLocation().getStartLine()` so earlier forward declarations in the same file never stretch `startLine`.
- **`functions.ql`** (`@kind table`):
  - **Purpose**: Extracts all compiled runtime kernel functions with non-empty bodies (excluding `*assert*` helpers) using `functionSignatureSpan`.
  - **Output Columns (`4`)**: `function_name`, `file`, `startLine`, `endLine`.
- **`structs.ql`** (`@kind table`):
  - **Purpose**: Extracts all named compiled runtime kernel `Struct` definitions (`struct_name`, `file`, `startLine`, `endLine`, `byteSize`) and recursively flattens nested anonymous `struct`/`union` members to emit every named field with its clean `field_path`, `field_type`, cumulative `byte_offset`, `bit_offset`, `bit_width`, `field_line`, and `is_function_ptr`.
  - **Output Columns (`12`)**: `struct_name`, `file`, `startLine`, `endLine`, `byteSize`, `field_name`, `field_path`, `field_type`, `byte_offset`, `bit_offset`, `bit_width`, `field_line`, `is_function_ptr` (imported into `struct_locations` and `struct_fields`).
- **`kernel-configs-needed.ql`** (`@kind table`):
  - **Purpose**: Extracts `#ifdef` / `#ifndef` / `#if defined(CONFIG_*)` preprocessor branches to identify kernel configuration options required to reach any file and line range.
  - **Output Columns (`5`)**: `config`, `path`, `ifdef`, `endif`, `else_` (`0` when no `#else` branch exists).
- **`macro-locations.ql`** & **`macro-invocations.ql`** (`@kind table`):
  - **Purpose**: Maps macro definitions (`Macro`) and macro expansion sites (`MacroInvocation`) across the runtime kernel tree.
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
  - **Purpose**: Classifies every struct field access (`FieldAccess`) across all compiled runtime kernel files (`not nonRuntimeKernelFile`) into `read` (`isRValue()`), `write` (`isModified()`), or `exec` (indirect call `ExprCall` through a function-pointer field), resolving nested anonymous `struct`/`union` accesses back to their enclosing named top-level `Struct` and recording `enclosing_function`.
  - **Output Columns (`5`)**: `access_type` (`read`|`write`|`exec`), `field_name`, `declaring_type`, `location`, `enclosing_function`.

### 2.4 Call Graph, Indirect Ops Dispatch, Async Edges & Entry Reachability
- **`ops_edges.ql`** (`@kind table`):
  - **Purpose**: Resolves indirect function-pointer calls (`ExprCall`, e.g., `dir->i_op->link(...)` or `filp->f_op->unlocked_ioctl(...)`) by matching the accessed struct `Field` against static ops table initializers (`ClassAggregateLiteral`, e.g., `struct file_operations`, `struct proto_ops`, `struct genl_ops`) and extracts enclosing ops-array/family wrapper context and declarative struct privilege flags (`GENL_ADMIN_PERM`, `GENL_UNS_ADMIN_PERM`, `NL_CFG_F_ADMIN`).
  - **Output Columns (`13`)**: `definition`, `parent`, `field_name`, `target_name`, `target_file`, `target_start`, `target_end`, `exprcall_file`, `exprcall_line`, `exprcall_parent_start`, `exprcall_parent_end`, `wrapper_context`, `capability`.
- **`syscall-node-pairs.ql`**, **`entry-node-pairs.ql`** & **`syscall-node-locs.ql`** (`@kind table`):
  - **Purpose**: Computes transitive call-graph reachability (`edges+`) from `__do_sys_*` syscalls (`syscall-node-pairs.ql`) and non-syscall kernel entry points (`entry-node-pairs.ql`: `netlink`, `sysctl`, `sysfs`, `debugfs`, `proc_ops`, `io_uring`, `uring_cmd`, `kthread`, `net_rx`, `bpf_entry`, `device_usb`, `device_pci`, etc.). Joined with `syscall-node-locs.ql` into `syscall_node` and `entry_node`.
- **`all-calls.ql`** & **`async-edges.ql`** (`@kind path-problem` $\rightarrow$ SARIF):
  - **Purpose**: `all-calls.ql` exports the full synchronous + indirect kernel call graph into `locations` and `edges`. `async-edges.ql` extracts deferred execution registrations (`workqueue`, `timer`, `rcu`, `tasklet`, `irq`, `kthread`, `notifier`) into `async_edges` (including `caller_file` and `callee_file` for static function disambiguation).

### 2.5 Capability & Condition Dominance Queries
- **`condition-graph-direct.ql`** (`@kind table`):
  - **Purpose**: Identifies intra-procedural capability checks (`capable`, `ns_capable`, `netlink_capable`, `sk_capable`, `file_ns_capable`, etc.), guarded line spans (`__guarded_span__:<ns_scope>`), Generic Netlink declarative gates (`__genl_ops_gate__:<ns_scope>`), `sysctl`, and `module_param` guards.
  - **Output Columns (`6`)**: `condition_type`, `check_location`, `if_location`, `argument`, `guarded_call`, `guarded_call_location`.
- **`condition-graph-all.ql`** (`@kind table`):
  - **Purpose**: Extends `condition-graph-direct.ql` inter-procedurally by computing all functions transitively reachable (`reachableFunc`) from calls directly guarded by a capability/condition check.
  - **Output Columns (`4`)**: `guarded_call_name`, `reachable_function_name`, `guarded_call_location`, `reachable_function_location`.

---

## 3. Exploratory & Standalone Queries

In addition to the 16 core pipeline queries, this directory includes standalone dataflow and call-graph queries for targeted vulnerability research:

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
codeql query run queries/structs.ql \
  --database=/path/to/linux_codeql_db \
  --output=/path/to/results_dir/structs.bqrs \
  --threads=0
```

### 2. Decode `.bqrs` Output to `.csv` or `.sarif`
```bash
# Decode table/problem queries (14 CSV queries) to CSV:
codeql bqrs decode /path/to/results_dir/structs.bqrs \
  --format=csv \
  --output=/path/to/results_dir/structs.csv

# Interpret path-problem queries (all-calls.ql or async-edges.ql) to SARIF:
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
  --query structs \
  --results-dir /path/to/results_dir \
  --btf-db /path/to/btf.db

# Validate all 16 decoded query outputs in a results directory:
pytest data_test -v \
  --results-dir /path/to/results_dir \
  --btf-db /path/to/btf.db
```

### 4. Import Decoded Outputs into SQLite (`data/codeql_importers/`)
```bash
python3 -m data.codeql_importers.import_functions /path/to/results_dir/functions.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_structs /path/to/results_dir/structs.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_configs /path/to/results_dir/kernel-configs-needed.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_ops_targets /path/to/results_dir/ops_edges.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_allocs /path/to/results_dir/allocs.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_allocations /path/to/results_dir/allocations.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_field_access /path/to/results_dir/field-acces-type.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_macros /path/to/results_dir/macro-locations.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_macro_invocations /path/to/results_dir/macro-invocations.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_syscall_node \
  --pairs /path/to/results_dir/syscall-node-pairs.csv \
  --locs /path/to/results_dir/syscall-node-locs.csv \
  --db /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_entry_node \
  --pairs /path/to/results_dir/entry-node-pairs.csv \
  --locs /path/to/results_dir/syscall-node-locs.csv \
  --db /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_conditions /path/to/results_dir/condition-graph-direct.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_conditions_reachable /path/to/results_dir/condition-graph-all.csv /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_all_calls /path/to/results_dir/all-calls.sarif /path/to/kernel_dashboard.db
python3 -m data.codeql_importers.import_async_edges /path/to/results_dir/async-edges.sarif /path/to/kernel_dashboard.db
```
