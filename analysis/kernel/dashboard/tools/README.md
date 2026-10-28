# Kernel Call-Graph, Source, Struct & Privilege Analysis CLI Tools (`tools/`)

This directory contains **six command-line analysis tools** (`locate_function.py`, `fetch_body.py`, `find_paths.py`, `inspect_calls.py`, `check_privilege.py`, `inspect_struct.py`) backed by eight shared domain libraries under `tools/lib/` (`callgraph.py`, `metadata.py`, `privilege.py`, `locator.py`, `source.py`, `inspector.py`, `ops.py`, `structs.py`) that query the unified Dashboard SQLite database (`kernel_dashboard-<version>.db`), optional Syzkaller coverage database, and optional kernel source tree to answer core vulnerability triage and attack-surface questions:

1. **`locate_function.py`** — *"Where is this function defined, is the symbol ambiguous across files, what are its exact `[sig_start_line, body_start_line, end_line]` boundaries, and if it is absent from the compiled DB, which Kconfig disabled it?"*
2. **`fetch_body.py`** — *"What is the exact line-numbered C source code of this function (or prefix up to `--up-to-line <L>`, with optional surrounding context and inline `[GATE]`, `[CALLEE]`, `[KCONFIG]`, and `[SYZKALLER]` annotations)?"*
3. **`find_paths.py`** — *"Which syscalls or non-syscall entry points can reach this line or function, and what is the shortest call chain (optionally with `--snippet-lines <N>` call-site C source lines at each hop)?"*
4. **`inspect_calls.py`** — *"Who calls this function (directly, asynchronously via `async_edges`, or indirectly via `ops_targets` function pointers—including `.open` handle-acquisition gates and sibling callbacks on the same ops table), what does it call, or what callbacks implement a given `--struct <ops> --field <slot>`?"*
5. **`check_privilege.py`** — *"Is this line or function reachable from an unprivileged user, or is every path gated by `capable()` / `ns_capable()` / `.open` acquisition gates / Kconfig / runtime tunables?"*
6. **`inspect_struct.py`** — *"What is the exact byte/bitfield layout of `struct <name>`, does it match DWARF/BTF (`types`), where is it allocated (`kmalloc_calls` / `allocs`), and which functions read, write, or execute its fields (`field_access` + `ops_targets`)?"*

```text
                                                       ┌──► locate_function.py  (Disambiguation, span detection & uncompiled Kconfig diagnosis)
                                                       ├──► fetch_body.py       (Line-numbered C source + --up-to-line + inline annotations)
kernel_dashboard-<ver>.db ──► tools/lib/{callgraph,   ├──► find_paths.py       (Syscall/entry shortest call chains + --snippet-lines + coverage)
                                    metadata,         ├──► inspect_calls.py    (Direct, ops_targets vtable + siblings + .open gates, & async_edges)
                                    privilege,        ├──► check_privilege.py  (Dijkstra capability-gate & 2D entry precondition verdict)
                                    locator,          └──► inspect_struct.py   (Struct layout, BTF parity, heap allocs, field_access & ops slots)
                                    source,
                                    inspector,
                                    ops,
                                    structs}.py
```

---

## 1. Architecture, Shared Libraries & Required SQLite Tables

### Shared Library Modules (`tools/lib/`)
- **`tools/lib/callgraph.py`**: Database connection & index management (`open_databases`, `ensure_indexes`, `table_exists`, `column_exists`, `clean_file_path`, `is_non_runtime_path`), `(function_name, file_path)` disambiguation (`FunctionKey`, `get_enclosing_function`, `get_functions_by_name`, `get_function_by_name`, `resolve_target_function_with_conn`, `load_functions_for_files`), reverse call-graph traversal across direct calls, `ops_targets` function pointers, and `async_edges` callbacks (`get_callers`, `query_direct_edge_rows`, `resolve_edge_caller`, `query_async_callers`, `iter_pruned_callers`, `is_node_visited`, `mark_node_visited`), syscall and non-syscall entry discovery (`is_syscall_root`, `load_entry_roots`, `is_entry_root`, `load_target_reachable_set`, `get_reachable_syscalls`, `get_reachable_entries`, `select_eval_roots`), and tree banner helpers (`format_root_label`, `format_target_banner`).
- **`tools/lib/metadata.py`**: Kernel version & source repository auto-detection (`detect_kernel_version`, `resolve_repo_dir`, `get_git_log_metadata`), Kconfig `#ifdef`/`#else`/Makefile precondition extraction and symbol metadata lookup (`get_line_configs`, `get_kconfig_metadata`), Syzkaller dynamic coverage correlation (`get_syzkaller_coverage`, `is_line_covered_by_syzkaller`), target and call-path step builders (`build_target_info`, `make_path_step`, `make_caller_step`, `format_ambiguous_symbol_error`), and shared CLI argument parsing (`add_common_cli_args`, `add_standard_tool_cli_args`, `verify_db_and_indexes`, `handle_common_cli_setup`, `extract_reachability_cli_kwargs`).
- **`tools/lib/privilege.py`**: Canonical UAPI + dynamic `CAP_*` constant resolution (`LINUX_UAPI_CAPABILITIES`, `load_capability_map`, `format_capability`, `deduplicate_gates`, `add_call_span`), polymorphic `conditions` table parsing across direct call gates, `__guarded_span__:<ns_scope>` line-span guards, `__genl_ops_gate__:<ns_scope>` Generic Netlink flags, `.open`/`.proc_open` handle-acquisition gate propagation including 1-hop permission helpers (`load_ops_acquisition_gates`), `sysctl` and `module_param` tunables (`load_condition_gates`, `get_call_site_gates`, `load_runtime_tunables`), the 2D entry-precondition model (`get_entry_precondition`), and capability verdict classification (`classify_gates`).
- **`tools/lib/locator.py`**: Function locator and disambiguation engine (`locate_functions`, `locate_functions_with_conn`, `classify_function_kind`, `detect_span_lines`, `diagnose_uncompiled_target`, `format_locate_text`).
- **`tools/lib/source.py`**: Function body and source window fetcher with dual-source fallback (`repo_dir` on disk or `git_log.data` in SQLite), `--up-to-line` prefix slicing, call-site snippet extraction (`fetch_callsite_snippet`), and inline CodeQL/Kconfig/Syzkaller line annotations (`fetch_function_body`, `fetch_function_body_with_conn`, `read_repo_window`, `read_git_log_window`, `collect_line_annotations`, `format_body_text`).
- **`tools/lib/inspector.py`**: Unified direct, indirect (`ops_targets` + `.open` acquisition gates + `ops_registrations`), and asynchronous (`async_edges`) caller/callee neighborhood queries and multi-hop tree construction (`inspect_function_calls`, `get_callers_for_function`, `build_caller_tree`, `get_callees_for_function`, `build_callee_tree`, `query_async_callees`).
- **`tools/lib/ops.py`**: Operations table registration, sibling callback discovery, `.open`/`.proc_open` acquisition gate lookup, and `--struct` / `--field` slot inspection (`inspect_ops_slot`, `inspect_ops_slot_with_conn`, `inspect_function_ops`, `inspect_function_ops_with_conn`, `format_ops_text`).
- **`tools/lib/structs.py`**: Struct and object lifecycle inspector (`inspect_struct`, `inspect_struct_with_conn`, `locate_struct_definitions`, `get_struct_fields_layout`, `get_struct_allocations`, `get_struct_field_accesses`, `get_struct_ops_summary`, `format_struct_text`) uniting CodeQL `struct_locations` / `struct_fields`, BTF `types` offset parity, `kmalloc_calls` / `allocs` heap allocation sites, and capability-gated `field_access` (`write`, `read`, `exec`) sites.

### CLI Tools Summary

| Tool | Core Question Answered | SQLite Tables Used | Output Formats |
| :--- | :--- | :--- | :--- |
| **`locate_function.py`** | Resolves function names (`exact`, `prefix`, `glob`, `regex`) or `--file`/`--line` coordinates to `(function_name, file_path)` keys, `[sig_start_line, body_start_line, end_line]` spans, function classification (`syscall_root`, `entry_root:<kind>`, `ops_callback`, `async_handler`, `header_inline`, `tu_definition`), caller/reachability degree counts, Kconfig/Syzkaller/Git metadata, and uncompiled Kconfig diagnosis when a symbol is absent from the compiled DB. | `function_locations`, `syscall_node`, `entry_node`, `locations`, `edges`, `ops_targets`, `async_edges`, `configs`, `kconfig_symbols`, `git_log` (+ optional Syzkaller DB & `repo_dir`) | `text` (default), `json` |
| **`fetch_body.py`** | Fetches exact 1-based line-numbered C source code for a function, prefix up to `--up-to-line`, or line window from `--repo-dir` (or `WORKSPACE_DIR/linux_v<ver>`) with automatic pure-DB fallback to `git_log.data`, optionally annotating lines with `[GATE]`, `[CALLEE]`, `[KCONFIG]`, and `[SYZKALLER]`. | `function_locations`, `git_log`, `locations`, `edges`, `conditions`, `macroinvocation_locations`, `configs` (+ optional Syzkaller DB & `repo_dir`) | `text` (default), `json` |
| **`find_paths.py`** | Finds shortest call paths from `__do_sys_*` syscalls and non-syscall `entry_node` roots to a target `(file, line)` or `function`, traversing direct calls (`edges`), indirect struct function-pointer calls (`ops_targets`), and asynchronous registrations (`async_edges`), with optional `--snippet-lines <N>` call-site C source lines at each hop. | `function_locations`, `syscall_node`, `entry_node`, `locations`, `edges`, `ops_targets`, `async_edges`, `configs`, `kconfig_symbols`, `git_log` (+ optional Syzkaller DB & `repo_dir`) | `tree` (default), `list`, `json`, `mermaid` |
| **`inspect_calls.py`** | Unified call, vtable, and async neighborhood inspector: inspects 1-hop or multi-hop callers (`--callers`), callees (`--callees`), or both (`--both`) across direct calls (`edges`), indirect ops dispatches (`ops_targets` with `.open`/`.proc_open` acquisition gates, ops table `definition`, and sibling callbacks), and deferred execution (`async_edges`), or enumerates callbacks for an ops slot (`--struct <name> [--field <slot>]`). | `function_locations`, `locations`, `edges`, `ops_targets`, `async_edges`, `conditions`, `macroinvocation_locations`, `configs`, `kconfig_symbols` (+ optional Syzkaller DB) | `summary` (default), `tree`, `list`, `json` |
| **`check_privilege.py`** | Crosses static call paths with control-flow-dominating capability checks (`conditions` + `LINUX_UAPI_CAPABILITIES` / `macroinvocation_locations`), `.open`/`.proc_open` acquisition gates, Kconfig guards, runtime tunables, and 2D non-syscall entry floors using a weighted Dijkstra search (`COST_UNGATED=1`, `COST_NS_CAPABLE=10,000`, `COST_CAPABLE=1,000,000`) to find the least-privileged path to a target. | `function_locations`, `syscall_node`, `entry_node`, `locations`, `edges`, `ops_targets`, `async_edges`, `conditions`, `macroinvocation_locations`, `configs`, `kconfig_symbols` (+ optional Syzkaller DB) | `summary` (default), `tree`, `paths`, `json` |
| **`inspect_struct.py`** | Inspects struct/union definitions and byte/bitfield layout (`struct_locations`, `struct_fields`), cross-validates offsets and sizes against DWARF/BTF (`types`), enumerates heap allocation sites (`kmalloc_calls`, `allocs`) with `GFP_*` flags, size ranges, and flexible-array detection, and lists capability-gated `write` / `read` / `exec` field accesses (`field_access`) and ops slots (`ops_targets`). | `struct_locations`, `struct_fields`, `types`, `kmalloc_calls`, `allocs`, `field_access`, `ops_targets`, `function_locations`, `syscall_node`, `entry_node`, `conditions` (+ optional `repo_dir`) | `text` (default), `json` |

> **Automatic Index Creation**: On first run, `callgraph.ensure_indexes()` automatically verifies and creates lightweight traversal indexes (`idx_fl_file_lines`, `idx_fl_name`, `idx_sn_fn`, `idx_sn_sys`, `idx_loc_msg`, `idx_loc_uri_line`, `idx_edges_target`, `idx_edges_source`, `idx_ops_target`, `idx_ops_exprcall`, plus conditional indexes on `configs`, `kconfig_symbols`, `async_edges`, `entry_node`, and `git_log`) if they do not already exist. You can also pre-build them explicitly with `--ensure-indexes`.

---

## 2. Tool 1: Function Locator & Uncompiled Kconfig Diagnoser (`locate_function.py`)

### Key Features
- **Multi-Mode Lookup**: Supports `--name <pattern>` with `--match {exact,prefix,glob,regex}` (optionally scoped by `--file <path>`) or `--file <path> --line <num>` to resolve the innermost enclosing function.
- **Static Symbol Disambiguation**: Identifies colliding static functions across translation units (`is_ambiguous = True`, e.g., `seq_show` or `probe` callbacks) and reports each candidate's `(function_name, file_path)` key, classification, and caller/reachability degree counts.
- **Exact Signature vs. Body Start Line Detection**: Distinguishes `sig_start_line` (return type / function signature) from `body_start_line` (`{`) and `end_line` (`}`).
- **Uncompiled Function Diagnosis**: When a function is absent from `function_locations` (e.g., disabled in `.config`), scans `repo_dir` and `configs` / `kconfig_symbols` to report the exact file, line, and blocking Kconfig symbols (e.g., `CONFIG_FB_SM750=n`, `CONFIG_STAGING=n`).

### CLI Usage & Examples
```bash
# Locate a function by exact name and inspect its degree counts and Kconfig guards:
python3 -m tools.locate_function \
  --db /path/to/kernel_dashboard.db \
  --name vfs_read

# List all definitions of a colliding static function across the kernel:
python3 -m tools.locate_function \
  --db /path/to/kernel_dashboard.db \
  --name seq_show

# Diagnose why an uncompiled driver function is missing from the CodeQL DB:
python3 -m tools.locate_function \
  --db /path/to/kernel_dashboard.db \
  --name lynxfb_pci_probe \
  --file drivers/staging/sm750fb/sm750.c
```

---

## 3. Tool 2: Function Body & Context Fetcher (`fetch_body.py`)

### Key Features
- **Dual-Source Extraction**: Reads full source files from `--repo-dir` (or auto-detected `${WORKSPACE_DIR}/linux_v<version>`) for arbitrary `--context <N>` lines around a function, and falls back automatically to `git_log.data` in SQLite when no checkout is present (`--git-log-only` forces pure-DB mode).
- **Call-Site Prefix Slicing (`--up-to-line <L>`)**: Slices a large function body from its signature (`sig_start_line`) down to `L + context`, capturing the parameter declarations, early validation checks, and capability guards leading up to a specific call site without dumping hundreds of trailing lines.
- **Inline Semantic Annotations (`--annotate`)**: Annotates source lines inside the function with `[GATE: capable(...)]`, `[CALLEE: ...]`, `[KCONFIG: ...]`, and `[SYZKALLER: COVERED]`.
- **Ambiguity Protection**: Rejects ambiguous function names with `AMBIGUOUS_SYMBOL` and lists candidate `--file` paths unless `--file` or `--allow-ambiguous` is passed.

### CLI Usage & Examples
```bash
# Fetch a function body with 3 lines of surrounding context and inline annotations:
python3 -m tools.fetch_body \
  --db /path/to/kernel_dashboard.db \
  --function msr_open \
  --context 3 --annotate

# Fetch only from the function signature down to a specific call site at line 3810:
python3 -m tools.fetch_body \
  --db /path/to/kernel_dashboard.db \
  --function do_tcp_setsockopt --up-to-line 3810 --context 2

# Fetch a disambiguated static function body in JSON format using pure-DB git_log:
python3 -m tools.fetch_body \
  --db /path/to/kernel_dashboard.db \
  --function seq_show --file fs/proc/fd.c \
  --git-log-only --format json
```

---

## 4. Tool 3: Syscall Reachability Path Finder (`find_paths.py`)

### Key Features
- **Target Resolution & Disambiguation**: Accepts `--file <path> --line <num>` or `--function <name> [--file <path>]`, keying BFS visited states by `(function_name, file_path)` so colliding static functions in different files never alias.
- **Hybrid Call-Graph Traversal**: Combines direct call edges (`locations` / `edges` from `all-calls.ql`), indirect ops-table dispatch edges (`ops_targets` from `ops_edges.ql`), and asynchronous edges (`async_edges` from `async-edges.ql`).
- **Inline Call-Site Source Snippets (`--snippet-lines <N>`)**: Attaches `±N` lines of C source code around each hop's call site (highlighting the call line with `>>`), allowing single-command inspection of argument passing along a call chain.
- **Syzkaller Coverage Correlation**: When `--syzkaller-db` is provided, annotates each step along the call path with dynamic coverage indicators and optional Syzkaller reproduction programs (`--show-repro`).

### CLI Usage & Examples
```bash
# Find the shortest syscall path to a specific source line:
python3 -m tools.find_paths \
  --db /path/to/kernel_dashboard.db \
  --file mm/shmem.c --line 1500

# Find paths to a function with ±1 line of C source snippet at each hop:
python3 -m tools.find_paths \
  --db /path/to/kernel_dashboard.db \
  --function nf_tables_newtable \
  --snippet-lines 1 --limit-syscalls 3

# Pin reachability search to a specific syscall and output a Mermaid diagram:
python3 -m tools.find_paths \
  --db /path/to/kernel_dashboard.db \
  --function unix_stream_connect \
  --syscall connect \
  --format mermaid
```

---

## 5. Tool 4: Unified Call, Ops-Table & Async Neighborhood Inspector (`inspect_calls.py`)

### Key Features
- **Bidirectional Function Inspection (`--function` or `--file` + `--line`)**:
  - `--callers`: Discovers direct callers, indirect callers invoking the function via `ops_targets` struct fields (automatically annotating `.open`/`.proc_open` handle-acquisition gates and listing the ops table `definition` and sibling callbacks on that struct instance), and asynchronous registrants (`async_edges`, e.g., `INIT_WORK` / `timer_setup`).
  - `--callees`: Discovers direct calls made by the function, indirect `ExprCall` sites within the function, and asynchronous handlers registered by the function (`async_edges`).
  - `--both` (default): Displays full 360-degree caller, ops registration/sibling, and callee context.
- **Forward Operations Slot Inspection (`--struct <ops_struct> [--field <slot>]`)**:
  - Lists all callbacks registered for a kernel operations struct (or specific field slot), their Kconfig and Syzkaller status, `.open`/`.proc_open` acquisition gates, and all `ExprCall` dispatch sites invoking that slot.
- **Multi-Hop Expansion**: Use `--depth <N>` to expand caller/callee trees up to `N` hops.

### CLI Usage & Examples
```bash
# Inspect callers, ops registrations/siblings, .open acquisition gates, and callees:
python3 -m tools.inspect_calls \
  --db /path/to/kernel_dashboard.db \
  --function msr_read --file arch/x86/kernel/msr.c

# Inspect callers and callees of an async workqueue handler:
python3 -m tools.inspect_calls \
  --db /path/to/kernel_dashboard.db \
  --function devlink_release --file net/devlink/core.c

# Inspect all callbacks and dispatch sites for file_operations.read:
python3 -m tools.inspect_calls \
  --db /path/to/kernel_dashboard.db \
  --struct file_operations --field read --limit 50
```

---

## 6. Tool 5: Capability & Unprivileged Reachability Analyzer (`check_privilege.py`)

### Key Features
- **Least-Privileged Path Discovery**: Uses Dijkstra's algorithm over the reverse call graph with edge weights penalizing capability checks (`COST_UNGATED = 1`, `COST_NS_CAPABLE = 10,000`, `COST_CAPABLE = 1,000,000`). If *any* unprivileged path exists alongside gated paths, `check_privilege.py` surfaces the ungated route first.
- **Symbolic `CAP_*` Resolution**: Resolves standard Linux UAPI capability numbers (`0..40`, e.g., `21` $\rightarrow$ `CAP_SYS_ADMIN`, `34` $\rightarrow$ `CAP_SYSLOG`) in $O(1)$ via `LINUX_UAPI_CAPABILITIES`, and correlates out-of-range check locations with `macroinvocation_locations`.
- **Handle-Acquisition Gate Propagation**: Automatically propagates capability gates from sibling `.open` / `.proc_open` callbacks (and their 1-hop permission helpers) onto `.read`, `.write`, `.read_iter`, `.write_iter`, `.unlocked_ioctl`, `.compat_ioctl`, `.mmap`, and `.poll` callbacks on the same ops table instance.
- **Intra-Procedural Target Line Checks**: When given `--file` and `--line` inside a function body, checks both inter-procedural gates on callers and intra-procedural `IfStmt` capability checks dominating the target line within the enclosing function.
- **Four Clear Security Verdicts**:
  - `REACHABLE WITH NO PRIVILEGE (UNGATED)`
  - `REACHABLE BEHIND USER NAMESPACE CAPABILITY` (`ns_capable(...)`)
  - `REACHABLE, BUT ONLY BEHIND <CAP_NAME>` (`capable(CAP_SYS_ADMIN)`, etc.)
  - `UNREACHABLE`

### `conditions` Table Schema & Polymorphic `call` Column Contract
The `conditions` table (`condition_type`, `condition_loc`, `if_stmt_loc`, `condition_arg`, `call`, `call_loc`) generated by `queries/condition-graph-direct.ql` uses a polymorphic `call` / `call_loc` encoding to represent three distinct kinds of gate records without schema changes:
1. **Direct Call-Site Gate Rows**: `call` is the CodeQL call string (e.g., `"call to foo"` or `"call to expression"`), and `call_loc` is the source location of the guarded `Call` expression.
2. **Guarded Line-Span Rows (`__guarded_span__:<ns_scope>`)**: `call` starts with `"__guarded_span__:"` followed by the classified user-namespace scope (`init_user_ns`, `net_ns`, `s_user_ns`, `mnt_ns`, `f_cred`, or `user_ns`), and `call_loc` encodes the controlled line interval `[minLine, maxLine]` as `"file://<path>:<minLine>:1:<maxLine>:1"`. Consumers (`load_condition_gates` in `tools/lib/privilege.py`) use this span to gate any direct call, indirect `ops_targets` dispatch, or `--line` target falling within `[minLine, maxLine]`.
3. **Generic Netlink Declarative Gate Rows (`__genl_ops_gate__:<ns_scope>`)**: `call` starts with `"__genl_ops_gate__:"` followed by `init_user_ns` (`GENL_ADMIN_PERM`) or `net_ns` (`GENL_UNS_ADMIN_PERM`), and `call_loc` encodes the gated Netlink handler function's body span `[startLine, endLine]`. Consumers attach these gates directly to the registered handler function.

> **Caveat on Single-Interval `[minLine, maxLine]` Span Approximation**: Controlled spans for `IfStmt` capability guards are represented as a single contiguous line interval `[minLine, maxLine]` (bounded for early-abort `if (!capable(...)) return/goto` guards by `min(labelLine) - 1`, the next `switch` case label, or the enclosing block end). If an aborting branch has multiple `goto` targets, `min(labelLine)` is a conservative lower bound; conversely, unusual intra-procedural control flow (such as backward jumps or intervening unconditional paths inside the same block) is approximated by line containment rather than full basic-block post-dominance.

### CLI Usage & Examples
```bash
# Check whether a specific kernel line is reachable without privileges:
python3 -m tools.check_privilege \
  --db /path/to/kernel_dashboard.db \
  --file net/core/sock.c --line 1420

# Evaluate privilege requirements across all reachable syscalls:
python3 -m tools.check_privilege \
  --db /path/to/kernel_dashboard.db \
  --function sk_setsockopt \
  --all-syscalls --limit-syscalls 10 \
  --format tree

# Print compact arrow-separated call chains with gate annotations:
python3 -m tools.check_privilege \
  --db /path/to/kernel_dashboard.db \
  --function shmem_link \
  --format paths
```

---

## 7. Tool 6: Struct Layout, Allocation & Field-Access Inspector (`inspect_struct.py`)

### Key Features
- **Struct & Union Layout + BTF Parity**: Queries `struct_locations` and `struct_fields` (including flattened anonymous unions/structs, bitfields, function-pointer members, and flexible arrays) and cross-validates byte/bit offsets and total struct sizes against DWARF/BTF (`types`). Automatically falls back to BTF `types` when a struct is only present in BTF.
- **Heap Allocation Sites (`kmalloc_calls` + `allocs`)**: Merges CodeQL `kmalloc_calls` and `allocs` rows for the struct, resolving the enclosing function, `GFP_*` flags, static/variable size bounds (`size_min`, `size_max`), flexible-array sizing expressions (`struct_size(...)`), and syscall/entry reachability.
- **Capability-Gated Field Accesses (`field_access`)**: Lists `write`, `read`, and `exec` (function-pointer call) sites on the struct (or a specific `--field` / `--struct sk_buff.priority` shorthand), annotating each access with its enclosing function, syscall/entry reachability, and dominating `capable()` / `ns_capable()` gates.
- **Ops Function-Pointer Slot Summary (`ops_targets`)**: Summarizes registered callbacks per function-pointer slot when the struct acts as an operations table.

### CLI Usage & Examples
```bash
# Inspect full layout, BTF parity, allocations, and field accesses for sk_buff:
python3 -m tools.inspect_struct \
  --db /path/to/kernel_dashboard.db \
  --struct sk_buff

# Inspect writes and reads to a specific field using struct.field shorthand:
python3 -m tools.inspect_struct \
  --db /path/to/kernel_dashboard.db \
  --struct sk_buff.priority --limit 10

# Inspect only heap allocations for msg_msg in JSON format:
python3 -m tools.inspect_struct \
  --db /path/to/kernel_dashboard.db \
  --struct msg_msg --section allocs --format json
```

---

## 8. Running Unit Tests & Linting (`tools/tests/`)

The `tools/tests/` directory contains self-contained unit tests for all shared libraries (`test_lib.py`) and all six CLI tools (`test_locate_function.py`, `test_fetch_body.py`, `test_find_paths.py`, `test_inspect_calls.py`, `test_check_privilege.py`, `test_inspect_struct.py`), sharing schema fixtures from `tools/tests/fixtures.py`:

```bash
# Run the full unit test suite:
pytest tools/tests -v

# Format and run pylint (80-column Google style, zero lint suppressions):
pyformat -i -s 4 tools/*.py tools/lib/*.py tools/tests/*.py
pylint --max-line-length=80 tools/*.py tools/lib/*.py tools/tests/*.py
```

---

## 9. Known Limitations & Design Tradeoffs

- **Out-of-Line Capability Wrapper Depth (`queries/condition_graph.qll`)**: `DirectCapabilityCheck` resolves up to 2 hops of out-of-line helper wrappers (`f -> g -> capable`). Deeper capability chains (3+ hops) where intermediate helpers perform side effects before returning a boolean are intentionally not treated as pure capability predicates.
- **Conjunctive vs. Disjunctive Guarded Spans (`__guarded_span__`)**: When a single `if` condition combines multiple capability checks (`if (!capable(A) && !capable(B)) return -EPERM` vs. `if (!capable(A) || !capable(B)) return -EPERM`), both capability checks share the same guarded line span `[minLine, maxLine]`. Consumers union the gates covering a call site rather than solving full boolean SAT over compound branch conditions.
- **Build-Configuration Scope (`kernel_dashboard-<ver>.db`)**: The CodeQL database reflects a single compiled kernel configuration and architecture (`x86_64`). Code inside `#ifdef CONFIG_X` blocks disabled in that build is not compiled into the AST and will not appear in `function_locations`, `edges`, or `conditions` (though raw `#ifdef` ranges remain visible in `configs`, and `locate_function.py` diagnoses uncompiled functions via `configs` and `kconfig_symbols`).
- **User-Namespace Scope (`ns_capable`) is Necessary, Not Sufficient**: When a path is gated by `ns_capable(ns->user_ns, CAP_*)` (`REACHABLE BEHIND USER NAMESPACE CAPABILITY`), unprivileged user-namespace reachability requires *both* the `ns_capable` check and that the object/subsystem can be instantiated inside a non-`init_net` / non-`init_user_ns` namespace. If an earlier caller or ops table binds the path to `init_net` or `init_user_ns`, global privilege is still required.
- **BPF Verifier Program-Type Allowlists (`bpf_entry`)**: Reachability from a `bpf_entry` root assumes `BPF_PROG_LOAD` succeeds (`CAP_BPF` or `kernel.unprivileged_bpf_disabled=0`), but individual BPF helpers and kfuncs are further restricted by per-program-type verifier allowlists (`get_func_proto` / `btf_kfunc_id_set`).
- **Bridge Traversal Depth Cap (`--max-bridge-depth`)**: Backward root collection (`get_reachable_syscalls`, `get_reachable_entries`) caps indirect/async bridge hops at `--max-bridge-depth` (default `6`) and direct hops at `20`. If traversal hits this cap with unexplored callers remaining and no root is found, `check_privilege.py` reports `UNREACHABLE (DEPTH-LIMITED)` (`target_info["depth_truncated"] = True`).
- **Async Context Bucketing (`queries/async_edges.qll`)**: `perf_event.overflow_handler` (PMI/NMI), `kprobe`/`kretprobe` handlers (trap context), and `ftrace_ops.func` (arbitrary function-entry context) are grouped under `mechanism = "irq"` (`context = "hardirq"`) for backward call-graph bridging.
