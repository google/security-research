# Kernel Call-Graph & Privilege Analysis CLI Tools (`tools/`)

This directory contains three command-line analysis tools (`find_paths.py`, `inspect_calls.py`, `check_privilege.py`) backed by shared domain libraries under `tools/lib/` (`callgraph.py`, `metadata.py`, `privilege.py`) that query the unified Dashboard SQLite database (`codeql_data-<version>.db`) and optional Syzkaller coverage database to answer core vulnerability triage and attack-surface questions:

1. **`find_paths.py`** — *"Which syscalls or non-syscall entry points can reach this line or function, and what is the call chain?"*
2. **`inspect_calls.py`** — *"Who calls this function (directly, asynchronously, or via `ops_targets` function pointers), and what does it call?"*
3. **`check_privilege.py`** — *"Is this line or function reachable from an unprivileged user, or is every path gated by `capable()` / `ns_capable()` / Kconfig / runtime tunables?"*

```text
                                                      ┌──► find_paths.py       (Syscall/entry-to-target shortest call chains + coverage)
                                                      │
codeql_data-<ver>.db ──► tools/lib/{callgraph,        ┼──► inspect_calls.py    (1-hop & multi-hop caller/callee neighborhood + ops dispatch)
                                    metadata,         │
                                    privilege}.py     └──► check_privilege.py  (Dijkstra capability-gate & 2D entry precondition verdict)
```

---

## 1. Architecture, Shared Libraries & Required SQLite Tables

### Shared Library Modules (`tools/lib/`)
- **`tools/lib/callgraph.py`**: Database connection & index management (`open_databases`, `ensure_indexes`, `table_exists`, `clean_file_path`), function and span lookup (`get_enclosing_function`, `get_function_by_name`, `load_functions_for_files`), reverse call-graph traversal across direct calls, `ops_targets` function pointers, and `async_edges` callbacks (`get_callers`, `iter_pruned_callers`), syscall and non-syscall entry discovery (`is_syscall_root`, `load_entry_roots`, `is_entry_root`, `load_target_reachable_set`, `get_reachable_syscalls`, `get_reachable_entries`, `select_eval_roots`), and tree banner helpers (`format_root_label`, `format_target_banner`).
- **`tools/lib/metadata.py`**: Kconfig `#ifdef`/`#else`/Makefile precondition extraction and symbol metadata lookup (`get_line_configs`, `get_kconfig_metadata`), Syzkaller dynamic coverage correlation (`get_syzkaller_coverage`, `is_line_covered_by_syzkaller`), target and call-path step builders (`build_target_info`, `make_path_step`, `make_caller_step`), and shared CLI argument parsing (`add_common_cli_args`, `handle_common_cli_setup`, `extract_reachability_cli_kwargs`).
- **`tools/lib/privilege.py`**: Dynamic `CAP_*` constant resolution (`load_capability_map`, `format_capability`, `deduplicate_gates`, `add_call_span`), polymorphic `conditions` table parsing across direct call gates, `__guarded_span__:<ns_scope>` line-span guards, `__genl_ops_gate__:<ns_scope>` Generic Netlink flags, `sysctl`, and `module_param` tunables (`load_condition_gates`, `get_call_site_gates`, `load_runtime_tunables`), the 2D entry-precondition model (`get_entry_precondition`), and capability verdict classification (`classify_gates`).

### CLI Tools Summary

| Tool | Core Question Answered | SQLite Tables Used | Output Formats |
| :--- | :--- | :--- | :--- |
| **`find_paths.py`** | Finds shortest call paths from `__do_sys_*` syscalls and non-syscall `entry_node` roots to a target `(file, line)` or `function`, traversing direct calls (`edges`), indirect struct function-pointer calls (`ops_targets`), and asynchronous registrations (`async_edges`). | `function_locations`, `syscall_node`, `entry_node`, `locations`, `edges`, `ops_targets`, `async_edges`, `configs`, `kconfig_symbols` (+ optional Syzkaller DB) | `tree` (default), `list`, `json`, `mermaid` |
| **`inspect_calls.py`** | Inspects 1-hop or multi-hop callers (`--callers`), callees (`--callees`), or both (`--both`), resolving indirect ops table dispatches (e.g., `inode_operations->link`, `file_operations->unlocked_ioctl`) and annotating call-site capability gates. | `function_locations`, `locations`, `edges`, `ops_targets`, `async_edges`, `conditions`, `macroinvocation_locations` (+ optional Syzkaller DB) | `summary` (default), `tree`, `list`, `json` |
| **`check_privilege.py`** | Crosses static call paths with control-flow-dominating capability checks (`conditions` + `macroinvocation_locations`), Kconfig guards, runtime tunables, and 2D non-syscall entry floors using a weighted Dijkstra search (`COST_UNGATED=1`, `COST_NS_CAPABLE=10,000`, `COST_CAPABLE=1,000,000`) to find the least-privileged path to a target. | `function_locations`, `syscall_node`, `entry_node`, `locations`, `edges`, `ops_targets`, `async_edges`, `conditions`, `macroinvocation_locations`, `configs`, `kconfig_symbols` (+ optional Syzkaller DB) | `summary` (default), `tree`, `paths`, `json` |

> **Automatic Index Creation**: On first run, `callgraph.ensure_indexes()` automatically verifies and creates lightweight traversal indexes (`idx_fl_file_lines`, `idx_fl_name`, `idx_sn_fn`, `idx_sn_sys`, `idx_loc_msg`, `idx_loc_uri_line`, `idx_edges_target`, `idx_edges_source`, `idx_ops_target`, `idx_ops_exprcall`, plus conditional indexes on `configs`, `kconfig_symbols`, `async_edges`, and `entry_node`) if they do not already exist. You can also pre-build them explicitly with `--ensure-indexes`.

---

## 2. Tool 1: Syscall Reachability Path Finder (`find_paths.py`)

### Key Features
- **Target Resolution**: Accepts either `--file <path> --line <num>` (resolving the enclosing kernel function automatically) or `--function <name>`.
- **Hybrid Call-Graph Traversal**: Combines direct call edges (`locations` / `edges` from `all-calls.ql`) with indirect ops-table dispatch edges (`ops_targets` from `ops_edges.ql`).
- **Syzkaller Coverage Correlation**: When `--syzkaller-db` is provided, annotates each step along the call path with dynamic coverage indicators and optional Syzkaller reproduction programs (`--show-repro`).

### CLI Usage & Examples
```bash
# Find the shortest syscall path to a specific source line:
python3 -m tools.find_paths \
  --db /path/to/codeql_data.db \
  --file mm/shmem.c --line 1500

# Find paths to a function across all reachable syscalls (up to 10 syscalls):
python3 -m tools.find_paths \
  --db /path/to/codeql_data.db \
  --function sk_setsockopt \
  --all-syscalls --limit-syscalls 10

# Pin reachability search to a specific syscall and output a Mermaid diagram:
python3 -m tools.find_paths \
  --db /path/to/codeql_data.db \
  --function unix_stream_connect \
  --syscall connect \
  --format mermaid
```

---

## 3. Tool 2: Call-Graph Neighborhood Inspector (`inspect_calls.py`)

### Key Features
- **Bidirectional Inspection**:
  - `--callers`: Discovers direct callers and indirect callers invoking the function via `ops_targets` struct fields (e.g., `vfs_link` $\rightarrow$ `inode_operations.link` $\rightarrow$ `shmem_link`).
  - `--callees`: Discovers direct calls made by the function and indirect `ExprCall` sites within the function, listing candidate target implementations.
  - `--both` (default): Displays full 360-degree caller and callee context.
- **Multi-Hop Expansion**: Use `--depth <N>` to expand caller/callee trees up to `N` hops.
- **Inline Capability Gate Annotations**: Automatically highlights whether any caller or outgoing call site is guarded by `capable()` / `ns_capable()`.

### CLI Usage & Examples
```bash
# Inspect both callers and callees of a function (1-hop summary):
python3 -m tools.inspect_calls \
  --db /path/to/codeql_data.db \
  --function shmem_link

# Inspect 2 hops of callers for a specific file and line in JSON format:
python3 -m tools.inspect_calls \
  --db /path/to/codeql_data.db \
  --file net/core/sock.c --line 1250 \
  --callers --depth 2 --format json

# Show all indirect dispatch candidates without truncation:
python3 -m tools.inspect_calls \
  --db /path/to/codeql_data.db \
  --function vfs_ioctl \
  --callees --all
```

---

## 4. Tool 3: Capability & Unprivileged Reachability Analyzer (`check_privilege.py`)

### Key Features
- **Least-Privileged Path Discovery**: Uses Dijkstra's algorithm over the reverse call graph with edge weights penalizing capability checks (`COST_UNGATED = 1`, `COST_NS_CAPABLE = 10,000`, `COST_CAPABLE = 1,000,000`). If *any* unprivileged path exists alongside gated paths, `check_privilege.py` surfaces the ungated route first.
- **Symbolic `CAP_*` Resolution**: Correlates `conditions` check locations with `macroinvocation_locations` to resolve integer capability constants (`21`, `12`, etc.) into human-readable names (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, etc.).
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
  --db /path/to/codeql_data.db \
  --file net/core/sock.c --line 1420

# Evaluate privilege requirements across all reachable syscalls:
python3 -m tools.check_privilege \
  --db /path/to/codeql_data.db \
  --function sk_setsockopt \
  --all-syscalls --limit-syscalls 10 \
  --format tree

# Print compact arrow-separated call chains with gate annotations:
python3 -m tools.check_privilege \
  --db /path/to/codeql_data.db \
  --function shmem_link \
  --format paths
```

---

## 5. Running Unit Tests & Linting (`tools/tests/`)

The `tools/tests/` directory contains unit and synthetic-database integration tests for both the shared libraries (`test_lib.py`) and all three CLI tools (`test_find_paths.py`, `test_inspect_calls.py`, `test_check_privilege.py`), sharing schema fixtures from `tools/tests/fixtures.py`:

```bash
# Run the full unit test suite:
pytest tools/tests -v

# Format and run pylint (80-column Google style, zero lint suppressions):
pyformat -i -s 4 tools/*.py tools/lib/*.py tools/tests/*.py
pylint --max-line-length=80 tools/*.py tools/lib/*.py tools/tests/*.py
```

---

## 6. Known Limitations & Design Tradeoffs

- **Out-of-Line Capability Wrapper Depth (`queries/condition_graph.qll`)**: `DirectCapabilityCheck` resolves up to 2 hops of out-of-line helper wrappers (`f -> g -> capable`). Deeper capability chains (3+ hops) where intermediate helpers perform side effects before returning a boolean are intentionally not treated as pure capability predicates.
- **Conjunctive vs. Disjunctive Guarded Spans (`__guarded_span__`)**: When a single `if` condition combines multiple capability checks (`if (!capable(A) && !capable(B)) return -EPERM` vs. `if (!capable(A) || !capable(B)) return -EPERM`), both capability checks share the same guarded line span `[minLine, maxLine]`. Consumers union the gates covering a call site rather than solving full boolean SAT over compound branch conditions.
- **Build-Configuration Scope (`codeql_data-<ver>.db`)**: The CodeQL database reflects a single compiled kernel configuration and architecture (`x86_64`). Code inside `#ifdef CONFIG_X` blocks disabled in that build is not compiled into the AST and will not appear in `function_locations`, `edges`, or `conditions` (though raw `#ifdef` ranges remain visible in `configs`).
- **User-Namespace Scope (`ns_capable`) is Necessary, Not Sufficient**: When a path is gated by `ns_capable(ns->user_ns, CAP_*)` (`REACHABLE BEHIND USER NAMESPACE CAPABILITY`), unprivileged user-namespace reachability requires *both* the `ns_capable` check and that the object/subsystem can be instantiated inside a non-`init_net` / non-`init_user_ns` namespace. If an earlier caller or ops table binds the path to `init_net` or `init_user_ns`, global privilege is still required.
- **BPF Verifier Program-Type Allowlists (`bpf_entry`)**: Reachability from a `bpf_entry` root assumes `BPF_PROG_LOAD` succeeds (`CAP_BPF` or `kernel.unprivileged_bpf_disabled=0`), but individual BPF helpers and kfuncs are further restricted by per-program-type verifier allowlists (`get_func_proto` / `btf_kfunc_id_set`).
- **Bridge Traversal Depth Cap (`--max-bridge-depth`)**: Backward root collection (`get_reachable_syscalls`, `get_reachable_entries`) caps indirect/async bridge hops at `--max-bridge-depth` (default `6`) and direct hops at `20`. If traversal hits this cap with unexplored callers remaining and no root is found, `check_privilege.py` reports `UNREACHABLE (DEPTH-LIMITED)` (`target_info["depth_truncated"] = True`).
- **Async Context Bucketing (`queries/async_edges.qll`)**: `perf_event.overflow_handler` (PMI/NMI), `kprobe`/`kretprobe` handlers (trap context), and `ftrace_ops.func` (arbitrary function-entry context) are grouped under `mechanism = "irq"` (`context = "hardirq"`) for backward call-graph bridging.

