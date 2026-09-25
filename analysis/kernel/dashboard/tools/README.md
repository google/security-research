# Kernel Call-Graph & Privilege Analysis CLI Tools (`tools/`)

This directory contains three command-line analysis tools that query the unified Dashboard SQLite database (`codeql_data-<version>.db`) and optional Syzkaller coverage database to answer core vulnerability triage and attack-surface questions:

1. **`find_paths.py`** — *"Which syscalls can reach this line or function, and what is the call chain?"*
2. **`inspect_calls.py`** — *"Who calls this function (directly or via `ops_targets` function pointers), and what does it call?"*
3. **`check_privilege.py`** — *"Is this line or function reachable from an unprivileged user, or is every path gated by `capable()` / `ns_capable()`?"*

```text
                       ┌──► find_paths.py       (Syscall-to-target shortest call chains + Syzkaller coverage)
                       │
codeql_data-<ver>.db ──┼──► inspect_calls.py    (1-hop & multi-hop caller/callee neighborhood + ops dispatch)
                       │
                       └──► check_privilege.py  (Dijkstra capability-gate & unprivileged reachability verdict)
```

---

## 1. Overview of Tools & Required SQLite Tables

| Tool | Core Question Answered | SQLite Tables Used | Output Formats |
| :--- | :--- | :--- | :--- |
| **`find_paths.py`** | Finds shortest call paths from `__do_sys_*` entry points to a target `(file, line)` or `function`, traversing both direct calls (`edges`) and indirect struct function-pointer calls (`ops_targets`). | `function_locations`, `syscall_node`, `locations`, `edges`, `ops_targets` (+ optional Syzkaller DB) | `tree` (default), `list`, `json`, `mermaid` |
| **`inspect_calls.py`** | Inspects 1-hop or multi-hop callers (`--callers`), callees (`--callees`), or both (`--both`), resolving indirect ops table dispatches (e.g., `inode_operations->link`, `file_operations->unlocked_ioctl`) and annotating call-site capability gates. | `function_locations`, `locations`, `edges`, `ops_targets`, `conditions`, `macroinvocation_locations` (+ optional Syzkaller DB) | `summary` (default), `tree`, `list`, `json` |
| **`check_privilege.py`** | Crosses static call paths with control-flow-dominating capability checks (`conditions` + `macroinvocation_locations`) using a weighted Dijkstra search (`COST_UNGATED=1`, `COST_NS_CAPABLE=10,000`, `COST_CAPABLE=1,000,000`) to find the least-privileged path to a target. | `function_locations`, `syscall_node`, `locations`, `edges`, `ops_targets`, `conditions`, `macroinvocation_locations` (+ optional Syzkaller DB) | `summary` (default), `tree`, `paths`, `json` |

> **Automatic Index Creation**: On first run, each tool automatically verifies and creates lightweight traversal indexes (`idx_fl_file_lines`, `idx_fl_name`, `idx_sn_fn`, `idx_sn_sys`, `idx_loc_msg`, `idx_loc_uri_line`, `idx_edges_target`, `idx_edges_source`, `idx_ops_target`, `idx_ops_exprcall`) if they do not already exist. You can also pre-build them explicitly with `--ensure-indexes`.

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

## 5. Running Unit Tests (`tools/tests/`)

The `tools/tests/` directory contains unit and synthetic-database integration tests for all three tools (`test_find_paths.py`, `test_inspect_calls.py`, `test_check_privilege.py`):

```bash
pytest tools/tests -v
```
