# Standalone CodeQL Linux Kernel Database Quality Test Suite (`codeql_db_test/`)

This directory contains a **standalone, self-referential CodeQL Database Quality Test Suite** designed to evaluate the structural health and completeness of any Linux kernel CodeQL database (`linux_codeql_db_v*`) before executing queries.

Complementary to `data_test/` (which validates the decoded output tables produced by queries), `codeql_db_test/` validates the *database itself*:

```text
CodeQL Database Creation ──► codeql_db_test/ (Is the database healthy?)
                                   │
                                   ▼
                        CodeQL Query Execution ──► data_test/ (Did each query produce valid data?)
```

Every check in this test suite is **intrinsic to the database under test** (or cross-validated against ground-truth BTF debug info from `data/field_information/extract-btf.py`), making it invariant across kernel versions (`6.1`, `6.6`, `6.12`, `6.18+`) and kernel configurations.

---

## 1. Why a Standalone Intrinsic CodeQL DB Test?

When `codeql database create` builds a database from a Linux kernel, compiler/extractor incompatibilities (such as GCC's `__seg_gs` named address spaces or Clang's C23 `__typeof_unqual__` macro expansion) do not cause `codeql` to fail—it still exits with code `0` (`Successfully created database`).

However, the resulting CodeQL database suffers severe, silent structural damage:
- **Mid-File Translation Unit Aborts (`Error limit reached.`)**: CodeQL's EDG frontend defaults to a per-TU error limit of 100 (`--error_limit 100`). As soon as a `.c` file hits ~20 unparseable per-cpu or networking macros, EDG emits `Error limit reached.` and aborts extracting the remainder of that translation unit.
- **Intra-Procedural `ErrorExpr` AST Black Holes**: Unparseable statement expressions inside surviving functions are silently replaced with `ErrorExpr` nodes. When these appear inside `if (...)` conditions or call arguments, they sever control-flow dominance (`dominates(condition, call)`) and call target resolution.
- **Dangling Call Targets & Broken Ops Tables**: When TUs abort mid-file, callers in other files and `file_operations` / `proto_ops` struct initializers point to function declarations whose `.c` definitions were never extracted (`!hasDefinition()`).

---

## 2. Test Suite Components

| File | Description |
| :--- | :--- |
| **`conftest.py`** | **Pytest Configuration & Session Fixtures**. Manages CLI options (`--codeql-db`, `--btf-db`, `--vmlinux`, `--ram`, `--threads`), executes all 5 `.ql` queries in a single shared session fixture (`codeql_query_results`), and renders the 6-domain diagnostic summary report via `pytest_terminal_summary`. |
| **`test_codeql_db.py`** | **Pytest Quality Test Suite**. Evaluates 25 quality checks across 6 test classes (`TestDomain1...` through `TestDomain6...`). Can be run via `pytest codeql_db_test` or executed directly as a script. |
| **`extraction_coverage.ql`** | Measures **Compilation-to-Extraction Coverage & Cross-Subsystem Parity**: computes what percentage of `.c` files compiled during the build (`Compilation.getAFileCompiled()`) yielded valid AST function definitions, and checks whether complex subsystems (`fs/`, `net/`) suffered a sudden drop relative to the internal core baseline (`mm/`, `kernel/`, `security/`). |
| **`ast_corruption.ql`** | Measures **Intra-Procedural AST & CFG Corruption**: counts `ErrorExpr` AST black holes globally, per defined function, inside branch conditions (`IfStmt`/`Loop`), and inside call arguments (`Call`). |
| **`callgraph_completeness.ql`** | Measures **Intrinsic Call-Graph & Ops Table Resolution**: computes what percentage of direct `FunctionCall` sites in `.c` files and function pointers in kernel operations tables (`file_operations`, `proto_ops`, `net_device_ops`, `inode_operations`) resolve to functions with extracted bodies (`hasDefinition()`). |
| **`kernel_invariants.ql`** | Measures **Universal Kernel Anchor Subgraph Invariants**: verifies that universal kernel entry points (`__sys_setsockopt`, `sk_setsockopt`, `unix_stream_connect`, `vfs_write`, `vfs_read`, `do_sys_openat2`) have extracted bodies, resolved 1-hop and 2-hop callees, and `0` `ErrorExpr` nodes in their call neighborhood. |
| **`btf_struct_sizes.ql`** | Measures **Kernel Struct Layout & BTF Type Integrity**: extracts 64-bit LP64 `(struct_name, byte_size)` definitions from CodeQL's type table (`max(s.getSize())` per struct name to avoid 32-bit VDSO shadowing) for intrinsic LP64 layout checks and ground-truth BTF cross-validation. |

---

## 3. The 6 Quality Domains (`25 Checks`)

### Domain 1: Extractor & Build-Tracer Log Forensics (`<db>/log/build-tracer.log`)
1. **EDG Translation Unit Aborts (`Error limit reached.`)**: Must be `0` aborted TUs (unpatched 6.18 has `560` aborted TUs).
2. **EDG Parse Error Density (`edg_errors / compiled_c_files`)**: Must be `< 0.05` errors per compiled `.c` file (healthy 6.1 is `0.01`; unpatched 6.18 is `1,148` errors/file).
3. **C23 `__typeof_unqual__` Macro Compatibility**: Must be `0` errors (detects `pto_tmp__`, `pao_tmp__`, `pscr_ret__` cascading errors from `CONFIG_CC_HAS_TYPEOF_UNQUAL=y`).
4. **Named Address Space Compatibility (`__seg_gs` / `__seg_fs`)**: Must be `0` errors (detects GCC named address space failures).

### Domain 2: Intrinsic Compilation-to-Extraction Completeness (`extraction_coverage.ql`)
5. **Global Compiled `.c` Extraction Rate (`extracted / compiled`)**: Must be `>= 85.0%` of compiled `.c` files.
6. **Core Subsystems Baseline (`mm/` + `kernel/` + `security/`)**: Establishes the internal baseline extraction rate (`>= 92.0%`).
7. **`fs/` Subsystem Extraction Parity**: Must be `>= 85.0%` and within `12%` of the internal core baseline.
8. **`net/` Subsystem Extraction Parity**: Must be `>= 70.0%` and within `26%` of the internal core baseline.

### Domain 3: Intra-Procedural AST & Control-Flow Integrity (`ast_corruption.ql`)
9. **Total `ErrorExpr` AST Black Holes**: Must be `0` (unpatched 6.18 has `16,580`).
10. **Corrupted Kernel Functions Percentage**: Must be `0.00%` (`0` corrupted functions).
11. **Branch Condition AST Corruption**: Must be `0` `ErrorExpr` nodes inside `IfStmt`/`Loop` conditions.
12. **Call Site Argument / Target AST Corruption**: Must be `0` `ErrorExpr` nodes inside `Call` arguments.

### Domain 4: Intrinsic Call-Graph & Ops Table Resolution (`callgraph_completeness.ql`)
13. **Global Direct `FunctionCall` Definition Resolution Rate**: `>= 97.5%` of direct kernel calls in `.c` files must resolve to defined functions with bodies.
14. **`fs/` Direct Call Definition Resolution Rate**: `>= 98.0%` resolved.
15. **`net/` Direct Call Definition Resolution Rate**: `>= 97.5%` resolved.
16. **Operations Table (`file_operations`/`proto_ops`) Pointer Resolution**: `>= 99.0%` of function pointers initialized in kernel ops structs must resolve to defined functions with bodies (`100.00%` across all patched kernels).

### Domain 5: Universal Kernel Anchor Subgraph Invariants (`kernel_invariants.ql`)
17–22. **Core Kernel Anchor Subgraph Integrity (`__sys_setsockopt`, `sk_setsockopt`, `unix_stream_connect`, `vfs_write`, `vfs_read`, `do_sys_openat2`)**: Verifies that each core anchor has an extracted AST body, resolved 1-hop and 2-hop callees (`0` missing definitions), and `0` `ErrorExpr` nodes in its call neighborhood.

### Domain 6: Kernel Struct Layout & BTF Type Integrity (`btf_struct_sizes.ql`)
23. **Extracted Named Kernel Struct Count**: Verifies CodeQL's type table extracted `>= 5,000` named kernel structs with `byte_size > 0`.
24. **Universal 64-Bit LP64 Kernel Struct Size Invariants**: Verifies exact byte sizes on Kconfig-independent 64-bit kernel structs (`list_head == 16`, `hlist_node == 16`, `msg_msg == 48`, `user_key_payload == 24`) and valid 64-bit LP64 bounds on core slab structs (`sk_buff`, `task_struct`, `file`, `inode`, `sock`, `mm_struct`, `vm_area_struct`, `page`), detecting any 32-bit VDSO truncation or type corruption.
25. **Ground-Truth BTF Struct Size Parity (`--btf-db`)**: Cross-validates CodeQL's extracted struct sizes against BTF debug info from `data/field_information/extract-btf.py` (via `--btf-db <sqlite>` or auto-extracted from `vmlinux`), verifying `100%` exact match on core security structs and `>= 98.0%` match across all shared structs.

---

## 4. Usage

### 1. Standard Pytest Mode (Auto-discovers or extracts BTF SQLite DB from sibling `vmlinux`)
```bash
pytest codeql_db_test -v \
  --codeql-db /path/to/linux_codeql_db_v6.1.111
```

### 2. Explicit BTF SQLite Database Verification
```bash
pytest codeql_db_test -v \
  --codeql-db /path/to/linux_codeql_db_v6.1.111 \
  --btf-db /path/to/btf.db
```

### 3. Filter Specific Domain or Check
```bash
pytest codeql_db_test -v -k Domain6 \
  --codeql-db /path/to/linux_codeql_db_v6.1.111 \
  --btf-db /path/to/btf.db
```
