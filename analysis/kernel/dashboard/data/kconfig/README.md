# Makefile/Kbuild & Kconfig Dependency Extractor (`data/kconfig/`)

[`kconfig_dump.py`](kconfig_dump.py) extracts file-level `Makefile`/`Kbuild` compilation guards into the `configs` table and `Kconfig*` symbol definitions + `.config` build values into the `kconfig_symbols` table.

---

## 1. Why Both Makefile/Kbuild and Kconfig Parsing Are Needed

CodeQL's `kernel-configs-needed.ql` query only extracts intra-file `#ifdef CONFIG_*` preprocessor directives. However, in the Linux kernel, entire `.c` files and subdirectories are conditionally compiled via `Makefile`/`Kbuild` rules (e.g., `obj-$(CONFIG_NF_TABLES) += nf_tables_api.o`), and individual `CONFIG_*` symbols depend on parent `Kconfig` symbols via `depends on` and `select`.

```text
Linux Kernel Tree (--repo_dir)
  │
  ├─► Part 1: Makefile & Kbuild Parser (collect_makefile_configs)
  │     ├── join_continuation_lines()      (Join '\' lines & strip '#' comments)
  │     ├── _update_cond_stack()           (Track ifdef/ifndef/ifeq/ifneq/else/endif)
  │     ├── _resolve_composite_configs()   (Fixpoint propagation across composite .o targets)
  │     └── _propagate_subdir_configs()    (Top-down directory inheritance of CONFIG_* guards)
  │           │
  │           ▼
  │     SQLite `configs` Table: (config, path, ifdef=1, endif=<file_lines>, else_=0)
  │
  └─► Part 2: Kconfig & .config Parser (collect_kconfig_symbols)
        ├── parse_dot_config()             (Parse CONFIG_X=y/m and '# CONFIG_X is not set')
        └── parse_kconfig_file()           (Indentation-aware config/menuconfig parser)
              │
              ▼
        SQLite `kconfig_symbols` Table: (config, type, prompt, depends_on, select_list, ...)
```

---

## 2. Part 1: How `Makefile` and `Kbuild` Rules Are Converted

### 2.1 Line Normalization & Conditional Stack (`_update_cond_stack`)
1. `join_continuation_lines()` strips `#` comments and joins backslash-continued (`\`) lines into normalized statements.
2. `_update_cond_stack()` maintains a stack of active conditional guards (`cond_stack`):
   - `ifdef CONFIG_FOO` / `ifeq ($(CONFIG_FOO),y)` $\rightarrow$ pushes `"CONFIG_FOO"`.
   - `ifndef CONFIG_FOO` / `ifeq ($(CONFIG_FOO),n)` / `ifneq ($(CONFIG_FOO),y)` $\rightarrow$ pushes `"!CONFIG_FOO"`.
   - `else` $\rightarrow$ inverts the top of `cond_stack` (`"CONFIG_FOO"` $\leftrightarrow$ `"!CONFIG_FOO"`).
   - `else ifeq ($(CONFIG_BAR),y)` $\rightarrow$ replaces the top of `cond_stack` with `"CONFIG_BAR"`.
   - `endif` $\rightarrow$ pops `cond_stack`.

### 2.2 Composite Module Fixpoint Resolution (`_resolve_composite_configs`)
Kernel Makefiles frequently group multiple `.o` files into a composite module (sometimes nested multiple levels deep):
```makefile
obj-$(CONFIG_KVM) += kvm.o
kvm-y := kvm_main.o coalesced_mmio.o
kvm-$(CONFIG_KVM_VFIO) += vfio.o
```
1. `parse_single_makefile()` records assignment edges `(lhs_prefix, obj_stem)`:
   - `("obj", "kvm")` with `{"CONFIG_KVM"}`
   - `("kvm", "kvm_main")` with `set()`
   - `("kvm", "vfio")` with `{"CONFIG_KVM_VFIO"}`
2. `_resolve_composite_configs()` propagates parent `CONFIG_*` sets along `lhs_prefix -> obj_stem` edges until a fixpoint is reached:
   - `kvm_main.c` inherits `{"CONFIG_KVM"}` from `kvm`.
   - `vfio.c` inherits `{"CONFIG_KVM", "CONFIG_KVM_VFIO"}`.
   - Composite parent stem `kvm` (where `lhs != rhs` and `kvm.o` is never self-included) is filtered out because `kvm.c` does not exist; only leaf `.c` files are emitted.

### 2.3 Top-Down Subdirectory Inheritance (`collect_makefile_configs`)
As `os.walk()` traverses the repository top-down:
1. If `net/Makefile` contains `obj-$(CONFIG_NETFILTER) += netfilter/`, `_propagate_subdir_configs()` attaches `{"CONFIG_NETFILTER"}` to `dir_inherited["net/netfilter"]`.
2. When `os.walk()` visits `net/netfilter/Makefile` (`obj-$(CONFIG_NF_TABLES) += nf_tables_api.o`), `nf_tables_api.c` receives the union of inherited directory guards and local file guards: `{"CONFIG_NETFILTER", "CONFIG_NF_TABLES"}`.
3. Each guard is emitted as a whole-file `configs` tuple `(config, rel_c_path, 1, count_file_lines(c_abs), 0)`, seamlessly integrating with intra-file `#ifdef` rows in `tools/find_paths.py` and `tools/check_privilege.py`.

---

## 3. Part 2: How `Kconfig` and `.config` Files Are Converted

### 3.1 `.config` Build Value Parsing (`parse_dot_config`)
Reads `<repo_dir>/.config` (or `--dot_config`) into a lookup dictionary:
- `CONFIG_NF_TABLES=y` $\rightarrow$ `build_vals["CONFIG_NF_TABLES"] = "y"`
- `# CONFIG_KVM_VFIO is not set` $\rightarrow$ `build_vals["CONFIG_KVM_VFIO"] = "n"`

### 3.2 Indentation-Aware `Kconfig` Parsing (`parse_kconfig_file`)
`Kconfig` files contain free-form `help` / `---help---` paragraphs that often mention words like `default` or `select`. To avoid false matches:
1. `_join_kconfig_lines()` joins backslash-continued expressions (`depends on NET && \` + `INET` $\rightarrow$ `depends on NET && INET`) while preserving leading indentation on the first line.
2. When a `config <SYM>` or `menuconfig <SYM>` header is encountered at column 0, `_new_kconfig_entry()` initializes a symbol record (`CONFIG_<SYM>`).
3. When `help` or `---help---` is encountered at indentation width `help_indent` (computed with tabs = 8 spaces via `_indent_width()`), all subsequent lines with `cur_indent > help_indent` are skipped until indentation returns to $\le$ `help_indent`.
4. `_apply_kconfig_attribute()` extracts:
   - **Type & inline prompt**: `bool "Prompt text"`, `tristate`, `int`, `hex`, `string`, or implicit type from `def_bool` / `def_tristate`.
   - **Dependencies**: Multiple `depends on <expr>` lines are joined with `" && "`.
   - **Reverse dependencies**: Multiple `select <SYM> [if <expr>]` lines are joined with `", "`.
   - **Defaults**: Multiple `default` / `def_bool` / `def_tristate` values are joined with `"; "`.

---

## 4. SQLite Schemas & Usage

### `configs` Table (Appended & Deduplicated)
| Column | Type | Value for Makefile Guards |
| :--- | :--- | :--- |
| `config` | `TEXT` | `CONFIG_*` or `!CONFIG_*` guard expression. |
| `path` | `TEXT` | Relative `.c` file path (e.g. `net/netfilter/nf_tables_api.c`). |
| `ifdef` | `INTEGER` | `1` (start of file). |
| `endif` | `INTEGER` | Total line count of the `.c` file. |
| `else_` | `INTEGER` | `0`. |

### `kconfig_symbols` Table
| Column | Type | Example (`CONFIG_NF_TABLES`) |
| :--- | :--- | :--- |
| `config` | `TEXT` | `CONFIG_NF_TABLES` |
| `type` | `TEXT` | `tristate` |
| `prompt` | `TEXT` | `Netfilter nf_tables support` |
| `depends_on` | `TEXT` | `NET && INET` |
| `select_list` | `TEXT` | `NETFILTER_NETLINK if NET` |
| `default_val` | `TEXT` | `m if EXPERIMENTAL; n` |
| `build_val` | `TEXT` | `y` |
| `kconfig_file` | `TEXT` | `net/netfilter/Kconfig` |
| `line_no` | `INTEGER` | `12` |

```bash
# Extract Makefile/Kbuild guards and Kconfig symbols into SQLite:
python3 -m data.kconfig.kconfig_dump \
  --repo_dir /path/to/linux \
  --db_file /path/to/codeql_data.db \
  [--dot_config /path/to/linux/.config]

# Run unit tests:
pytest data/kconfig/tests -v
```
