# Git Commit Metadata & Function Source Dumper (`data/git_log/`)

[`git_log_dump.py`](git_log_dump.py) enriches the functions extracted by CodeQL (`function_locations` table) with their latest Git commit hash, author timestamp, and raw C source code from the Linux kernel Git repository (`git_log` table).

---

## 1. End-to-End Processing Pipeline

```text
SQLite `function_locations`              Linux Kernel Git Repo (--repo_dir)
(function_name, file_path, start, end)                  │
  │                                                     ├─► setup_repository()
  │                                                     │     ├── Unshallow if --is-shallow-repository
  │                                                     │     └── git commit-graph write --changed-paths
  ▼                                                     ▼
filter_tracked_locations() ◄─────── git -C <repo> ls-files (Tracked files set)
  │
  ▼
run_parallel_git_log()
  └── GNU parallel -P <no_cpu> ──► git log -n 1 --format="{},%at,%H" --no-patch -L <start>,<end>:<file>
  │
  ▼
parse_git_log_records() ◄────────── Slice source lines file_lines[start_line - 1 : end_line]
  │
  ▼
SQLite `git_log` Table
```

---

## 2. Step-by-Step Processing Logic

### Step 1: Repository Preparation & Commit-Graph Acceleration (`setup_repository`)
Running `git log -L <start>,<end>:<file>` across 50,000+ kernel functions on a raw repository is prohibitively slow without commit-graph bloom filters, and fails outright on shallow (`--depth 1`) clones:
1. Checks `git rev-parse --is-shallow-repository`; if `"true"`, runs `git fetch --unshallow` to retrieve full commit history.
2. Enables `core.commitGraph = true` and `commitGraph.readChangedPaths = true`.
3. Runs `git commit-graph write --reachable --changed-paths` so Git can skip commits that did not touch `<file>` in $O(1)$ time via changed-path Bloom filters.

### Step 2: Tracked File Filtering & Commit Mismatch Guard (`filter_tracked_locations`)
CodeQL databases include functions compiled from build-time generated files (such as `arch/x86/lib/inat-tables.c` or `lib/oid_registry_data.c`) that are not tracked in Git, and a user might accidentally point `--repo_dir` at a different commit than `--codeql_db`:
1. Runs `git -C <repo_folder> ls-files` to build an in-memory `tracked_files` set.
2. Filters `function_locations` to functions whose `file_path` is tracked in Git.
3. Computes `match_percentage = matched_count / total_count * 100`:
   - If `matched_count < total_count` and `--force` is not set, prompts interactively on a TTY or aborts automatically if `match_percentage < 95.0%`.

### Step 3: Parallel `git log -L` Execution (`run_parallel_git_log`)
1. Writes every tracked function span into a temporary input file (`tmp2`), one line per function in `<start_line>,<end_line>:<file_path>` format:
   ```text
   18,24:arch/x86/boot/compressed/error.c
   266,268:include/linux/compiler.h
   ```
2. Invokes GNU `parallel` across `--no_cpu` worker processes:
   ```bash
   /usr/bin/parallel --workdir <repo_folder> --group -P <no_cpu> -a <input_tmp> -- \
     /usr/bin/git --no-pager log -n 1 --format={},%at,%H --no-patch -L {}
   ```
   Here `{}` is replaced by `<start_line>,<end_line>:<file_path>` in both `--format={},%at,%H` and `-L {}`, so each worker emits a single CSV-like line containing the input coordinates followed by the latest commit's Unix author timestamp (`%at`) and 40-char SHA (`%H`):
   ```text
   18,24:arch/x86/boot/compressed/error.c,1680000000,11223344556677889900aabbccddeeff11223344
   ```

### Step 4: Output Parsing & Function Source Extraction (`parse_git_log_records`)
1. Replaces `:` with `,` in each output line and splits into 5 fields:
   - `start_line = int(chunks[0])`
   - `end_line = int(chunks[1])`
   - `file_path = chunks[2]`
   - `author_date = int(chunks[3])`
   - `commit = chunks[4]`
2. Reads `<repo_folder>/<file_path>` once into an in-memory `file_cache[file_path]` list of lines so files containing dozens of functions are only read from disk once.
3. Slices `function_code = "".join(file_lines[start_line - 1 : end_line])` and bulk-inserts `(start_line, end_line, file_path, author_date, commit, function_code)` into `git_log`.

---

## 3. SQLite Schema (`git_log`) & Usage

| Column | Type | Description |
| :--- | :--- | :--- |
| `start_line` | `UNSIGNED BIG INT` | 1-based starting line of the function (part of `PRIMARY KEY`). |
| `end_line` | `UNSIGNED BIG INT` | 1-based ending line of the function (part of `PRIMARY KEY`). |
| `file_path` | `TEXT` | Relative kernel source file path (part of `PRIMARY KEY`). |
| `author_date` | `UNSIGNED BIG INT` | Unix epoch timestamp (`%at`) of the last commit modifying this function. |
| `commit` | `VARCHAR(40)` | 40-character Git SHA (`%H`) of the last commit modifying this function. |
| `data` | `TEXT` | Raw C source code of the function (`lines[start_line-1 : end_line]`). |

```bash
# Populate git_log in the unified database:
python3 -m data.git_log.git_log_dump \
  --repo_dir /path/to/linux \
  --codeql_db /path/to/codeql_data.db \
  --db_file /path/to/codeql_data.db \
  --no_cpu 32 --force

# Run unit tests:
pytest data/git_log/tests -v
```
