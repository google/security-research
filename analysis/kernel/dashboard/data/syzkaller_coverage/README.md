# Syzkaller Dynamic Coverage Parser & Line Remapper (`data/syzkaller_coverage/`)

[`syzkaller_coverage.py`](syzkaller_coverage.py) parses Syzkaller/Syzbot code coverage reports (HTML, JSON, JSONL, gzip-compressed `.gz` files, or direct Syzbot URLs), deduplicates and merges multi-report inputs, optionally remaps line numbers across kernel commits via `git diff -U0`, and populates five relational tables in SQLite.

---

## 1. End-to-End Processing Pipeline

```text
Input Sources (HTML / JSON / JSONL / *.gz / URLs)
  │
  ├─► get_sk_cov_data()
  │     ├── Local JSON/JSONL(.gz) ──► "__STREAM_FILE__:<path>" (Zero-RAM streaming)
  │     └── HTML / URLs (.gz)     ──► Decompress & decode string
  │
  ├─► get_all_data()
  │     ├── JSON/JSONL ──► get_json_data() ──┐
  │     └── HTML       ──► get_html_path()   ├──► merge_dicts() (Global ID canonicalization)
  │                        get_html_syzk_cov()│        │
  │                        get_html_prog()  ──┘        ├─► get_syscalls() (Regex syscall parser)
  │                                                    │
  ├─► [--remap_lines] remap_coverage_data() ◄──────────┘
  │     └── git diff -U0 -M <cov_commit> <target_commit> ──► remap_line()
  │
  ▼
SQLite Tables: `file_path`, `syzk_cov`, `syzk_prog`, `syzk_sys`, `syscalls`
```

---

## 2. How HTML Coverage Reports Are Converted

A Syzkaller HTML coverage report embeds three distinct sections in a single document. [`syzkaller_coverage.py`](syzkaller_coverage.py) extracts and correlates them via internal numeric IDs:

### Step 1: Kernel File Path Table (`get_html_path`)
Uses `lxml.etree` XPath (`.//a[@id and @href and contains(@onclick,"onFileClick")]`) to parse the file tree sidebar:
```html
<a id="path/fs/open.c" href="#contents_42" onclick="onFileClick(42)">open.c</a>
```
- Extracts `file_id = "42"` from `onFileClick(42)` and strips the `"path/"` prefix from `id` to yield `("42", "fs/open.c")`.

### Step 2: Covered Lines & Reaching Program IDs (`get_html_syzk_cov`)
Scans `<div class="file" id="contents_<file_id>"><table><tr><td class='count'>...</td>` blocks line-by-line (1-indexed):
```html
<div class="file" id="contents_42"><table><tr><td class='count'>
<span class="cov" onclick="onProgClick(7, event)">15</span>
```
- The line's 1-based offset within `<td class='count'>` gives `code_line_no`, and `onProgClick(7, ...)` gives the reaching Syzkaller program `prog_id = "7"`, producing `("42", code_line_no, "7")`.

### Step 3: Syzkaller Reproducer Programs (`get_html_prog`)
Extracts every `<pre class="file" id="prog_<prog_id>">...</pre>` block and unescapes HTML entities:
```html
<pre class="file" id="prog_7">
r0 = openat$foo(0xffffffffffffff9c, &amp;(0x7f0000000000), 0x0, 0x0)
ioctl$bar(r0, 0x1234, 0x0)
</pre>
```
- Yields `("7", "r0 = openat$foo(...)\nioctl$bar(...)")`.

---

## 3. How Streaming JSON / JSONL (`.gz`) Exports Are Converted

Syzbot's raw coverage exports (`.jsonl` or `.jsonl.gz`) can exceed several gigabytes. Instead of reading the entire file into memory:
1. `get_sk_cov_data()` tags local JSON/JSONL files with a lightweight marker `"__STREAM_FILE__:<filepath>"`.
2. `_iter_json_records()` opens the plain or gzipped file lazily and yields one parsed JSON object per line (or streams a top-level JSON array `[...]`).
3. For each record, `get_json_data()` assigns a sequential `prog_id` and expands basic-block line spans (`from_line..to_line`) into individual covered lines:

```json
{
  "program": "r0 = openat$bar(0x0, 0x0)\nioctl(r0, 0x2)\n",
  "coverage": [
    {
      "file_path": "fs/open.c",
      "functions": [
        {
          "func_name": "do_sys_openat2",
          "blocks": [{"hit_count": 3, "from_line": 100, "to_line": 102}]
        }
      ]
    }
  ]
}
```
$\rightarrow$ Expands `from_line: 100, to_line: 102` into coverage tuples `(file_id, 100, prog_id)`, `(file_id, 101, prog_id)`, `(file_id, 102, prog_id)`.

---

## 4. Multi-Report Merging & Syscall Extraction

### 4.1 Global ID Canonicalization (`merge_dicts`)
When multiple coverage files are passed on the CLI, `file_id` `0` in Report A and `file_id` `0` in Report B refer to different kernel files. `merge_dicts()`:
1. Collects the union of all `file_path` strings and `prog_code` strings across all input sources.
2. Sorts them lexicographically to assign deterministic global IDs (`0..N-1`).
3. Translates every `(old_file_id, code_line_no, old_prog_id)` tuple into `(global_file_id, code_line_no, global_prog_id)` and deduplicates via a set.

### 4.2 Syscall Name Extraction (`get_syscalls`)
For each unique program in `syzk_prog`, `get_syscalls()` applies the regex `((?:\w+ = )?(?P<syscall>[^$(]+)(?:[$]\w+)?.+)` to:
- Strip leading return-variable assignments (`r0 = `),
- Strip Syzkaller specialization suffixes (`$foo` in `openat$foo`),
- Deduplicate `(prog_id, syscall)` pairs so a program calling `read()` 10 times produces a single `(prog_id, "read")` row.

---

## 5. Cross-Commit Line Remapping (`--remap_lines` & `RemapConfig`)

Syzbot coverage reports are often generated on an upstream commit (`cov_commit`) that differs slightly from the kernel commit analyzed by CodeQL (`target_commit`). When `--remap_lines` is enabled:

1. **Commit Auto-Detection (`extract_cov_commit`)**: If `--cov_commit` is omitted, scans the filename (`ci-upstream-kasan-gce-7d0a66e4.html`) or file header (`"kernel_commit": "..."` / `commit/?id=...`) to detect the coverage commit hash, unshallowing `--repo_dir` if necessary (`ensure_commit_in_repo`).
2. **Zero-Context Diff Parsing (`parse_git_diff_u0`)**: Runs `git -C <repo_dir> diff -U0 -M <cov_sha> <target_sha>` and extracts per-file rename mappings and sorted `@@ -old_start,old_count +new_start,new_count @@` hunks.
3. **Line Translation (`remap_line`)**: Walks the sorted hunks while accumulating `cum_delta = sum(new_count - old_count)`:
   - **Before hunk (`old_line < old_start`)**: Returns `old_line + cum_delta` (shifted by all preceding hunks).
   - **Inside hunk (`old_start <= old_line < old_start + old_count`)**:
     - If `offset_in_hunk < new_count` (in-place modification): Maps to `new_start + offset_in_hunk`.
     - If `offset_in_hunk >= new_count` (line was deleted): Returns `None` and drops the stale coverage point.
   - **Deleted files (`+++ /dev/null`)**: Drops all coverage rows for that file.
   - **Renamed files (`-M`)**: Updates `file_path` to the new path in `target_commit`.

---

## 6. SQLite Schema & Usage

| Table | Columns | Description |
| :--- | :--- | :--- |
| **`file_path`** | `file_id PRIMARY KEY`, `file_path TEXT` | Canonicalized kernel source file paths. |
| **`syzk_cov`** | `(file_id, code_line_no, prog_id) PRIMARY KEY` | Covered source lines linked to reaching Syzkaller programs. |
| **`syzk_prog`** | `prog_id PRIMARY KEY`, `prog_code TEXT` | Full text of Syzkaller reproducer/corpus programs. |
| **`syzk_sys`** / **`syscalls`** | `prog_id`, `syscall TEXT` | Unique base syscalls invoked by each `prog_id`. |

```bash
# Import a local JSONL.gz coverage file and remap lines to repo HEAD:
python3 -m data.syzkaller_coverage.syzkaller_coverage \
  /path/to/coverage.jsonl.gz \
  --db_file /path/to/codeql_data.db \
  --remap_lines --repo_dir /path/to/linux --target_commit HEAD

# Run unit tests:
pytest data/syzkaller_coverage/tests -v
```
