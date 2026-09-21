#!/usr/bin/python3
"""
Syzkaller Coverage Parser.
Parses Syzkaller code coverage reports (in HTML or JSON/JSONL format, including
gzip-compressed files and URLs) and exports the coverage data into a structured
SQLite3 database containing kernel file paths, covered line numbers, syzkaller
programs, and executed syscalls.
"""
import logging
import sqlite3
import html
import os
import gzip
import json
import argparse
import re
import operator
import subprocess
from urllib.request import urlopen
from urllib.parse import urlparse
from urllib.parse import urlsplit
from contextlib import closing
from io import StringIO
from lxml import etree
def sk_cov_url_or_file(source: str) -> str:
    """Validate that the input is a readable local file or a valid syzbot/syzkaller URL."""
    logging.info("Validating URL or file provided: %s" % source)
    expanded = os.path.expanduser(source)
    if os.path.isfile(expanded) and os.access(expanded, os.R_OK):
        return expanded
    result = urlparse(source)
    if (
        result.scheme == "file"
        and os.path.isfile(result.path)
        and os.access(result.path, os.R_OK)
    ):
        return source
    if (
        result.scheme
        and result.netloc
        and (
            "syzbot" in result.path
            or "syzkaller" in result.path
            or "syzbot" in result.netloc
            or "syzkaller" in result.netloc
        )
    ):
        return source
    logging.critical(
        "File not found or unreadable, and not a valid syzbot/syzkaller URL: %s"
        % source
    )
    raise ValueError
def can_create_file(filename: str) -> str:
    """Validate that the target file path can be created in a writable directory."""
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()
    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)
    else:
        logging.critical("Wrong path provided: %s" % filename)
        raise ValueError
def is_gzipped(data: bytes) -> bool:
    """Check if byte payload starts with standard gzip magic bytes (0x1f 0x8b)."""
    return len(data) >= 2 and data[:2] == b"\x1f\x8b"
def is_gzipped_file(filepath: str) -> bool:
    """Check if a local file starts with standard gzip magic bytes (0x1f 0x8b)."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(2)
        return is_gzipped(magic)
    except Exception:
        return False
def is_json_source(source: str, text_data: str) -> bool:
    """Check if a source is JSON or JSONL format based on filename extension or content prefix."""
    if text_data.startswith("__STREAM_FILE__:"):
        return True
    lower_src = source.lower()
    if any(
        lower_src.endswith(ext)
        for ext in (".json", ".jsonl", ".json.gz", ".jsonl.gz")
    ):
        return True
    stripped = text_data.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")
def _iter_json_records(data_str: str):
    """Yield JSON records from either an in-memory string or a streamed local file marker."""
    if data_str.startswith("__STREAM_FILE__:"):
        filepath = data_str[len("__STREAM_FILE__:") :]
        opener = (
            (lambda p: gzip.open(p, "rt", encoding="utf-8", errors="replace"))
            if is_gzipped_file(filepath)
            else (lambda p: open(p, "r", encoding="utf-8", errors="replace"))
        )
        with opener(filepath) as f:
            first_chunk = ""
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                if not first_chunk:
                    first_chunk = stripped
                    if first_chunk.startswith("["):
                        f.seek(0)
                        for rec in json.load(f):
                            yield rec
                        return
                yield json.loads(stripped)
    else:
        stripped = data_str.lstrip()
        if stripped.startswith("["):
            for rec in json.loads(data_str):
                yield rec
        else:
            for line in data_str.splitlines():
                if line.strip():
                    yield json.loads(line)
def get_json_data(data_str: str) -> (list, list, list):
    """Parse JSON or JSONL coverage report data into file path, coverage, and program tuples."""
    path_dict = {}
    prog_list = []
    cov_set = set()
    for i, record in enumerate(_iter_json_records(data_str)):
        prog_code = record.get("program", "").strip()
        if not prog_code:
            continue
        prog_id = i
        prog_list.append((prog_id, prog_code))
        for cov_item in record.get("coverage", []):
            file_path = cov_item.get("file_path", "").strip()
            if not file_path:
                continue
            if file_path not in path_dict:
                path_dict[file_path] = len(path_dict)
            file_id = path_dict[file_path]
            for func in cov_item.get("functions", []):
                for block in func.get("blocks", []):
                    from_line = block.get("from_line", 0)
                    to_line = block.get("to_line", from_line)
                    if from_line > 0:
                        for line_no in range(from_line, to_line + 1):
                            cov_set.add(
                                (file_id, line_no, prog_id)
                            )
    path_list = [
        (file_id, file_path) for file_path, file_id in path_dict.items()
    ]
    return path_list, list(cov_set), prog_list
def get_sk_cov_data(save_file: str, sk_cov_sources: list) -> dict:
    """Fetch coverage report content from local files or URLs, optionally saving downloaded URL reports."""
    out = {}
    file_idx = 0
    for source in sk_cov_sources:
        is_url = False
        if os.path.isfile(source):
            if save_file:
                logging.warning(
                    "Ignoring --save_file option for local file source: %s"
                    % source
                )
            if is_json_source(source, ""):
                logging.info("Streaming local JSON/JSONL file %s without loading into RAM" % source)
                out[source] = f"__STREAM_FILE__:{source}"
                continue
            logging.info("Getting data from local file %s" % source)
            with open(source, mode="rb") as file:
                data = file.read()
        else:
            logging.info("Getting data from URL %s" % source)
            is_url = True
            with urlopen(source) as response:
                data = response.read()
        if is_gzipped(data):
            logging.info("Decompressing gzip data...")
            data = gzip.decompress(data)
        if save_file and is_url:
            logging.info("Saving coverage data in file")
            target_file = (
                save_file
                if len(sk_cov_sources) == 1
                else f"{save_file}.{file_idx}"
            )
            with open(target_file, mode="wb") as file:
                file.write(data)
            file_idx += 1
        out[source] = data.decode(errors="replace")
    return out
def get_html_prog(html_data: str) -> list:
    """Extract syzkaller program IDs and program code from an HTML coverage report."""
    pos = -1
    data = []
    logging.info('Looking for <pre class="file" id="prog_ patterns')
    while True:
        prog_section = '<pre class="file" id="prog_'
        pos = html_data.find(prog_section, pos + 1)
        if pos == -1:
            break
        prog_id_pos = pos + len(prog_section)
        pos = html_data.find('"', prog_id_pos + 1)
        if pos == -1:
            break
        prog_id = html_data[prog_id_pos:pos]
        prog_code_pos = pos + len('">')
        pos = html_data.find("</pre>", prog_code_pos)
        prog_code = html.unescape(html_data[prog_code_pos:pos].strip())
        logging.debug(prog_code)
        data.append((prog_id, prog_code.strip()))
    if not data:
        logging.critical('No <pre class="file" id="prog_ has been found')
        raise ValueError
    return data
def get_syscalls(prog_list: list) -> list:
    """Extract unique (prog_id, syscall) pairs from syzkaller program code strings."""
    data = []
    seen = set()
    logging.info("Gathering syscalls from syzkaller programs...")
    for prog in prog_list:
        results = re.findall(
            r"((?:\w+ = )?(?P<syscall>[^$(]+)(?:[$]\w+)?.+)\n?", prog[1]
        )
        if results:
            for syscall in results:
                pair = (prog[0], syscall[1].strip())
                if pair not in seen:
                    seen.add(pair)
                    data.append(pair)
    if not data:
        logging.critical(
            "Something went wrong. No syscalls found in syzkaller programs."
        )
        raise ValueError
    logging.info("Total number of unique (prog_id, syscall) pairs: %d" % len(data))
    return data
def get_html_syzk_cov(html_data: str) -> list:
    """Extract covered file IDs, line numbers, and reaching program IDs from an HTML coverage report."""
    pos = -1
    data = []
    logging.info('Looking for class="file" id="contents patterns')
    while True:
        file_section = 'class="file" id="contents_'
        pos = html_data.find(file_section, pos + 1)
        if pos == -1:
            break
        file_id_pos = pos + len(file_section)
        pos = html_data.find('"', file_id_pos + 1)
        if pos == -1:
            break
        file_id = html_data[file_id_pos:pos]
        prefix_pos = pos + len('"')
        prefix = "><table><tr><td class='count'>"
        coverage_pos = pos + len('"') + len(prefix)
        if html_data[prefix_pos:coverage_pos] != prefix:
            # error
            continue
        pos = html_data.find("</td>", coverage_pos)
        coverage = html_data[coverage_pos:pos].splitlines()
        for code_line_no, line in enumerate(coverage):
            code_line_no += 1  # 0 - indexed
            program_event = "onProgClick("
            if program_event in line:
                comma_pos = line.find(",", len(program_event))
                prog_id = line[
                    line.find(program_event) + len(program_event) : comma_pos
                ]
                data.append((file_id, code_line_no, prog_id * 1))
                logging.debug("%s,%s,%s" % (file_id, code_line_no, prog_id * 1))
    if not data:
        logging.critical('No class="file" id="contents has been found')
        raise ValueError
    return data
def get_html_path(html_data: str) -> list:
    """Extract file IDs and kernel file paths from an HTML coverage report."""
    # grep '<a'.*'id='.*onFileClick ${COVERAGE_HTML} | sed 's/.* id=\(.*\?\) onclick=\(.*\?\)>/\1,\2/' > ${COVERAGE_HTML}.files.csv
    html_parser = etree.HTMLParser()
    tree = etree.parse(StringIO(html_data), html_parser)
    a_tag_list = tree.xpath(
        './/a[@id and @href and contains(@onclick,"onFileClick")]'
    )
    if not a_tag_list:
        logging.critical("No <a> tags with href, id, onclick attributes")
        raise ValueError
    logging.info(
        "Found some <a> tags to process. Number of lines: %d" % len(a_tag_list)
    )
    data = []
    for tag in a_tag_list:
        # Remove redundant JavaScript and get clean integer for file_id
        file_id = re.search(r"\(\s*(\d*)\s*\)", tag.get("onclick")).group(1)
        if not file_id:
            logging.critical(
                "OOOPS! Something has changed in syzkaller HTML! Can't parse onclick attribute data"
            )
            raise ValueError
        #  We also want to cut away "path/" from beginning of the path string supplied by syzkaller
        if not tag.get("id").startswith("path/"):
            logging.critical(
                "OOOPS! Something has changed in syzkaller HTML! Can't parse id attribute data"
            )
            raise ValueError
        file_path = tag.get("id")[5:]
        logging.debug("%s,%s" % (file_id, file_path))
        data.append((file_id, file_path))
    logging.info(
        "Amount of data entries extracted from tags and cleaned from duplicats. Number of lines: %d"
        % len(data)
    )
    # Syzkaller HTML contains duplicates of the <a> tags with file_ids. Removing these lines from final data.
    seen = set()
    uniq_data = [
        (file_id, file_path.strip())
        for file_id, file_path in data
        if file_id not in seen and not seen.add(file_id)
    ]
    return uniq_data
def get_all_data(sources_dict: dict) -> (dict, dict, dict, dict):
    """Parse and merge coverage data across all input sources into unified path, coverage, program, and syscall tables."""
    if not sources_dict:
        return {}, {}, {}, []
    all_path = {}
    all_syzk_cov = {}
    all_prog = {}
    for name, data in sources_dict.items():
        if is_json_source(name, data):
            logging.info("Parsing JSON/JSONL coverage data from %s" % name)
            path_data, cov_data, prog_data = get_json_data(data)
            all_path[name] = path_data
            all_syzk_cov[name] = cov_data
            all_prog[name] = prog_data
            logging.info("Amount of path data: %d" % len(all_path[name]))
            logging.info("Amount of syz_cov data: %d" % len(all_syzk_cov[name]))
            logging.info("Amount of programs data: %d" % len(all_prog[name]))
        else:
            all_path[name] = get_html_path(data)
            print("Path data obtained from file: %s" % name)
            logging.info("Amount of path data: %d" % len(all_path[name]))
            all_syzk_cov[name] = get_html_syzk_cov(data)
            print("Syzk_cov data obtained from %s" % name)
            logging.info(
                "Amount of syz_cov data: %d" % len(all_syzk_cov[name])
            )
            all_prog[name] = get_html_prog(data)
            print("Prog data obtained from: %s" % name)
            logging.info("Amount of programs data: %d" % len(all_prog[name]))
    all_path, all_syzk_cov, all_prog = merge_dicts(
        all_path, all_syzk_cov, all_prog
    )
    all_syscalls = get_syscalls(all_prog)
    return (all_path, all_syzk_cov, all_prog, all_syscalls)
def merge_dicts(
    all_path: dict, all_syzk_cov: dict, all_prog: dict
) -> (list, list, list):
    """Merge and deduplicate path, coverage, and program dictionaries from multiple sources into unified lists."""
    if (len(all_path) != len(all_syzk_cov)) or (len(all_path) != len(all_prog)):
        logging.critical(
            "OOOPS! Input dicts have different size. This is toally wrong!"
        )
        raise ValueError
    # Collect unique file paths and programs across all sources
    unique_file_path = set()
    unique_prog_code = set()
    for name in all_path:
        for _, fp in all_path[name]:
            unique_file_path.add(fp)
        for _, pc in all_prog[name]:
            unique_prog_code.add(pc)
    file_path_to_id = {
        fp: idx for idx, fp in enumerate(sorted(unique_file_path))
    }
    prog_code_to_id = {
        pc: idx for idx, pc in enumerate(sorted(unique_prog_code))
    }
    file_id_map = {}
    prog_id_map = {}
    for name in all_path:
        file_id_map[name] = {
            int(old_id): file_path_to_id[fp] for old_id, fp in all_path[name]
        }
        prog_id_map[name] = {
            int(old_id): prog_code_to_id[pc] for old_id, pc in all_prog[name]
        }
    agreg_syzk_cov_set = set()
    for name in all_syzk_cov:
        f_map = file_id_map[name]
        p_map = prog_id_map[name]
        for f_id, code_line_no, p_id in all_syzk_cov[name]:
            agreg_syzk_cov_set.add(
                (f_map[int(f_id)], int(code_line_no), p_map[int(p_id)])
            )
    agreg_file_path = [
        (idx, fp) for fp, idx in file_path_to_id.items()
    ]
    agreg_prog_code = [
        (idx, pc) for pc, idx in prog_code_to_id.items()
    ]
    return (agreg_file_path, list(agreg_syzk_cov_set), agreg_prog_code)
def extract_cov_commit(sources: list, sources_dict: dict) -> str:
    """Attempt to auto-detect the Syzkaller coverage commit hash from filenames or report headers."""
    for src in sources:
        base = os.path.basename(src)
        m = re.search(
            r"[-_]([0-9a-f]{7,40})\.(?:html|json|jsonl)(?:\.gz)?$", base, re.IGNORECASE
        )
        if m:
            return m.group(1)

    for src, data in sources_dict.items():
        if data.startswith("__STREAM_FILE__:"):
            filepath = data[len("__STREAM_FILE__:") :]
            opener = (
                (lambda p: gzip.open(p, "rt", encoding="utf-8", errors="replace"))
                if is_gzipped_file(filepath)
                else (lambda p: open(p, "r", encoding="utf-8", errors="replace"))
            )
            try:
                with opener(filepath) as f:
                    head = f.read(16384)
            except Exception:
                head = ""
        else:
            head = data[:16384]

        m = re.search(r'"(?:kernel_)?commit"\s*:\s*"([0-9a-f]{7,40})"', head)
        if m:
            return m.group(1)
        m = re.search(r"(?:commit/|id=)([0-9a-f]{7,40})", head)
        if m:
            return m.group(1)
    return None


def ensure_commit_in_repo(repo_dir: str, commit: str) -> str:
    """Ensure that the given commit or tag exists in repo_dir, unshallowing if necessary, and return its full SHA."""
    try:
        sha = subprocess.check_output(
            ["git", "-C", repo_dir, "rev-parse", "--verify", f"{commit}^{{commit}}"],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8").strip()
        return sha
    except subprocess.CalledProcessError:
        is_shallow = (
            subprocess.check_output(
                ["git", "-C", repo_dir, "rev-parse", "--is-shallow-repository"]
            )
            .decode("utf-8")
            .strip()
            == "true"
        )
        if is_shallow:
            logging.info(
                "Commit '%s' not found in shallow repo %s; running 'git fetch --unshallow'..."
                % (commit, repo_dir)
            )
            subprocess.run(
                ["git", "-C", repo_dir, "fetch", "--unshallow"], check=True
            )
            sha = subprocess.check_output(
                ["git", "-C", repo_dir, "rev-parse", "--verify", f"{commit}^{{commit}}"]
            ).decode("utf-8").strip()
            return sha
        raise ValueError(
            f"Commit or tag '{commit}' not found in git repository: {repo_dir}"
        )


def parse_git_diff_u0(diff_text: str) -> dict:
    """Parse unified diff output from `git diff -U0 -M` into per-file hunk intervals and rename/delete status."""
    file_changes = {}
    current_old_file = None
    current_new_file = None
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_old_file = None
            current_new_file = None
        elif line.startswith("--- "):
            path = line[4:].strip()
            if path.startswith("a/"):
                current_old_file = path[2:]
            elif path == "/dev/null":
                current_old_file = None
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                current_new_file = path[2:]
            elif path == "/dev/null":
                current_new_file = None
            if current_old_file:
                file_changes[current_old_file] = {
                    "new_file": current_new_file,
                    "hunks": [],
                }
        elif line.startswith("@@ ") and current_old_file:
            m = hunk_re.match(line)
            if m:
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) is not None else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) is not None else 1
                file_changes[current_old_file]["hunks"].append(
                    (old_start, old_count, new_start, new_count)
                )

    return file_changes


def remap_line(hunks: list, old_line: int):
    """Map an old line number to a new line number using sorted -U0 diff hunks, or return None if deleted."""
    cum_delta = 0
    for old_start, old_count, new_start, new_count in hunks:
        if old_count == 0:
            # Pure insertion after old_start
            if old_line <= old_start:
                return old_line + cum_delta
            cum_delta += new_count
        else:
            # Deletion or modification covering [old_start, old_start + old_count)
            if old_line < old_start:
                return old_line + cum_delta
            if old_line < old_start + old_count:
                offset_in_hunk = old_line - old_start
                if offset_in_hunk < new_count:
                    return new_start + offset_in_hunk
                return None
            cum_delta += new_count - old_count
    return old_line + cum_delta


def remap_coverage_data(
    all_path: list,
    all_syzk_cov: list,
    repo_dir: str,
    cov_commit: str,
    target_commit: str = "HEAD",
) -> (list, list):
    """Remap file paths and covered line numbers from cov_commit to target_commit using git diff -U0."""
    if not repo_dir or not os.path.isdir(os.path.join(repo_dir, ".git")):
        raise ValueError(
            f"Valid Git repository (--repo_dir) is required for line remapping: {repo_dir}"
        )

    cov_sha = ensure_commit_in_repo(repo_dir, cov_commit)
    target_sha = ensure_commit_in_repo(repo_dir, target_commit)

    if cov_sha == target_sha:
        logging.info(
            "Syzkaller coverage commit (%s) matches target commit (%s); no line remapping required."
            % (cov_sha[:12], target_sha[:12])
        )
        return all_path, all_syzk_cov

    logging.info(
        "Computing git diff -U0 between coverage commit %s (%s) and target %s (%s)..."
        % (cov_commit, cov_sha[:12], target_commit, target_sha[:12])
    )
    diff_text = subprocess.check_output(
        ["git", "-C", repo_dir, "diff", "-U0", "-M", cov_sha, target_sha]
    ).decode("utf-8", errors="replace")

    file_changes = parse_git_diff_u0(diff_text)
    if not file_changes:
        logging.info("No file differences found between %s and %s." % (cov_sha[:12], target_sha[:12]))
        return all_path, all_syzk_cov

    old_id_to_path = {int(fid): fp for fid, fp in all_path}
    remapped_paths = {}
    deleted_fids = set()

    for fid, fp in old_id_to_path.items():
        if fp in file_changes:
            new_fp = file_changes[fp]["new_file"]
            if new_fp is None:
                deleted_fids.add(fid)
            else:
                remapped_paths[fid] = new_fp
        else:
            remapped_paths[fid] = fp

    # Deduplicate new file paths and assign clean IDs
    unique_new_paths = sorted(set(remapped_paths.values()))
    new_path_to_id = {fp: idx for idx, fp in enumerate(unique_new_paths)}
    old_fid_to_new_fid = {
        fid: new_path_to_id[new_fp] for fid, new_fp in remapped_paths.items()
    }

    remapped_cov_set = set()
    unchanged_count = 0
    shifted_count = 0
    dropped_count = 0

    for fid, line_no, prog_id in all_syzk_cov:
        fid = int(fid)
        if fid in deleted_fids:
            dropped_count += 1
            continue
        fp = old_id_to_path[fid]
        new_fid = old_fid_to_new_fid[fid]
        if fp not in file_changes:
            remapped_cov_set.add((new_fid, int(line_no), int(prog_id)))
            unchanged_count += 1
        else:
            hunks = file_changes[fp]["hunks"]
            new_line = remap_line(hunks, int(line_no))
            if new_line is None or new_line <= 0:
                dropped_count += 1
            else:
                remapped_cov_set.add((new_fid, new_line, int(prog_id)))
                if new_line == int(line_no) and remapped_paths[fid] == fp:
                    unchanged_count += 1
                else:
                    shifted_count += 1

    new_all_path = [(idx, fp) for fp, idx in new_path_to_id.items()]
    logging.info(
        "Line remapping summary (%s -> %s): %d unchanged, %d shifted, %d dropped across %d modified kernel files."
        % (
            cov_sha[:12],
            target_sha[:12],
            unchanged_count,
            shifted_count,
            dropped_count,
            len(file_changes),
        )
    )
    return new_all_path, list(remapped_cov_set)


def create_sql_db(
    db_file: str,
    sources_dict: dict,
    remap_lines: bool = False,
    repo_dir: str = None,
    cov_commit: str = None,
    target_commit: str = "HEAD",
    sources_list: list = None,
) -> None:
    """Create SQLite3 database and populate it with parsed syzkaller coverage tables."""
    all_path, all_syzk_cov, all_prog, all_syscalls = get_all_data(sources_dict)
    if remap_lines:
        if not cov_commit:
            cov_commit = extract_cov_commit(
                sources_list or list(sources_dict.keys()), sources_dict
            )
            if cov_commit:
                logging.info(
                    "Auto-detected Syzkaller coverage commit hash: %s" % cov_commit
                )
            else:
                raise ValueError(
                    "Could not auto-detect Syzkaller coverage commit hash from filename or content; please pass --cov_commit explicitly."
                )
        all_path, all_syzk_cov = remap_coverage_data(
            all_path, all_syzk_cov, repo_dir, cov_commit, target_commit
        )
    with closing(sqlite3.connect(db_file)) as conn:
        conn.execute("PRAGMA synchronous = OFF;")
        conn.execute("PRAGMA journal_mode = MEMORY;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        # Process path
        with conn as con:
            con.execute("DROP TABLE IF EXISTS file_path;")
            logging.info("Creating kernel file path table in syzkaller DB")
            con.execute(
                "CREATE TABLE file_path (file_id UNSIGNED BIG INT PRIMARY KEY NOT NULL, file_path TEXT NOT NULL);"
            )
            logging.info(
                "Inserting (file_id, file_path) data into Sqlite DB (file_path table). Number of lines: %d"
                % len(all_path)
            )
            con.executemany("INSERT INTO file_path VALUES(?, ?);", all_path)
        # Process syzk_cov
        with conn as con:
            con.execute("DROP TABLE IF EXISTS syzk_cov;")
            logging.info("Creating syzk_cov table in syzkaller DB")
            con.execute(
                "CREATE TABLE syzk_cov (file_id UNSIGNED BIG INT NOT NULL, code_line_no UNSIGNED BIG INT NOT NULL, prog_id UNSIGNED BIG INT NOT NULL, PRIMARY KEY (file_id, code_line_no, prog_id));"
            )
            logging.info(
                "Inserting (file_id, code_line_no, prog_id) data into Sqlite DB (syzk_cov table). Number of lines: %d"
                % len(all_syzk_cov)
            )
            con.executemany(
                "INSERT INTO syzk_cov VALUES(?, ?, ?);",
                all_syzk_cov,
            )
        # Process prog
        with conn as con:
            con.execute("DROP TABLE IF EXISTS syzk_prog;")
            logging.info("Creating prog table in syzkaller DB")
            con.execute(
                "CREATE TABLE syzk_prog (prog_id UNSIGNED BIG INT PRIMARY KEY NOT NULL, prog_code TEXT NOT NULL);"
            )
            logging.info(
                "Inserting (prog_id, prog_code) data into Sqlite DB (syzk_prog table). Number of lines: %d"
                % len(all_prog)
            )
            con.executemany("INSERT INTO syzk_prog VALUES(?, ?);", all_prog)
        # Process syzk_sys and syscalls
        with conn as con:
            con.execute("DROP TABLE IF EXISTS syzk_sys;")
            con.execute("DROP TABLE IF EXISTS syscalls;")
            logging.info("Creating syzk_sys and syscalls tables in syzkaller DB")
            con.execute(
                "CREATE TABLE syzk_sys (prog_id UNSIGNED BIG INT NOT NULL, syscall TEXT NOT NULL);"
            )
            con.execute(
                "CREATE TABLE syscalls (prog_id UNSIGNED BIG INT NOT NULL, syscall TEXT NOT NULL);"
            )
            logging.info(
                "Inserting (prog_id, syscall) data into Sqlite DB (syzk_sys and syscalls tables). Number of lines: %d"
                % len(all_syscalls)
            )
            con.executemany("INSERT INTO syzk_sys VALUES(?, ?);", all_syscalls)
            con.executemany("INSERT INTO syscalls VALUES(?, ?);", all_syscalls)


def main():
    """Parse CLI arguments and execute the syzkaller coverage parsing workflow."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
    parser = argparse.ArgumentParser(
        description="Parse syzkaller HTML or JSON/JSONL coverage reports from local files or URLs into a SQLite3 DB."
    )
    parser.add_argument(
        "sk_cov_url_or_file",
        help="Syzkaller Coverage URL (e.g. https://storage.googleapis.com/syzbot-assets/0422343bda5a/ci2-linux-6-1-kasan-aa4cd140.html) or path to a local HTML or JSON/JSONL coverage file.",
        type=sk_cov_url_or_file,
        nargs="+",
    )
    parser.add_argument(
        "--save_file",
        dest="save_file",
        nargs="?",
        help="Path where to save raw downloaded syzkaller coverage file(s).",
        type=can_create_file,
        default=None,
    )
    parser.add_argument(
        "--db_file",
        nargs="?",
        help="Path where to store resulting Sqlite3 DB file.",
        type=can_create_file,
        default="syzkaller.db",
    )
    parser.add_argument(
        "--remap_lines",
        action="store_true",
        help="Remap coverage line numbers from coverage commit to target commit using git diff -U0.",
    )
    parser.add_argument(
        "--repo_dir",
        type=str,
        default=None,
        help="Path to local Linux kernel Git repository (required when --remap_lines is enabled).",
    )
    parser.add_argument(
        "--cov_commit",
        type=str,
        default=None,
        help="Git commit hash or tag of the Syzkaller coverage report (auto-detected from filename/content if omitted).",
    )
    parser.add_argument(
        "--target_commit",
        type=str,
        default="HEAD",
        help="Target Git commit hash or tag in --repo_dir to remap line numbers to (default: HEAD).",
    )
    args = parser.parse_args()
    if args.remap_lines and not args.repo_dir:
        parser.error("--repo_dir is required when --remap_lines is enabled.")

    sources_dict = get_sk_cov_data(args.save_file, args.sk_cov_url_or_file)
    if args.save_file and any(
        not os.path.isfile(src) for src in args.sk_cov_url_or_file
    ):
        print("Coverage data saved in: %s" % args.save_file)
    create_sql_db(
        args.db_file,
        sources_dict,
        remap_lines=args.remap_lines,
        repo_dir=args.repo_dir,
        cov_commit=args.cov_commit,
        target_commit=args.target_commit,
        sources_list=args.sk_cov_url_or_file,
    )


if __name__ == "__main__":
    main()
