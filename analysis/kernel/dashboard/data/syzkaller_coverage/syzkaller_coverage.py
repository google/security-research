#!/usr/bin/python3
# pylint: disable=duplicate-code,c-extension-no-member
"""Syzkaller Coverage Parser.

Parses Syzkaller code coverage reports (in HTML or JSON/JSONL format, including
gzip-compressed files and URLs) and exports the coverage data into a structured
SQLite3 database containing kernel file paths, covered line numbers, syzkaller
programs, and executed syscalls.
"""

import argparse
from contextlib import closing
import gzip
import html
from io import StringIO
import json
import logging
import os
import re
import sqlite3
import subprocess
from urllib.parse import urlparse
from urllib.request import urlopen

from lxml import etree


def sk_cov_url_or_file(source: str) -> str:
    """Validates that the input is a readable local file or syzkaller URL."""
    logging.info("Validating URL or file provided: %s", source)
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
    is_syz_domain = any(
        kw in (result.path + result.netloc) for kw in ("syzbot", "syzkaller")
    )
    if result.scheme and result.netloc and is_syz_domain:
        return source
    logging.critical(
        "File not found or unreadable, and not a valid syzbot/syzkaller URL: %s",
        source,
    )
    raise ValueError


def can_create_file(filename: str) -> str:
    """Validates that the target file path can be created in a writable dir."""
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()
    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)
    logging.critical("Wrong path provided: %s", filename)
    raise ValueError


def is_gzipped(data: bytes) -> bool:
    """Checks if byte payload starts with standard gzip magic bytes."""
    return len(data) >= 2 and data[:2] == b"\x1f\x8b"


def is_gzipped_file(filepath: str) -> bool:
    """Checks if a local file starts with standard gzip magic bytes."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(2)
        return is_gzipped(magic)
    except OSError:
        return False


def _read_file_head(filepath: str, size: int = 16384) -> str:
    """Reads up to size characters from a plain or gzip-compressed file."""
    try:
        if is_gzipped_file(filepath):
            with gzip.open(
                filepath, "rt", encoding="utf-8", errors="replace"
            ) as f:
                return f.read(size)
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.read(size)
    except OSError:
        return ""


def is_json_source(source: str, text_data: str) -> bool:
    """Checks if a source is JSON or JSONL based on extension or prefix."""
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


def _stream_json_handle(f):
    """Yields JSON records from an open file-like object."""
    first_chunk = ""
    for line in f:
        stripped = line.strip()
        if not stripped:
            continue
        if not first_chunk:
            first_chunk = stripped
            if first_chunk.startswith("["):
                f.seek(0)
                yield from json.load(f)
                return
        yield json.loads(stripped)


def _iter_json_records(data_str: str):
    """Yields JSON records from a string or a streamed local file marker."""
    if data_str.startswith("__STREAM_FILE__:"):
        filepath = data_str[len("__STREAM_FILE__:") :]
        if is_gzipped_file(filepath):
            with gzip.open(
                filepath, "rt", encoding="utf-8", errors="replace"
            ) as f:
                yield from _stream_json_handle(f)
        else:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                yield from _stream_json_handle(f)
    else:
        stripped = data_str.lstrip()
        if stripped.startswith("["):
            yield from json.loads(data_str)
        else:
            for line in data_str.splitlines():
                if line.strip():
                    yield json.loads(line)


def _extract_cov_lines_from_item(cov_item: dict) -> list[int]:
    """Extracts covered line numbers from a coverage item's function blocks."""
    lines = []
    for func in cov_item.get("functions", []):
        for block in func.get("blocks", []):
            from_line = block.get("from_line", 0)
            to_line = block.get("to_line", from_line)
            if from_line > 0:
                lines.extend(range(from_line, to_line + 1))
    return lines


def get_json_data(data_str: str) -> tuple[list, list, list]:
    """Parses JSON/JSONL coverage report data into path, cov, and prog lists."""
    path_dict = {}
    prog_list = []
    cov_set = set()
    for prog_id, record in enumerate(_iter_json_records(data_str)):
        prog_code = record.get("program", "").strip()
        if not prog_code:
            continue
        prog_list.append((prog_id, prog_code))
        for cov_item in record.get("coverage", []):
            file_path = cov_item.get("file_path", "").strip()
            if not file_path:
                continue
            file_id = path_dict.setdefault(file_path, len(path_dict))
            for line_no in _extract_cov_lines_from_item(cov_item):
                cov_set.add((file_id, line_no, prog_id))
    path_list = [
        (file_id, file_path) for file_path, file_id in path_dict.items()
    ]
    return path_list, list(cov_set), prog_list


def get_sk_cov_data(save_file: str, sk_cov_sources: list) -> dict:
    """Fetches coverage report content from local files or URLs."""
    out = {}
    file_idx = 0
    for source in sk_cov_sources:
        is_url = False
        if os.path.isfile(source):
            if save_file:
                logging.warning(
                    "Ignoring --save_file option for local file source: %s",
                    source,
                )
            if is_json_source(source, ""):
                logging.info(
                    "Streaming local JSON/JSONL file %s without loading RAM",
                    source,
                )
                out[source] = f"__STREAM_FILE__:{source}"
                continue
            logging.info("Getting data from local file %s", source)
            with open(source, mode="rb") as file:
                data = file.read()
        else:
            logging.info("Getting data from URL %s", source)
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
    """Extracts syzkaller program IDs and code from an HTML coverage report."""
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
    """Extracts unique (prog_id, syscall) pairs from syzkaller programs."""
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
    logging.info(
        "Total number of unique (prog_id, syscall) pairs: %d", len(data)
    )
    return data


def get_html_syzk_cov(html_data: str) -> list:
    """Extracts covered file IDs, line numbers, and reaching program IDs."""
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
                logging.debug("%s,%s,%s", file_id, code_line_no, prog_id * 1)
    if not data:
        logging.critical('No class="file" id="contents has been found')
        raise ValueError
    return data


def get_html_path(html_data: str) -> list:
    """Extracts file IDs and kernel file paths from an HTML coverage report."""
    html_parser = etree.HTMLParser()
    tree = etree.parse(StringIO(html_data), html_parser)
    a_tag_list = tree.xpath(
        './/a[@id and @href and contains(@onclick,"onFileClick")]'
    )
    if not a_tag_list:
        logging.critical("No <a> tags with href, id, onclick attributes")
        raise ValueError
    logging.info(
        "Found some <a> tags to process. Number of lines: %d", len(a_tag_list)
    )
    data = []
    for tag in a_tag_list:
        file_id = re.search(r"\(\s*(\d*)\s*\)", tag.get("onclick")).group(1)
        if not file_id:
            logging.critical(
                "OOOPS! Something has changed in syzkaller HTML! "
                "Can't parse onclick attribute data"
            )
            raise ValueError
        if not tag.get("id").startswith("path/"):
            logging.critical(
                "OOOPS! Something has changed in syzkaller HTML! "
                "Can't parse id attribute data"
            )
            raise ValueError
        file_path = tag.get("id")[5:]
        logging.debug("%s,%s", file_id, file_path)
        data.append((file_id, file_path))
    logging.info(
        "Amount of data entries extracted from tags and cleaned. "
        "Number of lines: %d",
        len(data),
    )
    seen = set()
    uniq_data = [
        (file_id, file_path.strip())
        for file_id, file_path in data
        if file_id not in seen and not seen.add(file_id)
    ]
    return uniq_data


def get_all_data(sources_dict: dict) -> tuple[list, list, list, list]:
    """Parses and merges coverage data across all input sources."""
    if not sources_dict:
        return {}, {}, {}, []
    all_path = {}
    all_syzk_cov = {}
    all_prog = {}
    for name, data in sources_dict.items():
        if is_json_source(name, data):
            logging.info("Parsing JSON/JSONL coverage data from %s", name)
            path_data, cov_data, prog_data = get_json_data(data)
            all_path[name] = path_data
            all_syzk_cov[name] = cov_data
            all_prog[name] = prog_data
            logging.info("Amount of path data: %d", len(all_path[name]))
            logging.info("Amount of syz_cov data: %d", len(all_syzk_cov[name]))
            logging.info("Amount of programs data: %d", len(all_prog[name]))
        else:
            all_path[name] = get_html_path(data)
            print(f"Path data obtained from file: {name}")
            logging.info("Amount of path data: %d", len(all_path[name]))
            all_syzk_cov[name] = get_html_syzk_cov(data)
            print(f"Syzk_cov data obtained from {name}")
            logging.info("Amount of syz_cov data: %d", len(all_syzk_cov[name]))
            all_prog[name] = get_html_prog(data)
            print(f"Prog data obtained from: {name}")
            logging.info("Amount of programs data: %d", len(all_prog[name]))
    merged_path, merged_cov, merged_prog = merge_dicts(
        all_path, all_syzk_cov, all_prog
    )
    all_syscalls = get_syscalls(merged_prog)
    return (merged_path, merged_cov, merged_prog, all_syscalls)


def merge_dicts(
    all_path: dict, all_syzk_cov: dict, all_prog: dict
) -> tuple[list, list, list]:
    """Merges and deduplicates path, coverage, and program dicts."""
    if (len(all_path) != len(all_syzk_cov)) or (len(all_path) != len(all_prog)):
        logging.critical(
            "OOOPS! Input dicts have different size. This is toally wrong!"
        )
        raise ValueError
    unique_file_path = {fp for items in all_path.values() for _, fp in items}
    unique_prog_code = {pc for items in all_prog.values() for _, pc in items}
    file_path_to_id = {
        fp: idx for idx, fp in enumerate(sorted(unique_file_path))
    }
    prog_code_to_id = {
        pc: idx for idx, pc in enumerate(sorted(unique_prog_code))
    }
    agreg_syzk_cov_set = set()
    for name, cov_entries in all_syzk_cov.items():
        f_map = {
            int(old_id): file_path_to_id[fp] for old_id, fp in all_path[name]
        }
        p_map = {
            int(old_id): prog_code_to_id[pc] for old_id, pc in all_prog[name]
        }
        for f_id, code_line_no, p_id in cov_entries:
            agreg_syzk_cov_set.add(
                (f_map[int(f_id)], int(code_line_no), p_map[int(p_id)])
            )
    return (
        [(idx, fp) for fp, idx in file_path_to_id.items()],
        list(agreg_syzk_cov_set),
        [(idx, pc) for pc, idx in prog_code_to_id.items()],
    )


def extract_cov_commit(sources: list, sources_dict: dict) -> str:
    """Attempts to auto-detect the Syzkaller coverage commit hash."""
    for src in sources:
        base = os.path.basename(src)
        m = re.search(
            r"[-_]([0-9a-f]{7,40})\.(?:html|json|jsonl)(?:\.gz)?$",
            base,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)

    for _, data in sources_dict.items():
        if data.startswith("__STREAM_FILE__:"):
            head = _read_file_head(data[len("__STREAM_FILE__:") :])
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
    """Ensures that the given commit or tag exists in repo_dir."""
    try:
        sha = (
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    repo_dir,
                    "rev-parse",
                    "--verify",
                    f"{commit}^{{commit}}",
                ],
                stderr=subprocess.DEVNULL,
            )
            .decode("utf-8")
            .strip()
        )
        return sha
    except subprocess.CalledProcessError as exc:
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
                "Commit '%s' not found in shallow repo %s; "
                "running 'git fetch --unshallow'...",
                commit,
                repo_dir,
            )
            subprocess.run(
                ["git", "-C", repo_dir, "fetch", "--unshallow"], check=True
            )
            sha = (
                subprocess.check_output(
                    [
                        "git",
                        "-C",
                        repo_dir,
                        "rev-parse",
                        "--verify",
                        f"{commit}^{{commit}}",
                    ]
                )
                .decode("utf-8")
                .strip()
            )
            return sha
        raise ValueError(
            f"Commit or tag '{commit}' not found in git repository: {repo_dir}"
        ) from exc


def parse_git_diff_u0(diff_text: str) -> dict:
    """Parses unified diff output from `git diff -U0 -M` into per-file hunks."""
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
    """Maps an old line number to a new line number using sorted -U0 hunks."""
    cum_delta = 0
    for old_start, old_count, new_start, new_count in hunks:
        if old_count == 0:
            if old_line <= old_start:
                return old_line + cum_delta
            cum_delta += new_count
        else:
            if old_line < old_start:
                return old_line + cum_delta
            if old_line < old_start + old_count:
                offset_in_hunk = old_line - old_start
                if offset_in_hunk < new_count:
                    return new_start + offset_in_hunk
                return None
            cum_delta += new_count - old_count
    return old_line + cum_delta


def _build_remapped_file_maps(all_path: list, file_changes: dict) -> dict:
    """Builds file path and ID lookup tables after applying file renames."""
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

    new_path_to_id = {
        fp: idx for idx, fp in enumerate(sorted(set(remapped_paths.values())))
    }
    return {
        "old_to_path": old_id_to_path,
        "remapped": remapped_paths,
        "new_path_to_id": new_path_to_id,
        "old_to_new": {
            fid: new_path_to_id[nfp] for fid, nfp in remapped_paths.items()
        },
        "deleted": deleted_fids,
    }


def _apply_file_and_line_remapping(
    all_path: list, all_syzk_cov: list, file_changes: dict
) -> tuple[list, list, list]:
    """Applies parsed git diff file/line changes to path and coverage lists."""
    maps = _build_remapped_file_maps(all_path, file_changes)
    remapped_cov_set = set()
    counts = [0, 0, 0]  # unchanged, shifted, dropped

    for fid, line_no, prog_id in all_syzk_cov:
        fid = int(fid)
        if fid in maps["deleted"]:
            counts[2] += 1
            continue
        fp = maps["old_to_path"][fid]
        new_fid = maps["old_to_new"][fid]
        if fp not in file_changes:
            remapped_cov_set.add((new_fid, int(line_no), int(prog_id)))
            counts[0] += 1
        else:
            new_line = remap_line(file_changes[fp]["hunks"], int(line_no))
            if new_line is None or new_line <= 0:
                counts[2] += 1
            else:
                remapped_cov_set.add((new_fid, new_line, int(prog_id)))
                idx = (
                    0
                    if (
                        new_line == int(line_no)
                        and maps["remapped"][fid] == fp
                    )
                    else 1
                )
                counts[idx] += 1

    new_all_path = [
        (idx, fp) for fp, idx in maps["new_path_to_id"].items()
    ]
    return new_all_path, list(remapped_cov_set), counts


def remap_coverage_data(
    all_path: list,
    all_syzk_cov: list,
    repo_dir: str,
    cov_commit: str,
    target_commit: str = "HEAD",
) -> tuple[list, list]:
    """Remaps file paths and covered lines from cov_commit to target_commit."""
    if not repo_dir or not os.path.isdir(os.path.join(repo_dir, ".git")):
        raise ValueError(
            f"Valid Git repository (--repo_dir) is required: {repo_dir}"
        )

    cov_sha = ensure_commit_in_repo(repo_dir, cov_commit)
    target_sha = ensure_commit_in_repo(repo_dir, target_commit)

    if cov_sha == target_sha:
        logging.info(
            "Syzkaller coverage commit (%s) matches target (%s); no remapping.",
            cov_sha[:12],
            target_sha[:12],
        )
        return all_path, all_syzk_cov

    logging.info(
        "Computing git diff -U0 between %s (%s) and target %s (%s)...",
        cov_commit,
        cov_sha[:12],
        target_commit,
        target_sha[:12],
    )
    file_changes = parse_git_diff_u0(
        subprocess.check_output(
            ["git", "-C", repo_dir, "diff", "-U0", "-M", cov_sha, target_sha]
        ).decode("utf-8", errors="replace")
    )
    if not file_changes:
        logging.info(
            "No file differences found between %s and %s.",
            cov_sha[:12],
            target_sha[:12],
        )
        return all_path, all_syzk_cov

    new_all_path, new_cov, counts = _apply_file_and_line_remapping(
        all_path, all_syzk_cov, file_changes
    )
    logging.info(
        "Line remapping summary (%s -> %s): %d unchanged, %d shifted, "
        "%d dropped across %d modified kernel files.",
        cov_sha[:12],
        target_sha[:12],
        counts[0],
        counts[1],
        counts[2],
        len(file_changes),
    )
    return new_all_path, new_cov


# pylint: disable=too-many-arguments,too-many-positional-arguments
def create_sql_db(
    db_file: str,
    sources_dict: dict,
    remap_lines: bool = False,
    repo_dir: str = None,
    cov_commit: str = None,
    target_commit: str = "HEAD",
    sources_list: list = None,
) -> None:
    """Creates SQLite3 database and populates syzkaller coverage tables."""
    all_path, all_syzk_cov, all_prog, all_syscalls = get_all_data(sources_dict)
    if remap_lines:
        if not cov_commit:
            cov_commit = extract_cov_commit(
                sources_list or list(sources_dict.keys()), sources_dict
            )
            if cov_commit:
                logging.info(
                    "Auto-detected Syzkaller coverage commit hash: %s",
                    cov_commit,
                )
            else:
                raise ValueError(
                    "Could not auto-detect Syzkaller coverage commit hash; "
                    "please pass --cov_commit explicitly."
                )
        all_path, all_syzk_cov = remap_coverage_data(
            all_path, all_syzk_cov, repo_dir, cov_commit, target_commit
        )
    with closing(sqlite3.connect(db_file)) as conn:
        conn.execute("PRAGMA synchronous = OFF;")
        conn.execute("PRAGMA journal_mode = MEMORY;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        with conn as con:
            con.execute("DROP TABLE IF EXISTS file_path;")
            logging.info("Creating kernel file path table in syzkaller DB")
            con.execute(
                "CREATE TABLE file_path ("
                "file_id UNSIGNED BIG INT PRIMARY KEY NOT NULL, "
                "file_path TEXT NOT NULL);"
            )
            logging.info(
                "Inserting (file_id, file_path) into file_path. Lines: %d",
                len(all_path),
            )
            con.executemany("INSERT INTO file_path VALUES(?, ?);", all_path)
        with conn as con:
            con.execute("DROP TABLE IF EXISTS syzk_cov;")
            logging.info("Creating syzk_cov table in syzkaller DB")
            con.execute(
                "CREATE TABLE syzk_cov ("
                "file_id UNSIGNED BIG INT NOT NULL, "
                "code_line_no UNSIGNED BIG INT NOT NULL, "
                "prog_id UNSIGNED BIG INT NOT NULL, "
                "PRIMARY KEY (file_id, code_line_no, prog_id));"
            )
            logging.info(
                "Inserting coverage into syzk_cov. Number of lines: %d",
                len(all_syzk_cov),
            )
            con.executemany(
                "INSERT INTO syzk_cov VALUES(?, ?, ?);",
                all_syzk_cov,
            )
        with conn as con:
            con.execute("DROP TABLE IF EXISTS syzk_prog;")
            logging.info("Creating prog table in syzkaller DB")
            con.execute(
                "CREATE TABLE syzk_prog ("
                "prog_id UNSIGNED BIG INT PRIMARY KEY NOT NULL, "
                "prog_code TEXT NOT NULL);"
            )
            logging.info(
                "Inserting programs into syzk_prog. Number of lines: %d",
                len(all_prog),
            )
            con.executemany("INSERT INTO syzk_prog VALUES(?, ?);", all_prog)
        with conn as con:
            con.execute("DROP TABLE IF EXISTS syzk_sys;")
            con.execute("DROP TABLE IF EXISTS syscalls;")
            logging.info("Creating syzk_sys and syscalls tables in DB")
            con.execute(
                "CREATE TABLE syzk_sys ("
                "prog_id UNSIGNED BIG INT NOT NULL, syscall TEXT NOT NULL);"
            )
            con.execute(
                "CREATE TABLE syscalls ("
                "prog_id UNSIGNED BIG INT NOT NULL, syscall TEXT NOT NULL);"
            )
            logging.info(
                "Inserting syscalls into syzk_sys and syscalls. Lines: %d",
                len(all_syscalls),
            )
            con.executemany(
                "INSERT INTO syzk_sys VALUES(?, ?);", all_syscalls
            )
            con.executemany(
                "INSERT INTO syscalls VALUES(?, ?);", all_syscalls
            )
# pylint: enable=too-many-arguments,too-many-positional-arguments


def main():
    """Parses CLI arguments and executes syzkaller coverage workflow."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
    parser = argparse.ArgumentParser(
        description="Parse syzkaller HTML/JSON/JSONL coverage into SQLite3 DB."
    )
    parser.add_argument(
        "sk_cov_url_or_file",
        help="Syzkaller Coverage URL or path to a local coverage file.",
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
        help="Remap coverage line numbers using git diff -U0.",
    )
    parser.add_argument(
        "--repo_dir",
        type=str,
        default=None,
        help="Path to local Linux kernel Git repository.",
    )
    parser.add_argument(
        "--cov_commit",
        type=str,
        default=None,
        help="Git commit hash or tag of the Syzkaller coverage report.",
    )
    parser.add_argument(
        "--target_commit",
        type=str,
        default="HEAD",
        help="Target Git commit hash or tag in --repo_dir (default: HEAD).",
    )
    args = parser.parse_args()
    if args.remap_lines and not args.repo_dir:
        parser.error("--repo_dir is required when --remap_lines is enabled.")

    sources_dict = get_sk_cov_data(args.save_file, args.sk_cov_url_or_file)
    if args.save_file and any(
        not os.path.isfile(src) for src in args.sk_cov_url_or_file
    ):
        print(f"Coverage data saved in: {args.save_file}")
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
