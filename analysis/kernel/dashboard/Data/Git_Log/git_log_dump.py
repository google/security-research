#!/usr/bin/env python3
"""Dumps Git blame and commit metadata into an SQLite database for CodeQL functions."""

import argparse
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from urllib.parse import urlparse
import git
from tqdm import tqdm

GIT = "/usr/bin/git"
PARALLEL = "/usr/bin/parallel"


class CloneProgress(git.RemoteProgress):
    """Progress bar callback for Git clone operations."""

    def update(self, op_code, cur_count, max_count=None, message=""):
        """Updates the tqdm progress bar for Git operations."""
        pbar = tqdm(total=max_count)
        pbar.update(cur_count)


def repo_url(repo_url: str) -> str:
    """Validates that repo_url is a valid URL with scheme and domain."""
    logging.info("Validating URL provided")
    result = urlparse(repo_url)
    if result.scheme and result.netloc:
        return repo_url
    else:
        logging.critical("Wrong URL provided: %s" % repo_url)
        raise ValueError


def can_read_dir(dirname: str) -> str:
    """Validates that a path is an existing readable directory."""
    if os.path.isdir(dirname) and os.access(dirname, os.R_OK):
        return dirname
    logging.critical("Directory not found or unreadable: %s" % dirname)
    raise ValueError


def can_create_file(filename: str) -> str:
    """Validates that a file path can be created in its target directory."""
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()

    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)

    logging.critical("Wrong path provided: %s" % filename)
    raise ValueError


def can_read_file(filename: str) -> str:
    """Validates that a file path exists and is readable."""
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        return filename

    logging.critical("Can't read file: %s" % filename)
    raise ValueError


def setup_git_log_schema(con: sqlite3.Connection) -> None:
    """Sets up the git_log table schema in SQLite database."""
    con.execute("PRAGMA journal_mode = OFF;")
    con.execute("PRAGMA synchronous = OFF;")
    con.execute("DROP TABLE IF EXISTS git_log;")
    con.execute(
        """CREATE TABLE git_log (
                start_line UNSIGNED BIG INT NOT NULL,
                end_line UNSIGNED BIG INT NOT NULL,
                file_path TEXT NOT NULL,
                author_date UNSIGNED BIG INT NOT NULL,
                `commit` VARCHAR(40) NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (file_path, start_line, end_line)
            );"""
    )
    logging.info("Git Log table created in DB.")


def filter_tracked_locations(
    repo_folder: str, function_locations: list, force: bool
) -> list:
    """Filters function locations to those tracked in git and checks for mismatches."""
    res = subprocess.run(
        [GIT, "-C", repo_folder, "ls-files"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    tracked_files = (
        set(res.stdout.splitlines())
        if (res.returncode == 0 and res.stdout)
        else set()
    )

    valid_locations = (
        [loc for loc in function_locations if loc[1] in tracked_files]
        if tracked_files
        else function_locations
    )

    total_count = len(function_locations)
    matched_count = len(valid_locations)
    match_percentage = (matched_count / total_count * 100) if total_count > 0 else 0.0

    logging.info(
        "Functions in CodeQL DB: %d, Functions matched in Git repository: %d (%.2f%%)"
        % (total_count, matched_count, match_percentage)
    )

    if matched_count < total_count and not force:
        unmatched_count = total_count - matched_count
        logging.warning(
            "CodeQL database may have been generated against a different commit! "
            "%d functions could not be found in the repository." % unmatched_count
        )
        if sys.stdin.isatty():
            ans = input("Do you want to continue anyway? [y/N]: ").strip().lower()
            if ans not in ("y", "yes"):
                logging.error("Aborting due to repository commit mismatch.")
                sys.exit(1)
        elif match_percentage < 95.0:
            logging.error(
                "Match percentage (%.2f%%) is below 95%% and --force was not specified. Aborting."
                % match_percentage
            )
            sys.exit(1)

    return valid_locations


def run_parallel_git_log(
    repo_folder: str, function_locations: list, no_cpu: int
) -> list[str]:
    """Runs parallel git log for function locations and returns output lines."""
    tmp = tempfile.NamedTemporaryFile()
    with tempfile.NamedTemporaryFile(delete_on_close=False) as tmp2:
        for loc in function_locations:
            tmp2.write(("%d,%d:%s\n" % (loc[2], loc[3], loc[1])).encode("utf-8"))
        tmp2.close()

        cmd = [
            PARALLEL,
            "--workdir",
            repo_folder,
            "--group",
            "-P",
            str(no_cpu),
            "-a",
            tmp2.name,
            "--",
            GIT,
            "--no-pager",
            "log",
            "-n",
            "1",
            "--format={},%at,%H",
            "--no-patch",
            "-L",
            "{}",
        ]

        logging.info("Command that we're running: %s" % " ".join(cmd))
        with open(tmp.name, "w", encoding="utf-8") as out_f:
            res = subprocess.run(cmd, stdout=out_f, check=False)
            if res.returncode != 0:
                logging.warning(
                    "GNU parallel completed with exit status %d (%d sub-jobs failed)."
                    % (res.returncode, res.returncode)
                )
        logging.info("Command execution complete!")

    with open(tmp.name, "r", encoding="utf-8", errors="ignore") as f:
        log_data = f.readlines()

    logging.info("TMP file contained: %d lines" % len(log_data))

    if not log_data:
        logging.critical("Log data is missing. Something wrong with command execution!")
        raise ValueError

    return log_data


def parse_git_log_records(repo_folder: str, log_data: list[str]) -> list:
    """Parses raw git log output lines into database row tuples."""
    data = []
    file_cache = {}

    for log_entry in log_data:
        chunks = log_entry.replace(":", ",").split(",")
        if len(chunks) < 5:
            logging.critical("Can't get log entry parsed: %s" % log_entry)
            raise ValueError

        start_line = int(chunks[0].strip())
        end_line = int(chunks[1].strip())
        file_path = chunks[2].strip()
        author_date = int(chunks[3].strip())
        commit = chunks[4].strip()

        if file_path not in file_cache:
            full_path = os.path.join(repo_folder, file_path)
            if os.path.isfile(full_path):
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_cache[file_path] = f.readlines()
            else:
                file_cache[file_path] = []

        file_lines = file_cache[file_path]
        function_code = "".join(file_lines[start_line - 1 : end_line])

        data.append(
            (start_line, end_line, file_path, author_date, commit, function_code)
        )

    logging.info("Git data processing for specified commit is complete")

    if not data:
        logging.critical(
            "Looks SUS no commit information has been dumped from GIT repository!"
        )
        raise ValueError

    return data


def create_log_table(
    repo: git.repo.base.Repo,
    no_cpu: int,
    con: sqlite3.Connection,
    function_locations: list,
    force: bool = False,
) -> int:
    """Executes parallel git log for function locations and populates the git_log table."""
    setup_git_log_schema(con)
    repo_folder = repo.git.rev_parse("--show-toplevel")

    valid_locations = filter_tracked_locations(repo_folder, function_locations, force)
    log_data = run_parallel_git_log(repo_folder, valid_locations, no_cpu)
    records = parse_git_log_records(repo_folder, log_data)

    con.executemany(
        """INSERT OR IGNORE INTO git_log VALUES(?, ?, ?, ?, ?, ?)""",
        records,
    )
    return len(records)


def create_sql_db(
    db_file: str, codeql_db: str, no_cpu: int, repo: git.repo.base.Repo, force: bool = False
) -> None:
    """Reads function locations from CodeQL database and creates the git_log table."""
    function_locations = []
    with closing(sqlite3.connect(codeql_db)) as conn:
        with conn as con:
            res = con.execute(
                "SELECT function_name, file_path, start_line, end_line from function_locations;"
            )
            function_locations = res.fetchall()

    if not function_locations:
        logging.critical(
            "Looks SUS no function location data obtained from CodeQL DB!"
        )
        raise ValueError

    logging.info(
        "The number of functions obtained from CodeQL DB: %d"
        % len(function_locations)
    )

    with closing(sqlite3.connect(db_file)) as conn:
        with conn as con:
            res = create_log_table(repo, no_cpu, con, function_locations, force=force)
            print(
                "GIT Log data saved into SQLite DB. Number of lines: %d" % res
            )


def check_tools() -> None:
    """Checks that git and parallel tools are installed and available."""
    subprocess.run(
        [GIT, "--version"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    subprocess.run(
        [PARALLEL, "--version"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def setup_repository(
    repo_url_val: str | None, repo_dir_val: str | None, commit: str | None
) -> git.repo.base.Repo:
    """Sets up local or remote Git repository and checks out target commit if specified."""
    if repo_dir_val:
        logging.info("Using local Linux repository folder: %s" % repo_dir_val)
        repo = git.Repo(repo_dir_val)
        if commit:
            logging.info("Making hard reset to commit: %s" % commit)
            repo.git.reset("--hard", commit)
        else:
            logging.info(
                "Skipping reset and using current repository commit: %s"
                % repo.head.commit.hexsha
            )
        return repo

    if not os.path.exists("linux"):
        logging.info(
            "Cloning the Git repo as linux folder is empty: %s" % repo_url_val
        )
        repo = git.Repo.clone_from(
            repo_url_val, "linux", branch="master", progress=CloneProgress()
        )
    else:
        logging.info("Reusing source code in Linux folder")
        repo = git.Repo("linux")
        repo.git.reset("--hard", "origin")
        repo.remotes.origin.pull()

    logging.info("Making hard reset to commit: %s" % commit)
    repo.git.reset("--hard", commit)
    return repo


def main():
    """Parses command-line arguments and runs Git log dump into SQLite DB."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    parser = argparse.ArgumentParser(
        description="Dump Git log information into SQLite database."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--repo_url",
        help="Linux Kernel Repository URL.",
        type=repo_url,
    )
    group.add_argument(
        "--repo_dir",
        help="Path to local Linux Kernel Repository directory.",
        type=can_read_dir,
    )

    parser.add_argument(
        "--codeql_db",
        help="CodeQL DB file that contains function data.",
        type=can_read_file,
        required=True,
    )
    parser.add_argument(
        "--commit",
        help="Commit hash or branch to hard reset to (required with --repo_url, optional with --repo_dir).",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--db_file",
        nargs="?",
        help="Path where to store Sqlite3 DB with Git Blame data.",
        type=can_create_file,
        default="git_log.db",
    )
    default_cpu_count = os.cpu_count() or 4
    parser.add_argument(
        "--no_cpu",
        nargs="?",
        help="No of CPU to use for Git Log data parsing (default: all available cores).",
        type=int,
        default=default_cpu_count,
    )
    parser.add_argument(
        "--force",
        "-f",
        help="Force execution even if CodeQL DB function count mismatches repository.",
        action="store_true",
    )
    args = parser.parse_args()

    if args.repo_url and not args.commit:
        parser.error("--commit is required when using --repo_url")

    check_tools()
    repo = setup_repository(args.repo_url, args.repo_dir, args.commit)
    create_sql_db(args.db_file, args.codeql_db, args.no_cpu, repo, force=args.force)


if __name__ == "__main__":
    main()
