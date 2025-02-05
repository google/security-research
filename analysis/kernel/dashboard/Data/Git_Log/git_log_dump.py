#!/usr/bin/python

import logging
import sqlite3
import argparse
import subprocess
import os
import git
import tempfile

from urllib.request import urlopen
from urllib.parse import urlparse
from urllib.parse import urlsplit
from contextlib import closing
from tqdm import tqdm


GIT = "/usr/bin/git"
PARALLEL = "/usr/bin/parallel"


class CloneProgress(git.RemoteProgress):
    def update(self, op_code, cur_count, max_count=None, message=""):
        pbar = tqdm(total=max_count)
        pbar.update(cur_count)


def repo_url(repo_url: str) -> str:
    logging.info("Validating URL provided")
    result = urlparse(repo_url)
    if result.scheme and result.netloc:
        return repo_url
    else:
        logging.critical("Wrong URL provided: %s" % repo_url)
        raise ValueError


def can_create_file(filename: str) -> str:
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()

    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)
    else:
        logging.critical("Wrong path provided: %s" % filename)
        raise ValueError


def can_read_file(filename: str) -> str:
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        return filename
    else:
        logging.critical("Can't read file: %s" % filename)
        raise ValueError


def create_log_table(
    repo: git.repo.base.Repo,
    no_cpu: int,
    con: sqlite3.Connection,
    function_locations: list,
) -> int:
    con.execute("DROP TABLE IF EXISTS git_log;")

    con.execute(
        """CREATE TABLE git_log (
                start_line UNSIGNED BIG INT NOT NULL,
                end_line UNSIGNED BIG INT NOT NULL,
                file_path TEXT NOT NULL,
                author_date UNSIGNED BIG INT NOT NULL,
                `commit` VARCHAR(40) NOT NULL
            );"""
    )
    logging.info("Git Log table created in DB.")

    data = []
    tmp = tempfile.NamedTemporaryFile()

    repo_folder = repo.git.rev_parse("--show-toplevel")

    with tempfile.NamedTemporaryFile(delete_on_close=False) as tmp2:
        for function_data in function_locations:
            tmp2.write(
                (
                    "%d,%d:%s\n"
                    % (function_data[2], function_data[3], function_data[1])
                ).encode("utf-8")
            )
        tmp2.close()

        with open(tmp2.name, mode="r") as f:
            command = (
                PARALLEL
                + " --workdir "
                + repo_folder
                + " --bar --group -P "
                + str(no_cpu)
                + " -a "
                + tmp2.name
                + " "
                + GIT
                + " --no-pager log --format=\\'{},%at,%H\\' --no-patch -L {}"
                + " >> "
                + tmp.name
            )

            logging.info("Command that we're running: %s" % command)
            os.system(command)
            logging.info("Command execution complete!")

    log_data = ""
    with open(tmp.name, "r", encoding="utf-8", errors="ignore") as f:
        log_data = f.readlines()

    logging.info("TMP file contained: %d lines" % len(log_data))

    if not log_data:
        logging.critical(
            "Log data is missing. Something wrong with command execution!"
        )
        raise ValueError

    for log_entry in log_data:
        log_entry_chunks = log_entry.replace(":", ",").split(",")

        if (not log_entry_chunks) or (len(log_entry_chunks) < 2):
            logging.critical("Can't get log entry parsed: %s" % log_entry)
            raise ValueError

        start_line = log_entry_chunks[0].strip()
        end_line = log_entry_chunks[1].strip()
        file_path = log_entry_chunks[2].strip()
        author_date = log_entry_chunks[3].strip()
        commit = log_entry_chunks[4].strip()

        data.append((start_line, end_line, file_path, author_date, commit))

    logging.info("Git data processing for specified commit is complete")

    if not data:
        logging.critical(
            "Looks SUS no commit information has been dumped from GIT repository!"
        )
        raise ValueError

    con.executemany(
        """INSERT INTO git_log
                    VALUES(:start_line, :end_line, :file_path, :author_date, :commit)""",
        data,
    )

    return len(data)


def create_sql_db(
    db_file: str, codeql_db: str, no_cpu: int, repo: git.repo.base.Repo
) -> None:
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
            res = create_log_table(repo, no_cpu, con, function_locations)
            print(
                "GIT Log data saved into SQLite DB. Number of lines: %d" % res
            )


def check_tools() -> None:
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


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "repo_url",
        help="Linux Kernel Repository URL.",
        type=repo_url,
        nargs=1,
    )
    parser.add_argument(
        "commit",
        help="Commit to which we should hard reset the repo.",
        type=str,
        nargs=1,
    )
    parser.add_argument(
        "codeql_db",
        help="CodeQL DB file that contains function data.",
        type=can_read_file,
        nargs=1,
    )
    parser.add_argument(
        "--db_file",
        nargs="?",
        help="Path where to store Sqlite3 DB with Git Blame data.",
        type=can_create_file,
        default="git_log.db",
    )
    parser.add_argument(
        "--no_cpu",
        nargs="?",
        help="No of CPU to use for Git Log data parsing.",
        type=int,
        default=5,
    )
    args = parser.parse_args()

    check_tools()

    repo = ""
    if not os.path.exists("linux"):
        logging.info(
            "Clonning the Git repo as linux folder is empty: %s"
            % args.repo_url[0]
        )
        repo = git.Repo.clone_from(
            args.repo_url[0], "linux", branch="master", progress=CloneProgress()
        )
    else:
        logging.info("Reusing source code in Linux folder")
        repo = git.Repo("linux")
        repo.git.reset("--hard", "origin")
        repo.remotes.origin.pull()

    logging.info("Making hard reset to commit: %s" % args.commit[0])
    repo.git.reset("--hard", args.commit[0])

    create_sql_db(args.db_file, args.codeql_db[0], args.no_cpu, repo)


if __name__ == "__main__":
    main()
