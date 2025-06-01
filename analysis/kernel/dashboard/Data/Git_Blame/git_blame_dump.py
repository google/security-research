#!/usr/bin/python3

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
FIND = "/usr/bin/find"
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


def create_blame_table(
    repo: git.repo.base.Repo, no_cpu: int, con: sqlite3.Connection
) -> int:
    con.execute("DROP TABLE IF EXISTS git_blame;")

    con.execute(
        """CREATE TABLE git_blame (
                file_path TEXT NOT NULL,
                `commit` VARCHAR(40) NOT NULL,
                line_no UNSIGNED BIG INT NOT NULL,
                data TEXT NOT NULL
            );"""
    )
    logging.info("Git Blame table created in DB.")

    data = []
    tmp = tempfile.NamedTemporaryFile()

    repo_folder = repo.git.rev_parse("--show-toplevel")
    command = (
        "cd "
        + repo_folder
        + "; "
        + FIND
        + " . -path ./tools -prune -o -path ./Documentation -prune -o -type f -print0 | "
        + PARALLEL
        + " --roundrobin --group -0 -P "
        + str(no_cpu)
        + " -I % "
        + GIT
        + " --no-pager blame -b -s -f -l -w --no-progress --root % >> "
        + tmp.name
    )

    logging.info("Command that we're running: %s" % command)

    os.system(command)

    logging.info("Command execution complete!")

    blame_data = ""
    with open(tmp.name, "r", encoding="utf-8", errors="ignore") as f:
        blame_data = f.readlines()

    logging.info("TMP file contained: %d lines" % len(blame_data))

    if not blame_data:
        logging.critical(
            "Can't get blame data for the file: %s" % entry.abspath
        )
        raise ValueError

    for blame_entry in blame_data:
        blame_entry_chunks = blame_entry.split()

        if (not blame_entry_chunks) or (len(blame_entry_chunks) < 2):
            logging.critical("Can't get blame entry parsed: %s" % blame_entry)
            raise ValueError

        commit = blame_entry_chunks[0].strip()
        line_number = blame_entry_chunks[2].strip()[:-1]
        code_line = blame_entry.split(blame_entry_chunks[2])[1]

        data.append((blame_entry_chunks[1], commit, line_number, code_line))

    logging.info("Git data processing for specified commit is complete")

    if not data:
        logging.critical(
            "Looks SUS no commit information has been dumped from GIT repository!"
        )
        raise ValueError

    con.executemany(
        """INSERT INTO git_blame
                    VALUES(:file_path, :commit, :line_no, :data)""",
        data,
    )

    return len(data)


def create_sql_db(db_file: str, no_cpu: int, repo: git.repo.base.Repo) -> None:
    with closing(sqlite3.connect(db_file)) as conn:
        with conn as con:
            res = create_blame_table(repo, no_cpu, con)
            print(
                "GIT Blame data saved into SQLite DB. Number of lines: %d" % res
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
        "--db_file",
        nargs="?",
        help="Path where to store Sqlite3 DB with Git Blame data.",
        type=can_create_file,
        default="git_blame.db",
    )
    parser.add_argument(
        "--no_cpu",
        nargs="?",
        help="No of CPU to use for Git Blame data parsing.",
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

    create_sql_db(args.db_file, args.no_cpu, repo)


if __name__ == "__main__":
    main()
