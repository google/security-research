#!/usr/bin/python3

import logging
import sqlite3
import html
import os
import argparse
import re
import operator

from urllib.request import urlopen
from urllib.parse import urlparse
from urllib.parse import urlsplit
from contextlib import closing

from io import StringIO
from lxml import etree


def sk_cov_url(sk_cov_url: str) -> str:
    logging.info("Validating URL provided")
    result = urlparse(sk_cov_url)
    if (
        result.scheme
        and result.netloc
        and (("syzbot" or "syzkaller") in result.path)
    ):
        return sk_cov_url
    else:
        logging.critical("Wrong URL provided: %s" % sk_cov_url)
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


def get_sk_cov_data(html_file: str, sk_cov_url: str) -> dict:
    out = {}
    file_idx = 0

    for url in sk_cov_url:
        with urlopen(url) as response:
            logging.info("Getting HTML data from %s" % url)
            data = response.read()

            if html_file:
                logging.info("Saving coverage data in HTML file")
                with open(
                    os.path.join(html_file, "." + str(file_idx)), mode="wb"
                ) as file:
                    file.write(data)
                file_idx += 1

            out[url] = data.decode()
    return out


def get_prog(html_data: str) -> list:
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
        loggin.critical('No <pre class="file" id="prog_ has been found')
        raise ValueError

    return data


def get_syscalls(prog_list: list) -> list:
    data = []

    logging.info("Gathering syscalls from syzkaller programs...")
    for prog in prog_list:
        results = re.findall(
            "((?:\w+ = )?(?P<syscall>[^$(]+)(?:[$]\w+)?.+)\n?", prog[1]
        )

        if results:
            for syscall in results:
                data.append((prog[0], syscall[1]))

    if not data:
        loggin.critical(
            "Something went wrong. No syscalls found in syzkaller programs."
        )
        raise ValueError

    logging.info("Total number of syscalls: %d" % len(data))

    return data


def get_syzk_cov(html_data: str) -> list:
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
        loggin.critical('No class="file" id="contents has been found')
        raise ValueError

    return data


def get_path(html_data: str) -> list:
    # grep '<a'.*'id='.*onFileClick ${COVERAGE_HTML} | sed 's/.* id=\(.*\?\) onclick=\(.*\?\)>/\1,\2/' > ${COVERAGE_HTML}.files.csv
    html_parser = etree.HTMLParser()
    tree = etree.parse(StringIO(html_data), html_parser)

    a_tag_list = tree.xpath(
        './/a[@id and @href and contains(@onclick,"onFileClick")]'
    )

    if not a_tag_list:
        loggin.critical("No <a> tags with href, id, onclick attributes")
        raise ValueError

    logging.info(
        "Found some <a> tags to process. Number of lines: %d" % len(a_tag_list)
    )

    data = []
    for tag in a_tag_list:
        # Remove redundant JavaScript and get clean integer for file_id
        file_id = re.search(r"\(\s*(\d*)\s*\)", tag.get("onclick")).group(1)

        if not file_id:
            loggin.critical(
                "OOOPS! Something has changed in syzkaller HTML! Can't parse onclick attribute data"
            )
            raise ValueError

        #  We also want to cut away "path/" from beginning of the path string supplied by syzkaller
        if not tag.get("id").startswith("path/"):
            loggin.critical(
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


def get_all_data(html_dict: dict) -> (dict, dict, dict):
    all_path = {}
    all_syzk_cov = {}
    all_prog = {}

    for html_name, html_data in html_dict.items():
        all_path[html_name] = get_path(html_data)
        print("Path data obtained from file: %s" % html_name)
        logging.info("Amount of path data: %d" % len(all_path[html_name]))

        all_syzk_cov[html_name] = get_syzk_cov(html_data)
        print("Syzk_cov data obtained from %s" % html_name)
        logging.info(
            "Amount of syz_cov data: %d" % len(all_syzk_cov[html_name])
        )

        all_prog[html_name] = get_prog(html_data)
        print("Prog data obtained from: %s" % html_name)
        logging.info("Amount of programs data: %d" % len(all_prog[html_name]))

    all_path, all_syzk_cov, all_prog = merge_dicts(
        all_path, all_syzk_cov, all_prog
    )
    all_syscalls = get_syscalls(all_prog)

    return (all_path, all_syzk_cov, all_prog, all_syscalls)


def merge_dicts(
    all_path: dict, all_syzk_cov: dict, all_prog: dict
) -> (list, list, list):
    if (len(all_path) != len(all_syzk_cov)) or (len(all_path) != len(all_prog)):
        loggin.critical(
            "OOOPS! Input dicts have different size. This is toally wrong!"
        )
        raise ValueError

    # Join all the table data to form file_name, line_no, program_code tuples
    tmp_all_cov = []
    for html_name in all_path:
        # [(file_id, file_path), ...]
        tmp_path = {element[0]: element[1] for element in all_path[html_name]}
        tmp_prog = {element[0]: element[1] for element in all_prog[html_name]}
        tmp_all_cov += [
            (tmp_path[element[0]], element[1], tmp_prog[element[2]])
            for element in all_syzk_cov[html_name]
        ]

    # Remove duplicates
    tmp_all_cov = list(set(tmp_all_cov))

    # Get unique file paths and unique program codes
    unique_file_path = set()
    unique_prog_code = set()
    for file_name, _, prog_code in tmp_all_cov:
        unique_file_path.add(file_name)
        unique_prog_code.add(prog_code)

    # Enumeration of unique file paths and programs
    file_path_dict = {
        file_path: id for id, file_path in enumerate(list(unique_file_path))
    }
    prog_code_dict = {
        prog_code: id for id, prog_code in enumerate(list(unique_prog_code))
    }

    # Swapping file paths and prog code with ids in syzk_cov
    agreg_syzk_cov = [
        (file_path_dict[file_path], code_line_no, prog_code_dict[prog_code])
        for file_path, code_line_no, prog_code in tmp_all_cov
    ]

    # Converting file paths and prog code dicts to list of tuples
    agreg_file_path = [
        (id, file_path) for file_path, id in file_path_dict.items()
    ]
    agreg_prog_code = [
        (id, prog_code) for prog_code, id in prog_code_dict.items()
    ]

    return (agreg_file_path, agreg_syzk_cov, agreg_prog_code)


def create_sql_db(db_file: str, html_dict: dict) -> None:
    all_path, all_syzk_cov, all_prog, all_syscalls = get_all_data(html_dict)

    with closing(sqlite3.connect(db_file)) as conn:
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
                "INSERT INTO syzk_cov VALUES(:file_id, :codeLine_no, :prog_id);",
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

        # Process syscalls
        with conn as con:
            con.execute("DROP TABLE IF EXISTS syscalls;")

            logging.info("Creating syscalls table in syzkaller DB")
            con.execute(
                "CREATE TABLE syscalls (prog_id UNSIGNED BIG INT NOT NULL, syscall TEXT NOT NULL);"
            )

            logging.info(
                "Inserting (prog_id, syscall) data into Sqlite DB (syzk_prog table). Number of lines: %d"
                % len(all_syscalls)
            )

            con.executemany("INSERT INTO syscalls VALUES(?, ?);", all_syscalls)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "sk_cov_url",
        help="Syzkaller Coverage URL like https://storage.googleapis.com/syzbot-assets/0422343bda5a/ci2-linux-6-1-kasan-aa4cd140.html, Get it here: https://syzkaller.appspot.com/upstream",
        type=sk_cov_url,
        nargs="+",
    )
    parser.add_argument(
        "--html_file",
        nargs="?",
        help="Path where to store syzkaller HTML file.",
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
    args = parser.parse_args()

    html_dict = get_sk_cov_data(args.html_file, args.sk_cov_url)

    if args.html_file:
        print("Coverage data in HTML format saved in: %s" % args.html_file)

    create_sql_db(args.db_file, html_dict)


if __name__ == "__main__":
    main()
