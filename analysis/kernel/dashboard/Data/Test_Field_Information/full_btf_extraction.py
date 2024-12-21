#!/usr/bin/python3
import logging
import sqlite3
import argparse
import json
import subprocess
import os
import tempfile
from contextlib import closing

PAHOLE = "/usr/bin/pahole"
BPFTOOL = "/usr/sbin/bpftool"
READELF = "/usr/bin/readelf"


def vmlinux(filename: str) -> str:
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()
    if (not os.path.isfile(filename)) or (not os.access(filename, os.R_OK)):
        logging.critical("Not a file or can't read the file: %s" % filename)
        raise ValueError
    result = subprocess.check_output([READELF, "-h", filename])
    if "ELF64" not in result.decode("utf-8"):
        logging.critical("Ooops! Not an ELF64 file: %s" % filename)
        raise ValueError
    result = subprocess.check_output([READELF, "-S", filename])
    if "debug" not in result.decode("utf-8"):
        logging.critical(
            "The binary provided isn't compiled with debug data (DWARF): %s"
            % filename
        )
        raise ValueError
    return os.path.join(base_dir, filename)


def can_create_file(filename: str) -> str:
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()
    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)
    else:
        logging.critical("Wrong path provided: %s" % filename)
        raise ValueError


def dump_btf_json(vmlinux: str) -> bytes:
    with tempfile.NamedTemporaryFile() as tmp:
        logging.info("TMP file created: %s" % tmp.name)
        subprocess.run(
            [PAHOLE, "--btf_encode_detached=%s" % tmp.name, vmlinux], check=True
        )
        if not os.path.getsize(tmp.name):
            logging.critical(
                "The tmp file doesn't contain valid BTF encoded data: %s"
                % tmp.name
            )
            raise ValueError
        logging.info("Data size in TMP file: %d" % os.path.getsize(tmp.name))
        raw_json_data = subprocess.check_output(
            [BPFTOOL, "btf", "dump", "--json", "file", tmp.name]
        )
        if not raw_json_data:
            logging.critical(
                "The JSON formated BTF data could not be extracted from BTF file: %s"
                % tmp.name
            )
            raise ValueError
        json_data = ""
        try:
            json_data = json.loads(raw_json_data)
            logging.info("Length of parsed BTF JSON: %d" % len(json_data))
        except ValueError:
            logging.critical("Can't parse BTF data in JSON format")
        return json_data


def create_members_table(json_data: dict, con: sqlite3.Connection) -> int:
    con.execute("DROP TABLE IF EXISTS members;")
    # types_id - ID from types table to run unions
    con.execute(
        """CREATE TABLE members (
                types_id UNSIGNED BIG INT NOT NULL,
                name TEXT NOT NULL,
                type_id UNSIGNED BIG INT NOT NULL,
                bits_offset UNSIGNED BIG INT NOT NULL,
                bitfield_size UNSIGNED BIG INT
                );"""
    )
    logging.info("Members table created in DB.")
    # {'name': 'state', 'type_id': 25, 'bits_offset': 0}
    data = []
    for types_dict in json_data["types"]:
        if "members" in types_dict:
            for member in types_dict["members"]:
                if len(member) == 3:
                    data.append(
                        (
                            types_dict["id"],
                            member["name"],
                            member["type_id"],
                            member["bits_offset"],
                            None,
                        )
                    )
                elif len(member) == 4:
                    data.append(
                        (
                            types_dict["id"],
                            member["name"],
                            member["type_id"],
                            member["bits_offset"],
                            member["bitfield_size"],
                        )
                    )
                else:
                    logging.critical(
                        "Oooooops! Something wrong happening with members data. Please debug: %s"
                        % str(types_dict)
                    )
                    raise ValueError
    if not data:
        loggin.critical(
            "Looks SUS no members structures found in the whole JSON BTF dump!"
        )
        raise ValueError
    logging.info(
        "Inserting (types_id, name, type_id, bits_offset, bitfield_size) data into Sqlite DB (members table). Number of lines: %d"
        % len(data)
    )
    con.executemany(
        "INSERT INTO members(types_id, name, type_id, bits_offset, bitfield_size) VALUES(?, ?, ?, ?, ?);",
        data,
    )
    return len(data)


def create_values_table(json_data: dict, con: sqlite3.Connection) -> int:
    con.execute("DROP TABLE IF EXISTS `values`;")
    # types_id - ID from types table to run unions
    # val - could be quite large or negative so don't fit into INTEGER
    con.execute(
        """CREATE TABLE `values` (
                types_id UNSIGNED BIG INT NOT NULL,
                name TEXT NOT NULL,
                val BLOB NOT NULL
                );"""
    )
    logging.info("Values table created in DB.")
    # {'name': 'MODULE_STATE_LIVE', 'val': 0}
    data = []
    for types_dict in json_data["types"]:
        if "values" in types_dict:
            for value in types_dict["values"]:
                if len(value) == 2:
                    data.append(
                        (types_dict["id"], value["name"], str(value["val"]))
                    )
                else:
                    logging.critical(
                        "Oooooops! Something wrong happening with values data. Please debug: %s"
                        % str(types_dict)
                    )
                    raise ValueError
    if not data:
        loggin.critical(
            "Looks SUS no values structures found in the whole JSON BTF dump!"
        )
        raise ValueError
    logging.info(
        "Inserting (types_id, name, val) data into Sqlite DB (values table). Number of lines: %d"
        % len(data)
    )
    con.executemany(
        "INSERT INTO `values`(types_id, name, val) VALUES(?, ?, ?);", data
    )
    return len(data)


def create_params_table(json_data: dict, con: sqlite3.Connection) -> int:
    con.execute("DROP TABLE IF EXISTS params;")
    # types_id - ID from types table to run unions
    con.execute(
        """CREATE TABLE params (
                types_id UNSIGNED BIG INT NOT NULL,
                name TEXT NOT NULL,
                type_id UNSIGNED BIG INT NOT NULL
                );"""
    )
    logging.info("Params table created in DB.")
    # {'name': '(anon)', 'type_id': 57}
    data = []
    for types_dict in json_data["types"]:
        if "params" in types_dict:
            for param in types_dict["params"]:
                if len(param) == 2:
                    data.append(
                        (types_dict["id"], param["name"], param["type_id"])
                    )
                else:
                    logging.critical(
                        "Oooooops! Something wrong happening with params data. Please debug: %s"
                        % str(types_dict)
                    )
                    raise ValueError
    if not data:
        logging.critical(
            "Looks SUS no params structures found in the whole JSON BTF dump!"
        )
        raise ValueError
    logging.info(
        "Inserting (types_id, name, type_id) data into Sqlite DB (params table). Number of lines: %d"
        % len(data)
    )
    con.executemany(
        "INSERT INTO params(types_id, name, type_id) VALUES(?, ?, ?);", data
    )
    return len(data)


def create_vars_table(json_data: dict, con: sqlite3.Connection) -> int:
    con.execute("DROP TABLE IF EXISTS vars;")
    # types_id - ID from types table to run unions
    con.execute(
        """CREATE TABLE vars (
                types_id UNSIGNED BIG INT NOT NULL,
                type_id UNSIGNED BIG INT NOT NULL,
                offset UNSIGNED BIG INT NOT NULL,
                size UNSIGNED BIG INT NOT NULL
                );"""
    )
    logging.info("Vars table created in DB.")
    # {'type_id': 8651, 'offset': 0, 'size': 48}
    data = []
    for types_dict in json_data["types"]:
        if "vars" in types_dict:
            for var in types_dict["vars"]:
                if len(var) == 3:
                    data.append(
                        (
                            types_dict["id"],
                            var["type_id"],
                            var["offset"],
                            var["size"],
                        )
                    )
                else:
                    logging.critical(
                        "Oooooops! Something wrong happening with vars data. Please debug: %s"
                        % str(types_dict)
                    )
                    raise ValueError
    if not data:
        logging.critical(
            "Looks SUS no vars structures found in the whole JSON BTF dump!"
        )
        raise ValueError
    logging.info(
        "Inserting (types_id, type_id, offset, size) data into Sqlite DB (vars table). Number of lines: %d"
        % len(data)
    )
    con.executemany(
        "INSERT INTO vars(types_id, type_id, offset, size) VALUES(?, ?, ?, ?);",
        data,
    )
    return len(data)


def create_types_table(json_data: dict, con: sqlite3.Connection) -> int:
    con.execute("DROP TABLE IF EXISTS types;")
    columns_identified = set(
        key
        for elem in json_data["types"]
        for key in elem
        if key not in ["vars", "params", "values", "members"]
    )
    if len(columns_identified) != 14:
        logging.critical(
            "Looks SUS! Unique columns found: %s. This doesn't match our parsing"
            % str(columns_identified)
        )
        raise ValueError
    con.execute(
        """CREATE TABLE types (
                id UNSIGNED BIG INT PRIMARY KEY NOT NULL,
                kind VARCHAR(15) NOT NULL,
                name TEXT NOT NULL,
                size UNSIGNED BIG INT,
                vlen UNSIGNED BIG INT,
                bits_offset UNSIGNED BIG INT,
                nr_bits UNSIGNED BIG INT, 
                encoding TEXT,
                linkage TEXT,
                nr_elems UNSIGNED BIG INT,
                fwd_kind TEXT,
                index_type_id UNSIGNED BIG INT,
                type_id UNSIGNED BIG INT,
                ret_type_id UNSIGNED BIG INT
                );"""
    )
    logging.info("Types table created in DB.")
    data = []
    entry = lambda defined: {
        key: (defined[key] if key in defined else None)
        for key in columns_identified
    }
    for types_dict in json_data["types"]:
        data.append(entry(types_dict))
    if not data:
        logging.critical(
            "Looks SUS no vars structures found in the whole JSON BTF dump!"
        )
        raise ValueError
    con.executemany(
        """INSERT INTO types 
                    VALUES(:id, :kind, :name, :size, :vlen, :bits_offset, :nr_bits,
                    :encoding, :linkage, :nr_elems, :fwd_kind, :index_type_id,
                    :type_id, :ret_type_id);""",
        data,
    )
    return len(data)


def create_sql_db(db_file: str, json_data: dict) -> None:
    with closing(sqlite3.connect(db_file)) as conn:
        with conn as con:
            res = create_members_table(json_data, con)
            print(
                "Members data saved in members table of BTF DB. Number of lines: %d"
                % res
            )
        with conn as con:
            res = create_values_table(json_data, con)
            print(
                "Values data saved in values table of BTF DB. Number of lines: %d"
                % res
            )
        with conn as con:
            res = create_params_table(json_data, con)
            print(
                "Params data saved in params table of BTF DB. Number of lines: %d"
                % res
            )
        with conn as con:
            res = create_vars_table(json_data, con)
            print(
                "Vars data saved in vars table of BTF DB. Number of lines: %d"
                % res
            )
        with conn as con:
            res = create_types_table(json_data, con)
            print(
                "Vars data saved in vars table of BTF DB. Number of lines: %d"
                % res
            )


def check_tools() -> None:
    subprocess.run(
        [PAHOLE, "--version"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    logging.info("Pahole found: %s" % PAHOLE)
    subprocess.run(
        [BPFTOOL, "--version"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    logging.info("Bpftool found: %s" % BPFTOOL)
    subprocess.run(
        [READELF, "-v"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    logging.info("Readelf found: %s" % READELF)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vmlinux",
        help="Kernel binary (vmlinux) with debug data (DWARF).",
        type=vmlinux,
        nargs=1,
    )
    parser.add_argument(
        "--json_file",
        nargs="?",
        help="Path where to store JSON file with BTF data extracted from vmlinux.",
        type=can_create_file,
        default=None,
    )
    parser.add_argument(
        "--db_file",
        nargs="?",
        help="Path where to store Sqlite3 DB with BTF data.",
        type=can_create_file,
        default="btf.db",
    )
    args = parser.parse_args()
    check_tools()
    json_data = dump_btf_json(args.vmlinux[0])
    create_sql_db(args.db_file, json_data)


if __name__ == "__main__":
    main()
