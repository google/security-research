#!/usr/bin/python3

import logging
import sqlite3
import argparse
import json
import subprocess
import os
import tempfile
import math
import sys

from contextlib import closing


PAHOLE = "/usr/bin/pahole"
BPFTOOL = "/usr/sbin/bpftool"
READELF = "/usr/bin/readelf"


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


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

    return os.path.join(base_dir, file_name)


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


def get_shallow(
    types,
    struct_name,
    struct_size,
    object,
    parent_type,
    prefix="",
    bits_offset=0,
):
    shallow_types = []
    type = types[object["type_id"]]

    while type["kind"] in ["TYPEDEF", "CONST", "VOLATILE", "RESTRICT"]:
        if (type["kind"] == "TYPEDEF") and (
            types[type["type_id"]]["name"] == "(anon)"
        ):
            # Sometimes we have inline structs and enumes defined via typedef.
            # They are considered as anonymous. So we want to put typedef name instead.
            #
            # Before this fix example:
            # {'id': 2184, 'kind': 'TYPEDEF', 'name': 'efi_memory_desc_t', 'type_id': 2183}
            # {'id': 2183, 'kind': 'STRUCT', 'name': '(anon)', 'size': 40, 'vlen': 6, 'members': [{'name': 'type', 'type_id': 33, 'bits_offset': 0}, {'name': 'pad', 'type_id': 33, 'bits_offset': 32}, {'name': 'phys_addr', 'type_id': 35, 'bits_offset': 64}, {'name': 'virt_addr', 'type_id': 35, 'bits_offset': 128}, {'name': 'num_pages', 'type_id': 35, 'bits_offset': 192}, {'name': 'attribute', 'type_id': 35, 'bits_offset': 256}]}
            #
            # After this fix example:
            # {'id': 2184, 'kind': 'TYPEDEF', 'name': 'efi_memory_desc_t', 'type_id': 2183}
            # {'id': 2183, 'kind': 'STRUCT', 'name': 'efi_memory_desc_t', 'size': 40, 'vlen': 6, 'members': [{'name': 'type', 'type_id': 33, 'bits_offset': 0}, {'name': 'pad', 'type_id': 33, 'bits_offset': 32}, {'name': 'phys_addr', 'type_id': 35, 'bits_offset': 64}, {'name': 'virt_addr', 'type_id': 35, 'bits_offset': 128}, {'name': 'num_pages', 'type_id': 35, 'bits_offset': 192}, {'name': 'attribute', 'type_id': 35, 'bits_offset': 256}]}
            name = type["name"]
            type = types[type["type_id"]]
            type["name"] = name
        else:
            type = types[type["type_id"]]

    if type["kind"] == "ARRAY" and type["nr_elems"] > 0:
        object_bits_offset = object["bits_offset"] + bits_offset
        for index in range(type["nr_elems"]):
            expanded_object = object.copy()
            expanded_object["type_id"] = type["type_id"]
            expanded_object["name"] += f"[{index}]"
            deeper_types = get_shallow(
                types,
                struct_name,
                struct_size,
                expanded_object,
                parent_type,
                prefix,
                object_bits_offset,
            )

            sorted_deepest = sorted(
                deeper_types, key=lambda x: x["bits_end"], reverse=True
            )

            for element in reversed(sorted_deepest):
                element["bits_offset"] = object_bits_offset
                element["bits_end"] -= object["bits_offset"]
                object_bits_offset = element["bits_end"]

            deepest_bits_end = (
                sorted_deepest[0]["bits_end"] if len(sorted_deepest) > 0 else 0
            )
            object_bits_offset = 8 * math.ceil(deepest_bits_end / 8)
            shallow_types += deeper_types
    elif type["kind"] == "STRUCT" or type["kind"] == "UNION":
        members = [(idx, member) for idx, member in enumerate(type["members"])]
        bitfield_id = -1
        for idx, member in members:
            if type["kind"] == "UNION":
                new_prefix = (
                    prefix + "/*" + str(idx) + ":" + object["name"] + "*/"
                )
            else:
                new_prefix = prefix + object["name"] + "."

            if "bitfield_size" in member:
                # Handle situations with bit masks like this:
                #
                # struct nft_table {
                # 	struct list_head		list;
                # 	struct rhltable			chains_ht;
                # 	struct list_head		chains;
                # 	struct list_head		sets;
                # 	struct list_head		objects;
                # 	struct list_head		flowtables;
                # 	u64				        hgenerator;
                # 	u64				        handle;
                # 	u32				        use;
                # 	u16				        family:6,
                # 					        flags:8,
                # 					        genmask:2;
                # 	u32				        nlpid;
                # 	char			        *name;
                # 	u16				        udlen;
                # 	u8				        *udata;
                # };
                if [
                    True
                    for id, mem in members
                    if (id == idx - 1) and ("bitfield_size" not in mem)
                ]:
                    bitfield_id = idx
                elif idx == 0:
                    bitfield_id = 0

                member["bits_offset"] = [
                    mem["bits_offset"]
                    for id, mem in members
                    if (id == bitfield_id)
                ][0]

                if (":" + str(member["bitfield_size"])) not in member["name"]:
                    member["name"] = (
                        member["name"] + ":" + str(member["bitfield_size"])
                    )

            deeper_types = get_shallow(
                types,
                struct_name,
                struct_size,
                member,
                type["name"],
                new_prefix,
                bits_offset + object["bits_offset"],
            )

            shallow_types += deeper_types
    else:
        kind = type["kind"]
        out_type = type["name"]
        is_flex = False

        if type["kind"] == "PTR":
            if "type_id" in type:
                pointer_type = type

                if pointer_type["type_id"] != 0:
                    pointer_type = types[pointer_type["type_id"]]

                    while "(anon)" in pointer_type["name"]:
                        if pointer_type["kind"] == "STRUCT":
                            struct_members = []
                            for member in pointer_type["members"]:
                                if member["type_id"] != 0:
                                    expanded_object = object.copy()
                                    expanded_object["type_id"] = member[
                                        "type_id"
                                    ]
                                    deeper_types = get_shallow(
                                        types,
                                        struct_name,
                                        struct_size,
                                        expanded_object,
                                        pointer_type["name"],
                                        prefix,
                                    )

                                    member_type = ""
                                    if member["name"] != "(anon)":
                                        member_type = (
                                            deeper_types[0]["type"]
                                            + member["name"]
                                            if deeper_types[0]["type"][-1]
                                            == "*"
                                            else deeper_types[0]["type"]
                                            + " "
                                            + member["name"]
                                        )
                                    else:
                                        member_type = (
                                            deeper_types[0]["type"] + "?"
                                            if deeper_types[0]["type"][-1]
                                            == "*"
                                            else deeper_types[0]["type"] + " ?"
                                        )
                                    struct_members.append(member_type)

                                elif member["type_id"] == 0:
                                    struct_members.append(
                                        "void *" + member["name"]
                                        if param["name"] != "(anon)"
                                        else "void *?"
                                    )

                            pointer_type["name"] = "struct {%s} *" % (
                                ", ".join(struct_members)
                            )

                        elif pointer_type["kind"] == "FUNC_PROTO":
                            # Example of function structure that we parse here:
                            #
                            # {'id': 86, 'kind': 'FUNC_PROTO', 'name': '(anon)', 'ret_type_id': 0, 'vlen': 1, 'params': [{'name': '(anon)', 'type_id': 85}]}
                            ret_type = {}
                            if pointer_type["ret_type_id"] != 0:
                                expanded_object = object.copy()
                                expanded_object["type_id"] = pointer_type[
                                    "ret_type_id"
                                ]
                                deeper_types = get_shallow(
                                    types,
                                    struct_name,
                                    struct_size,
                                    expanded_object,
                                    pointer_type["name"],
                                    prefix,
                                )

                                ret_type["name"] = deeper_types[0]["type"]

                            else:
                                ret_type["name"] = "void"

                            fun_params = []
                            for param in pointer_type["params"]:
                                if param["type_id"] != 0:
                                    expanded_object = object.copy()
                                    expanded_object["type_id"] = param[
                                        "type_id"
                                    ]
                                    expanded_object["bits_offset"] = 0
                                    deeper_types = get_shallow(
                                        types,
                                        struct_name,
                                        struct_size,
                                        expanded_object,
                                        pointer_type["name"],
                                        prefix,
                                    )

                                    param_type = ""
                                    if param["name"] != "(anon)":
                                        param_type = (
                                            deeper_types[0]["type"]
                                            + param["name"]
                                            if deeper_types[0]["type"][-1]
                                            == "*"
                                            else deeper_types[0]["type"]
                                            + " "
                                            + param["name"]
                                        )
                                    else:
                                        param_type = (
                                            deeper_types[0]["type"] + "?"
                                            if deeper_types[0]["type"][-1]
                                            == "*"
                                            else deeper_types[0]["type"] + " ?"
                                        )
                                    fun_params.append(param_type)

                                elif param["type_id"] == 0:
                                    param_type = (
                                        "void *" + param["name"]
                                        if param["name"] != "(anon)"
                                        else "void *?"
                                    )
                                    fun_params.append(param_type)

                            pointer_type["name"] = "%s (*<name>) (%s)" % (
                                ret_type["name"],
                                ", ".join(fun_params),
                            )

                        elif pointer_type["type_id"] != 0:
                            pointer_type = types[pointer_type["type_id"]]
                        else:
                            pointer_type["name"] = "void"
                else:
                    pointer_type["name"] = "void"

                if pointer_type["kind"] == "STRUCT":
                    out_type = (
                        "struct " + pointer_type["name"] + " *"
                        if pointer_type["name"][-1] != ")"
                        else "struct " + pointer_type["name"]
                    )
                elif pointer_type["kind"] == "CONST":
                    out_type = (
                        "const " + pointer_type["name"] + " *"
                        if pointer_type["name"][-1] != ")"
                        else "const " + pointer_type["name"]
                    )
                else:
                    out_type = (
                        pointer_type["name"] + " *"
                        if pointer_type["name"][-1] != ")"
                        else pointer_type["name"]
                    )

            nr_bits = 64  # PTR_SIZE
            bits_end = bits_offset + object["bits_offset"] + nr_bits
        elif type["kind"] == "ENUM" or type["kind"] == "ENUM64":
            nr_bits = type["size"] * 8
            bits_end = bits_offset + object["bits_offset"] + nr_bits
        elif type["kind"] == "ARRAY":
            expanded_object = object.copy()
            expanded_object["type_id"] = type["type_id"]
            expanded_object["bits_offset"] = 0
            deeper_types = get_shallow(
                types,
                struct_name,
                struct_size,
                expanded_object,
                type["name"],
                prefix,
                0,
            )

            sorted_deepest = sorted(
                deeper_types, key=lambda x: x["bits_end"], reverse=True
            )
            nr_bits = sorted_deepest[0]["bits_end"]

            while type["kind"] in [
                "TYPEDEF",
                "CONST",
                "VOLATILE",
                "ARRAY",
                "RESTRICT",
            ]:
                if (type["kind"] == "TYPEDEF") and (
                    types[type["type_id"]]["name"] == "(anon)"
                ):
                    # Sometimes we have inline structs and enumes defined via typedef.
                    # They are considered as anonymous. So we want to put typedef name instead.
                    #
                    # Before this fix example:
                    # {'id': 2184, 'kind': 'TYPEDEF', 'name': 'efi_memory_desc_t', 'type_id': 2183}
                    # {'id': 2183, 'kind': 'STRUCT', 'name': '(anon)', 'size': 40, 'vlen': 6, 'members': [{'name': 'type', 'type_id': 33, 'bits_offset': 0}, {'name': 'pad', 'type_id': 33, 'bits_offset': 32}, {'name': 'phys_addr', 'type_id': 35, 'bits_offset': 64}, {'name': 'virt_addr', 'type_id': 35, 'bits_offset': 128}, {'name': 'num_pages', 'type_id': 35, 'bits_offset': 192}, {'name': 'attribute', 'type_id': 35, 'bits_offset': 256}]}
                    #
                    # After this fix example:
                    # {'id': 2184, 'kind': 'TYPEDEF', 'name': 'efi_memory_desc_t', 'type_id': 2183}
                    # {'id': 2183, 'kind': 'STRUCT', 'name': 'efi_memory_desc_t', 'size': 40, 'vlen': 6, 'members': [{'name': 'type', 'type_id': 33, 'bits_offset': 0}, {'name': 'pad', 'type_id': 33, 'bits_offset': 32}, {'name': 'phys_addr', 'type_id': 35, 'bits_offset': 64}, {'name': 'virt_addr', 'type_id': 35, 'bits_offset': 128}, {'name': 'num_pages', 'type_id': 35, 'bits_offset': 192}, {'name': 'attribute', 'type_id': 35, 'bits_offset': 256}]}
                    name = type["name"]
                    type = types[type["type_id"]]
                    type["name"] = name
                else:
                    type = types[type["type_id"]]

            kind = "ARRAY<" + type["kind"] + ">"
            is_flex = True
            bits_end = bits_offset + object["bits_offset"]
        else:
            if "nr_bits" not in type:
                eprint(type)

            nr_bits = type["nr_bits"]
            bits_end = bits_offset + object["bits_offset"] + nr_bits

        shallow_types.append(
            {
                "struct_name": struct_name,
                "struct_size": struct_size,
                "parent_type": parent_type,
                "kind": kind,
                "type": out_type,
                "name": prefix + object["name"],
                "bits_offset": bits_offset + object["bits_offset"],
                "nr_bits": nr_bits,
                "bits_end": bits_end,
                "is_flex": is_flex,
            }
        )

    return shallow_types


def create_types_table(json_data: dict, con: sqlite3.Connection) -> int:
    con.execute("DROP TABLE IF EXISTS types;")

    con.execute(
        """CREATE TABLE types (
                struct_name TEXT NOT NULL,
		        struct_size UNSIGNED BIG INT NOT NULL,
		        parent_type TEXT NOT NULL,
                kind VARCHAR(15) NOT NULL,
		        type TEXT NOT NULL,
                name TEXT NOT NULL,
		        bits_offset UNSIGNED BIG INT,
		        nr_bits UNSIGNED BIG INT,
		        bits_end UNSIGNED BIG INT,
		        is_flex BOOLEAN NOT NULL
                );"""
    )
    logging.info("Types table created in DB.")

    data = []

    types = {}
    for type in json_data["types"]:
        types[type["id"]] = type

    for type in json_data["types"]:
        if type["kind"] == "STRUCT":
            for member in type["members"]:
                data += get_shallow(
                    types, type["name"], type["size"], member, type["name"]
                )

    if not data:
        logging.critical(
            "Looks SUS no vars structures found in the whole JSON BTF dump!"
        )
        raise ValueError

    con.executemany(
        """INSERT INTO types 
                    VALUES(:struct_name, :struct_size, :parent_type, :kind, :type,
                    :name, :bits_offset, :nr_bits, :bits_end, :is_flex)""",
        data,
    )

    return len(data)


def create_sql_db(db_file: str, json_data: dict) -> None:
    with closing(sqlite3.connect(db_file)) as conn:
        sqlite3.register_adapter(bool, int)
        sqlite3.register_converter("BOOLEAN", lambda v: bool(int(v)))

        with conn as con:
            res = create_types_table(json_data, con)
            print("BTF data saved into Sqlite DB. Number of lines: %d" % res)


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
