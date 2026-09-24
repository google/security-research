#!/usr/bin/python3
# pylint: disable=invalid-name,duplicate-code
"""Extracts Linux kernel BTF type information from a vmlinux binary into SQLite."""

import argparse
from contextlib import closing
import json
import logging
import math
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile


PAHOLE = shutil.which("pahole") or "/usr/bin/pahole"
BPFTOOL = shutil.which("bpftool") or "/usr/sbin/bpftool"
READELF = shutil.which("readelf") or "/usr/bin/readelf"


def eprint(*args, **kwargs):
    """Prints output to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def has_btf_section(filename: str) -> bool:
    """Checks if the ELF binary contains an embedded .BTF section."""
    result = subprocess.check_output([READELF, "-S", filename]).decode("utf-8")
    return ".BTF" in result


def vmlinux(filename: str) -> str:
    """Validates that the file is an ELF64 binary with BTF or debug data."""
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()

    if (not os.path.isfile(filename)) or (not os.access(filename, os.R_OK)):
        logging.critical("Not a file or can't read the file: %s", filename)
        raise ValueError

    result = subprocess.check_output([READELF, "-h", filename])
    if "ELF64" not in result.decode("utf-8"):
        logging.critical("Ooops! Not an ELF64 file: %s", filename)
        raise ValueError

    result = subprocess.check_output([READELF, "-S", filename]).decode("utf-8")
    if ".BTF" not in result and "debug" not in result:
        logging.critical(
            "The binary provided isn't compiled with BTF or debug data: %s",
            filename,
        )
        raise ValueError

    return os.path.join(base_dir, file_name)


def can_create_file(filename: str) -> str:
    """Validates that the output directory exists and is writable."""
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()

    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)
    logging.critical("Wrong path provided: %s", filename)
    raise ValueError


def dump_btf_json(vmlinux_path: str) -> dict:
    """Dumps BTF data from vmlinux as JSON via bpftool or Pahole."""
    if has_btf_section(vmlinux_path):
        logging.info(
            "Embedded .BTF section found in %s; extracting via bpftool.",
            vmlinux_path,
        )
        raw_json_data = subprocess.check_output(
            [BPFTOOL, "btf", "dump", "--json", "file", vmlinux_path]
        )
    else:
        logging.info(
            "No embedded .BTF section in %s; encoding detached BTF via pahole.",
            vmlinux_path,
        )
        with tempfile.NamedTemporaryFile() as tmp:
            logging.info("TMP file created: %s", tmp.name)

            subprocess.run(
                [PAHOLE, f"--btf_encode_detached={tmp.name}", vmlinux_path],
                check=True,
            )

            if not os.path.getsize(tmp.name):
                logging.critical(
                    "The tmp file doesn't contain valid BTF encoded data: %s",
                    tmp.name,
                )
                raise ValueError

            logging.info(
                "Data size in TMP file: %d", os.path.getsize(tmp.name)
            )
            raw_json_data = subprocess.check_output(
                [BPFTOOL, "btf", "dump", "--json", "file", tmp.name]
            )

    if not raw_json_data:
        logging.critical(
            "The JSON formatted BTF data could not be extracted from: %s",
            vmlinux_path,
        )
        raise ValueError

    json_data = {}
    try:
        json_data = json.loads(raw_json_data)
        logging.info("Length of parsed BTF JSON: %d", len(json_data))
    except ValueError:
        logging.critical("Can't parse BTF data in JSON format")

    return json_data


def unwrap_modifiers(btf_type: dict, types: dict) -> dict:
    """Unwraps modifier wrappers (TYPEDEF, CONST, VOLATILE, RESTRICT, TYPE_TAG).

    Assigns typedef names to inline anonymous structs/enums.
    """
    modifiers = ["TYPEDEF", "CONST", "VOLATILE", "RESTRICT", "TYPE_TAG"]
    while btf_type.get("kind") in modifiers:
        if (btf_type["kind"] == "TYPEDEF") and (
            types.get(btf_type.get("type_id", 0), {}).get("name") == "(anon)"
        ):
            name = btf_type["name"]
            btf_type = types[btf_type["type_id"]]
            btf_type["name"] = name
        elif "type_id" in btf_type and btf_type["type_id"] != 0:
            btf_type = types[btf_type["type_id"]]
        else:
            break
    return btf_type


# pylint: disable=too-many-arguments,too-many-positional-arguments
def format_func_proto(
    pointer_type: dict,
    types: dict,
    struct_name: str,
    struct_size: int,
    obj: dict,
    prefix: str,
) -> str:
    """Formats function prototype signature for FUNC_PROTO pointer targets."""
    ret_type_name = "void"
    if pointer_type.get("ret_type_id", 0) != 0:
        expanded_object = obj.copy()
        expanded_object["type_id"] = pointer_type["ret_type_id"]
        deeper_types = get_shallow(
            types,
            struct_name,
            struct_size,
            expanded_object,
            pointer_type.get("name", "(anon)"),
            prefix,
        )
        if deeper_types:
            ret_type_name = deeper_types[0]["type"]

    fun_params = []
    for param in pointer_type.get("params", []):
        if param.get("type_id", 0) != 0:
            expanded_object = obj.copy()
            expanded_object["type_id"] = param["type_id"]
            expanded_object["bits_offset"] = 0
            deeper_types = get_shallow(
                types,
                struct_name,
                struct_size,
                expanded_object,
                pointer_type.get("name", "(anon)"),
                prefix,
            )

            if deeper_types:
                ptype = deeper_types[0]["type"]
                pname = param["name"]
                if pname != "(anon)":
                    param_str = (
                        (ptype + pname)
                        if ptype.endswith("*")
                        else (ptype + " " + pname)
                    )
                else:
                    param_str = (
                        (ptype + "?") if ptype.endswith("*") else (ptype + " ?")
                    )
                fun_params.append(param_str)
        else:
            pname = param.get("name", "")
            param_str = ("void *" + pname) if pname != "(anon)" else "void *?"
            fun_params.append(param_str)

    return f"{ret_type_name} (*<name>) ({', '.join(fun_params)})"


def format_anonymous_struct_or_union(
    pointer_type: dict,
    types: dict,
    struct_name: str,
    struct_size: int,
    obj: dict,
    prefix: str,
) -> str:
    """Formats inline member strings for anonymous struct/union pointers."""
    struct_members = []
    for member in pointer_type.get("members", []):
        if member.get("type_id", 0) != 0:
            expanded_object = obj.copy()
            expanded_object["type_id"] = member["type_id"]
            deeper_types = get_shallow(
                types,
                struct_name,
                struct_size,
                expanded_object,
                pointer_type.get("name", "(anon)"),
                prefix,
            )

            if deeper_types:
                mtype = deeper_types[0]["type"]
                mname = member["name"]
                if mname != "(anon)":
                    mem_str = (
                        (mtype + mname)
                        if mtype.endswith("*")
                        else (mtype + " " + mname)
                    )
                else:
                    mem_str = (
                        (mtype + "?") if mtype.endswith("*") else (mtype + " ?")
                    )
                struct_members.append(mem_str)

        elif member.get("type_id", 0) == 0:
            mname = member.get("name", "")
            mem_str = ("void *" + mname) if mname != "(anon)" else "void *?"
            struct_members.append(mem_str)

    kind_str = pointer_type["kind"].lower()
    return f"{kind_str} {{{', '.join(struct_members)}}} *"


def resolve_pointer_target(
    btf_type: dict,
    types: dict,
    struct_name: str,
    struct_size: int,
    obj: dict,
    prefix: str,
) -> str:
    """Resolves pointer target type and formats output type string."""
    if "type_id" not in btf_type:
        return "(anon) *"

    if btf_type["type_id"] == 0:
        return "void *"

    pointer_type = types[btf_type["type_id"]]
    depth = 0

    while "(anon)" in pointer_type.get("name", ""):
        depth += 1
        if depth > 100:
            break

        if pointer_type["kind"] in ["STRUCT", "UNION"]:
            pointer_type["name"] = format_anonymous_struct_or_union(
                pointer_type, types, struct_name, struct_size, obj, prefix
            )
            break
        if pointer_type["kind"] == "FUNC_PROTO":
            pointer_type["name"] = format_func_proto(
                pointer_type, types, struct_name, struct_size, obj, prefix
            )
            break
        if "type_id" in pointer_type and pointer_type["type_id"] != 0:
            pointer_type = types[pointer_type["type_id"]]
        elif "type_id" in pointer_type and pointer_type["type_id"] == 0:
            pointer_type["name"] = "void"
            break
        else:
            break

    pname = pointer_type.get("name", "void")
    pkind = pointer_type.get("kind", "")

    if pkind == "STRUCT":
        return (
            ("struct " + pname + " *")
            if not pname.endswith(")")
            else ("struct " + pname)
        )
    if pkind == "CONST":
        return (
            ("const " + pname + " *")
            if not pname.endswith(")")
            else ("const " + pname)
        )
    return (pname + " *") if not pname.endswith(")") else pname


def process_array_type(
    btf_type: dict,
    types: dict,
    struct_name: str,
    struct_size: int,
    obj: dict,
    parent_type: str,
    prefix: str,
    bits_offset: int,
) -> list:
    """Processes fixed-size array members by recursively unrolling indices."""
    shallow_types = []
    object_bits_offset = obj["bits_offset"] + bits_offset

    for index in range(btf_type["nr_elems"]):
        expanded_object = obj.copy()
        expanded_object["type_id"] = btf_type["type_id"]
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
            element["bits_end"] -= obj["bits_offset"]
            object_bits_offset = element["bits_end"]

        object_bits_offset = 8 * math.ceil(
            (sorted_deepest[0]["bits_end"] if sorted_deepest else 0) / 8
        )
        shallow_types += deeper_types

    return shallow_types


def process_struct_or_union_type(
    btf_type: dict,
    types: dict,
    struct_name: str,
    struct_size: int,
    obj: dict,
    prefix: str,
    bits_offset: int,
) -> list:
    """Processes struct or union members, including bitfield offsets."""
    shallow_types = []
    members = list(enumerate(btf_type.get("members", [])))
    bitfield_id = -1

    for idx, member in members:
        if btf_type["kind"] == "UNION":
            new_prefix = prefix + "/*" + str(idx) + ":" + obj["name"] + "*/"
        else:
            new_prefix = prefix + obj["name"] + "."

        if "bitfield_size" in member:
            if [
                True
                for mem_id, mem in members
                if (mem_id == idx - 1) and ("bitfield_size" not in mem)
            ]:
                bitfield_id = idx
            elif idx == 0:
                bitfield_id = 0

            member["bits_offset"] = [
                mem["bits_offset"]
                for mem_id, mem in members
                if mem_id == bitfield_id
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
            btf_type.get("name", "(anon)"),
            new_prefix,
            bits_offset + obj["bits_offset"],
        )

        shallow_types += deeper_types

    return shallow_types


def process_pointer_or_scalar_type(
    btf_type: dict,
    types: dict,
    struct_name: str,
    struct_size: int,
    obj: dict,
    parent_type: str,
    prefix: str,
    bits_offset: int,
) -> list:
    """Processes leaf node types (PTR, ENUM, ARRAY flex, INT, FLOAT, FWD)."""
    kind = btf_type["kind"]
    out_type = btf_type.get("name", "(anon)")
    is_flex = False

    if btf_type["kind"] == "PTR":
        out_type = resolve_pointer_target(
            btf_type, types, struct_name, struct_size, obj, prefix
        )
        nr_bits = 64  # PTR_SIZE
        bits_end = bits_offset + obj["bits_offset"] + nr_bits
    elif btf_type["kind"] in ["ENUM", "ENUM64"]:
        nr_bits = btf_type.get("size", 4) * 8
        bits_end = bits_offset + obj["bits_offset"] + nr_bits
    elif btf_type["kind"] == "ARRAY":
        expanded_object = obj.copy()
        expanded_object["type_id"] = btf_type["type_id"]
        expanded_object["bits_offset"] = 0
        sorted_deepest = sorted(
            get_shallow(
                types,
                struct_name,
                struct_size,
                expanded_object,
                btf_type.get("name", "(anon)"),
                prefix,
                0,
            ),
            key=lambda x: x["bits_end"],
            reverse=True,
        )
        nr_bits = sorted_deepest[0]["bits_end"] if sorted_deepest else 0

        kind = (
            "ARRAY<"
            + unwrap_modifiers(types[btf_type["type_id"]], types)["kind"]
            + ">"
        )
        is_flex = True
        bits_end = bits_offset + obj["bits_offset"]
    else:
        if "nr_bits" in btf_type:
            nr_bits = btf_type["nr_bits"]
        elif "size" in btf_type:
            nr_bits = btf_type["size"] * 8
        else:
            nr_bits = 0
        bits_end = bits_offset + obj["bits_offset"] + nr_bits

    return [
        {
            "struct_name": struct_name,
            "struct_size": struct_size,
            "parent_type": parent_type,
            "kind": kind,
            "type": out_type,
            "name": prefix + obj["name"],
            "bits_offset": bits_offset + obj["bits_offset"],
            "nr_bits": nr_bits,
            "bits_end": bits_end,
            "is_flex": is_flex,
        }
    ]


def get_shallow(
    types,
    struct_name,
    struct_size,
    obj,
    parent_type,
    prefix="",
    bits_offset=0,
):
    """Recursively flattens BTF member types into shallow field records."""
    btf_type = unwrap_modifiers(types[obj["type_id"]], types)

    if btf_type["kind"] == "ARRAY" and btf_type.get("nr_elems", 0) > 0:
        return process_array_type(
            btf_type,
            types,
            struct_name,
            struct_size,
            obj,
            parent_type,
            prefix,
            bits_offset,
        )
    if btf_type["kind"] in ["STRUCT", "UNION"]:
        return process_struct_or_union_type(
            btf_type,
            types,
            struct_name,
            struct_size,
            obj,
            prefix,
            bits_offset,
        )
    return process_pointer_or_scalar_type(
        btf_type,
        types,
        struct_name,
        struct_size,
        obj,
        parent_type,
        prefix,
        bits_offset,
    )
# pylint: enable=too-many-arguments,too-many-positional-arguments


def create_types_table(json_data: dict, con: sqlite3.Connection) -> int:
    """Creates SQLite 'types' table schema and populates extracted fields."""
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
    for btf_type in json_data["types"]:
        types[btf_type["id"]] = btf_type

    for btf_type in json_data["types"]:
        if btf_type["kind"] == "STRUCT":
            sname = btf_type.get("name", "(anon)")
            ssize = btf_type.get("size", 0)
            for member in btf_type.get("members", []):
                data += get_shallow(types, sname, ssize, member, sname)

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
    """Connects to SQLite database file and writes BTF type records."""
    with closing(sqlite3.connect(db_file)) as conn:
        sqlite3.register_adapter(bool, int)
        sqlite3.register_converter("BOOLEAN", lambda v: bool(int(v)))

        with conn as con:
            res = create_types_table(json_data, con)
            print(f"BTF data saved into Sqlite DB. Number of lines: {res}")


def check_tools(require_pahole: bool = True) -> None:
    """Verifies that Bpftool, Readelf, and Pahole CLI utilities exist."""
    tools = [
        ("Bpftool", BPFTOOL, ["--version"], "bpftool"),
        ("Readelf", READELF, ["-v"], "binutils"),
    ]
    if require_pahole:
        tools.insert(0, ("Pahole", PAHOLE, ["--version"], "dwarves"))

    for name, path, flag, pkg in tools:
        if not path or not os.path.exists(path):
            logging.critical(
                "Tool '%s' not found at '%s'! "
                "Please install it (e.g. 'sudo apt install %s').",
                name,
                path,
                pkg,
            )
            raise FileNotFoundError(
                f"Required binary '{name}' not found at {path}"
            )

        try:
            subprocess.run(
                [path] + flag,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            logging.info("%s found: %s", name, path)
        except (subprocess.CalledProcessError, OSError) as exc:
            logging.critical(
                "Tool '%s' at '%s' failed execution check: %s",
                name,
                path,
                exc,
            )
            raise ValueError(
                f"Tool '{name}' failed execution check: {exc}"
            ) from exc


def main():
    """CLI entry point for extracting BTF field data from vmlinux to SQLite."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "vmlinux",
        help="Kernel binary (vmlinux) with BTF or debug data (DWARF).",
        type=vmlinux,
        nargs=1,
    )
    parser.add_argument(
        "--json_file",
        nargs="?",
        help="Path where to store JSON file with BTF data from vmlinux.",
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

    check_tools(require_pahole=not has_btf_section(args.vmlinux[0]))

    json_data = dump_btf_json(args.vmlinux[0])

    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f)
        logging.info("Saved BTF JSON output to: %s", args.json_file)

    create_sql_db(args.db_file, json_data)


if __name__ == "__main__":
    main()
