#!/usr/bin/python3

import logging
import sqlite3
import argparse

from contextlib import closing


def find_type_by_id(
    type_id: int, cur: sqlite3.Cursor, indent: int, rec_dep: int
) -> None:
    res = cur.execute(
        "SELECT id, kind, name, size, index_type_id, type_id, ret_type_id FROM types WHERE id = ?",
        (type_id,),
    ).fetchall()

    if not res:
        return

    if len(res) != 1:
        logging.critical("Hm. More than one types entry found: %s", str(res))
        raise ValueError

    print(
        " " * indent
        + "-- TYPE --\n"
        + " " * indent
        + "id: "
        + str(res[0][0])
        + "\n"
        + " " * indent
        + "kind: "
        + str(res[0][1])
        + "\n"
        + " " * indent
        + "name: "
        + str(res[0][2])
        + "\n"
        + " " * indent
        + "size: "
        + str(res[0][3])
        + "\n"
        + " " * indent
        + "index_type_id: "
        + str(res[0][4])
        + "\n"
        + " " * indent
        + "ret_type_id: "
        + str(res[0][6])
        + "\n"
    )
    find_params(res[0][0], cur, indent, rec_dep)
    find_members(res[0][0], cur, indent, rec_dep)
    find_vars(res[0][0], cur, indent, rec_dep)
    find_values(res[0][0], cur, indent)

    if res[0][5] and (indent <= rec_dep * 2):
        find_type_by_id(res[0][5], cur, indent + 2, rec_dep)


def find_type_by_name(
    struct_name: str, cur: sqlite3.Cursor, rec_dep: int
) -> None:
    res = cur.execute(
        "SELECT id FROM types WHERE name = ?",
        (struct_name,),
    ).fetchall()

    if not res:
        logging.critical("Can't find provided type name in kernel's BTF data.")
        raise ValueError

    if len(res) != 1:
        logging.critical("Hm. More than one types entry found: %s", str(res))
        raise ValueError

    find_type_by_id(res[0][0], cur, 0, rec_dep)


def find_params(
    types_id: int, cur: sqlite3.Cursor, indent: int, rec_dep: int
) -> None:
    params = cur.execute(
        "SELECT types_id, name, type_id FROM params WHERE types_id = ?",
        (types_id,),
    ).fetchall()

    if not params:
        return

    print(" " * indent + "-- PARAMS --")

    for param in params:
        print(
            " " * indent
            + "id: "
            + str(param[0])
            + "\n"
            + " " * indent
            + "name: "
            + str(param[1])
            + "\n"
        )

        (
            find_type_by_id(param[2], cur, indent + 2, rec_dep)
            if param[2]
            else None
        )


def find_members(
    types_id: int, cur: sqlite3.Cursor, indent: int, rec_dep: int
) -> None:
    members = cur.execute(
        "SELECT types_id, name, type_id, bits_offset, bitfield_size FROM members WHERE types_id = ?",
        (types_id,),
    ).fetchall()

    if not members:
        return

    print(" " * indent + "-- MEMBERS --")

    for member in members:
        print(
            " " * indent
            + "id: "
            + str(member[0])
            + "\n"
            + " " * indent
            + "name: "
            + str(member[1])
            + "\n"
            + " " * indent
            + "bits_offset: "
            + str(member[3])
            + "\n"
            + " " * indent
            + "bitfield_size: "
            + str(member[4])
            + "\n"
        )

        (
            find_type_by_id(member[2], cur, indent + 2, rec_dep)
            if member[2]
            else None
        )


def find_vars(
    types_id: int, cur: sqlite3.Cursor, indent: int, rec_dep: int
) -> None:
    vars = cur.execute(
        "SELECT types_id, type_id, offset, size FROM vars WHERE types_id = ?",
        (types_id,),
    ).fetchall()

    if not vars:
        return

    print(" " * indent + "-- VARS --")

    for var in vars:
        print(
            " " * indent
            + "id: "
            + str(var[0])
            + "\n"
            + " " * indent
            + "offset: "
            + str(var[2])
            + "\n"
            + " " * indent
            + "size: "
            + str(var[3])
            + "\n"
        )

        find_type_by_id(var[1], cur, indent + 2, rec_dep) if var[1] else None


def find_values(types_id: int, cur: sqlite3.Cursor, indent: int) -> None:
    values = cur.execute(
        "SELECT types_id, val, name FROM `values` WHERE types_id = ?",
        (types_id,),
    ).fetchall()

    if not values:
        return

    print(" " * indent + "-- VALUES --")

    for value in values:
        print(
            " " * indent
            + "id: "
            + str(value[0])
            + "\n"
            + " " * indent
            + "val: "
            + str(value[1])
            + "\n"
            + " " * indent
            + "name: "
            + str(value[2])
            + "\n"
        )


def open_sql_db(db_file: str, struct_name: list, rec_dep: int) -> None:
    with closing(sqlite3.connect(db_file)) as conn:
        with closing(conn.cursor()) as cur:
            for struct in struct_name:
                print("----------------> %s <---------------------" % struct)

                find_type_by_name(struct, cur, rec_dep)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("btf_db", help="Sqlite3 DB with BTF data.", nargs=1)
    parser.add_argument(
        "struct_name",
        help="Structure to look for in BTF database.",
        nargs="*",
        default=["msg_msg"],
    )
    parser.add_argument(
        "recursion_depth",
        nargs="?",
        type=int,
        help="Depth of recursive type querying.",
        default="5",
    )

    args = parser.parse_args()

    open_sql_db(args.btf_db[0], args.struct_name, args.recursion_depth)


if __name__ == "__main__":
    main()
