#!/usr/bin/env python3
"""Build the syscall_node table from the two split CodeQL query outputs."""
import argparse
import csv
import os
import sqlite3
import sys
from collections import defaultdict

try:
    from utils import detect_prefix, trim_filename
except ImportError:
    from Data.CodeQL.utils import detect_prefix, trim_filename


def loc_string(file, sl, sc, el, ec):
    """Assemble a 'file:startLine:startCol:endLine:endCol' location string."""
    return f"{file}:{sl}:{sc}:{el}:{ec}"


def load_locs(path):
    """
    Load location components from locs.csv.
    Returns:
      by_fn_file: map of (function_name, relative_file) -> list of location strings
      by_name: map of function_name -> list of (relative_file, location_string)
      prefix: detected common root directory prefix
    """
    sample_files = []
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2 and row[1]:
                sample_files.append(row[1].strip().strip('"'))
                if len(sample_files) >= 1000:
                    break

    prefix = detect_prefix(sample_files)

    by_fn_file = defaultdict(list)
    by_name = defaultdict(list)

    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) < 6:
                continue
            name = row[0].strip().strip('"')
            raw_file = row[1].strip().strip('"')
            file = trim_filename(raw_file, prefix)
            sl, sc, el, ec = row[2], row[3], row[4], row[5]
            loc = loc_string(file, sl, sc, el, ec)
            by_fn_file[(name, file)].append(loc)
            by_name[name].append((file, loc))

    return by_fn_file, by_name, prefix


def syscall_locations(by_name):
    """Map each __do_sys_* entry to its definition location, preferring .c files."""
    out = {}
    for name, file_loc_pairs in by_name.items():
        if name.startswith("__do_sys_"):
            c_locs = [loc for file, loc in file_loc_pairs if file.endswith(".c")]
            if c_locs:
                out[name] = c_locs[0]
            elif file_loc_pairs:
                out[name] = file_loc_pairs[0][1]
    return out


def gen_rows(pairs_path, by_fn_file, by_name, sysloc, prefix=""):
    """
    Yield (syscall, function, syscall_location, function_location) rows.
    If pairs.csv provides a 3rd column (file), joins on (function, file) to
    eliminate cross-file Cartesian collisions on duplicate function names.
    """
    miss_fn = miss_sys = 0
    seen = set()

    with open(pairs_path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) < 2:
                continue
            syscall = row[0].strip().strip('"')
            function = row[1].strip().strip('"')
            if syscall == "syscall" and function == "function":
                continue  # Header row

            sloc = sysloc.get(syscall)
            if sloc is None:
                miss_sys += 1
                continue

            # Check if file path is available in column 3
            if len(row) >= 3 and row[2].strip().strip('"'):
                raw_file = row[2].strip().strip('"')
                file = trim_filename(raw_file, prefix)
                flocs = by_fn_file.get((function, file))
                if not flocs:
                    # Fallback to by_name if file-specific match not found
                    flocs = [loc for _, loc in by_name.get(function, [])]
            else:
                flocs = [loc for _, loc in by_name.get(function, [])]

            if not flocs:
                miss_fn += 1
                continue

            for floc in flocs:
                row_tuple = (syscall, function, sloc, floc)
                if row_tuple not in seen:
                    seen.add(row_tuple)
                    yield row_tuple

    if miss_fn:
        print(f"WARNING: {miss_fn} pairs had a function with no location", file=sys.stderr)
    if miss_sys:
        print(f"WARNING: {miss_sys} pairs had a syscall with no root location", file=sys.stderr)


def write_db(db_path, rows):
    """Drop, recreate and index the syscall_node table, then insert all rows."""
    con = sqlite3.connect(db_path)
    con.execute("DROP TABLE IF EXISTS syscall_node")
    con.execute(
        "CREATE TABLE syscall_node ("
        "syscall TEXT, function TEXT, syscall_location TEXT, function_location TEXT)"
    )
    con.executemany("INSERT INTO syscall_node VALUES (?,?,?,?)", rows)
    con.execute("CREATE INDEX idx_syscall_node_function ON syscall_node(function)")
    con.execute("CREATE INDEX idx_syscall_node_syscall ON syscall_node(syscall)")
    con.commit()
    n = con.execute("SELECT count(*) FROM syscall_node").fetchone()[0]
    con.close()
    print(f"built {db_path}: syscall_node has {n} rows", file=sys.stderr)


def write_csv(out_path, rows):
    """Write all rows to a CSV file."""
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        n = sum(1 for _ in map(w.writerow, rows))
    print(f"wrote {n} rows to {out_path}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="Assemble syscall_node table/CSV from split CodeQL query outputs."
    )
    ap.add_argument(
        "--pairs",
        required=True,
        help="syscall-node-pairs.ql output (syscall, function[, file])",
    )
    ap.add_argument(
        "--locs",
        required=True,
        help="syscall-node-locs.ql output (name, file, sl, sc, el, ec)",
    )
    ap.add_argument("--db", help="build/refresh syscall_node in this SQLite DB (primary mode)")
    ap.add_argument("--out", help="alternatively, write the rows to a CSV file")
    args = ap.parse_args()

    if not os.path.isfile(args.pairs):
        sys.exit(f"Error: pairs file not found: {args.pairs}")
    if not os.path.isfile(args.locs):
        sys.exit(f"Error: locs file not found: {args.locs}")
    if not args.db and not args.out:
        sys.exit("need --out or --db")

    by_fn_file, by_name, prefix = load_locs(args.locs)
    sysloc = syscall_locations(by_name)
    rows = gen_rows(args.pairs, by_fn_file, by_name, sysloc, prefix)

    if args.db:
        write_db(args.db, rows)
    elif args.out:
        write_csv(args.out, rows)


if __name__ == "__main__":
    main()
