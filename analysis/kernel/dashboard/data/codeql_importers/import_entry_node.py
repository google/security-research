#!/usr/bin/env python3
"""Build entry_node table from entry-node-pairs.ql and syscall-node-locs.ql."""

import argparse
from collections import defaultdict
import csv
import os
import sqlite3
import sys

try:
    from utils import detect_prefix, trim_filename
except ImportError:
    from Data.CodeQL.utils import detect_prefix, trim_filename


def loc_string(file_path, sl, sc, el, ec):
    """Assemble a 'file:startLine:startCol:endLine:endCol' location string."""
    return f"{file_path}:{sl}:{sc}:{el}:{ec}"


def _sample_loc_files(path, limit=1000):
    """Collects up to `limit` sample file paths from a locs CSV file."""
    sample_files = []
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) >= 2 and row[1]:
                sample_files.append(row[1].strip().strip('"'))
                if len(sample_files) >= limit:
                    break
    return sample_files


def load_locs(path):
    """Load location components from locs.csv.

    Args:
      path: Path to the locs CSV file.

    Returns:
      Tuple of (by_fn_file, by_name, prefix).
    """
    prefix = detect_prefix(_sample_loc_files(path))
    by_fn_file = defaultdict(list)
    by_name = defaultdict(list)

    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) < 6:
                continue
            name = row[0].strip().strip('"')
            file_path = trim_filename(row[1].strip().strip('"'), prefix)
            loc = loc_string(file_path, row[2], row[3], row[4], row[5])
            by_fn_file[(name, file_path)].append(loc)
            by_name[name].append((file_path, loc))

    return by_fn_file, by_name, prefix


def entry_locations(by_name):
    """Map each function name to its definition location (.c preferred)."""
    out = {}
    for name, file_loc_pairs in by_name.items():
        c_locs = [loc for f, loc in file_loc_pairs if f.endswith(".c")]
        if c_locs:
            out[name] = c_locs[0]
        elif file_loc_pairs:
            out[name] = file_loc_pairs[0][1]
    return out


def _resolve_fn_locs(row, function, by_fn_file, by_name, prefix):
    """Resolves function location strings for an entry-node-pairs.csv row."""
    if len(row) >= 4 and row[3].strip().strip('"'):
        file_path = trim_filename(row[3].strip().strip('"'), prefix)
        flocs = by_fn_file.get((function, file_path))
        if flocs:
            return flocs
    return [loc for _, loc in by_name.get(function, [])]


def _parse_pair_row(row):
    """Extract (entry_kind, entry, function) from a pairs CSV row."""
    return (
        row[0].strip().strip('"'),
        row[1].strip().strip('"'),
        row[2].strip().strip('"'),
    )


def gen_rows(pairs_path, by_fn_file, by_name, entloc, prefix=""):
    """Yield (entry_kind, entry, function, entry_location, function_location).

    Joins on (function, file) using the 4th column of entry-node-pairs.csv to
    eliminate cross-file Cartesian collisions on duplicate function names.

    Args:
      pairs_path: Path to entry-node-pairs CSV file.
      by_fn_file: Dict mapping (function, file) to list of location strings.
      by_name: Dict mapping function name to list of (file, location) pairs.
      entloc: Dict mapping entry root name to its root location string.
      prefix: Detected root directory prefix to strip from file paths.

    Yields:
      5-tuples (entry_kind, entry, function, entry_location, function_location).
    """
    misses = [0, 0]
    seen = set()

    with open(pairs_path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            entry_kind, entry, function = _parse_pair_row(row)
            if entry_kind == "entry_kind" and entry == "entry":
                continue

            eloc = entloc.get(entry)
            if eloc is None:
                misses[0] += 1
                continue

            flocs = _resolve_fn_locs(row, function, by_fn_file, by_name, prefix)
            if not flocs:
                misses[1] += 1
                continue

            for floc in flocs:
                if (entry_kind, entry, function, eloc, floc) not in seen:
                    seen.add((entry_kind, entry, function, eloc, floc))
                    yield (entry_kind, entry, function, eloc, floc)

    if misses[1]:
        print(
            f"WARNING: {misses[1]} pairs had a function with no location",
            file=sys.stderr,
        )
    if misses[0]:
        print(
            f"WARNING: {misses[0]} pairs had an entry root with no location",
            file=sys.stderr,
        )


def write_db(db_path, rows):
    """Drop, recreate and index the entry_node table, then insert all rows."""
    con = sqlite3.connect(db_path)
    con.execute("DROP TABLE IF EXISTS entry_node")
    con.execute(
        "CREATE TABLE entry_node ("
        "entry_kind TEXT, entry TEXT, function TEXT, "
        "entry_location TEXT, function_location TEXT)"
    )
    con.executemany("INSERT INTO entry_node VALUES (?,?,?,?,?)", rows)
    con.execute(
        "CREATE INDEX idx_entry_node_function ON entry_node(function)"
    )
    con.execute(
        "CREATE INDEX idx_entry_node_entry ON entry_node(entry)"
    )
    con.execute(
        "CREATE INDEX idx_entry_node_kind ON entry_node(entry_kind)"
    )
    con.commit()
    n = con.execute("SELECT count(*) FROM entry_node").fetchone()[0]
    con.close()
    print(f"built {db_path}: entry_node has {n} rows", file=sys.stderr)


def write_csv(out_path, rows):
    """Write all rows to a CSV file."""
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        n = sum(1 for _ in map(writer.writerow, rows))
    print(f"wrote {n} rows to {out_path}", file=sys.stderr)


def main():
    """Parses CLI arguments and builds the entry_node table or CSV."""
    ap = argparse.ArgumentParser(
        description=(
            "Assemble entry_node table/CSV from entry-node-pairs.ql and "
            "syscall-node-locs.ql outputs."
        )
    )
    ap.add_argument(
        "--pairs",
        required=True,
        help="entry-node-pairs.ql output (entry_kind, entry, function[, file])",
    )
    ap.add_argument(
        "--locs",
        required=True,
        help="syscall-node-locs.ql output (name, file, sl, sc, el, ec)",
    )
    ap.add_argument(
        "--db",
        help="build/refresh entry_node in this SQLite DB (primary mode)",
    )
    ap.add_argument(
        "--out", help="alternatively, write the rows to a CSV file"
    )
    args = ap.parse_args()

    if not os.path.isfile(args.pairs):
        sys.exit(f"Error: pairs file not found: {args.pairs}")
    if not os.path.isfile(args.locs):
        sys.exit(f"Error: locs file not found: {args.locs}")
    if not args.db and not args.out:
        sys.exit("need --out or --db")

    by_fn_file, by_name, prefix = load_locs(args.locs)
    entloc = entry_locations(by_name)
    rows = gen_rows(args.pairs, by_fn_file, by_name, entloc, prefix)

    if args.db:
        write_db(args.db, rows)
    elif args.out:
        write_csv(args.out, rows)


if __name__ == "__main__":
    main()
