#!/usr/bin/env python3
"""Multiplicity-Aware Function Locator & Disambiguator CLI."""

import argparse
import json
import re
import sqlite3
import sys

from tools.lib.locator import format_locator_text, locate_functions
from tools.lib.metadata import add_standard_tool_cli_args, verify_db_and_indexes

__all__ = [
    "locate_functions",
    "format_locator_text",
    "main",
]


def _build_arg_parser() -> argparse.ArgumentParser:
    """Create argument parser for locate_function CLI."""
    ap = argparse.ArgumentParser(
        description=(
            "Resolve kernel function names or file:line locations to canonical"
            " (function_name, file_path) candidates with degree and Kconfig"
            " metadata."
        )
    )
    add_standard_tool_cli_args(
        ap, include_syzkaller=True, include_repo_dir=True
    )
    ap.add_argument(
        "--name",
        "--function",
        "-fn",
        dest="name",
        help="Function name or pattern to locate",
    )
    ap.add_argument("--file", "-f", help="Optional file path or suffix filter")
    ap.add_argument(
        "--line",
        "-l",
        type=int,
        help="Line number within --file to resolve enclosing function",
    )
    ap.add_argument(
        "--match",
        choices=["exact", "substring", "regex"],
        default="exact",
        help="Matching mode for --name (default: exact)",
    )
    ap.add_argument(
        "--include-non-runtime",
        action="store_true",
        help="Include pre-boot/host binary definitions (arch/*/boot/*, etc.)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of candidates to return (default: 50)",
    )
    return ap


def main() -> None:
    """CLI entry point for locate_function."""
    ap = _build_arg_parser()
    args = ap.parse_args()
    if verify_db_and_indexes(args):
        return
    if not args.name and not (args.file and args.line is not None):
        ap.print_help()
        sys.exit("\nError: Provide either --name or (--file AND --line).")

    try:
        res = locate_functions(
            args.db,
            name=args.name,
            file_path=args.file,
            line_number=args.line,
            match_mode=args.match,
            repo_dir=args.repo_dir,
            syzkaller_db=args.syzkaller_db,
            include_non_runtime=args.include_non_runtime,
            limit=args.limit,
            verbose=args.verbose,
        )
    except (
        FileNotFoundError,
        ValueError,
        sqlite3.Error,
        re.error,
    ) as e:
        sys.exit(f"Error: {e}")

    if args.format == "json":
        print(json.dumps(res, indent=2))
    else:
        print(format_locator_text(res))
    if res["count"] == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
