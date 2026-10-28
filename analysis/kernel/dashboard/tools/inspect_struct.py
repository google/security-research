#!/usr/bin/env python3
"""Kernel Struct Layout, Allocation & Field Access Lifecycle Inspector CLI."""

import argparse
from typing import Optional, Tuple

from tools.lib.metadata import (
    add_standard_tool_cli_args,
    run_json_or_text_cli,
)
from tools.lib.structs import (
    format_struct_text,
    inspect_struct,
    inspect_struct_with_conn,
)

__all__ = [
    "format_struct_text",
    "inspect_struct",
    "inspect_struct_with_conn",
    "main",
]


def _split_struct_and_field(
    raw_struct: str, explicit_field: Optional[str]
) -> Tuple[str, Optional[str]]:
    """Split 'struct_name.field_name' shorthand when --field is omitted."""
    if explicit_field or "." not in raw_struct:
        return raw_struct, explicit_field
    parts = raw_struct.split(".", 1)
    return parts[0], parts[1]


def _build_arg_parser() -> argparse.ArgumentParser:
    """Create argument parser for inspect_struct CLI."""
    ap = argparse.ArgumentParser(
        description=(
            "Inspect kernel C struct/union layouts (struct_locations &"
            " struct_fields), BTF offset parity (types), heap allocations"
            " (allocs & kmalloc_calls), field read/write/exec sites"
            " (field_access), and registered ops slots (ops_targets)."
        )
    )
    add_standard_tool_cli_args(
        ap, include_syzkaller=False, include_repo_dir=True
    )
    ap.add_argument(
        "--struct",
        "--name",
        "-s",
        dest="struct_name",
        required=True,
        help="Struct or union name (or 'struct_name.field_name' shorthand)",
    )
    ap.add_argument(
        "--file",
        "-f",
        default=None,
        help="Optional header/source file path filter to disambiguate struct",
    )
    ap.add_argument(
        "--field",
        default=None,
        help="Optional field name or dotted field path filter",
    )
    ap.add_argument(
        "--access-type",
        choices=["all", "write", "read", "exec"],
        default="all",
        help="Filter field_access rows by access type (default: all)",
    )
    ap.add_argument(
        "--match",
        choices=["exact", "wildcard", "substring", "regex"],
        default="exact",
        help="Struct name matching mode (default: exact)",
    )
    ap.add_argument(
        "--section",
        choices=["all", "layout", "allocs", "accesses", "ops"],
        default="all",
        help="Output section filter (default: all)",
    )
    ap.add_argument(
        "--include-source",
        action="store_true",
        help="Include raw C struct definition lines from --repo-dir",
    )
    ap.add_argument(
        "--btf-db",
        default=None,
        help="Optional path to separate BTF SQLite DB (default: --db)",
    )
    ap.add_argument(
        "--allocs-db",
        default=None,
        help="Optional path to separate allocs SQLite DB (default: --db)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max field_access rows per category in output (default: 50)",
    )
    ap.add_argument(
        "--show-all",
        action="store_true",
        help="Show all field_access rows without --limit truncation",
    )
    return ap


def main() -> None:
    """CLI entry point for inspect_struct."""
    args = _build_arg_parser().parse_args()
    s_name, f_filter = _split_struct_and_field(args.struct_name, args.field)
    run_json_or_text_cli(
        args,
        lambda: inspect_struct(
            args.db,
            s_name,
            file_filter=args.file,
            field_filter=f_filter,
            access_type=args.access_type,
            match_mode=args.match,
            section=args.section,
            include_source=args.include_source,
            btf_db=args.btf_db,
            allocs_db=args.allocs_db,
            repo_dir=args.repo_dir,
            limit=args.limit,
            show_all=args.show_all,
            verbose=args.verbose,
        ),
        lambda res: format_struct_text(
            res, limit=args.limit, show_all=args.show_all
        ),
    )


if __name__ == "__main__":
    main()
