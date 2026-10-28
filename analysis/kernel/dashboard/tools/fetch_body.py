#!/usr/bin/env python3
"""Function Body & Context Source Fetcher CLI."""

import argparse

from tools.lib.metadata import (
    add_standard_tool_cli_args,
    run_json_or_text_cli,
)
from tools.lib.source import fetch_function_body, format_body_text

__all__ = [
    "fetch_function_body",
    "format_body_text",
    "main",
]


def _build_arg_parser() -> argparse.ArgumentParser:
    """Create argument parser for fetch_body CLI."""
    ap = argparse.ArgumentParser(
        description=(
            "Fetch line-numbered C source for a kernel function or file span"
            " from disk (--repo-dir / WORKSPACE_DIR) or git_log.data fallback."
        )
    )
    add_standard_tool_cli_args(
        ap, include_syzkaller=True, include_repo_dir=True
    )
    ap.add_argument(
        "--function",
        "--name",
        "-fn",
        dest="function",
        help="Function name to fetch",
    )
    ap.add_argument(
        "--file", "-f", help="File path (for disambiguation or explicit span)"
    )
    ap.add_argument(
        "--start-line",
        type=int,
        default=None,
        help="Explicit 1-based start line in --file",
    )
    ap.add_argument(
        "--end-line",
        type=int,
        default=None,
        help="Explicit 1-based end line in --file",
    )
    ap.add_argument(
        "--up-to-line",
        type=int,
        default=None,
        help=(
            "Truncate function body after this line + --context"
            " (keeps signature through target call site)"
        ),
    )
    ap.add_argument(
        "--context",
        "-C",
        type=int,
        default=5,
        help=(
            "Lines of context before signature and after closing '}'"
            " (default: 5)"
        ),
    )
    ap.add_argument(
        "--annotate",
        action="store_true",
        help=(
            "Annotate lines with capability gates, callees, Kconfig, and"
            " Syzkaller"
        ),
    )
    ap.add_argument(
        "--git-log-only",
        action="store_true",
        help="Force pure-DB reading from git_log.data without disk checkout",
    )
    ap.add_argument(
        "--allow-ambiguous",
        action="store_true",
        help="Pick first candidate if --function matches multiple files",
    )
    return ap


def main() -> None:
    """CLI entry point for fetch_body."""
    args = _build_arg_parser().parse_args()
    run_json_or_text_cli(
        args,
        lambda: fetch_function_body(
            args.db,
            function_name=args.function,
            file_path=args.file,
            start_line=args.start_line,
            end_line=args.end_line,
            up_to_line=args.up_to_line,
            context=args.context,
            annotate=args.annotate,
            repo_dir=args.repo_dir,
            force_git_log=args.git_log_only,
            allow_ambiguous=args.allow_ambiguous,
            syzkaller_db=args.syzkaller_db,
            verbose=args.verbose,
        ),
        format_body_text,
    )


if __name__ == "__main__":
    main()
