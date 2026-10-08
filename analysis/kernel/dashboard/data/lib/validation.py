"""Shared path, file, directory, CLI tool, and line-continuation helpers."""

from collections.abc import Iterable, Sequence
import logging
import os
import subprocess


def can_read_dir(dirname: str) -> str:
    """Validates that `dirname` is an existing readable directory.

    Args:
        dirname: Directory path to validate.

    Returns:
        The absolute path to `dirname`.

    Raises:
        ValueError: If `dirname` does not exist or is not readable.
    """
    if os.path.isdir(dirname) and os.access(dirname, os.R_OK):
        return os.path.abspath(dirname)
    logging.critical("Can't read directory '%s'.", dirname)
    raise ValueError(f"Directory is not readable: {dirname}")


def can_read_file(filename: str) -> str:
    """Validates that `filename` is an existing readable file.

    Args:
        filename: File path to validate.

    Returns:
        The validated `filename` string.

    Raises:
        ValueError: If `filename` does not exist or is not readable.
    """
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        return filename
    logging.critical("The file '%s' cannot be read.", filename)
    raise ValueError(f"File is not readable: {filename}")


def can_create_file(filename: str) -> str:
    """Validates that `filename` can be created in its parent directory.

    Args:
        filename: Target file path to validate.

    Returns:
        Normalized path joining the validated parent directory and filename.

    Raises:
        ValueError: If the parent directory does not exist or is not writable.
    """
    base_dir, file_name = os.path.split(filename)
    if not base_dir:
        base_dir = os.getcwd()
    if os.path.isdir(base_dir) and os.access(base_dir, os.W_OK):
        return os.path.join(base_dir, file_name)
    logging.critical(
        "The file '%s' cannot be created in '%s' directory.",
        file_name,
        base_dir,
    )
    raise ValueError(f"Cannot create file '{file_name}' in '{base_dir}'")


def verify_cli_tools(tool_commands: Sequence[Sequence[str]]) -> None:
    """Verifies that all required external CLI tools execute successfully.

    Args:
        tool_commands: Sequence of command argument lists (e.g. `[['git',
          '--version']]`).

    Raises:
        subprocess.CalledProcessError: If any command returns a non-zero exit
            status.
    """
    for cmd in tool_commands:
        subprocess.run(
            list(cmd),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def join_continuation_lines(lines: Iterable[str]) -> list[tuple[int, str]]:
    """Joins backslash-continued lines and strips `#` comments.

    Args:
        lines: Iterable of raw text lines (e.g. from a Makefile or Kbuild file).

    Returns:
        List of `(start_line_number, normalized_line)` tuples for non-empty
        logical lines.
    """
    result: list[tuple[int, str]] = []
    buf = ""
    start_line = 1
    for idx, raw in enumerate(lines, start=1):
        comment_pos = raw.find("#")
        if comment_pos != -1:
            raw = raw[:comment_pos]
        stripped = raw.rstrip("\r\n")
        if not buf:
            start_line = idx
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
        else:
            buf += stripped
            cleaned = " ".join(buf.split())
            if cleaned:
                result.append((start_line, cleaned))
            buf = ""
    if buf.strip():
        result.append((start_line, " ".join(buf.split())))
    return result
