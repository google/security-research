#!/usr/bin/env python3
"""Path trimming utility functions for CodeQL CSV dataset processing."""

from collections import Counter
from typing import Sequence

KERNEL_TOP_DIRS = (
    "arch/",
    "block/",
    "certs/",
    "crypto/",
    "drivers/",
    "fs/",
    "include/",
    "init/",
    "io_uring/",
    "ipc/",
    "kernel/",
    "lib/",
    "mm/",
    "net/",
    "rust/",
    "samples/",
    "scripts/",
    "security/",
    "sound/",
    "tools/",
    "usr/",
    "virt/",
)


def _strip_file_scheme(path: str) -> str:
    """Strips leading file:// scheme if present while preserving absolute slash."""
    if not path:
        return ""
    if path.startswith("file:///"):
        return path[len("file://") :]
    if path.startswith("file://"):
        return path[len("file://") :]
    return path


def detect_prefix(paths: Sequence[str]) -> str:
    """Scans all paths in a dataset to find the most common kernel root prefix."""
    prefixes = []
    for raw_path in paths:
        path = _strip_file_scheme(raw_path)
        if not path or not path.startswith("/"):
            continue
        for top_dir in KERNEL_TOP_DIRS:
            idx = path.find("/" + top_dir)
            if idx != -1:
                prefixes.append(path[: idx + 1])
                break

    if prefixes:
        # Return the statistical majority root prefix across all dataset paths
        return Counter(prefixes).most_common(1)[0][0]
    return ""


def trim_filename(path: str, prefix: str = "") -> str:
    """Strips the detected root directory prefix from a file path."""
    if not path:
        return ""

    path = _strip_file_scheme(path)
    clean_prefix = _strip_file_scheme(prefix) if prefix else ""

    if clean_prefix and path.startswith(clean_prefix):
        return path[len(clean_prefix) :]

    # Fallback for individual paths that did not match the detected root prefix
    for top_dir in KERNEL_TOP_DIRS:
        idx = path.find("/" + top_dir)
        if idx != -1:
            return path[idx + 1 :]
        if path.startswith(top_dir):
            return path

    return path
