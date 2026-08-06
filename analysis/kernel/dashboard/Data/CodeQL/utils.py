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


def detect_prefix(paths: Sequence[str]) -> str:
    """Scans all paths in a dataset to find the most common kernel root prefix."""
    prefixes = []
    for path in paths:
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

    if prefix and path.startswith(prefix):
        return path[len(prefix) :]

    # Fallback for individual paths that did not match the detected root prefix
    for top_dir in KERNEL_TOP_DIRS:
        idx = path.find("/" + top_dir)
        if idx != -1:
            return path[idx + 1 :]
        if path.startswith(top_dir):
            return path

    return path
