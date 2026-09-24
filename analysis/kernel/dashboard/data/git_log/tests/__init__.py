"""Package init for git_log tests."""

from pathlib import Path

__path__.extend(str(d) for d in Path(__file__).parents[2].glob("*/tests"))
