"""Package init for btf_data tests."""

from pathlib import Path

__path__.extend(str(p) for p in Path(__file__).parents[2].glob("*/tests"))
