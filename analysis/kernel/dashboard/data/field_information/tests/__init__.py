"""Package init for field_information tests."""

from pathlib import Path

__path__.extend(str(p) for p in Path(__file__).parents[2].glob("*/tests"))
