"""Unit test package for CodeQL SQLite importers."""

from pathlib import Path

__path__.extend(
    str(p) for p in Path(__file__).resolve().parents[3].glob("**/tests")
)
