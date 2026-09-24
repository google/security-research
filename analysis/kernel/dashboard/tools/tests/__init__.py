"""Unit tests for the Kernel Dashboard CLI tools."""

from pathlib import Path

__path__.extend(
    str(p) for p in Path(__file__).resolve().parents[2].glob("**/tests")
)
