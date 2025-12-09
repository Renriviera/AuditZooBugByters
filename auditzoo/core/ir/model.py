"""CPG-centered IR model for AuditZoo.

This module defines minimal wrapper types around Joern's CPG.
The IR is not a language-neutral abstraction - it directly exposes CPG concepts
with convenience identifiers for common operations.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProgramId:
    """Unique identifier for a program/project."""

    id: str

    def __str__(self) -> str:
        return self.id


@dataclass
class Function:
    """A function/method in the program.

    Wraps a CPG method node with convenience fields.
    """

    cpg_id: str  # CPG node ID for this method
    program_id: ProgramId
    name: str
    signature: str | None = None
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    parameters: list[str] = field(default_factory=list)
    return_type: str | None = None
    language: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.program_id}:{self.name}"


# Legacy compatibility types (optional, can be removed if not needed)
@dataclass(frozen=True)
class FunctionId:
    """Legacy function identifier (optional).

    Kept for compatibility with existing code. New code should use
    Function.cpg_id directly.
    """

    program_id: ProgramId
    name: str
    file: str | None = None
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.program_id}:{self.name}"


# CPG Node Reference Type
CPGNodeId = str  # Type alias for CPG node IDs (strings)


@dataclass
class Program:
    """Top-level program/project representation.

    Minimal metadata wrapper - most information is in the CPG.
    """

    id: ProgramId
    name: str
    root_path: str
    language: str
    cpg_path: str | None = None  # Path to CPG database file
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 0  # Logical version for change tracking
