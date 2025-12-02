"""Canonical IR model for auditzoo.

This module defines the language-neutral intermediate representation that all
analyses use, regardless of the backend (LSP, Joern, TreeSitter).
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum


@dataclass(frozen=True)
class ProgramId:
    """Unique identifier for a program/project."""

    id: str

    def __str__(self) -> str:
        return self.id


@dataclass(frozen=True)
class FunctionId:
    """Unique identifier for a function within a program."""

    program_id: ProgramId
    name: str
    file: Optional[str] = None
    line: Optional[int] = None

    def __str__(self) -> str:
        return f"{self.program_id}:{self.name}"


@dataclass(frozen=True)
class NodeId:
    """Unique identifier for a node/statement."""

    function_id: FunctionId
    node_index: int

    def __str__(self) -> str:
        return f"{self.function_id}:node{self.node_index}"


@dataclass(frozen=True)
class BasicBlockId:
    """Unique identifier for a basic block."""

    function_id: FunctionId
    block_index: int

    def __str__(self) -> str:
        return f"{self.function_id}:bb{self.block_index}"


class NodeKind(Enum):
    """Types of IR nodes."""

    CALL = "call"
    ASSIGNMENT = "assignment"
    RETURN = "return"
    BRANCH = "branch"
    LITERAL = "literal"
    IDENTIFIER = "identifier"
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    UNKNOWN = "unknown"


@dataclass
class IRNode:
    """A node in the IR (statement, expression, etc.)."""

    id: NodeId
    kind: NodeKind
    code: str
    line: Optional[int] = None
    column: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BasicBlock:
    """A basic block in the control flow graph."""

    id: BasicBlockId
    nodes: List[NodeId]
    successors: List[BasicBlockId] = field(default_factory=list)
    predecessors: List[BasicBlockId] = field(default_factory=list)


@dataclass
class Function:
    """A function in the program."""

    id: FunctionId
    name: str
    file: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    language: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Program:
    """Top-level program/project representation."""

    id: ProgramId
    name: str
    root_path: str
    language: str
    functions: Dict[str, FunctionId] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    version: int = 0
