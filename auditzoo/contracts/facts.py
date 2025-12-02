"""Shared fact types for semantic information.

This module defines the fact types that analyses produce and consume.
All facts are stored in the central fact store maintained by IRStoreAgent.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class FactType(Enum):
    """Types of facts that can be stored."""

    POINTS_TO = "points_to"
    RANGE = "range"
    TAINT = "taint"
    SLICE = "slice"
    ISSUE = "issue"
    CALL_GRAPH = "call_graph"


@dataclass
class Fact:
    """Base class for all facts."""

    fact_type: FactType
    program_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PointsToFact(Fact):
    """Points-to analysis result."""

    pointer: str  # Variable or expression
    targets: List[str]  # Possible targets
    context: Optional[str] = None  # Context (function, location)

    def __init__(
        self,
        program_id: str,
        pointer: str,
        targets: List[str],
        context: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            fact_type=FactType.POINTS_TO, program_id=program_id, metadata=kwargs
        )
        self.pointer = pointer
        self.targets = targets
        self.context = context


@dataclass
class RangeFact(Fact):
    """Range/interval analysis result."""

    variable: str
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    location: Optional[str] = None

    def __init__(
        self,
        program_id: str,
        variable: str,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        location: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            fact_type=FactType.RANGE, program_id=program_id, metadata=kwargs
        )
        self.variable = variable
        self.min_value = min_value
        self.max_value = max_value
        self.location = location


@dataclass
class TaintFact(Fact):
    """Taint analysis result."""

    source: str  # Taint source
    sink: str  # Taint sink
    path: List[str]  # Path from source to sink
    taint_kind: str = "generic"

    def __init__(
        self,
        program_id: str,
        source: str,
        sink: str,
        path: List[str],
        taint_kind: str = "generic",
        **kwargs
    ):
        super().__init__(
            fact_type=FactType.TAINT, program_id=program_id, metadata=kwargs
        )
        self.source = source
        self.sink = sink
        self.path = path
        self.taint_kind = taint_kind


@dataclass
class SliceFact(Fact):
    """Program slicing result."""

    seed: str  # Starting point for slice
    nodes: List[str]  # Nodes in the slice
    direction: str = "backward"  # "backward" or "forward"

    def __init__(
        self,
        program_id: str,
        seed: str,
        nodes: List[str],
        direction: str = "backward",
        **kwargs
    ):
        super().__init__(
            fact_type=FactType.SLICE, program_id=program_id, metadata=kwargs
        )
        self.seed = seed
        self.nodes = nodes
        self.direction = direction


class IssueSeverity(Enum):
    """Severity levels for issues."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IssueFact(Fact):
    """Issue/vulnerability detection result."""

    issue_type: str  # e.g., "buffer_overflow", "access_control"
    severity: IssueSeverity
    location: str  # Where the issue occurs
    message: str  # Description
    details: Dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        program_id: str,
        issue_type: str,
        severity: IssueSeverity,
        location: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(
            fact_type=FactType.ISSUE, program_id=program_id, metadata=kwargs
        )
        self.issue_type = issue_type
        self.severity = severity
        self.location = location
        self.message = message
        self.details = details or {}


@dataclass
class CallGraphFact(Fact):
    """Call graph information."""

    caller: str
    callee: str
    call_site: Optional[str] = None

    def __init__(
        self,
        program_id: str,
        caller: str,
        callee: str,
        call_site: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            fact_type=FactType.CALL_GRAPH, program_id=program_id, metadata=kwargs
        )
        self.caller = caller
        self.callee = callee
        self.call_site = call_site
