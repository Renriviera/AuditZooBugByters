"""Shared fact types for semantic information.

This module defines the fact types that analyses produce and consume.
All facts are serialized as CPG Tags and stored in the CPG database.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FactType(Enum):
    """Types of facts that can be stored."""

    POINTS_TO = "points_to"
    RANGE = "range"
    TAINT = "taint"
    SLICE = "slice"
    ISSUE = "issue"
    CALL_GRAPH = "call_graph"


@dataclass
class Fact(ABC):
    """Base class for all facts.

    All facts must be serializable to CPG Tags (JSON-compatible dicts).
    Facts should reference CPG nodes by their string IDs.
    """

    fact_type: FactType
    program_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @abstractmethod
    def to_tag(self) -> dict:
        """Serialize fact to CPG Tag format (JSON-compatible dict).

        Returns:
            A dictionary that can be serialized to JSON and stored as a CPG tag.
        """
        pass

    @classmethod
    @abstractmethod
    def from_tag(cls, tag_data: dict) -> "Fact":
        """Deserialize fact from CPG Tag data.

        Args:
            tag_data: Dictionary loaded from CPG tag

        Returns:
            Reconstructed fact instance
        """
        pass


@dataclass
class PointsToFact(Fact):
    """Points-to analysis result.

    References CPG nodes for pointer and targets.
    """

    cpg_pointer_id: str = field(default="unknown")  # CPG node ID for the pointer
    cpg_target_ids: list[str] = field(
        default_factory=list
    )  # CPG node IDs for possible targets
    context: str | None = None  # Context (function name, location)

    def __init__(
        self,
        program_id: str,
        cpg_pointer_id: str,
        cpg_target_ids: list[str],
        context: str | None = None,
        **kwargs,
    ):
        super().__init__(
            fact_type=FactType.POINTS_TO, program_id=program_id, metadata=kwargs
        )
        self.cpg_pointer_id = cpg_pointer_id
        self.cpg_target_ids = cpg_target_ids
        self.context = context

    def to_tag(self) -> dict:
        """Serialize to CPG Tag."""
        return {
            "type": "points_to",
            "program_id": self.program_id,
            "pointer": self.cpg_pointer_id,
            "targets": self.cpg_target_ids,
            "context": self.context,
            "metadata": self.metadata,
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "PointsToFact":
        """Deserialize from CPG Tag."""
        return cls(
            program_id=tag_data["program_id"],
            cpg_pointer_id=tag_data["pointer"],
            cpg_target_ids=tag_data["targets"],
            context=tag_data.get("context"),
            **tag_data.get("metadata", {}),
        )


@dataclass
class RangeFact(Fact):
    """Range/interval analysis result.

    References CPG node for the variable.
    """

    cpg_variable_id: str = field(default="unknown")  # CPG node ID for the variable
    min_value: int | None = None
    max_value: int | None = None
    cpg_location_id: str | None = None  # CPG node ID for location

    def __init__(
        self,
        program_id: str,
        cpg_variable_id: str,
        min_value: int | None = None,
        max_value: int | None = None,
        cpg_location_id: str | None = None,
        **kwargs,
    ):
        super().__init__(
            fact_type=FactType.RANGE, program_id=program_id, metadata=kwargs
        )
        self.cpg_variable_id = cpg_variable_id
        self.min_value = min_value
        self.max_value = max_value
        self.cpg_location_id = cpg_location_id

    def to_tag(self) -> dict:
        """Serialize to CPG Tag."""
        return {
            "type": "range",
            "program_id": self.program_id,
            "variable": self.cpg_variable_id,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "location": self.cpg_location_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "RangeFact":
        """Deserialize from CPG Tag."""
        return cls(
            program_id=tag_data["program_id"],
            cpg_variable_id=tag_data["variable"],
            min_value=tag_data.get("min_value"),
            max_value=tag_data.get("max_value"),
            cpg_location_id=tag_data.get("location"),
            **tag_data.get("metadata", {}),
        )


@dataclass
class TaintFact(Fact):
    """Taint analysis result.

    References CPG nodes for source, sink, and path.
    """

    cpg_source_id: str = field(default="unknown")  # CPG node ID for taint source
    cpg_sink_id: str = field(default="unknown")  # CPG node ID for taint sink
    cpg_path_ids: list[str] = field(
        default_factory=list
    )  # CPG node IDs along the path from source to sink
    taint_kind: str = "generic"  # Type of taint (e.g., "sql_injection", "xss")

    def __init__(
        self,
        program_id: str,
        cpg_source_id: str,
        cpg_sink_id: str,
        cpg_path_ids: list[str],
        taint_kind: str = "generic",
        **kwargs,
    ):
        super().__init__(
            fact_type=FactType.TAINT, program_id=program_id, metadata=kwargs
        )
        self.cpg_source_id = cpg_source_id
        self.cpg_sink_id = cpg_sink_id
        self.cpg_path_ids = cpg_path_ids
        self.taint_kind = taint_kind

    def to_tag(self) -> dict:
        """Serialize to CPG Tag."""
        return {
            "type": "taint",
            "program_id": self.program_id,
            "source": self.cpg_source_id,
            "sink": self.cpg_sink_id,
            "path": self.cpg_path_ids,
            "kind": self.taint_kind,
            "metadata": self.metadata,
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "TaintFact":
        """Deserialize from CPG Tag."""
        return cls(
            program_id=tag_data["program_id"],
            cpg_source_id=tag_data["source"],
            cpg_sink_id=tag_data["sink"],
            cpg_path_ids=tag_data["path"],
            taint_kind=tag_data.get("kind", "generic"),
            **tag_data.get("metadata", {}),
        )


@dataclass
class SliceFact(Fact):
    """Program slicing result.

    References CPG nodes for seed and sliced nodes.
    """

    cpg_seed_id: str = field(
        default="unknown"
    )  # CPG node ID for the starting point of slice
    cpg_node_ids: list[str] = field(default_factory=list)  # CPG node IDs in the slice
    direction: str = "backward"  # "backward" or "forward"

    def __init__(
        self,
        program_id: str,
        cpg_seed_id: str,
        cpg_node_ids: list[str],
        direction: str = "backward",
        **kwargs,
    ):
        super().__init__(
            fact_type=FactType.SLICE, program_id=program_id, metadata=kwargs
        )
        self.cpg_seed_id = cpg_seed_id
        self.cpg_node_ids = cpg_node_ids
        self.direction = direction

    def to_tag(self) -> dict:
        """Serialize to CPG Tag."""
        return {
            "type": "slice",
            "program_id": self.program_id,
            "seed": self.cpg_seed_id,
            "nodes": self.cpg_node_ids,
            "direction": self.direction,
            "metadata": self.metadata,
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "SliceFact":
        """Deserialize from CPG Tag."""
        return cls(
            program_id=tag_data["program_id"],
            cpg_seed_id=tag_data["seed"],
            cpg_node_ids=tag_data["nodes"],
            direction=tag_data.get("direction", "backward"),
            **tag_data.get("metadata", {}),
        )


class IssueSeverity(Enum):
    """Severity levels for issues."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IssueFact(Fact):
    """Issue/vulnerability detection result.

    References CPG node for location.
    """

    issue_type: str = field(
        default="unknown"
    )  # e.g., "buffer_overflow", "access_control"
    severity: IssueSeverity = field(init=False)
    cpg_location_id: str = field(
        default="unknown"
    )  # CPG node ID where the issue occurs
    message: str = field(default="")  # Description
    details: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        program_id: str,
        issue_type: str,
        severity: IssueSeverity,
        cpg_location_id: str,
        message: str,
        details: dict[str, Any] | None = None,
        **kwargs,
    ):
        super().__init__(
            fact_type=FactType.ISSUE, program_id=program_id, metadata=kwargs
        )
        self.issue_type = issue_type
        self.severity = severity
        self.cpg_location_id = cpg_location_id
        self.message = message
        self.details = details or {}

    def to_tag(self) -> dict:
        """Serialize to CPG Tag."""
        return {
            "type": "issue",
            "program_id": self.program_id,
            "issue_type": self.issue_type,
            "severity": self.severity.value,
            "location": self.cpg_location_id,
            "message": self.message,
            "details": self.details,
            "metadata": self.metadata,
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "IssueFact":
        """Deserialize from CPG Tag."""
        return cls(
            program_id=tag_data["program_id"],
            issue_type=tag_data["issue_type"],
            severity=IssueSeverity(tag_data["severity"]),
            cpg_location_id=tag_data["location"],
            message=tag_data["message"],
            details=tag_data.get("details", {}),
            **tag_data.get("metadata", {}),
        )


@dataclass
class CallGraphFact(Fact):
    """Call graph information.

    References CPG nodes for caller, callee, and call site.
    """

    cpg_caller_id: str = field(default="unknown")  # CPG node ID for the calling method
    cpg_callee_id: str = field(default="unknown")  # CPG node ID for the called method
    cpg_call_site_id: str | None = None  # CPG node ID for the call site

    def __init__(
        self,
        program_id: str,
        cpg_caller_id: str,
        cpg_callee_id: str,
        cpg_call_site_id: str | None = None,
        **kwargs,
    ):
        super().__init__(
            fact_type=FactType.CALL_GRAPH, program_id=program_id, metadata=kwargs
        )
        self.cpg_caller_id = cpg_caller_id
        self.cpg_callee_id = cpg_callee_id
        self.cpg_call_site_id = cpg_call_site_id

    def to_tag(self) -> dict:
        """Serialize to CPG Tag."""
        return {
            "type": "call_graph",
            "program_id": self.program_id,
            "caller": self.cpg_caller_id,
            "callee": self.cpg_callee_id,
            "call_site": self.cpg_call_site_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "CallGraphFact":
        """Deserialize from CPG Tag."""
        return cls(
            program_id=tag_data["program_id"],
            cpg_caller_id=tag_data["caller"],
            cpg_callee_id=tag_data["callee"],
            cpg_call_site_id=tag_data.get("call_site"),
            **tag_data.get("metadata", {}),
        )
