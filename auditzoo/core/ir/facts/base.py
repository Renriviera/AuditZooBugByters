"""Shared fact types for semantic information.

This module defines the fact system for attaching analysis results to CodeUnits.

Conceptual model:
- UnitFact: Attached to a single CodeUnit (stored per-node)
- RelationFact: Connects two CodeUnits (stored at graph level)
- Graph updaters are serializable (operation type + parameters)

Storage:
- Unit facts: Stored on the CodeUnit node
- Relation facts: Stored globally, reference two node_ids
- Backend sync: Unit facts -> per-node tags, Relation facts -> global tags
- Graph updaters: Serialized as operation type enum + parameters
"""

import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

import networkx as nx

from auditzoo.core.ir.model import (
    CodeUnitRelation,
    IRInvalidFactError,
)
from auditzoo.core.ir.model.errors import IRRelationKindError


class GraphUpdateOp(Enum):
    """Graph update operations for relation facts.

    These define how a relation fact should update the NetworkX graph.
    The operation is serializable and can be stored in backend tags.
    """

    ADD_EDGE = "add_edge"  # Add an edge between source and target
    REMOVE_EDGE = "remove_edge"  # Remove an edge between source and target
    UPDATE_EDGE = "update_edge"  # Update edge attributes


@dataclass(frozen=True)
class GraphUpdater:
    """Serializable specification for how to update the graph.

    This replaces lambdas with a data structure that can be serialized.

    Attributes:
        operation: Type of graph operation (add/remove/update edge)
        relation_kind: RelationKind to use for the edge (e.g., CALLS, INHERITS)
        edge_attrs: Additional edge attributes to set

    Example:
        # Create an updater for adding a CALLS edge
        updater = GraphUpdater(
            operation=GraphUpdateOp.ADD_EDGE,
            relation_kind="CALLS",
            edge_attrs={"confidence": 0.8, "context": "dynamic"}
        )
    """

    operation: GraphUpdateOp
    relation: CodeUnitRelation
    edge_attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "operation": self.operation.value,
            "relation": self.relation.to_dict(),
            "edge_attrs": self.edge_attrs,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GraphUpdater":
        """Deserialize from dict."""
        return cls(
            operation=GraphUpdateOp(data["operation"]),
            relation=CodeUnitRelation.from_dict(data["relation"]),
            edge_attrs=data.get("edge_attrs", {}),
        )

    def execute(self, graph: nx.MultiDiGraph, source_id: str, target_id: str):
        """Execute this graph update operation.

        Args:
            graph: NetworkX graph instance
            source_id: Source node ID
            target_id: Target node ID
        """
        if self.operation == GraphUpdateOp.ADD_EDGE:
            # Add edge to graph with attributes
            graph.add_edge(source_id, target_id, key=self.relation, **self.edge_attrs)
        elif self.operation == GraphUpdateOp.REMOVE_EDGE:
            # Remove edge from graph, based on relation type
            if graph.has_edge(source_id, target_id, key=self.relation):
                graph.remove_edge(source_id, target_id, key=self.relation)
        elif self.operation == GraphUpdateOp.UPDATE_EDGE:
            # Update edge attributes
            if graph.has_edge(source_id, target_id, key=self.relation):
                graph.edges[source_id, target_id, self.relation].update(self.edge_attrs)


@dataclass(frozen=True)
class UnitFact(ABC):
    """Base class for facts attached to a single CodeUnit.

    Unit facts annotate individual CodeUnits with analysis results.
    They are stored as attributes on the graph node.
    """

    _registry: ClassVar[dict[str, type["UnitFact"]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not inspect.isabstract(cls):
            cls._registry[cls.__name__] = cls

    def id(self) -> str:
        """Get the unique ID of this unit fact."""
        return f"{self.__class__.__name__}_{self.__hash__()}"

    @abstractmethod
    def _to_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs dict for serialization."""
        pass

    @classmethod
    @abstractmethod
    def _from_kwargs(cls, **kwargs) -> "UnitFact":
        """Create instance from kwargs dict."""
        pass

    def to_dict(self) -> dict:
        """
        Serialize to dict for storage.
        """
        out: dict[str, Any] = {
            "__kind__": "unit",
            "__class__": self.__class__.__name__,
            "kwargs": self._to_kwargs(),
        }
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "UnitFact":
        """Deserialize from dict."""
        kind_name = data["__class__"]
        kind_cls = cls._registry.get(kind_name)
        if not kind_cls:
            raise IRRelationKindError(f"Unknown RelationKind: {kind_name}")

        kwargs = data.get("kwargs", {})
        return kind_cls._from_kwargs(**kwargs)


@dataclass(frozen=True)
class RelationFact(ABC):
    """Base class for facts that connect two CodeUnits.

    Relation facts represent relationships between CodeUnits (e.g., calls, data flow).
    They are stored at the graph level and reference two node IDs.

    Attributes:
        name: Type/category of this relation (e.g., "CallFact", "DataFlowFact")
        source_node_id: ID of the source CodeUnit
        target_node_id: ID of the target CodeUnit
        graph_updater: Serializable specification for how to update the graph
        metadata: Additional metadata about this relation
    """

    source_node_id: str  # Source CodeUnit ID
    target_node_id: str  # Target CodeUnit ID
    graph_updater: GraphUpdater  # How to update the graph

    _registry: ClassVar[dict[str, type["RelationFact"]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not inspect.isabstract(cls):
            cls._registry[cls.__name__] = cls

    def id(self) -> str:
        """Get the unique ID of this relation fact."""
        return f"{self.__class__.__name__}_{self.__hash__()}"

    @abstractmethod
    def _to_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs dict for serialization."""
        pass

    @classmethod
    @abstractmethod
    def _from_kwargs(cls, **kwargs) -> "RelationFact":
        """Create instance from kwargs dict."""
        pass

    def to_dict(self) -> dict:
        """Serialize to dict for storage."""
        out: dict[str, Any] = {
            "__kind__": "relation",
            "__class__": self.__class__.__name__,
            "kwargs": self._to_kwargs(),
        }
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "RelationFact":
        """Deserialize from dict."""
        kind_name = data["__class__"]
        kind_cls = cls._registry.get(kind_name)
        if not kind_cls:
            raise IRRelationKindError(f"Unknown RelationKind: {kind_name}")

        kwargs = data.get("kwargs", {})
        return kind_cls._from_kwargs(**kwargs)

    def apply_graph_update(self, graph: nx.MultiDiGraph) -> None:
        """Apply this relation fact's graph update to the view's graph.

        Args:
            graph: IRView's NetworkX graph
        """
        self.graph_updater.execute(graph, self.source_node_id, self.target_node_id)


def deserialize_fact(data: dict) -> UnitFact | RelationFact:
    """Deserialize a fact from dict.

    Args:
        data: Dictionary with '__kind__' and '__class__' fields

    Returns:
        Reconstructed fact instance

    Raises:
        ValueError: If fact cannot be deserialized
    """
    fact_kind = data.get("__kind__")
    if not fact_kind:
        raise IRInvalidFactError("Fact data missing '__kind__' field")

    if fact_kind == "unit":
        # Deserialize unit facts
        return UnitFact.from_dict(data)

    elif fact_kind == "relation":
        # Deserialize relation facts
        # Graph updater is now serialized in the data
        return RelationFact.from_dict(data)

    else:
        raise IRInvalidFactError(f"Unknown fact_kind: {fact_kind}")
