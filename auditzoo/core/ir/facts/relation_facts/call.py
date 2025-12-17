from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.facts.base import GraphUpdateOp, GraphUpdater, RelationFact
from auditzoo.core.ir.model import RKRegistry
from auditzoo.core.ir.model.base import CodeUnitRelation


@dataclass(frozen=True)
class CallFact(RelationFact):
    """Relation fact representing a function call between two CodeUnits.

    Use this to add call relationships that weren't detected by static analysis
    (e.g., dynamic calls, reflection, callbacks).

    Attributes:
        call_site_node_id: Optional ID of the call site CodeUnit
        call_context: Description of how/when the call happens
    """

    def __init__(
        self,
        source_node_id: str,
        target_node_id: str,
        call_site_node_id: str,
        call_context: str | None = None,
    ):
        # Build edge attributes for the graph updater
        edge_attrs = {}
        if call_context:
            edge_attrs["context"] = call_context

        # Create graph updater for CALLS edge
        updater = GraphUpdater(
            operation=GraphUpdateOp.ADD_EDGE,
            relation=CodeUnitRelation(
                RKRegistry.Calls(), call_site_node_id=call_site_node_id
            ),
            edge_attrs=edge_attrs,
        )

        super().__init__(
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            graph_updater=updater,
        )

    def _to_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs dict for serialization."""
        return {
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "call_site_node_id": self.graph_updater.relation.metadata.get(
                "call_site_node_id"
            ),
            "call_context": self.graph_updater.edge_attrs.get("context"),
        }

    @classmethod
    def _from_kwargs(cls, **kwargs) -> "CallFact":
        """Create instance from kwargs dict."""
        return cls(
            source_node_id=kwargs["source_node_id"],
            target_node_id=kwargs["target_node_id"],
            call_site_node_id=kwargs["call_site_node_id"],
            call_context=kwargs.get("call_context"),
        )
