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
    """

    def __init__(
        self,
        source_node_id: str,
        target_node_id: str,
        **kwargs: Any,
    ):
        # Create graph updater for CALLS edge
        updater = GraphUpdater(
            operation=GraphUpdateOp.ADD_EDGE,
            relation=CodeUnitRelation(RKRegistry.Calls(), **kwargs),
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
            "metadata": self.graph_updater.relation.metadata,
        }

    @classmethod
    def _from_kwargs(cls, **kwargs) -> "CallFact":
        """Create instance from kwargs dict."""
        return cls(
            source_node_id=kwargs["source_node_id"],
            target_node_id=kwargs["target_node_id"],
            **kwargs.get("metadata", {}),
        )
