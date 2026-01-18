"""IR Storage Agent - Provides direct access to all IRView operations.

This agent is the sole handler for IRRequest messages. It exposes ALL IRView
operations via the request/response protocol with full parameter support.

This agent does NOT use LLM - it's purely deterministic, providing complete
CRUD operations on the code property graph stored in IRView.
"""

from typing import Any

from autogen_core import MessageContext, RoutedAgent, message_handler

from auditzoo.core.ir.model import (
    CodeLocation,
    CodeUnitKind,
    RelationKind,
)
from auditzoo.core.ir.view import IRView
from auditzoo.core.protocol.requests import IRRequest
from auditzoo.core.protocol.responses import Response

# JSON schemas for request validation
REQUEST_SCHEMAS = {
    "query": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "response_ty": {"type": "string"},
        },
        "required": ["query"],
    },
    "fetch_unit": {
        "type": "object",
        "properties": {
            "file_path": {"type": "string"},
            "line_start": {"type": "integer"},
            "line_end": {"type": "integer"},
            "column_start": {"type": "integer"},
        },
        "required": ["file_path", "line_start", "line_end"],
    },
    "get_unit": {
        "type": "object",
        "properties": {
            "unit_id": {"type": "string"},
            "fetch_backend": {"type": "boolean"},
        },
        "required": ["unit_id"],
    },
    "has_unit": {
        "type": "object",
        "properties": {
            "unit_id": {"type": "string"},
            "fetch_backend": {"type": "boolean"},
        },
        "required": ["unit_id"],
    },
    "get_all_units_by_kind": {
        "type": "object",
        "properties": {
            # Note: kind is a CodeUnitKind instance (Python object), not validated by JSON schema
            "kind": {},  # accept anything; presence enforced via "required"
            "fetch_backend": {"type": "boolean"},
        },
        "required": ["kind"],
    },
    "get_all_relations_by_kind": {
        "type": "object",
        "properties": {
            # Note: kind is a RelationKind instance (Python object), not validated by JSON schema
            "kind": {},  # accept anything; presence enforced via "required"
            "fetch_backend": {"type": "boolean"},
        },
        "required": ["kind"],
    },
    "get_related_units": {
        "type": "object",
        "properties": {
            "unit_id": {"type": "string"},
            # Note: kind is a RelationKind instance (Python object), not validated by JSON schema
            "kind": {},  # accept anything; presence enforced via "required"
            "direction": {"type": "string", "enum": ["in", "out", "both"]},
            "fetch_backend": {"type": "boolean"},
        },
        "required": ["unit_id", "kind", "direction"],
    },
    "get_unit_facts": {
        "type": "object",
        "properties": {
            "unit_id": {"type": "string"},
            "fact_cls": {"type": "string"},
            "fetch_backend": {"type": "boolean"},
        },
        "required": ["unit_id"],
    },
    "get_relation_facts": {
        "type": "object",
        "properties": {
            "fact_cls": {"type": "string"},
        },
    },
    "filter_graph": {
        "type": "object",
        "properties": {
            "filter_expr": {"type": "string"},
        },
        "required": ["filter_expr"],
    },
    "get_reachable_units": {
        "type": "object",
        "properties": {
            "unit_id": {"type": "string"},
            "filter_expr": {"type": "string"},
            "max_depth": {"type": ["integer", "null"]},
        },
        "required": ["unit_id", "filter_expr"],
    },
    "find_shortest_path": {
        "type": "object",
        "properties": {
            "from_unit_id": {"type": "string"},
            "to_unit_id": {"type": "string"},
            "filter_expr": {"type": "string"},
        },
        "required": ["from_unit_id", "to_unit_id", "filter_expr"],
    },
}


class IRStorageAgent(RoutedAgent):
    """Agent providing complete access to all IRView operations.

    Handles all IRRequest messages (ir.*) and provides full CRUD operations on the
    code property graph. This agent has direct access to the IRView instance
    and exposes ALL its operations through the request/response protocol.

    All requests are validated using JSON Schema before processing.

    Supported request types:
        ## Backend Queries
        - ir.query: Execute raw backend query

        ## Unit Management
        - ir.fetch_unit: Fetch unit by source location
        - ir.get_unit: Get a code unit by ID
        - ir.has_unit: Check if unit exists
        - ir.get_all_units_by_kind: Get all units of specific kind
        - ir.get_all_units: Get all units in graph (no backend fetch)

        ## Relation Management
        - ir.get_all_relations_by_kind: Get all relations of specific kind
        - ir.get_related_units: Get related units (callers, callees, etc.)
        - ir.get_all_relations: Get all relations (no backend fetch)

        ## Graph Queries (no backend fetch)
        - ir.filter_graph: Create filtered subgraph
        - ir.get_reachable_units: Get transitively reachable units
        - ir.find_shortest_path: Find shortest path between units

        ## Fact Management
        - ir.add_unit_fact: Add a fact to a code unit
        - ir.add_relation_fact: Add a relation fact
        - ir.get_unit_facts: Get facts for a unit
        - ir.get_relation_facts: Get all relation facts
        - ir.load_facts: Load all facts from backend

        ## Sync & Cache
        - ir.preload_from_backend: Preload common data
        - ir.sync_backend: Sync all facts to backend
        - ir.get_graph_stats: Get graph statistics
        - ir.reload: Reload from backend
        - ir.cleanup: Cleanup graph

    Example:
        from auditzoo.core.ir.model import UKRegistry, RKRegistry

        # Get a code unit
        request = IRRequest(type="get_unit", payload={"unit_id": "func_123"})
        response = await runtime.send_message(request, IRStorageAgent)

        # Get all functions - pass CodeUnitKind instance directly
        request = IRRequest(
            type="get_all_units_by_kind",
            payload={
                "kind": UKRegistry.Function(),  # Direct Python object
                "fetch_backend": True
            }
        )

        # Get callers with full parameters - pass RelationKind instance directly
        request = IRRequest(
            type="get_related_units",
            payload={
                "unit_id": "func_123",
                "kind": RKRegistry.Calls(),  # Direct Python object
                "direction": "in",
                "fetch_backend": True
            }
        )
    """

    def __init__(self, ir_view: IRView) -> None:
        """Initialize IRStorageAgent.

        Args:
            ir_view: IRView instance providing access to the code property graph
        """
        super().__init__(description="IR Storage Agent - Complete IRView API access")
        self._ir_view = ir_view

    @message_handler
    async def handle_ir_request(
        self, message: IRRequest, ctx: MessageContext
    ) -> Response:
        """Handle IR request messages with validation.

        Args:
            message: IRRequest with type and payload
            ctx: Message context from autogen

        Returns:
            Response with success/data or error
        """
        try:
            # Validate request payload if schema exists
            request_type = message.type.removeprefix("ir.")
            if request_type in REQUEST_SCHEMAS:
                if not message.validate(REQUEST_SCHEMAS[request_type]):
                    return Response(success=False, error="Request validation failed")

            # Route to appropriate handler
            handler = getattr(self, f"_handle_{request_type}", None)
            if handler is None:
                return Response(
                    success=False,
                    error=f"Unknown IR request type: {message.type}",
                )

            return await handler(message.payload)  # type: ignore

        except Exception as e:
            return Response(
                success=False,
                error=f"IR operation failed: {type(e).__name__}: {e}",
            )

    # ============================================
    # Backend Queries
    # ============================================

    async def _handle_query(self, payload: dict[str, Any]) -> Response:
        """Handle ir.query - execute raw backend query.

        Payload:
            query: str - Query string
            response_ty: str (optional, default="json") - Response type
        """
        query = payload["query"]
        response_ty = payload.get("response_ty", "json")

        result = await self._ir_view.query(query, response_ty=response_ty)
        return Response(success=True, data={"result": result})

    # ============================================
    # Unit Management
    # ============================================

    async def _handle_fetch_unit(self, payload: dict[str, Any]) -> Response:
        """Handle ir.fetch_unit - fetch unit by source location.

        Payload:
            file_path: str
            line_start: int
            line_end: int
            column_start: int (optional)
        """
        location = CodeLocation(
            file_path=payload["file_path"],
            line_start=payload["line_start"],
            line_end=payload["line_end"],
            column_start=payload.get("column_start"),
        )

        unit = await self._ir_view.fetch_unit(location)
        if not unit:
            return Response(success=False, error="Unit not found at specified location")

        return Response(success=True, data={"unit": unit})

    async def _handle_get_unit(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_unit - get unit by ID.

        Payload:
            unit_id: str
            fetch_backend: bool (optional, default=True)
        """
        unit_id = payload["unit_id"]
        fetch_backend = payload.get("fetch_backend", True)

        unit = await self._ir_view.get_unit(unit_id, fetch_backend=fetch_backend)
        if not unit:
            return Response(success=False, error=f"Unit not found: {unit_id}")

        return Response(success=True, data={"unit": unit})

    async def _handle_has_unit(self, payload: dict[str, Any]) -> Response:
        """Handle ir.has_unit - check if unit exists.

        Payload:
            unit_id: str
            fetch_backend: bool (optional, default=True)
        """
        unit_id = payload["unit_id"]
        fetch_backend = payload.get("fetch_backend", True)

        exists = await self._ir_view.has_unit(unit_id, fetch_backend=fetch_backend)
        return Response(success=True, data={"exists": exists})

    async def _handle_get_all_units_by_kind(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_all_units_by_kind - get all units of specific kind.

        Payload:
            kind: CodeUnitKind instance
            fetch_backend: bool (optional, default=True)
        """
        kind = payload["kind"]
        fetch_backend = payload.get("fetch_backend", True)

        if not isinstance(kind, CodeUnitKind):
            return Response(
                success=False,
                error=f"kind must be a CodeUnitKind instance, got {type(kind).__name__}",
            )

        units = await self._ir_view.get_all_units_by_kind(
            kind, fetch_backend=fetch_backend
        )

        return Response(
            success=True,
            data={"units": units},
        )

    async def _handle_get_all_units(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_all_units - get all units (no backend fetch)."""
        units = self._ir_view.get_all_units()
        return Response(
            success=True,
            data={"units": units},
        )

    # ============================================
    # Relation Management
    # ============================================

    async def _handle_get_all_relations_by_kind(
        self, payload: dict[str, Any]
    ) -> Response:
        """Handle ir.get_all_relations_by_kind.

        Payload:
            kind: RelationKind instance
            fetch_backend: bool (optional, default=True)
        """
        kind = payload["kind"]
        fetch_backend = payload.get("fetch_backend", True)

        if not isinstance(kind, RelationKind):
            return Response(
                success=False,
                error=f"kind must be a RelationKind instance, got {type(kind).__name__}",
            )

        relations = await self._ir_view.get_all_relations_by_kind(
            kind, fetch_backend=fetch_backend
        )

        return Response(
            success=True,
            data={"relations": relations},
        )

    async def _handle_get_related_units(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_related_units - get related units.

        Payload:
            unit_id: str
            kind: RelationKind instance
            direction: "in" | "out" | "both"
            fetch_backend: bool (optional, default=True)
        """
        unit_id = payload["unit_id"]
        kind = payload["kind"]
        direction = payload["direction"]
        fetch_backend = payload.get("fetch_backend", True)

        unit = await self._ir_view.get_unit(unit_id, fetch_backend=fetch_backend)
        if not unit:
            return Response(success=False, error=f"Unit not found: {unit_id}")

        if not isinstance(kind, RelationKind):
            return Response(
                success=False,
                error=f"kind must be a RelationKind instance, got {type(kind).__name__}",
            )

        related = await self._ir_view.get_related_units(
            unit, kind, direction, fetch_backend=fetch_backend
        )

        return Response(
            success=True,
            data={"neighbors": related},
        )

    async def _handle_get_all_relations(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_all_relations - get all relations (no backend fetch)."""
        relations = self._ir_view.get_all_relations()
        return Response(
            success=True,
            data={"relations": relations},
        )

    # ======================================================
    # Graph Queries (No Backend Fetch): Not Yet Implemented
    # ======================================================

    async def _handle_filter_graph(self, payload: dict[str, Any]) -> Response:
        """Handle ir.filter_graph - filter graph by expression.

        Note: This requires a filter expression that will be evaluated.
        For now, returns error as we need to define filter expression syntax.
        """
        return Response(
            success=False,
            error="filter_graph not yet implemented - needs filter expression syntax definition",
        )

    async def _handle_get_reachable_units(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_reachable_units.

        Note: This requires a filter expression. Not yet implemented.
        """
        return Response(
            success=False,
            error="get_reachable_units not yet implemented - needs filter expression syntax",
        )

    async def _handle_find_shortest_path(self, payload: dict[str, Any]) -> Response:
        """Handle ir.find_shortest_path.

        Note: This requires a filter expression. Not yet implemented.
        """
        return Response(
            success=False,
            error="find_shortest_path not yet implemented - needs filter expression syntax",
        )

    # ============================================
    # Fact Management: Not Yet Implemented
    # ============================================

    async def _handle_add_unit_fact(self, payload: dict[str, Any]) -> Response:
        """Handle ir.add_unit_fact.

        TODO: Implement fact deserialization.
        """
        return Response(
            success=False,
            error="add_unit_fact not yet implemented - needs fact deserialization",
        )

    async def _handle_add_relation_fact(self, payload: dict[str, Any]) -> Response:
        """Handle ir.add_relation_fact.

        TODO: Implement fact deserialization.
        """
        return Response(
            success=False,
            error="add_relation_fact not yet implemented - needs fact deserialization",
        )

    async def _handle_get_unit_facts(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_unit_facts - get facts for a unit.

        TODO: Implement fact serialization and filtering.
        """
        return Response(
            success=False,
            error="get_unit_facts not yet implemented - needs fact serialization",
        )

    async def _handle_get_relation_facts(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_relation_facts - get all relation facts.

        TODO: Implement fact serialization and filtering.
        """
        return Response(
            success=False,
            error="get_relation_facts not yet implemented - needs fact serialization",
        )

    async def _handle_load_facts(self, payload: dict[str, Any]) -> Response:
        """Handle ir.load_facts - load all facts from backend."""
        await self._ir_view.load_facts()
        return Response(success=True, data={"message": "Facts loaded from backend"})

    # ============================================
    # Sync & Cache Management
    # ============================================

    async def _handle_preload_from_backend(self, payload: dict[str, Any]) -> Response:
        """Handle ir.preload_from_backend - preload common data."""
        await self._ir_view.preload_from_backend()
        return Response(success=True, data={"message": "Data preloaded from backend"})

    async def _handle_sync_backend(self, payload: dict[str, Any]) -> Response:
        """Handle ir.sync_backend - sync all facts to backend."""
        await self._ir_view.sync_backend()
        return Response(success=True, data={"message": "Facts synced to backend"})

    async def _handle_get_graph_stats(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_graph_stats - get graph statistics."""
        stats = self._ir_view.get_graph_stats()
        return Response(success=True, data=stats)

    async def _handle_reload(self, payload: dict[str, Any]) -> Response:
        """Handle ir.reload - reload from backend."""
        await self._ir_view.reload()
        return Response(success=True, data={"message": "IRView reloaded from backend"})

    async def _handle_cleanup(self, payload: dict[str, Any]) -> Response:
        """Handle ir.cleanup - cleanup graph.

        Payload:
            sync_to_backend: bool (optional, default=False)
        """
        sync_to_backend = payload.get("sync_to_backend", False)
        await self._ir_view.cleanup(sync_to_backend=sync_to_backend)
        return Response(success=True, data={"message": "IRView cleaned up"})
