"""IRStorageAgent exposes IRView operations over the request/response protocol.

It handles all ir.* requests and performs deterministic IR CRUD/query work.
"""

from typing import Any, Literal

from autogen_core import MessageContext
from typing_extensions import NotRequired

from auditzoo.core.agents.base import BaseAgent
from auditzoo.core.ir.model import (
    CodeLocation,
    CodeUnitKind,
    RelationKind,
)
from auditzoo.core.ir.view import IRView
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response
from auditzoo.core.protocol.utils import to_schema, typed_dict

# JSON schemas for request validation
REQUEST_SCHEMAS = {
    "query": to_schema(typed_dict(query=str, response_ty=str)),
    "fetch_unit": to_schema(
        typed_dict(
            file_path=str,
            line_start=int,
            line_end=int,
            column_start=NotRequired[int],
        )
    ),
    "get_unit": to_schema(
        typed_dict(
            unit_id=str,
            fetch_backend=NotRequired[bool],
        )
    ),
    "has_unit": to_schema(
        typed_dict(
            unit_id=str,
            fetch_backend=NotRequired[bool],
        )
    ),
    "get_all_units_by_kind": to_schema(
        typed_dict(
            kind=CodeUnitKind,
            fetch_backend=NotRequired[bool],
        )
    ),
    "get_all_relations_by_kind": to_schema(
        typed_dict(
            kind=RelationKind,
            fetch_backend=NotRequired[bool],
        )
    ),
    "get_related_units": to_schema(
        typed_dict(
            unit_id=str,
            kind=RelationKind,
            direction=Literal["in", "out", "both"],
            fetch_backend=NotRequired[bool],
        )
    ),
    "get_unit_facts": to_schema(
        typed_dict(
            unit_id=str,
            fact_cls=NotRequired[str],
            fetch_backend=NotRequired[bool],
        )
    ),
    "get_relation_facts": to_schema(
        typed_dict(
            fact_cls=NotRequired[str],
        )
    ),
    "filter_graph": to_schema(
        typed_dict(
            filter_expr=str,
        )
    ),
    "get_reachable_units": to_schema(
        typed_dict(
            unit_id=str,
            filter_expr=str,
            max_depth=NotRequired[int | None],
        )
    ),
    "find_shortest_path": to_schema(
        typed_dict(
            from_unit_id=str,
            to_unit_id=str,
            filter_expr=str,
        )
    ),
}


class IRStorageAgent(BaseAgent):
    """Agent providing full access to IRView via ir.* requests.

    Requests are validated with JSON Schema when a schema is available.
    """

    def __init__(self, ir_view: IRView) -> None:
        """Initialize IRStorageAgent.

        Args:
            ir_view: IRView instance providing access to the code property graph
        """
        super().__init__(description="IR Storage Agent - Complete IRView API access")
        self._ir_view = ir_view

    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        """Route ir.* requests to the matching handler."""
        # TODO (ZZ): We should have lock here to prevent race conditions on IRView
        try:
            # Validate request payload if schema exists
            request_type = message.type.removeprefix("ir.")
            if request_type in REQUEST_SCHEMAS:
                if not message.validate(REQUEST_SCHEMAS[request_type]):
                    return Response.fail(error="Request validation failed")

            # Route to appropriate handler
            handler = getattr(self, f"_handle_{request_type}", None)
            if handler is None:
                return Response.fail(
                    error=f"Unknown IR request type: {message.type}",
                )

            return await handler(message.payload)  # type: ignore

        except Exception as e:
            return Response.fail(
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
        return Response.ok(result)

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
            return Response.fail("Unit not found at specified location")

        return Response.ok(unit)

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
            return Response.fail(f"Unit not found: {unit_id}")

        return Response.ok(unit)

    async def _handle_has_unit(self, payload: dict[str, Any]) -> Response:
        """Handle ir.has_unit - check if unit exists.

        Payload:
            unit_id: str
            fetch_backend: bool (optional, default=True)
        """
        unit_id = payload["unit_id"]
        fetch_backend = payload.get("fetch_backend", True)

        exists = await self._ir_view.has_unit(unit_id, fetch_backend=fetch_backend)
        return Response.ok(exists)

    async def _handle_get_all_units_by_kind(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_all_units_by_kind - get all units of specific kind.

        Payload:
            kind: CodeUnitKind instance
            fetch_backend: bool (optional, default=True)
        """
        kind = payload["kind"]
        fetch_backend = payload.get("fetch_backend", True)

        if not isinstance(kind, CodeUnitKind):
            return Response.fail(
                f"kind must be a CodeUnitKind instance, got {type(kind).__name__}",
            )

        units = await self._ir_view.get_all_units_by_kind(
            kind, fetch_backend=fetch_backend
        )

        return Response.ok(units)

    async def _handle_get_all_units(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_all_units - get all units (no backend fetch)."""
        units = self._ir_view.get_all_units()
        return Response.ok(units)

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
            return Response.fail(
                f"kind must be a RelationKind instance, got {type(kind).__name__}"
            )

        relations = await self._ir_view.get_all_relations_by_kind(
            kind, fetch_backend=fetch_backend
        )

        return Response.ok(relations)

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
            return Response.fail(f"Unit not found: {unit_id}")

        if not isinstance(kind, RelationKind):
            return Response.fail(
                f"kind must be a RelationKind instance, got {type(kind).__name__}"
            )

        related = await self._ir_view.get_related_units(
            unit, kind, direction, fetch_backend=fetch_backend
        )

        return Response.ok(related)

    async def _handle_get_all_relations(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_all_relations - get all relations (no backend fetch)."""
        relations = self._ir_view.get_all_relations()
        return Response.ok(relations)

    # ======================================================
    # Graph Queries (No Backend Fetch): Not Yet Implemented
    # ======================================================

    async def _handle_filter_graph(self, payload: dict[str, Any]) -> Response:
        """Handle ir.filter_graph - filter graph by expression.

        Note: This requires a filter expression that will be evaluated.
        For now, returns error as we need to define filter expression syntax.
        """
        return Response.fail(
            "filter_graph not yet implemented - needs filter expression syntax definition",
        )

    async def _handle_get_reachable_units(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_reachable_units.

        Note: This requires a filter expression. Not yet implemented.
        """
        return Response.fail(
            "get_reachable_units not yet implemented - needs filter expression syntax",
        )

    async def _handle_find_shortest_path(self, payload: dict[str, Any]) -> Response:
        """Handle ir.find_shortest_path.

        Note: This requires a filter expression. Not yet implemented.
        """
        return Response.fail(
            "find_shortest_path not yet implemented - needs filter expression syntax",
        )

    # ============================================
    # Fact Management: Not Yet Implemented
    # ============================================

    async def _handle_add_unit_fact(self, payload: dict[str, Any]) -> Response:
        """Handle ir.add_unit_fact.

        TODO: Implement fact deserialization.
        """
        return Response.fail(
            "add_unit_fact not yet implemented - needs fact deserialization",
        )

    async def _handle_add_relation_fact(self, payload: dict[str, Any]) -> Response:
        """Handle ir.add_relation_fact.

        TODO: Implement fact deserialization.
        """
        return Response.fail(
            "add_relation_fact not yet implemented - needs fact deserialization",
        )

    async def _handle_get_unit_facts(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_unit_facts - get facts for a unit.

        TODO: Implement fact serialization and filtering.
        """
        return Response.fail(
            "get_unit_facts not yet implemented - needs fact serialization",
        )

    async def _handle_get_relation_facts(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_relation_facts - get all relation facts.

        TODO: Implement fact serialization and filtering.
        """
        return Response.fail(
            "get_relation_facts not yet implemented - needs fact serialization",
        )

    async def _handle_load_facts(self, payload: dict[str, Any]) -> Response:
        """Handle ir.load_facts - load all facts from backend."""
        await self._ir_view.load_facts()
        return Response.ok(None)

    # ============================================
    # Sync & Cache Management
    # ============================================

    async def _handle_preload_from_backend(self, payload: dict[str, Any]) -> Response:
        """Handle ir.preload_from_backend - preload common data."""
        await self._ir_view.preload_from_backend()
        return Response.ok(None)

    async def _handle_sync_backend(self, payload: dict[str, Any]) -> Response:
        """Handle ir.sync_backend - sync all facts to backend."""
        await self._ir_view.sync_backend()
        return Response.ok(None)

    async def _handle_get_graph_stats(self, payload: dict[str, Any]) -> Response:
        """Handle ir.get_graph_stats - get graph statistics."""
        stats = self._ir_view.get_graph_stats()
        return Response.ok(data=stats)

    async def _handle_reload(self, payload: dict[str, Any]) -> Response:
        """Handle ir.reload - reload from backend."""
        await self._ir_view.reload()
        return Response.ok(None)

    async def _handle_cleanup(self, payload: dict[str, Any]) -> Response:
        """Handle ir.cleanup - cleanup graph.

        Payload:
            sync_to_backend: bool (optional, default=False)
        """
        sync_to_backend = payload.get("sync_to_backend", False)
        await self._ir_view.cleanup(sync_to_backend=sync_to_backend)
        return Response.ok(None)
