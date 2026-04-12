"""Base class for analysis agents.

Provides helper methods for IR access via IRStorageAgent. Subclasses implement
_handle_request and handle task.* messages.
"""

from typing import Any, cast

from autogen_core import AgentId, MessageContext

from auditzoo.core.agents.base import BaseAgent
from auditzoo.core.ir.model import RKRegistry, UKRegistry
from auditzoo.core.ir.model.base import CodeUnit, CodeUnitRelation
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response
from auditzoo.core.protocol.utils import to_schema


class BaseAnalysisAgent(BaseAgent):
    """Base class for all analysis agents.

    Subclasses implement _handle_request for their analyses.
    """

    def __init__(
        self,
        description: str,
    ) -> None:
        """Initialize BaseAnalysisAgent.

        Args:
            description: Description of this agent's purpose
        """
        super().__init__(description=description)
        self._ir_agent_id: AgentId | None = None

    def register_ir_agent(self, ir_agent_id: AgentId) -> None:
        """Register the IRStorageAgent's AgentId.

        Args:
            ir_agent_id: AgentId of the IRStorageAgent
        """
        self._ir_agent_id = ir_agent_id

    # ============================================
    # Syntactic Sugar Methods
    # ============================================

    async def get_functions(self, ctx: MessageContext) -> list[CodeUnit]:
        """Get all function units from the IR."""
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_all_units_by_kind",
            payload={"kind": UKRegistry.Function()},
            response_schema=to_schema(list[CodeUnit]),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get functions: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        return cast(list[CodeUnit], response.data)

    async def get_files(self, ctx: MessageContext) -> list[CodeUnit]:
        """Get all file units from the IR."""
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_all_units_by_kind",
            payload={"kind": UKRegistry.File()},
            response_schema=to_schema(list[CodeUnit]),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get files: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        return response.data if response.data else []

    async def get_repo_structure(self, ctx: MessageContext) -> CodeUnit | None:
        """Get the repository unit from the IR, if present."""
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        # Get all Repository units (should be just one)
        request = Request(
            type="ir.get_all_units_by_kind",
            payload={"kind": UKRegistry.Repository()},
            response_schema=to_schema(list[CodeUnit]),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get repository structure: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        units = response.data if response.data else []
        return units[0] if units else None

    async def get_callers(
        self, function_id: str, ctx: MessageContext
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        """Get callers for a function."""
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_related_units",
            payload={
                "unit_id": function_id,
                "kind": RKRegistry.Calls(),
                "direction": "in",  # Incoming calls = callers
            },
            response_schema=to_schema(list[tuple[CodeUnit, str, CodeUnitRelation]]),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get callers for {function_id}: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        neighbors = response.data
        return [(caller_unit, relation) for caller_unit, _, relation in neighbors]

    async def get_callees(
        self, function_id: str, ctx: MessageContext
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        """Get callees for a function."""
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_related_units",
            payload={
                "unit_id": function_id,
                "kind": RKRegistry.Calls(),
                "direction": "out",  # Outgoing calls = callees
            },
            response_schema=to_schema(list[tuple[CodeUnit, str, CodeUnitRelation]]),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get callees for {function_id}: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        neighbors = response.data
        return [(callee_unit, relation) for callee_unit, _, relation in neighbors]

    async def get_unit(self, unit_id: str, ctx: MessageContext) -> CodeUnit | None:
        """Get a code unit by ID."""
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_unit",
            payload={"unit_id": unit_id},
            response_schema=to_schema(CodeUnit),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response):
            raise RuntimeError("Invalid response type from IR agent")

        if not response.success:
            # Unit not found is not an error, just return None
            return None

        return cast(CodeUnit, response.data)

    async def query_ir(self, query: str, response_ty: str, ctx: MessageContext) -> Any:
        """Execute a raw backend query via IRStorageAgent."""
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")
        request = Request(
            type="ir.query", payload={"query": query, "response_ty": response_ty}
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"IR query failed: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        return response.data
