"""Base Analysis Agent - Foundation for all analysis agents.

This is the base class for all analysis agents in the system. It provides syntactic
sugar methods for common IR operations by sending Request messages to the IRStorageAgent.

Subclasses should:
1. Inherit from BaseAnalysisAgent
2. Implement _handle_request for their specific task types
3. Use the provided sugar methods (get_functions, get_callers, etc.) to access IR data
4. Define custom data structures in payload (dataclasses, TypedDicts, plain dicts)
5. Optionally define response schemas for type awareness on caller side
6. Optionally integrate LLM for complex analysis tasks

Important Notes:
- BaseAnalysisAgent does NOT implement _handle_request - this is left abstract
  for subclasses to implement. Each analysis agent defines its own task handling.
- Do NOT use @message_handler on _handle_request in subclasses (handled by BaseAgent)
- Do NOT inherit from Request to create custom request types (AutoGen doesn't support it)
- Instead, put your custom data structures in the payload dict

Response Schema Best Practice:
- Define response schemas as module-level constants in your agent file
- Callers import these schemas to understand expected response structure
- Schemas provide runtime validation and documentation
- Only define schemas when no circular import would occur

Example:
    # In your agent file
    from dataclasses import dataclass, asdict

    # Define custom payload structure
    @dataclass
    class TaintParams:
        source: str
        sink: str
        max_depth: int = 10

    # Define response schema (optional but recommended)
    TAINT_RESPONSE_SCHEMA = {
        "type": "object",
        "properties": {
            "paths": {"type": "array"},
            "vulnerable": {"type": "boolean"}
        },
        "required": ["paths", "vulnerable"]
    }

    class TaintAnalyzer(BaseAnalysisAgent):
        async def _handle_request(self, message: Request, ctx: MessageContext):
            if message.type != "task.taint_analysis":
                return Response.fail("Unknown task")

            # Extract structured data from payload
            params = TaintParams(**message.payload)

            # Use sugar methods
            functions = await self.get_functions(ctx)
            # ... analysis logic ...

            return Response.ok(data={"paths": [...], "vulnerable": True})

    # Caller code
    from my_agent import TAINT_RESPONSE_SCHEMA

    request = Request(
        type="task.taint_analysis",
        payload=asdict(TaintParams(source="user_input", sink="sql_query")),
        response_schema=TAINT_RESPONSE_SCHEMA  # Optional validation
    )
"""

from typing import Any, cast

from autogen_core import AgentId, MessageContext
from pydantic import TypeAdapter

from auditzoo.core.agents.base import BaseAgent
from auditzoo.core.ir.model import RKRegistry, UKRegistry
from auditzoo.core.ir.model.base import CodeUnit, CodeUnitRelation
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response


class BaseAnalysisAgent(BaseAgent):
    """Base class for all analysis agents.

    Provides syntactic sugar methods for common IR operations. Analysis agents
    send Request messages to the IRStorageAgent and receive responses.

    Subclasses must implement _handle_request for their specific analyses
    (e.g., taint analysis, vulnerability scanning).

    Note:
        This class does NOT implement _handle_request - it remains abstract.
        Each analysis agent subclass must provide its own implementation.

    Example:
        class TaintAnalysisAgent(BaseAnalysisAgent):
            async def _handle_request(
                self, message: Request, ctx: MessageContext
            ) -> Response:
                if message.type != "task.taint_analysis":
                    return Response.fail("Unknown task type")

                # Use sugar methods to access IR
                functions = await self.get_functions(ctx)

                for func in functions:
                    callers = await self.get_callers(func.id, ctx)
                    # ... perform taint analysis ...

                return Response.ok(data={"vulnerabilities": [...]})
    """

    def __init__(
        self,
        description: str,
    ) -> None:
        """Initialize BaseAnalysisAgent.

        Args:
            description: Description of this agent's purpose
            ir_storage_agent_id: AgentId of the IRStorageAgent to send requests to
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
        """Get all functions from the IR.

        Args:
            ctx: Message context from autogen

        Returns:
            List of function dictionaries with id, name, code, etc.

        Raises:
            RuntimeError: If IR request fails
        """
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_all_units_by_kind",
            payload={"kind": UKRegistry.Function()},
            response_schema=TypeAdapter(list[CodeUnit]).json_schema(),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get functions: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        return cast(list[CodeUnit], response.data)

    async def get_files(self, ctx: MessageContext) -> list[dict[str, Any]]:
        """Get all files from the IR.

        Args:
            ctx: Message context from autogen

        Returns:
            List of file dictionaries with id, name, code, etc.

        Raises:
            RuntimeError: If IR request fails
        """
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_all_units_by_kind",
            payload={"kind": UKRegistry.File()},
            response_schema=TypeAdapter(list[CodeUnit]).json_schema(),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get files: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        return response.data if response.data else []

    async def get_repo_structure(self, ctx: MessageContext) -> dict[str, Any] | None:
        """Get repository structure from the IR.

        Args:
            ctx: Message context from autogen

        Returns:
            Repository structure data, or None if not found

        Raises:
            RuntimeError: If IR request fails
        """
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        # Get all Repository units (should be just one)
        request = Request(
            type="ir.get_all_units_by_kind",
            payload={"kind": UKRegistry.Repository()},
            response_schema=TypeAdapter(list[CodeUnit]).json_schema(),
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
        """Get all functions that call the specified function.

        Args:
            ctx: Message context from autogen
            function_id: ID of the function to get callers for

        Returns:
            List of caller function dictionaries

        Raises:
            RuntimeError: If IR request fails
        """
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_related_units",
            payload={
                "unit_id": function_id,
                "kind": RKRegistry.Calls(),
                "direction": "in",  # Incoming calls = callers
            },
            response_schema=TypeAdapter(
                list[tuple[CodeUnit, str, CodeUnitRelation]]
            ).json_schema(),
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
        """Get all functions called by the specified function.

        Args:
            ctx: Message context from autogen
            function_id: ID of the function to get callees for

        Returns:
            List of callee function dictionaries

        Raises:
            RuntimeError: If IR request fails
        """
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_related_units",
            payload={
                "unit_id": function_id,
                "kind": RKRegistry.Calls(),
                "direction": "out",  # Outgoing calls = callees
            },
            response_schema=TypeAdapter(
                list[tuple[CodeUnit, str, CodeUnitRelation]]
            ).json_schema(),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"Failed to get callees for {function_id}: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        neighbors = response.data
        return [(callee_unit, relation) for callee_unit, _, relation in neighbors]

    async def get_unit(self, unit_id: str, ctx: MessageContext) -> CodeUnit | None:
        """Get a specific code unit by ID.

        Args:
            ctx: Message context from autogen
            unit_id: ID of the unit to retrieve

        Returns:
            Code unit dictionary, or None if not found

        Raises:
            RuntimeError: If IR request fails
        """
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        request = Request(
            type="ir.get_unit",
            payload={"unit_id": unit_id},
            response_schema=TypeAdapter(CodeUnit).json_schema(),
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response):
            raise RuntimeError("Invalid response type from IR agent")

        if not response.success:
            # Unit not found is not an error, just return None
            return None

        return cast(CodeUnit, response.data)

    async def query_ir(self, query: str, response_ty: str, ctx: MessageContext) -> Any:
        if self._ir_agent_id is None:
            raise RuntimeError("IRStorageAgent ID not registered")

        """Execute a raw query against the IR backend.

        Args:
            ctx: Message context from autogen
            query: Query string in backend query language
            response_ty: Expected response type (default: "json")

        Returns:
            Query results

        Raises:
            RuntimeError: If query fails
        """
        request = Request(
            type="ir.query", payload={"query": query, "response_ty": response_ty}
        )
        response = await self.send_message(request, self._ir_agent_id)

        if not isinstance(response, Response) or not response.success:
            raise RuntimeError(
                f"IR query failed: {response.error if isinstance(response, Response) else 'Unknown error'}"
            )

        return response.data.get("result") if response.data else None
