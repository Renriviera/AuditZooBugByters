"""IRStoreAgent: Central store for IR and facts.

This agent is the single source of truth for:
- IR views per program
- Fact storage
- Program version tracking
"""

from collections import defaultdict

from autogen_core import message_handler

from auditzoo.contracts.facts import Fact
from auditzoo.core.agents.base import BaseZooAgent
from auditzoo.core.ir.view import IRView
from auditzoo.core.protocol.ir_messages import (
    CheckFactsExistRequest,
    CheckFactsExistResponse,
    GetFactsRequest,
    GetFactsResponse,
    GetIRVersionRequest,
    GetIRVersionResponse,
    UpdateFactsRequest,
    UpdateFactsResponse,
)


class IRStoreAgent(BaseZooAgent):
    """Central agent managing IR views and facts.

    This agent:
    - Holds IR views for each program
    - Maintains a fact store (keyed by program_id and fact_type)
    - Tracks version numbers per program
    - Processes all fact updates sequentially to prevent race conditions
    """

    def __init__(self):
        super().__init__("ir_store")
        self._ir_views: dict[str, IRView] = {}
        self._facts: dict[str, list[Fact]] = defaultdict(list)
        self._versions: dict[str, int] = defaultdict(int)

    def register_ir_view(self, program_id: str, ir_view: IRView):
        """Register an IR view for a program."""
        self._ir_views[program_id] = ir_view
        self.log_info(f"Registered IR view for program {program_id}")

    def get_ir_view(self, program_id: str) -> IRView | None:
        """Get the IR view for a program."""
        return self._ir_views.get(program_id)

    @message_handler
    async def handle_get_facts(self, message: GetFactsRequest, ctx) -> GetFactsResponse:
        """Handle a request to get facts."""
        return await self._handle_get_facts(message)

    @message_handler
    async def handle_update_facts(
        self, message: UpdateFactsRequest, ctx
    ) -> UpdateFactsResponse:
        """Handle a request to update facts."""
        return await self._handle_update_facts(message)

    @message_handler
    async def handle_get_version(
        self, message: GetIRVersionRequest, ctx
    ) -> GetIRVersionResponse:
        """Handle a request to get the IR version."""
        return await self._handle_get_version(message)

    @message_handler
    async def handle_check_facts(
        self, message: CheckFactsExistRequest, ctx
    ) -> CheckFactsExistResponse:
        """Handle a request to check which fact types exist."""
        return await self._handle_check_facts_exist(message)

    async def _handle_get_facts(self, request: GetFactsRequest) -> GetFactsResponse:
        """Handle a request to get facts."""
        program_id = request.program_id
        all_facts = self._facts.get(program_id, [])

        # Filter by fact types if specified
        if request.fact_types:
            filtered_facts = [f for f in all_facts if f.fact_type in request.fact_types]
        else:
            filtered_facts = all_facts

        # Apply additional filters
        for key, value in request.filters.items():
            filtered_facts = [
                f for f in filtered_facts if getattr(f, key, None) == value
            ]

        version = self._versions[program_id]
        self.log_debug(f"Retrieved {len(filtered_facts)} facts for {program_id}")

        return GetFactsResponse(
            program_id=program_id, facts=filtered_facts, version=version
        )

    async def _handle_update_facts(
        self, request: UpdateFactsRequest
    ) -> UpdateFactsResponse:
        """Handle a request to update facts."""
        program_id = request.program_id

        try:
            if request.replace:
                # Replace existing facts of the same type
                fact_types_to_replace = {f.fact_type for f in request.facts}
                self._facts[program_id] = [
                    f
                    for f in self._facts.get(program_id, [])
                    if f.fact_type not in fact_types_to_replace
                ]

            # Add new facts
            self._facts[program_id].extend(request.facts)

            # Increment version
            self._versions[program_id] += 1
            new_version = self._versions[program_id]

            self.log_info(
                f"Updated {len(request.facts)} facts for {program_id}, "
                f"version now {new_version}"
            )

            return UpdateFactsResponse(
                program_id=program_id, success=True, version=new_version
            )
        except Exception as e:
            self.log_error(f"Error updating facts for {program_id}: {e}")
            return UpdateFactsResponse(
                program_id=program_id,
                success=False,
                version=self._versions[program_id],
                error=str(e),
            )

    async def _handle_get_version(
        self, request: GetIRVersionRequest
    ) -> GetIRVersionResponse:
        """Handle a request to get the IR version."""
        version = self._versions[request.program_id]
        return GetIRVersionResponse(program_id=request.program_id, version=version)

    async def _handle_check_facts_exist(
        self, request: CheckFactsExistRequest
    ) -> CheckFactsExistResponse:
        """Handle a request to check which fact types exist."""
        program_id = request.program_id
        all_facts = self._facts.get(program_id, [])
        existing_types = {f.fact_type for f in all_facts}

        existing = [ft for ft in request.fact_types if ft in existing_types]
        missing = [ft for ft in request.fact_types if ft not in existing_types]

        return CheckFactsExistResponse(
            program_id=program_id, existing=existing, missing=missing
        )
