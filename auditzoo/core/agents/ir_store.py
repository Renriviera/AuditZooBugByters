"""IRStoreAgent: Central store for IR and facts.

This agent is the single source of truth for:
- IR views per program
- Fact storage
- Program version tracking
"""

from collections import defaultdict

from autogen_core import message_handler

from auditzoo.core.agents.base import BaseZooAgent
from auditzoo.core.ir.facts import RelationFact, UnitFact
from auditzoo.core.ir.view import IRView
from auditzoo.core.protocol.ir_messages import (
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
        self._facts: dict[str, list[UnitFact | RelationFact]] = defaultdict(list)
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
        raise NotImplementedError("GetFactsRequest handling not yet implemented")

    @message_handler
    async def handle_update_facts(
        self, message: UpdateFactsRequest, ctx
    ) -> UpdateFactsResponse:
        """Handle a request to update facts."""
        raise NotImplementedError("UpdateFactsRequest handling not yet implemented")

    @message_handler
    async def handle_get_version(
        self, message: GetIRVersionRequest, ctx
    ) -> GetIRVersionResponse:
        """Handle a request to get the IR version."""
        raise NotImplementedError("GetIRVersionRequest handling not yet implemented")
