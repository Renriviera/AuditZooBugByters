"""AnalysisContext for analysis agents.

This module provides the context object that analysis agents use to interact
with the infrastructure (IR, facts, dependency management).
"""

from typing import List, Optional, Dict, Any
from auditzoo.core.agents.ir_store import IRStoreAgent
from auditzoo.core.agents.dependency_mgr import (
    DependencyManagerAgent,
    EnsureFactsRequest,
)
from auditzoo.core.agents.task_router import TaskRouterAgent
from auditzoo.core.ir.view import IRView
from auditzoo.core.protocol.ir_messages import (
    GetFactsRequest,
    UpdateFactsRequest,
    GetIRVersionRequest,
)
from auditzoo.core.protocol.envelope import ResultEnvelope, TaskEnvelope
from auditzoo.contracts.facts import Fact, FactType


class AnalysisContext:
    """Context for analysis agents to interact with infrastructure.

    Provides methods for:
    - Accessing IR views
    - Getting and updating facts
    - Ensuring required facts exist
    - Sending results
    - Logging
    """

    def __init__(
        self,
        ir_store: IRStoreAgent,
        dependency_manager: DependencyManagerAgent,
        task_router: TaskRouterAgent,
    ):
        self.ir_store = ir_store
        self.dependency_manager = dependency_manager
        self.task_router = task_router

    async def get_ir_view(self, program_id: str) -> Optional[IRView]:
        """Get the IR view for a program."""
        return self.ir_store.get_ir_view(program_id)

    async def get_ir_version(self, program_id: str) -> int:
        """Get the current IR version for a program."""
        request = GetIRVersionRequest(program_id=program_id)
        response = await self.ir_store.handle_message(request)
        return response.version

    async def get_facts(
        self,
        program_id: str,
        fact_types: Optional[List[FactType]] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Fact]:
        """Get facts for a program.

        Args:
            program_id: Target program
            fact_types: Optional filter by fact types
            filters: Optional additional filters

        Returns:
            List of matching facts
        """
        request = GetFactsRequest(
            program_id=program_id, fact_types=fact_types, filters=filters or {}
        )
        response = await self.ir_store.handle_message(request)
        return response.facts

    async def update_facts(
        self, program_id: str, facts: List[Fact], replace: bool = False
    ) -> bool:
        """Update facts for a program.

        Args:
            program_id: Target program
            facts: Facts to add or update
            replace: If True, replace existing facts of same type

        Returns:
            True if successful, False otherwise
        """
        request = UpdateFactsRequest(
            program_id=program_id, facts=facts, replace=replace
        )
        response = await self.ir_store.handle_message(request)
        return response.success

    async def ensure_facts(
        self,
        program_id: str,
        required_facts: List[FactType],
        language: Optional[str] = None,
    ) -> bool:
        """Ensure that required facts exist for a program.

        This will trigger prerequisite analyses if needed.

        Args:
            program_id: Target program
            required_facts: Fact types that must exist
            language: Optional language hint

        Returns:
            True if all facts are available, False otherwise
        """
        request = EnsureFactsRequest(
            program_id=program_id, required_facts=required_facts, language=language
        )
        response = await self.dependency_manager.handle_message(request)
        return response.success

    async def send_result(self, result: ResultEnvelope):
        """Send a result envelope back to the router."""
        await self.task_router.handle_message(result)

    async def dispatch_task(self, task: TaskEnvelope):
        """Dispatch a new task to the router."""
        await self.task_router.handle_message(task)
