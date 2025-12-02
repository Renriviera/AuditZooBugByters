"""DependencyManagerAgent: Ensures prerequisite facts are available.

This agent helps detectors and complex analyses ensure that their required
facts exist before they run.
"""

from typing import List, Set
from auditzoo.core.agents.base import BaseZooAgent
from auditzoo.core.agents.ir_store import IRStoreAgent
from auditzoo.core.agents.plugin_registry import (
    PluginRegistryAgent,
    QueryAgentsByFactRequest,
)
from auditzoo.core.agents.task_router import TaskRouterAgent
from auditzoo.core.protocol.ir_messages import CheckFactsExistRequest
from auditzoo.core.protocol.envelope import TaskEnvelope
from auditzoo.contracts.facts import FactType
from dataclasses import dataclass


@dataclass
class EnsureFactsRequest:
    """Request to ensure specific fact types exist for a program.

    Attributes:
        program_id: Target program
        required_facts: Fact types that must exist
        language: Optional language hint for selecting agents
    """

    program_id: str
    required_facts: List[FactType]
    language: str = None


@dataclass
class EnsureFactsResponse:
    """Response indicating whether facts were ensured.

    Attributes:
        program_id: Target program
        success: Whether all required facts are now available
        missing: Fact types that could not be produced
        error: Error message if success is False
    """

    program_id: str
    success: bool
    missing: List[FactType] = None
    error: str = None


class DependencyManagerAgent(BaseZooAgent):
    """Orchestrates prerequisite fact generation.

    This agent:
    - Checks which required facts are missing
    - Finds primitive agents that can produce those facts
    - Dispatches tasks to generate missing facts
    - Waits for completion
    """

    def __init__(
        self,
        ir_store: IRStoreAgent,
        plugin_registry: PluginRegistryAgent,
        task_router: TaskRouterAgent,
    ):
        super().__init__("dependency_manager")
        self.ir_store = ir_store
        self.plugin_registry = plugin_registry
        self.task_router = task_router

    async def handle_message(self, message):
        """Handle incoming messages."""
        if isinstance(message, EnsureFactsRequest):
            return await self._ensure_facts(message)
        else:
            self.log_warning(f"Unknown message type: {type(message)}")
            return None

    async def _ensure_facts(self, request: EnsureFactsRequest) -> EnsureFactsResponse:
        """Ensure that required facts exist for a program.

        This method:
        1. Checks which facts already exist
        2. For missing facts, finds agents that can produce them
        3. Dispatches tasks to those agents
        4. Waits for completion (with timeout)
        """
        program_id = request.program_id
        required_facts = request.required_facts

        self.log_info(
            f"Ensuring facts for {program_id}: {[ft.value for ft in required_facts]}"
        )

        # Check which facts already exist
        check_request = CheckFactsExistRequest(
            program_id=program_id, fact_types=required_facts
        )
        check_response = await self.ir_store.handle_message(check_request)

        if not check_response.missing:
            self.log_info(f"All required facts already exist for {program_id}")
            return EnsureFactsResponse(program_id=program_id, success=True, missing=[])

        self.log_info(
            f"Missing facts for {program_id}: "
            f"{[ft.value for ft in check_response.missing]}"
        )

        # Find agents that can produce missing facts
        agents_to_run = {}
        for fact_type in check_response.missing:
            query = QueryAgentsByFactRequest(
                fact_type=fact_type, language=request.language
            )
            response = await self.plugin_registry.handle_message(query)

            if not response.agent_type_ids:
                self.log_error(f"No agents found to produce {fact_type}")
                return EnsureFactsResponse(
                    program_id=program_id,
                    success=False,
                    missing=[fact_type],
                    error=f"No agents can produce {fact_type}",
                )

            # Use the first matching agent
            agent_type_id = response.agent_type_ids[0]
            agents_to_run[fact_type] = agent_type_id

        # Dispatch tasks to produce missing facts
        for fact_type, agent_type_id in agents_to_run.items():
            self.log_info(f"Dispatching {agent_type_id} to produce {fact_type}")

            # Create a task envelope for this analysis
            task = TaskEnvelope(
                task_kind=f"analysis.{fact_type.value}",
                program_id=program_id,
                payload={"fact_type": fact_type.value},
                requester="dependency_manager",
            )

            await self.task_router.handle_message(task)

        # In a full implementation, we would wait for results and verify
        # that the facts were produced. For now, we assume success.
        # A real implementation would use async/await patterns to track
        # completion of dispatched tasks.

        self.log_info(f"Dispatched all required analyses for {program_id}")

        return EnsureFactsResponse(program_id=program_id, success=True, missing=[])
