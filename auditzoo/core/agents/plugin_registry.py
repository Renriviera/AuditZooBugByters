"""PluginRegistryAgent: Registry of agent types and capabilities.

This agent maintains a type-level registry of analysis agents and their
capabilities (task kinds, fact types, languages).
"""

from typing import Dict, List, Optional, Set
from auditzoo.core.agents.base import BaseZooAgent
from auditzoo.contracts.capabilities import AgentCapability
from auditzoo.contracts.facts import FactType
from dataclasses import dataclass


@dataclass
class RegisterAgentRequest:
    """Request to register an agent type."""

    capability: AgentCapability


@dataclass
class QueryAgentsByTaskRequest:
    """Request to find agents that can handle a task kind."""

    task_kind: str
    language: Optional[str] = None


@dataclass
class QueryAgentsByTaskResponse:
    """Response with agents that can handle a task."""

    agent_type_ids: List[str]


@dataclass
class QueryAgentsByFactRequest:
    """Request to find agents that can produce a fact type."""

    fact_type: FactType
    language: Optional[str] = None


@dataclass
class QueryAgentsByFactResponse:
    """Response with agents that can produce a fact."""

    agent_type_ids: List[str]


@dataclass
class GetCapabilityRequest:
    """Request to get capability info for an agent type."""

    agent_type_id: str


@dataclass
class GetCapabilityResponse:
    """Response with capability information."""

    capability: Optional[AgentCapability]


class PluginRegistryAgent(BaseZooAgent):
    """Registry of agent types and their capabilities.

    This agent maintains a type-level registry (not instance-level).
    It answers queries like:
    - Which agent types can handle task kind X?
    - Which agent types can produce fact type Y?
    """

    def __init__(self):
        super().__init__("plugin_registry")
        self._capabilities: Dict[str, AgentCapability] = {}

    def register_agent_type(self, capability: AgentCapability):
        """Register an agent type with its capabilities."""
        self._capabilities[capability.agent_type_id] = capability
        self.log_info(
            f"Registered agent type: {capability.agent_type_id}, "
            f"tasks={capability.task_kinds}, produces={capability.produces}"
        )

    async def handle_message(self, message):
        """Handle incoming messages."""
        if isinstance(message, RegisterAgentRequest):
            self.register_agent_type(message.capability)
            return True
        elif isinstance(message, QueryAgentsByTaskRequest):
            return self._query_by_task(message)
        elif isinstance(message, QueryAgentsByFactRequest):
            return self._query_by_fact(message)
        elif isinstance(message, GetCapabilityRequest):
            return self._get_capability(message)
        else:
            self.log_warning(f"Unknown message type: {type(message)}")
            return None

    def _query_by_task(
        self, request: QueryAgentsByTaskRequest
    ) -> QueryAgentsByTaskResponse:
        """Find agent types that can handle a task kind."""
        matching = []
        for agent_id, capability in self._capabilities.items():
            if capability.can_handle_task(request.task_kind):
                if request.language is None or capability.supports_language(
                    request.language
                ):
                    matching.append(agent_id)

        self.log_debug(
            f"Found {len(matching)} agents for task {request.task_kind}: {matching}"
        )
        return QueryAgentsByTaskResponse(agent_type_ids=matching)

    def _query_by_fact(
        self, request: QueryAgentsByFactRequest
    ) -> QueryAgentsByFactResponse:
        """Find agent types that can produce a fact type."""
        matching = []
        for agent_id, capability in self._capabilities.items():
            if capability.can_produce_fact(request.fact_type):
                if request.language is None or capability.supports_language(
                    request.language
                ):
                    matching.append(agent_id)

        self.log_debug(
            f"Found {len(matching)} agents for fact {request.fact_type}: {matching}"
        )
        return QueryAgentsByFactResponse(agent_type_ids=matching)

    def _get_capability(self, request: GetCapabilityRequest) -> GetCapabilityResponse:
        """Get capability info for a specific agent type."""
        capability = self._capabilities.get(request.agent_type_id)
        return GetCapabilityResponse(capability=capability)

    def get_all_capabilities(self) -> Dict[str, AgentCapability]:
        """Get all registered capabilities."""
        return dict(self._capabilities)
