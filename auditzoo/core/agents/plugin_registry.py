"""PluginRegistryAgent: Simple registry of analysis agents.

This agent maintains a registry of analysis agents by their agent_id.
Agents are called directly by ID (no capabilities-based routing).
"""

from dataclasses import dataclass

from auditzoo.core.agents.base import BaseZooAgent


@dataclass
class RegisterAgentRequest:
    """Request to register an agent."""

    agent_id: str
    agent_type_id: str
    description: str = ""


@dataclass
class GetAgentRequest:
    """Request to get agent info."""

    agent_id: str


@dataclass
class GetAgentResponse:
    """Response with agent information."""

    agent_id: str | None
    agent_type_id: str | None
    description: str | None


class PluginRegistryAgent(BaseZooAgent):
    """Simple registry of analysis agents.

    This agent maintains a registry of agent IDs and basic metadata.
    Agents are called directly by their agent_id.

    No capabilities-based routing - users must know which agent to call.
    """

    def __init__(self):
        super().__init__("plugin_registry")
        # Map: agent_id -> (agent_type_id, description)
        self._agents: dict[str, tuple[str, str]] = {}

    def register_agent(self, agent_id: str, agent_type_id: str, description: str = ""):
        """Register an agent with its ID and metadata.

        Args:
            agent_id: Unique agent ID (e.g., "slicing/default")
            agent_type_id: Agent type (e.g., "slicing")
            description: Optional human-readable description
        """
        self._agents[agent_id] = (agent_type_id, description)
        self.log_info(f"Registered agent: {agent_id} (type: {agent_type_id})")

    async def handle_message(self, message):
        """Handle incoming messages."""
        if isinstance(message, RegisterAgentRequest):
            self.register_agent(
                message.agent_id, message.agent_type_id, message.description
            )
            return True
        elif isinstance(message, GetAgentRequest):
            return self._get_agent(message)
        else:
            self.log_warning(f"Unknown message type: {type(message)}")
            return None

    def _get_agent(self, request: GetAgentRequest) -> GetAgentResponse:
        """Get agent info by ID."""
        agent_info = self._agents.get(request.agent_id)
        if agent_info:
            agent_type_id, description = agent_info
            return GetAgentResponse(
                agent_id=request.agent_id,
                agent_type_id=agent_type_id,
                description=description,
            )
        else:
            return GetAgentResponse(agent_id=None, agent_type_id=None, description=None)

    def get_all_agents(self) -> dict[str, tuple[str, str]]:
        """Get all registered agents.

        Returns:
            Dictionary mapping agent_id to (agent_type_id, description)
        """
        return dict(self._agents)

    def list_agent_ids(self) -> list[str]:
        """Get list of all registered agent IDs.

        Returns:
            List of agent IDs
        """
        return list(self._agents.keys())
