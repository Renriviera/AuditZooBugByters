"""Registry helpers for analysis agents.

This module provides utilities for registering analysis agent types.
Agents are called directly by ID (no capabilities-based routing).
"""

from collections.abc import Callable

# Global registry of agent types
_agent_registry: dict[str, type] = {}


def register_analysis_agent(
    agent_type_id: str, agent_class: type, description: str = ""
):
    """Register an analysis agent type.

    Args:
        agent_type_id: Unique identifier for this agent type (e.g., "slicing")
        agent_class: The agent class
        description: Optional human-readable description
    """
    _agent_registry[agent_type_id] = agent_class


def analysis_agent(agent_type_id: str, description: str = "") -> Callable:
    """Decorator to register an analysis agent.

    Usage:
        @analysis_agent("slicing", "Performs program slicing analysis")
        class SlicingAgent(BaseAnalysisAgent):
            ...
    """

    def decorator(cls: type) -> type:
        register_analysis_agent(agent_type_id, cls, description)
        return cls

    return decorator


def get_registered_agents() -> dict[str, type]:
    """Get all registered agent types.

    Returns:
        Dictionary mapping agent_type_id to agent class
    """
    return dict(_agent_registry)


def get_agent_factory(agent_type_id: str) -> Callable:
    """Get a factory function for creating agent instances.

    Args:
        agent_type_id: Type ID of the agent

    Returns:
        A factory function that takes instance_id and returns an agent instance

    Raises:
        ValueError: If agent_type_id is not registered
    """
    agent_class = _agent_registry.get(agent_type_id)
    if not agent_class:
        raise ValueError(f"Unknown agent type: {agent_type_id}")

    def factory(instance_id: str):
        return agent_class(agent_type_id, instance_id)

    return factory
