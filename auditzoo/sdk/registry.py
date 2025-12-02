"""Registry helpers for analysis agents.

This module provides utilities for registering analysis agent types and
their capabilities with the plugin registry.
"""

from typing import Type, Callable
from auditzoo.contracts.capabilities import AgentCapability


# Global registry of agent types
_agent_registry: dict[str, Type] = {}
_capability_registry: dict[str, AgentCapability] = {}


def register_analysis_agent(
    agent_type_id: str, agent_class: Type, capability: AgentCapability
):
    """Register an analysis agent type.

    Args:
        agent_type_id: Unique identifier for this agent type
        agent_class: The agent class
        capability: Capability description
    """
    _agent_registry[agent_type_id] = agent_class
    _capability_registry[agent_type_id] = capability


def analysis_agent(capability: AgentCapability) -> Callable:
    """Decorator to register an analysis agent.

    Usage:
        @analysis_agent(AgentCapability(
            agent_type_id="slicing",
            task_kinds={"slicing.request"},
            produces={FactType.SLICE}
        ))
        class SlicingAgent(BaseAnalysisAgent):
            ...
    """

    def decorator(cls: Type) -> Type:
        # Extract agent_type_id from capability
        agent_type_id = capability.agent_type_id
        register_analysis_agent(agent_type_id, cls, capability)
        return cls

    return decorator


def get_registered_agents() -> dict[str, Type]:
    """Get all registered agent types."""
    return dict(_agent_registry)


def get_registered_capabilities() -> dict[str, AgentCapability]:
    """Get all registered capabilities."""
    return dict(_capability_registry)


def get_agent_factory(agent_type_id: str) -> Callable:
    """Get a factory function for creating agent instances.

    Args:
        agent_type_id: Type ID of the agent

    Returns:
        A factory function that takes instance_id and returns an agent instance
    """
    agent_class = _agent_registry.get(agent_type_id)
    if not agent_class:
        raise ValueError(f"Unknown agent type: {agent_type_id}")

    def factory(instance_id: str):
        return agent_class(agent_type_id, instance_id)

    return factory
