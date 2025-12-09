"""Base class for analysis agents.

This module provides the base class that all analysis agents (primitives and
detectors) should inherit from.
"""

from abc import ABC, abstractmethod

from autogen_core import MessageContext, RoutedAgent, message_handler

from auditzoo.contracts.capabilities import AgentCapability
from auditzoo.core.protocol.envelope import ResultEnvelope, TaskEnvelope


class AnalysisContext:
    """Context object passed to analysis agents.

    This will be fully defined in context.py, but we need a forward
    declaration here for the type hints.
    """

    pass


class BaseAnalysisAgent(RoutedAgent, ABC):
    """Base class for all analysis agents.

    Analysis authors should:
    1. Inherit from this class
    2. Define their capabilities
    3. Implement the handle_task method

    The framework handles:
    - Message routing
    - Agent registration
    - Context setup
    """

    def __init__(self, agent_type_id: str, instance_id: str):
        """Initialize the analysis agent.

        Args:
            agent_type_id: Unique identifier for this agent type
            instance_id: Unique identifier for this specific instance
        """
        super().__init__(f"{agent_type_id}/{instance_id}")
        self.agent_type_id = agent_type_id
        self.instance_id = instance_id
        self.agent_id = f"{agent_type_id}/{instance_id}"
        self._context: AnalysisContext | None = None

    def set_context(self, context: AnalysisContext):
        """Set the analysis context.

        This is called by the runtime during initialization.
        """
        self._context = context

    @property
    @abstractmethod
    def capabilities(self) -> AgentCapability:
        """Return the capabilities of this agent type.

        This should be implemented as a property that returns an
        AgentCapability object describing what this agent can do.
        """
        pass

    @abstractmethod
    async def handle_task(
        self, task: TaskEnvelope, context: AnalysisContext
    ) -> ResultEnvelope:
        """Handle a task envelope.

        Args:
            task: The task to handle
            context: Analysis context for accessing IR, facts, etc.

        Returns:
            A result envelope indicating success or failure
        """
        pass

    @message_handler
    async def handle_task_envelope(
        self, message: TaskEnvelope, ctx: MessageContext
    ) -> ResultEnvelope:
        """Handle a TaskEnvelope message.

        This is the AutoGen-Core entry point with type-safe routing.
        """
        if self._context is None:
            raise RuntimeError("AnalysisContext not set for agent")
        return await self.handle_task(message, self._context)
