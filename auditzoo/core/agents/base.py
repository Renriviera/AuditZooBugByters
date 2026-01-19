"""Base agent with request handling and response validation.

This module provides the abstract BaseAgent class that all agents inherit from.
It handles message routing and optional response validation.
"""

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from autogen_core import AgentRuntime, MessageContext, RoutedAgent, message_handler
from autogen_core._agent_type import AgentType
from typing_extensions import Self

from auditzoo.core.protocol.errors import ProtocolValidationError
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response


class BaseAgent(RoutedAgent, ABC):
    """Abstract base class for all agents.

    - handle_message is the only @message_handler entry point.
    - _handle_request contains agent logic and should not be decorated.
    - Optional response validation runs when response_schema is provided.
    """

    def __init__(self, description: str) -> None:
        """Initialize BaseAgent.

        Args:
            description: Human-readable description of this agent's purpose
        """
        super().__init__(description=description)

    @classmethod
    async def register_all(
        cls,
        runtime: AgentRuntime,
        type: str,
        factory: Callable[[], Self | Awaitable[Self]],
        *args,
        skip_class_subscriptions: bool = False,
        skip_direct_message_subscription: bool = False,
    ) -> AgentType:
        """Register this agent and any sub-agents.

        Override to register sub-agents before registering the parent. The runtime
        calls register_all so nested agents are registered implicitly.
        """
        return await super().register(
            runtime,
            type,
            factory,
            skip_class_subscriptions=skip_class_subscriptions,
            skip_direct_message_subscription=skip_direct_message_subscription,
        )

    @message_handler
    async def handle_message(self, message: Request, ctx: MessageContext) -> Response:
        """Handle incoming requests with optional response validation."""
        try:
            # Delegate actual handling to subclass
            response = await self._handle_request(message, ctx)

            # Validate response if schema provided and response is successful
            if message.response_schema != {}:
                try:
                    response.validate(message.response_schema)
                except ProtocolValidationError as e:
                    error = (
                        f"Response validation failed against schema: {e}\n"
                        f"Schema: {message.response_schema}\n"
                        f"Response data: {response.data}"
                    )
                    return Response.fail(error)

            return response
        except Exception as e:
            return Response.fail(
                f"Exception in handling request at Agent {self.id}: {e}"
            )

    @abstractmethod
    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        """Handle the actual request logic."""
        pass
