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
    """Abstract base class for all agents in AuditZoo.

    This class provides:
    1. Message handling infrastructure via handle_message
    2. Optional response validation against JSON schemas
    3. Abstract _handle_request method for subclasses to implement

    Architecture:
    - handle_message: Entry point, decorated with @message_handler
      - Receives Request messages from AutoGen
      - Delegates to _handle_request
      - Validates response against schema if provided
    - _handle_request: Abstract method, implemented by subclasses
      - Contains the actual agent logic
      - Must NOT be decorated with @message_handler
    - _validate_response: Helper for validating responses against schemas

    Important: AutoGen Compatibility
    ---------------------------------
    Do NOT use @message_handler on _handle_request in subclasses.
    AutoGen's routing doesn't support inheritance for handler methods.
    Only handle_message (in this base class) should have @message_handler.

    Response Schema Best Practice:
    -------------------------------
    If your agent handles specific request types, define response schemas
    as constants in your agent file. Callers can import these schemas to
    validate responses and understand the expected data structure.

    Example:
        # In my_agent.py (callee)
        MY_TASK_RESPONSE_SCHEMA = {
            "type": "object",
            "properties": {
                "results": {"type": "array"},
                "confidence": {"type": "number"}
            },
            "required": ["results"]
        }

        class MyAgent(BaseAgent):
            def __init__(self):
                super().__init__(description="My custom agent")

            async def _handle_request(
                self, message: Request, ctx: MessageContext
            ) -> Response:
                if message.type != "task.my_task":
                    return Response.fail("Unknown task type")

                # Process request...
                results = [...]
                return Response.ok(data={"results": results, "confidence": 0.95})

        # In caller code
        from my_agent import MY_TASK_RESPONSE_SCHEMA

        request = Request(
            type="task.my_task",
            payload={"param": "value"},
            response_schema=MY_TASK_RESPONSE_SCHEMA  # Optional validation
        )
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
        *,
        skip_class_subscriptions: bool = False,
        skip_direct_message_subscription: bool = False,
    ) -> AgentType:
        """
        This function supports register all sub-agents that will be used by
        the current agent.

        By default, it will only register the agent itself.
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
        """Handle incoming request messages with optional response validation.

        This is the entry point for all messages. It:
        1. Delegates to subclass's _handle_request implementation
        2. Validates response against schema if provided and successful
        3. Returns the response (validated or not)

        Args:
            message: Incoming request message
            ctx: Message context from AutoGen

        Returns:
            Response from the handler, validated if schema was provided
        """
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
        """Handle the actual request logic.

        Subclasses must implement this method to process requests.
        This is where the agent's business logic lives.

        Args:
            message: Incoming request message
            ctx: Message context from AutoGen

        Returns:
            Response with success status and data/error

        Note:
            This method should NOT be decorated with @message_handler.
            It's called internally by handle_message.
        """
        pass
