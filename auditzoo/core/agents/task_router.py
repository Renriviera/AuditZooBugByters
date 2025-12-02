"""TaskRouterAgent: Routes task envelopes to analysis agents.

This agent routes TaskEnvelopes to appropriate analysis agent instances,
using type-id/instance-id naming and relying on AutoGen-Core's dynamic
agent spawning.
"""

from typing import Optional
from autogen_core import message_handler
from auditzoo.core.agents.base import BaseZooAgent
from auditzoo.core.protocol.envelope import TaskEnvelope, ResultEnvelope
from auditzoo.core.agents.plugin_registry import (
    PluginRegistryAgent,
    QueryAgentsByTaskRequest,
)


class TaskRouterAgent(BaseZooAgent):
    """Routes task envelopes to analysis agents.

    This agent:
    - Receives TaskEnvelopes
    - Consults PluginRegistry to find eligible agent types
    - Constructs agent instance IDs using type-id/instance-id naming
    - Sends tasks to those agent instances (AutoGen-Core spawns if needed)
    """

    def __init__(self, plugin_registry: PluginRegistryAgent):
        super().__init__("task_router")
        self.plugin_registry = plugin_registry

    @message_handler
    async def handle_task_envelope(self, message: TaskEnvelope, ctx) -> bool:
        """Handle a TaskEnvelope message."""
        return await self._route_task(message)

    @message_handler
    async def handle_result_envelope(self, message: ResultEnvelope, ctx) -> bool:
        """Handle a ResultEnvelope message."""
        return await self._handle_result(message)

    async def _route_task(self, task: TaskEnvelope) -> bool:
        """Route a task to appropriate analysis agents.

        Returns:
            True if routing succeeded, False otherwise
        """
        self.log_info(
            f"Routing task {task.task_id} of kind {task.task_kind} "
            f"for program {task.program_id}"
        )

        # Query plugin registry for agents that can handle this task
        query = QueryAgentsByTaskRequest(task_kind=task.task_kind)
        response = await self.plugin_registry.handle_message(query)

        if not response.agent_type_ids:
            self.log_error(f"No agents found for task kind {task.task_kind}")
            return False

        # For simplicity, route to the first matching agent type
        # More sophisticated routing logic could be added here
        agent_type_id = response.agent_type_ids[0]

        # Construct instance ID from program and task
        # In a real implementation, this might be more sophisticated
        instance_id = f"{task.program_id}_{task.task_id}"

        self.log_info(f"Routing to agent type {agent_type_id}, instance {instance_id}")

        # In a real AutoGen-Core integration, we would send the task
        # to the agent identified by (agent_type_id, instance_id)
        # The runtime would spawn a new instance if needed
        # For now, this is a placeholder
        await self._send_to_agent(agent_type_id, instance_id, task)

        return True

    async def _send_to_agent(
        self, agent_type_id: str, instance_id: str, task: TaskEnvelope
    ):
        """Send a task to a specific agent instance.

        This is where integration with AutoGen-Core would happen.
        The runtime would handle spawning new instances as needed.
        """
        # Placeholder for AutoGen-Core integration
        self.log_debug(f"Sending task {task.task_id} to {agent_type_id}/{instance_id}")
        pass

    async def _handle_result(self, result: ResultEnvelope) -> bool:
        """Handle a result envelope from an analysis agent."""
        self.log_info(
            f"Received result for task {result.task_id}: " f"success={result.success}"
        )

        if not result.success:
            self.log_warning(f"Task {result.task_id} failed: {result.error}")

        # Forward result to requester or other interested parties
        # Placeholder for now
        return True
