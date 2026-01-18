"""Agent system for multi-agent code analysis.

This module provides the agent infrastructure for analyzing code using AutoGen Core.

Architecture:
    - BaseAgent: Abstract base class with message handling and validation
    - IRStorageAgent: Direct access to IRView, handles all ir.* requests
    - BaseAnalysisAgent: Base class for analysis agents, provides syntactic sugar

Usage:
    from auditzoo.core.agents import IRStorageAgent, BaseAnalysisAgent

    # Create IR storage agent
    ir_agent = IRStorageAgent(ir_view)

    # Create custom analysis agent
    class MyAnalysisAgent(BaseAnalysisAgent):
        async def _handle_request(self, message: Request, ctx: MessageContext):
            if message.type != "task.my_task":
                return Response.fail("Unknown task")

            functions = await self.get_functions(ctx)
            # ... perform analysis ...
            return Response.ok(data={"result": "..."})
"""

from auditzoo.core.agents.base import BaseAgent
from auditzoo.core.agents.base_analysis_agent import BaseAnalysisAgent
from auditzoo.core.agents.ir_storage_agent import IRStorageAgent

__all__ = ["BaseAgent", "IRStorageAgent", "BaseAnalysisAgent"]
