"""Agent system for multi-agent code analysis.

This module provides the agent infrastructure for analyzing code using AutoGen Core.

Architecture:
    - IRStorageAgent: Direct access to IRView, handles all ir.* requests
    - BaseAnalysisAgent: Base class for analysis agents, provides syntactic sugar

Usage:
    from auditzoo.core.agents import IRStorageAgent, BaseAnalysisAgent

    # Create IR storage agent
    ir_agent = IRStorageAgent(ir_view)

    # Create custom analysis agent
    class MyAnalysisAgent(BaseAnalysisAgent):
        @message_handler
        async def handle_task(self, message: TaskRequest, ctx: MessageContext):
            functions = await self.get_functions(ctx)
            # ... perform analysis ...
"""

from auditzoo.core.agents.base_analysis_agent import BaseAnalysisAgent
from auditzoo.core.agents.ir_storage_agent import IRStorageAgent

__all__ = ["IRStorageAgent", "BaseAnalysisAgent"]
