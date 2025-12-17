"""Runtime engine for auditzoo.

This module bootstraps the AutoGen-Core runtime and wires together all
the core agents and analysis agents.
"""

import logging

from autogen_core import SingleThreadedAgentRuntime

from auditzoo.core.agents.ir_store import IRStoreAgent
from auditzoo.core.agents.plugin_registry import (
    PluginRegistryAgent,
    RegisterAgentRequest,
)
from auditzoo.core.ir.view import IRView
from auditzoo.sdk.context import AnalysisContext
from auditzoo.sdk.registry import get_agent_factory, get_registered_agents

logger = logging.getLogger("auditzoo.runtime")


class AuditZooRuntime:
    """Main runtime for auditzoo.

    This class:
    - Bootstraps the core infrastructure agents (IRStore, PluginRegistry)
    - Registers analysis agent types
    - Wires in IR views from preprocessing
    - Provides the main interface for starting/stopping the analysis runtime

    Agents communicate directly via AutoGen-Core message passing by agent ID.
    No task routing or dependency management - users orchestrate analyses manually.
    """

    def __init__(self):
        """Initialize the runtime."""
        self.ir_store: IRStoreAgent | None = None
        self.plugin_registry: PluginRegistryAgent | None = None
        self.analysis_context: AnalysisContext | None = None
        self._runtime: SingleThreadedAgentRuntime | None = None
        self._initialized = False
        self._running = False

    async def initialize(self):
        """Initialize the runtime and create core agents.

        This should be called before registering IR views or starting analyses.
        """
        if self._initialized:
            logger.warning("Runtime already initialized")
            return

        logger.info("Initializing auditzoo runtime")

        # Create AutoGen-Core runtime
        self._runtime = SingleThreadedAgentRuntime()

        # Create core infrastructure agents
        self.ir_store = IRStoreAgent()
        self.plugin_registry = PluginRegistryAgent()

        # Create analysis context (only needs ir_store now)
        self.analysis_context = AnalysisContext(self.ir_store)

        # Register core agents with AutoGen-Core runtime
        await self._runtime.register("ir_store", lambda: self.ir_store)  # type: ignore[attr-defined]
        await self._runtime.register("plugin_registry", lambda: self.plugin_registry)  # type: ignore[attr-defined]

        logger.info("Core agents created and registered")

        # Register built-in analysis agent types
        await self._register_builtin_agents()

        self._initialized = True
        logger.info("Runtime initialized")

    async def _register_builtin_agents(self):
        """Register built-in analysis agent types from auditzoo.analyses.

        This imports the analysis modules which triggers their @analysis_agent
        decorators, populating the registry.
        """
        # Import analysis modules to trigger registration
        # This automatically populates the SDK registry via decorators
        # try:
        #     from auditzoo.analyses.detectors.access_control import agent as ac_agent
        #     from auditzoo.analyses.primitives.slicing import agent as slicing_agent
        # except ImportError as e:
        #     logger.warning(f"Could not import some analysis modules: {e}")

        # Register agent types with plugin registry and AutoGen-Core runtime
        registered_agents = get_registered_agents()
        for agent_type_id, _agent_class in registered_agents.items():
            # Register with plugin registry (simple metadata tracking)
            request = RegisterAgentRequest(
                agent_id=f"{agent_type_id}/default",
                agent_type_id=agent_type_id,
                description=f"{agent_type_id} analysis agent",
            )
            await self.plugin_registry.handle_message(request)  # type: ignore[union-attr]

            # Register agent factory with AutoGen-Core runtime
            factory = get_agent_factory(agent_type_id)

            def make_agent_factory(factory, context):
                """Create a factory function that sets context."""

                def agent_factory(instance_id: str):
                    agent = factory(instance_id)
                    agent.set_context(context)
                    return agent

                return agent_factory

            await self._runtime.register(  # type: ignore[union-attr]
                agent_type_id, make_agent_factory(factory, self.analysis_context)
            )

            logger.info(f"Registered agent type: {agent_type_id}")

    def register_ir_view(self, program_id: str, ir_view: IRView):
        """Register an IR view for a program.

        This should be called after preprocessing, before starting analyses.

        Args:
            program_id: Program identifier
            ir_view: IR view created during preprocessing
        """
        if not self._initialized:
            raise RuntimeError("Runtime not initialized")

        self.ir_store.register_ir_view(program_id, ir_view)  # type: ignore[union-attr]
        logger.info(f"Registered IR view for program: {program_id}")

    async def start(self):
        """Start the runtime.

        After this, agents can process messages.
        """
        if not self._initialized:
            raise RuntimeError("Runtime not initialized")

        if self._running:
            logger.warning("Runtime already running")
            return

        logger.info("Starting auditzoo runtime")

        # Start the AutoGen-Core runtime
        await self._runtime.start()  # type: ignore[union-attr,misc]

        self._running = True
        logger.info("Runtime started")

    async def stop(self):
        """Stop the runtime.

        This gracefully shuts down all agents.
        """
        if not self._running:
            return

        logger.info("Stopping auditzoo runtime")

        # Stop the AutoGen-Core runtime
        await self._runtime.stop()  # type: ignore[union-attr]

        self._running = False
        logger.info("Runtime stopped")

    def is_running(self) -> bool:
        """Check if the runtime is running."""
        return self._running


# Global runtime instance
_runtime: AuditZooRuntime | None = None


def get_runtime() -> AuditZooRuntime:
    """Get the global runtime instance.

    Returns:
        The global runtime instance

    Raises:
        RuntimeError: If runtime not initialized
    """
    global _runtime
    if _runtime is None:
        raise RuntimeError("Runtime not initialized. Call create_runtime() first.")
    return _runtime


async def create_runtime() -> AuditZooRuntime:
    """Create and initialize the global runtime instance.

    Returns:
        The initialized runtime
    """
    global _runtime
    if _runtime is not None:
        logger.warning("Runtime already exists")
        return _runtime

    _runtime = AuditZooRuntime()
    await _runtime.initialize()
    return _runtime


async def shutdown_runtime():
    """Shutdown the global runtime instance."""
    global _runtime
    if _runtime is not None:
        await _runtime.stop()
        _runtime = None
