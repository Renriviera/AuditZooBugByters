"""Runtime engine for auditzoo.

This module bootstraps the AutoGen-Core runtime and wires together all
the core agents and analysis agents.
"""

from typing import Dict, List, Optional
import logging
from autogen_core import SingleThreadedAgentRuntime, AgentId, AgentType
from auditzoo.core.agents.ir_store import IRStoreAgent
from auditzoo.core.agents.plugin_registry import (
    PluginRegistryAgent,
    RegisterAgentRequest,
)
from auditzoo.core.agents.task_router import TaskRouterAgent
from auditzoo.core.agents.dependency_mgr import DependencyManagerAgent
from auditzoo.core.ir.view import IRView
from auditzoo.sdk.registry import get_registered_capabilities, get_agent_factory
from auditzoo.sdk.context import AnalysisContext


logger = logging.getLogger("auditzoo.runtime")


class AuditZooRuntime:
    """Main runtime for auditzoo.

    This class:
    - Bootstraps the core infrastructure agents
    - Registers analysis agent types
    - Wires in IR views from preprocessing
    - Provides the main interface for starting/stopping the analysis runtime
    """

    def __init__(self):
        """Initialize the runtime."""
        self.ir_store: Optional[IRStoreAgent] = None
        self.plugin_registry: Optional[PluginRegistryAgent] = None
        self.task_router: Optional[TaskRouterAgent] = None
        self.dependency_manager: Optional[DependencyManagerAgent] = None
        self.analysis_context: Optional[AnalysisContext] = None
        self._runtime: Optional[SingleThreadedAgentRuntime] = None
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
        self.task_router = TaskRouterAgent(self.plugin_registry)
        self.dependency_manager = DependencyManagerAgent(
            self.ir_store, self.plugin_registry, self.task_router
        )

        # Create analysis context
        self.analysis_context = AnalysisContext(
            self.ir_store, self.dependency_manager, self.task_router
        )

        # Register core agents with AutoGen-Core runtime
        await self._runtime.register("ir_store", lambda: self.ir_store)
        await self._runtime.register("plugin_registry", lambda: self.plugin_registry)
        await self._runtime.register("task_router", lambda: self.task_router)
        await self._runtime.register(
            "dependency_manager", lambda: self.dependency_manager
        )

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
        try:
            from auditzoo.analyses.primitives.slicing import agent as slicing_agent
            from auditzoo.analyses.detectors.access_control import agent as ac_agent
        except ImportError as e:
            logger.warning(f"Could not import some analysis modules: {e}")

        # Register agent types with plugin registry and AutoGen-Core runtime
        capabilities = get_registered_capabilities()
        for agent_type_id, capability in capabilities.items():
            # Register with plugin registry
            request = RegisterAgentRequest(capability=capability)
            await self.plugin_registry.handle_message(request)

            # Register agent factory with AutoGen-Core runtime
            factory = get_agent_factory(agent_type_id)

            def make_agent_factory(factory, context):
                """Create a factory function that sets context."""

                def agent_factory(instance_id: str):
                    agent = factory(instance_id)
                    agent.set_context(context)
                    return agent

                return agent_factory

            await self._runtime.register(
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

        self.ir_store.register_ir_view(program_id, ir_view)
        logger.info(f"Registered IR view for program: {program_id}")

    async def start(self):
        """Start the runtime.

        After this, agents can process tasks.
        """
        if not self._initialized:
            raise RuntimeError("Runtime not initialized")

        if self._running:
            logger.warning("Runtime already running")
            return

        logger.info("Starting auditzoo runtime")

        # Start the AutoGen-Core runtime
        await self._runtime.start()

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
        await self._runtime.stop()

        self._running = False
        logger.info("Runtime stopped")

    async def submit_task(self, task):
        """Submit a task to the runtime for processing.

        Args:
            task: TaskEnvelope to process

        Returns:
            Task ID for tracking
        """
        if not self._running:
            raise RuntimeError("Runtime not running")

        # Send task to task router via AutoGen-Core runtime
        await self._runtime.send_message(task, AgentId("task_router", "default"))

        return task.task_id

    def is_running(self) -> bool:
        """Check if the runtime is running."""
        return self._running


# Global runtime instance
_runtime: Optional[AuditZooRuntime] = None


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
