"""Analysis runtime for backend, IRView, and agent lifecycle."""

import asyncio
import atexit
from collections.abc import Callable

from autogen_core import AgentId, AgentRuntime, SingleThreadedAgentRuntime

from auditzoo.backends.ingestion import create_backend
from auditzoo.core.agents import BaseAnalysisAgent, IRStorageAgent
from auditzoo.core.ir.backend_api import BackendConfig, CPGBackend
from auditzoo.core.ir.view import IRView
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response

_connected_backends: set[CPGBackend] = set()


def _cleanup_backends() -> None:
    """Cleanup function to disconnect all connected backends at exit."""

    async def disconnect_all() -> None:
        for backend in list(_connected_backends):
            try:
                if backend.is_connected():
                    await backend.disconnect()
            except Exception:
                pass  # Ignore errors during cleanup

    asyncio.run(disconnect_all())


atexit.register(_cleanup_backends)


class AnalysisRuntime:
    """Orchestrates backend connection, IRView, and agent messaging."""

    def __init__(self, config: BackendConfig) -> None:
        """Initialize AnalysisRuntime with backend configuration.

        Note: This does NOT create the backend yet. Call initialize() or use
        async context manager to actually create and connect the backend.

        Args:
            config: Backend configuration (type, source_path, etc.)
        """
        # Store config for lazy backend creation
        self._backend_config = config

        # These are initialized in initialize()
        self._backend: CPGBackend | None = None
        self._ir_view: IRView | None = None
        self._runtime: SingleThreadedAgentRuntime | None = None
        self._ir_agent_id: AgentId | None = None

        # Track registered agents (agent_name -> agent_type)
        self._registered_agents: dict[str, type[BaseAnalysisAgent]] = {}

    async def __aenter__(self) -> "AnalysisRuntime":
        """Initialize runtime for use in an async context manager."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Cleanup runtime on context exit."""
        await self.stop()

    async def initialize(self) -> None:
        """Create backend, IRView, AutoGen runtime, and IRStorageAgent."""
        if self._backend is not None:
            raise AnalysisRuntimeError("Backend already initialized")

        # 1. Backend setup: create_backend connects and returns ready backend
        self._backend = await create_backend(self._backend_config)
        _connected_backends.add(self._backend)

        # 2. IRView setup: IRView.create connects backend and preloads data
        self._ir_view = await IRView.create(self._backend)

        # 3. AutoGen runtime setup: create but don't start yet
        self._runtime = SingleThreadedAgentRuntime()

        # 4. Register IRStorageAgent: uses class name as agent identifier
        agent_cls_name = IRStorageAgent.__name__

        # Capture ir_view in closure for factory function
        ir_view = self._ir_view

        # Register with AutoGen (using the agent's own register method)
        await IRStorageAgent.register(
            self._runtime, agent_cls_name, lambda: IRStorageAgent(ir_view)
        )

        # Store AgentId for later use (format: "IRStorageAgent/default")
        self._ir_agent_id = AgentId(agent_cls_name, "default")

    def start(self) -> None:
        """Start AutoGen message processing (after initialize())."""
        if self._runtime is None:
            raise RuntimeError("Runtime not initialized. Call initialize() first.")

        # Start AutoGen runtime's message processing loop
        self._runtime.start()

    async def stop(self) -> None:
        """Stop runtime, sync IRView, and disconnect backend."""
        # Collect errors but don't stop cleanup process
        errors = []

        # 1. Stop AutoGen runtime: halts message processing
        if self._runtime is not None:
            try:
                await self._runtime.stop()
            except Exception as e:
                errors.append(f"AutoGen runtime stop failed: {e}")
            finally:
                # Always clear reference, even if stop failed
                self._runtime = None

        # 2. Cleanup IRView: syncs any pending facts to backend
        if self._ir_view is not None:
            try:
                await self._ir_view.cleanup(sync_to_backend=True)
            except Exception as e:
                errors.append(f"IRView cleanup failed: {e}")
            finally:
                # Always clear reference, even if cleanup failed
                self._ir_view = None

        # 3. Disconnect backend: CRITICAL - must always execute
        #    Uses separate try-except to isolate from previous failures
        if self._backend is not None:
            try:
                # Only disconnect if actually connected
                if self._backend.is_connected():
                    await self._backend.disconnect()
            except Exception as e:
                errors.append(f"Backend disconnect failed: {e}")
            # Note: We don't set self._backend = None here to allow
            # checking backend state after stop() if needed

        # 4. Clear runtime state
        self._ir_agent_id = None
        self._registered_agents.clear()

        # Report all errors that occurred during cleanup
        if errors:
            raise AnalysisRuntimeError(" | ".join(errors))

    async def register_agent(
        self,
        agent_type: type[BaseAnalysisAgent],
        agent_name: str,
        agent_factory: Callable[[], BaseAnalysisAgent],
    ) -> None:
        """Register an analysis agent and inject the IRStorageAgent ID."""
        if self._runtime is None:
            raise AnalysisRuntimeError(
                "Runtime not initialized. Call initialize() first."
            )

        if self._ir_agent_id is None:
            raise AnalysisRuntimeError("IRStorageAgent ID not registered.")

        if (
            agent_name in self._registered_agents
            and self._registered_agents[agent_name] != agent_type
        ):
            raise AnalysisRuntimeError(f"Agent '{agent_name}' already registered")

        # Capture IR agent ID for injection into agent
        ir_agent_id = self._ir_agent_id

        # Wrapper factory: creates agent and injects IR agent reference
        def factory_wrapper() -> BaseAnalysisAgent:
            # Call user's factory to create agent
            agent = agent_factory()

            # Inject IRStorageAgent ID so agent can communicate with IR
            agent.register_ir_agent(ir_agent_id)

            return agent

        # Use register_all so sub-agents can be registered with the parent.
        await agent_type.register_all(self._runtime, agent_name, factory_wrapper)

        # Track this agent (agent_name -> agent_type mapping)
        self._registered_agents[agent_name] = agent_type

    async def send_message(self, request: Request, target: AgentId) -> Response:
        """Send a Request to a target agent and return its Response."""
        if self._runtime is None:
            raise AnalysisRuntimeError("Runtime not initialized")

        # Delegate to AutoGen runtime to route message to target agent
        # AutoGen handles message delivery and waits for response
        response = await self._runtime.send_message(request, target)

        # Validate response type (ensure agent returned proper Response object)
        if not isinstance(response, Response):
            raise AnalysisRuntimeError(
                f"Invalid response type from agent: {type(response).__name__}"
            )

        return response

    @property
    def ir_agent_id(self) -> AgentId:
        """Return the IRStorageAgent's AgentId."""
        if self._ir_agent_id is None:
            raise AnalysisRuntimeError("Runtime not initialized")
        return self._ir_agent_id

    @property
    def ir_view(self) -> IRView:
        """Return the IRView instance."""
        if self._ir_view is None:
            raise AnalysisRuntimeError("Runtime not initialized")
        return self._ir_view

    @property
    def backend(self) -> CPGBackend:
        """Return the connected backend instance."""
        if self._backend is None:
            raise AnalysisRuntimeError("Backend not initialized")
        return self._backend

    @property
    def autogen_runtime(self) -> AgentRuntime:
        """Return the underlying AutoGen runtime."""
        if self._runtime is None:
            raise AnalysisRuntimeError("Runtime not initialized")
        return self._runtime


# ============================================
# Error Classes
# ============================================


class AnalysisRuntimeError(Exception):
    """Runtime-related errors."""

    pass
