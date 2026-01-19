"""Analysis runtime for managing backend, IRView, and agents.

This module provides the AnalysisRuntime class that wraps AutoGen Core runtime
and manages the full lifecycle of backend connections, IRView, and agents.
"""

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
    """Runtime for managing the entire analysis pipeline.

    This class orchestrates:
    - Backend creation and connection (via BackendConfig)
    - IRView lifecycle
    - AutoGen Core runtime
    - Agent registration and message routing

    Key design:
    - Takes BackendConfig instead of CPGBackend instance (lazy initialization)
    - Separates initialization (async) from start (sync)
    - Uses factory pattern for agent registration
    - Ensures cleanup even on failures
    """

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
        """Async context manager entry point.

        Calls initialize() to set up backend, IRView, and AutoGen runtime.

        Returns:
            Self for use in 'async with' statement

        Usage:
            async with AnalysisRuntime(config) as runtime:
                # Runtime is initialized and ready
                response = await runtime.send_message(...)
        """
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit point.

        Ensures cleanup happens even if exceptions occurred in the with block.
        Calls stop() which guarantees backend disconnection.

        Args:
            exc_type: Exception type if raised in with block
            exc_val: Exception value if raised
            exc_tb: Exception traceback if raised

        Note:
            Cleanup happens regardless of whether an exception occurred.
        """
        await self.stop()

    async def initialize(self) -> None:
        """Initialize the runtime: create backend, IRView, and register IRStorageAgent.

        This method performs async initialization:
        1. Creates backend from config (async, may involve connections)
        2. Creates IRView from backend (async, preloads data)
        3. Sets up AutoGen runtime
        4. Registers IRStorageAgent automatically

        After this, call start() to begin message processing, or use the
        async context manager which calls this automatically.

        Raises:
            AnalysisRuntimeError: If already initialized
        """
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
        """Start the AutoGen runtime to enable message processing.

        This is a synchronous method that starts the AutoGen message loop.
        Must be called after initialize().

        Note: When using async context manager, you typically don't need to
        call this manually - the runtime is ready after __aenter__.

        Raises:
            RuntimeError: If initialize() hasn't been called yet
        """
        if self._runtime is None:
            raise RuntimeError("Runtime not initialized. Call initialize() first.")

        # Start AutoGen runtime's message processing loop
        self._runtime.start()

    async def stop(self) -> None:
        """Stop the runtime and perform complete cleanup.

        Cleanup sequence (all steps execute even if previous ones fail):
        1. Stop AutoGen runtime (stop message processing)
        2. Cleanup IRView (sync facts to backend)
        3. Disconnect backend (close connections)
        4. Clear internal state

        Key guarantees:
        - Safe to call multiple times (idempotent)
        - Backend ALWAYS disconnects (even if other steps fail)
        - Uses try-finally to ensure state cleanup
        - Collects and reports all errors that occur

        Raises:
            AnalysisRuntimeError: If any cleanup step fails (after attempting all)
        """
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
        """Register an analysis agent with the runtime.

        This method:
        1. Validates runtime state and uniqueness of agent name
        2. Wraps user's factory to inject IR agent reference
        3. Registers agent with AutoGen using agent's own register method
        4. Tracks registration for lifecycle management

        Can be called dynamically after initialize() - supports runtime agent addition.

        Args:
            agent_type: The agent class (e.g., VulnScanner)
            agent_name: Unique identifier for this agent instance
            agent_factory: Function that creates agent instance (without IR agent ID)

        Raises:
            AnalysisRuntimeError: If runtime not initialized or IR agent missing
            ValueError: If agent_name already registered

        Example:
            await runtime.register_agent(
                VulnScanner,
                "vuln_scanner",
                lambda: VulnScanner(description="Scanner")
            )
        """
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

        # Register with AutoGen using agent class's own register_all method
        # This ensures agent's message handlers are properly registered
        await agent_type.register_all(self._runtime, agent_name, factory_wrapper)

        # Track this agent (agent_name -> agent_type mapping)
        self._registered_agents[agent_name] = agent_type

    async def send_message(self, request: Request, target: AgentId) -> Response:
        """Send a message to an agent - the main entry point for all operations.

        This is how you kick off any analysis or IR query:
        - User code calls this to initiate processing
        - Runtime routes request to target agent via AutoGen
        - Agent processes and returns response
        - Runtime validates and returns response to user

        Flow:
            User -> send_message() -> AutoGen -> Agent.handle_*() -> Response -> User

        Args:
            request: Request object (IRRequest, TaskRequest, etc.)
            target: AgentId specifying which agent should handle this request

        Returns:
            Response from the agent (success/failure with data/error)

        Raises:
            AnalysisRuntimeError: If runtime not initialized or response is invalid

        Example:
            # Send IR request
            response = await runtime.send_message(
                IRRequest(type="get_stats", payload={}),
                runtime.ir_agent_id
            )

            # Send task request
            response = await runtime.send_message(
                TaskRequest(type="scan", payload={}),
                AgentId("vuln_scanner", "default")
            )
        """
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
        """Get the IRStorageAgent's AgentId.

        This is commonly used when:
        - Creating analysis agents (they need IR agent ID to communicate)
        - Sending messages directly to IRStorageAgent

        Returns:
            AgentId of IRStorageAgent (format: "IRStorageAgent/default")

        Raises:
            AnalysisRuntimeError: If initialize() hasn't been called yet

        Example:
            # Pass to analysis agent constructor
            agent = VulnScanner(
                description="Scanner",
                ir_storage_agent_id=runtime.ir_agent_id
            )

            # Send message directly to IR agent
            response = await runtime.send_message(
                request, runtime.ir_agent_id
            )
        """
        if self._ir_agent_id is None:
            raise AnalysisRuntimeError("Runtime not initialized")
        return self._ir_agent_id

    @property
    def ir_view(self) -> IRView:
        """Get direct access to the IRView instance.

        Use this for advanced scenarios where you need to bypass agents
        and directly manipulate the IR graph (e.g., in scripts, notebooks).

        For normal agent-based analysis, use send_message() instead.

        Returns:
            IRView instance with full graph access

        Raises:
            AnalysisRuntimeError: If initialize() hasn't been called yet

        Example:
            # Direct graph access
            functions = await runtime.ir_view.get_all_units_by_kind(
                UKRegistry.Function()
            )
        """
        if self._ir_view is None:
            raise AnalysisRuntimeError("Runtime not initialized")
        return self._ir_view

    @property
    def backend(self) -> CPGBackend:
        """Get the backend instance.

        Useful for checking backend state or accessing backend-specific features.

        Returns:
            CPGBackend instance (connected)

        Raises:
            AnalysisRuntimeError: If initialize() hasn't been called yet

        Example:
            # Check backend connection
            if runtime.backend.is_connected():
                ...
        """
        if self._backend is None:
            raise AnalysisRuntimeError("Backend not initialized")
        return self._backend

    @property
    def autogen_runtime(self) -> AgentRuntime:
        """Get the underlying AutoGen runtime.

        This exposes the raw AutoGen runtime for advanced use cases:
        - Custom message routing
        - Direct agent inspection
        - Low-level runtime control

        Most users should use AnalysisRuntime's high-level API instead.

        Returns:
            AutoGen SingleThreadedAgentRuntime instance

        Raises:
            AnalysisRuntimeError: If initialize() hasn't been called yet
        """
        if self._runtime is None:
            raise AnalysisRuntimeError("Runtime not initialized")
        return self._runtime


# ============================================
# Error Classes
# ============================================


class AnalysisRuntimeError(Exception):
    """Exception raised for runtime-related errors.

    This includes:
    - Runtime not initialized/started when operation requires it
    - Backend creation/connection failures
    - Agent registration conflicts
    - Cleanup failures during shutdown

    The exception message contains details about what went wrong.
    """

    pass
