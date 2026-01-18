"""Runtime module for multi-agent analysis system.

This module provides the AnalysisRuntime class that manages:
- Backend connection lifecycle
- IRView creation and management
- AutoGen Core runtime
- Agent registration and routing

Usage:
    from auditzoo.core.runtime import AnalysisRuntime
    from auditzoo.backends.joern import JoernBackend

    backend = JoernBackend(source_path="./src")
    async with AnalysisRuntime(backend) as runtime:
        response = await runtime.send_message(...)
"""

from auditzoo.core.runtime.runtime import AnalysisRuntime

__all__ = ["AnalysisRuntime"]
