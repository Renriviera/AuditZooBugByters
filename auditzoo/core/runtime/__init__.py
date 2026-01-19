"""Runtime module for multi-agent analysis.

Usage:
    from auditzoo.core.runtime import AnalysisRuntime
    from auditzoo.backends.ingestion import auto_detect_backend

    config = auto_detect_backend("./src")
    async with AnalysisRuntime(config) as runtime:
        response = await runtime.send_message(...)
"""

from auditzoo.core.runtime.runtime import AnalysisRuntime

__all__ = ["AnalysisRuntime"]
