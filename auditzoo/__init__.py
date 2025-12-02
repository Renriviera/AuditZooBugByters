"""AuditZoo: Pluggable, agent-based program analysis framework.

AuditZoo provides a unified infrastructure for building and composing
program analyses using AutoGen-Core agents.
"""

__version__ = "0.1.0"

from auditzoo.core.runtime.engine import (
    create_runtime,
    get_runtime,
    shutdown_runtime,
    AuditZooRuntime,
)

__all__ = ["create_runtime", "get_runtime", "shutdown_runtime", "AuditZooRuntime"]
