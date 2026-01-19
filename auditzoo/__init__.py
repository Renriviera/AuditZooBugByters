"""AuditZoo: agent-based program analysis framework.

Quick Start:
    from auditzoo import AnalysisRuntime
    from auditzoo.backends.ingestion import auto_detect_backend

    config = auto_detect_backend("./my_project")
    async with AnalysisRuntime(config) as runtime:
        response = await runtime.send_message(...)
"""

__version__ = "0.1.0"

# Ingestion utilities
from auditzoo.backends.ingestion import auto_detect_backend, create_backend

# Agents
from auditzoo.core.agents import BaseAgent, BaseAnalysisAgent, IRStorageAgent

# Backend
from auditzoo.core.ir.backend_api import BackendConfig, CPGBackend

# IR Model - Core types
from auditzoo.core.ir.model import (
    CodeLocation,
    CodeUnit,
    CodeUnitKind,
    CodeUnitRelation,
    RelationDirection,
    RelationKind,
    RKRegistry,
    UKRegistry,
)

# Protocol
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.responses import Response

# Runtime
from auditzoo.core.runtime import AnalysisRuntime

__all__ = [
    # Version
    "__version__",
    # Runtime
    "AnalysisRuntime",
    # Agents
    "BaseAgent",
    "BaseAnalysisAgent",
    "IRStorageAgent",
    # Protocol
    "Request",
    "Response",
    # IR Model
    "CodeUnit",
    "CodeUnitKind",
    "CodeUnitRelation",
    "RelationKind",
    "CodeLocation",
    "RelationDirection",
    "UKRegistry",
    "RKRegistry",
    # Backend
    "CPGBackend",
    "BackendConfig",
    # Ingestion
    "auto_detect_backend",
    "create_backend",
]
