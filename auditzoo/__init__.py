"""AuditZoo: Pluggable, agent-based program analysis framework.

AuditZoo provides a unified infrastructure for building and composing
program analyses using AutoGen-Core agents.

Key Components:
    - Runtime: AnalysisRuntime for managing backend and agents
    - Agents: BaseAnalysisAgent, IRStorageAgent for IR access
    - Protocol: Request/Response messaging
    - IR Model: CodeUnit, Relations, Facts
    - Backends: Joern, and more

Quick Start:
    from auditzoo import AnalysisRuntime, BaseAnalysisAgent
    from auditzoo.core.protocol import TaskRequest, Response
    from auditzoo.backends.ingestion import auto_detect_backend

    # Create runtime
    config = auto_detect_backend("./my_project")
    async with AnalysisRuntime(config) as runtime:
        # Register custom agent
        await runtime.register_agent(...)

        # Send analysis request
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
