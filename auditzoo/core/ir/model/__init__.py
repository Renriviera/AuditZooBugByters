"""IR model for AuditZoo.

Provides code unit and relation abstractions backed by CPG.
"""

# Import submodules as namespaces
from auditzoo.core.ir.model import relation_kinds as RKRegistry  # Relation Collection
from auditzoo.core.ir.model import unit_kinds as UKRegistry  # Unit Collection

# Import base classes for direct use
from .base import (
    CodeLocation,
    CodeUnit,
    CodeUnitKind,
    CodeUnitRelation,
    RelationDirection,
    RelationKind,
)

# Import errors
from .errors import (
    IRBackendError,
    IRError,
    IRInvalidFactError,
    IRRelationKindError,
    IRUnimplementedError,
    IRUnknownFactError,
    IRValueError,
)

__all__ = [
    # Namespaces
    "UKRegistry",
    "RKRegistry",
    # Base classes
    "CodeUnit",
    "CodeLocation",
    "CodeUnitKind",
    "RelationKind",
    "CodeUnitRelation",
    "RelationDirection",
    # Errors
    "IRError",
    "IRInvalidFactError",
    "IRUnknownFactError",
    "IRValueError",
    "IRRelationKindError",
    "IRUnimplementedError",
    "IRBackendError",
]
