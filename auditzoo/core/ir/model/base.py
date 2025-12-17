"""CPG-centered IR model for AuditZoo.

This module defines the core IR model types used throughout AuditZoo.
The model is built around CodeUnit, a flexible abstraction that can represent
any granularity of code (file, class, function, statement, etc.) backed by CPG nodes.

Core Components:
- CodeUnit: Represents a unit of code with unique ID, kind, code, signature, and location.
  Units are intentionally kept minimal - the core model only has these essential fields.
  Additional attributes can be stored in Facts (see facts.py).

- CodeLocation: Represents source code location in a file (path, line range, column).

- CodeUnitKind: Abstract base class for kinds of code units. This is the extensibility
  point for defining what kind of code unit something is (function, class, statement, etc.).
  Each kind can have additional fields - e.g., ContainedInRelation has a 'level' field
  to specify containment granularity (function/class/module).

- RelationKind: Abstract base class for relationships between code units. Kinds represent
  the general category of relation (e.g., "calls", "contains", "annotated_by"), while
  individual instances can have additional fields for specificity:
  * Example: ContainsRelation has a 'level' field ("function", "class", "module")

- CodeUnitRelation: Wraps a RelationKind with additional metadata. This is where
  relation-specific attributes are stored (e.g., call_site for calls, confidence scores).

Graph Structure:
- CodeUnits are stored as graph nodes (keyed by unit ID)
- Relations define edges in a NetworkX MultiDiGraph
- The RelationKind (or its identifier) is used as the edge KEY in the graph
- Additional edge attributes are stored in the edge data dict (e.g., call_site_id, confidence)
- This allows multiple different relation types between the same pair of code units

Extensibility Design:

1. Extending CodeUnitKind:
   - Create a new class inheriting from CodeUnitKind
   - Add any kind-specific fields as dataclass attributes
   - Implement to_query() and from_response() for backend integration
   - Auto-registers via __init_subclass__ in base class

2. Extending RelationKind:
   - Create a new class inheriting from RelationKind
   - Add any relation-specific fields (e.g., 'level' for containment)
   - Implement _to_kwargs(), _from_kwargs(), to_query(), from_response()
   - Auto-registers via __init_subclass__ in base class

3. Extending Facts (see facts.py):
   - Create classes inheriting from UnitFact or RelationFact
   - Facts attach analysis results to CodeUnits without modifying the core model
   - UnitFacts attach to single nodes, RelationFacts connect two nodes
   - Auto-registers via __init_subclass__ in base class

Philosophy:
- Keep the core model minimal (CodeUnit, CodeUnitRelation)
- Use Kinds for type categorization with type-specific fields
- Use Facts for attaching analysis results and findings
- Use edge attributes for relation-specific metadata
- This separation avoids model bloat while maintaining extensibility
"""

import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Literal, Optional

from auditzoo.core.ir.model.errors import IRRelationKindError

RelationDirection = Literal["in", "out"]


@dataclass
class CodeLocation:
    """Location of code in a source file.

    Attributes:
        file_path: Path to the source file
        line_start: Starting line number (1-indexed)
        line_end: Ending line number (inclusive)
        column_start: Optional starting column (1-indexed)
    """

    file_path: Path
    line_start: int
    line_end: int
    column_start: int | None = None

    def __str__(self) -> str:
        loc_str = f"{self.file_path}:{self.line_start}"
        if self.line_end != self.line_start:
            loc_str += f"-{self.line_end}"
        if self.column_start is not None:
            loc_str += f":{self.column_start}"
        return loc_str

    def contains(self, other: "CodeLocation") -> bool:
        """Check if this location contains another location.

        Args:
            other: Another CodeLocation to check
        Returns:
            True if this location fully contains the other location
        """
        if self.file_path != other.file_path:
            return False
        if self.line_start > other.line_start or self.line_end < other.line_end:
            return False
        if self.column_start is not None and other.column_start is not None:
            if (
                self.line_start == other.line_start
                and self.column_start > other.column_start
            ):
                return False
        return True


@dataclass(frozen=True)
class CodeUnitKind(ABC):
    """Kinds of code units.

    This is an abstract base class for different kinds of code units.
    """

    # Registry: subclass name -> subclass type
    _registry: ClassVar[dict[str, type["CodeUnitKind"]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not inspect.isabstract(cls):
            cls._registry[cls.__name__] = cls

    @abstractmethod
    def to_query(self, backend_type: str, language: str | None = None) -> str:
        """Convert to a backend-specific query string.

        Args:
            backend_type: Type of backend ("joern", "treesitter", etc.)
            language: Programming language (optional, may affect query)

        Returns:
            Backend-specific query string to select this kind of code unit
        """
        pass

    @abstractmethod
    def from_response(
        self, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> Optional["CodeUnit"]:
        """Convert a backend query response to a CodeUnit of this kind.

        Args:
            response: Raw response from backend CPG query
            backend_type: Type of backend ("joern", "treesitter", etc.)
            language: Programming language (optional, may affect query)

        Returns:
            CodeUnit instance representing the code unit, or None if not applicable
        """
        pass

    @classmethod
    def parse_response(
        cls, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> Optional["CodeUnit"]:
        """Convert a backend query response to a CodeUnit by trying all registered kinds. It will return the first matching kind.

        Args:
            response: Raw response from backend CPG query
            backend_type: Type of backend ("joern", "treesitter", etc.)
            language: Programming language (optional, may affect query)

        Returns:
            CodeUnit instance representing the code unit, or None if not applicable
        """
        for kind_cls in cls._registry.values():
            unit = kind_cls().from_response(response, backend_type, language)
            if unit is not None:
                return unit

        return None


@dataclass(frozen=True)
class RelationKind(ABC):
    """Types of relationships between code units.

    These represent semantic relationships in the program structure,
    such as calls, inheritance, references, etc.
    """

    _registry: ClassVar[dict[str, type["RelationKind"]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not inspect.isabstract(cls):
            cls._registry[cls.__name__] = cls

    @abstractmethod
    def to_query(
        self, source_unit_id: str, backend_type: str, language: str | None = None
    ) -> str:
        """Convert to a backend-specific query string.

        Args:
            source_unit_id: ID of the source code unit
            backend_type: Type of backend ("joern", "treesitter", etc.)
            language: Programming language (optional, may affect query)

        Returns:
            Backend-specific query string to select this relationship
        """
        pass

    @abstractmethod
    def from_response(
        self, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> tuple["CodeUnit", "CodeUnitRelation"] | None:
        """Convert a backend query response to a related CodeUnit and relation.

        Args:
            response: Raw response from backend CPG query
            backend_type: Type of backend ("joern", "treesitter", etc.)
            language: Programming language (optional, may affect query)

        Returns:
            Tuple of related CodeUnit and CodeUnitRelation, or None if no relation found
        """
        pass

    @abstractmethod
    def _to_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs dict for serialization."""
        pass

    @classmethod
    @abstractmethod
    def _from_kwargs(cls, **kwargs) -> "RelationKind":
        """Create instance from kwargs dict."""
        pass

    def to_dict(self) -> dict:
        """
        Serialize to dict for storage.
        """
        out: dict[str, Any] = {
            "__class__": self.__class__.__name__,
            "kwargs": self._to_kwargs(),
        }
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "RelationKind":
        """Deserialize from dict."""
        kind_name = data["__class__"]
        kind_cls = cls._registry.get(kind_name)
        if not kind_cls:
            raise IRRelationKindError(f"Unknown RelationKind: {kind_name}")

        kwargs = data.get("kwargs", {})
        return kind_cls._from_kwargs(**kwargs)


@dataclass(frozen=True)
class CodeUnitRelation:
    """Describes a relationship between code units.

    Attributes:
        kind: The type of relationship
        metadata: Optional additional metadata about the relation
    """

    kind: RelationKind
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init__(self, kind: RelationKind, **kwargs):
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "metadata", kwargs)

    def to_dict(self) -> dict:
        """Serialize to dict for storage."""
        return {
            "kind": self.kind.to_dict(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CodeUnitRelation":
        """Deserialize from dict."""
        kind = RelationKind.from_dict(data["kind"])
        metadata = data.get("metadata", {})
        return cls(kind=kind, **metadata)


@dataclass(frozen=True)
class CodeUnit:
    """A flexible unit of code at any granularity (file, class, function, etc.).

    CodeUnit is the central abstraction in AuditZoo's IR model. It can represent
    code at any level of granularity, from entire files down to individual statements.

    Each CodeUnit has a unique identifier (`id`) which is either:
    - The CPG node ID (if backed by Joern/TreeSitter CPG)
    - A synthetic ID (if created programmatically without CPG backing)

    CodeUnits are hashable and can be used in sets, dicts, and graph structures.
    Identity and equality are based solely on the `id` field.

    A synthetic CodeUnit cannot be stored in the IRView, but can be used
    for temporary analysis or transformations.

    Attributes:
        id: Unique identifier for this CodeUnit (CPG node ID or synthetic)
        is_synthetic: True if this unit is synthetic (not backend-backed)
        kind: The kind of this code unit
        code: The actual source code text for this unit
        signature: Human-readable identifier (e.g., "int foo(char* str)" for functions,
                  "MyClass" for classes, file path for files)
        location: Source code location of this unit
        metadata: Optional additional metadata about this unit

    Examples:
        # CPG-backed function
        CodeUnit.from_cpg(
            cpg_node_id="node_123",
            kind=CodeUnitType(kind=CodeUnitKind.FUNCTION),
            code="def foo(x):\\n    return x + 1",
            signature="foo(x)",
            location=CodeLocation(Path("main.py"), 10, 11)
        )

        # Synthetic unit (no CPG backing)
        CodeUnit.synthetic(
            kind=CodeUnitType(kind=CodeUnitKind.CLASS),
            code="class MyClass:\\n    pass",
            signature="MyClass",
            location=CodeLocation(Path("main.py"), 1, 2)
        )
    """

    # === Identity ===
    id: str  # Unique identifier (CPG node ID or synthetic)

    # === Structure ===
    kind: CodeUnitKind
    code: str
    signature: str
    location: CodeLocation

    # === Backend Reference ===
    is_synthetic: bool  # True if synthetic (not backend-backed)

    def __hash__(self) -> int:
        """Hash based on unique ID.

        This allows CodeUnit to be used in sets, as dict keys, and in graph structures.
        """
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Equality based on unique ID.

        Two CodeUnits are considered equal if they have the same ID,
        regardless of their content. This allows the same logical code
        unit to be updated while maintaining identity in graphs and sets.

        Args:
            other: Object to compare with

        Returns:
            True if other is a CodeUnit with the same ID
        """
        if not isinstance(other, CodeUnit):
            return False
        return self.id == other.id

    @classmethod
    def from_cpg(
        cls,
        cpg_node_id: str,
        kind: CodeUnitKind,
        code: str,
        signature: str,
        location: CodeLocation,
    ) -> "CodeUnit":
        """Create a CodeUnit backed by a CPG node.

        Args:
            cpg_node_id: CPG node identifier from backend
            unit_type: Type/kind of code unit
            code: Source code text
            signature: Human-readable signature
            location: Source code location

        Returns:
            CodeUnit with id = cpg_node_id
        """
        return cls(
            id=cpg_node_id,
            kind=kind,
            code=code,
            signature=signature,
            location=location,
            is_synthetic=False,
        )

    @classmethod
    def synthetic(
        cls,
        kind: CodeUnitKind,
        code: str,
        signature: str,
        location: CodeLocation,
        id_prefix: str = "synthetic",
    ) -> "CodeUnit":
        """Create a synthetic CodeUnit (not backed by CPG).

        Args:
            kind: Type/kind of code unit
            code: Source code text
            signature: Human-readable signature
            location: Source code location
            id_prefix: Prefix for generated ID (default: "synthetic")

        Returns:
            CodeUnit with auto-generated synthetic ID
        """
        import uuid

        synthetic_id = f"{id_prefix}_{uuid.uuid4().hex[:12]}"

        return cls(
            id=synthetic_id,
            kind=kind,
            code=code,
            signature=signature,
            location=location,
            is_synthetic=True,
        )
