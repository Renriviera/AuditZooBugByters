from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitRelation, RelationKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class ContainedIn(RelationKind):
    """Kind of containment relation between code units.

    Represents a code unit being contained within another unit.
    Examples: method contained in class, function contained in module,
    statement contained in function.

    ConatinedInRelation is a single-directional relation, which means that
    it cannot be reversedly traversed to represent "contains" relationship.
    """

    level: str  # e.g., "class", "function", "module", "file"

    def _to_kwargs(self) -> dict[str, Any]:
        raise IRUnimplementedError(
            "ContainedInRelationKind._to_kwargs() not implemented"
        )

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        raise IRUnimplementedError(
            "ContainedInRelationKind._from_kwargs() not implemented"
        )

    def to_query(
        self, source_unit_id: str, backend_type: str, language: str | None = None
    ) -> str:
        raise IRUnimplementedError(
            f"ContainedInRelationKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        raise IRUnimplementedError(
            f"ContainedInRelationKind.from_response() not implemented for backend '{backend_type}'"
        )


@dataclass(frozen=True)
class Contains(RelationKind):
    """Kind of containment relation between code units.

    Represents a code unit containing another unit.
    Examples: class containing method, module containing function,
    file containing module.

    ContainsRelation is a single-directional relation, which means that
    it cannot be reversedly traversed to represent "contained in" relationship.
    """

    level: str  # e.g., "class", "function", "module", "file"

    def _to_kwargs(self) -> dict[str, Any]:
        raise IRUnimplementedError("ContainsRelationKind._to_kwargs() not implemented")

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        raise IRUnimplementedError(
            "ContainsRelationKind._from_kwargs() not implemented"
        )

    def to_query(
        self, source_unit_id: str, backend_type: str, language: str | None = None
    ) -> str:
        raise IRUnimplementedError(
            f"ContainsRelationKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        raise IRUnimplementedError(
            f"ContainsRelationKind.from_response() not implemented for backend '{backend_type}'"
        )
