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
    """

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
        self, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> tuple[CodeUnit, CodeUnitRelation] | None:
        raise IRUnimplementedError(
            f"ContainedInRelationKind.from_response() not implemented for backend '{backend_type}'"
        )
