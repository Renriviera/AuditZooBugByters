from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitRelation, RelationKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class AnnotatedBy(RelationKind):
    """Kind of annotation/comment relation between code units.

    Represents a code unit being annotated/commented by another unit.
    Examples: function annotated by docstring, class annotated by decorator.
    """

    def _to_kwargs(self) -> dict[str, Any]:
        raise IRUnimplementedError(
            "AnnotatedByRelationKind._to_kwargs() not implemented"
        )

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        raise IRUnimplementedError(
            "AnnotatedByRelationKind._from_kwargs() not implemented"
        )

    def to_query(
        self, source_unit_id: str, backend_type: str, language: str | None = None
    ) -> str:
        raise IRUnimplementedError(
            f"AnnotatedByRelationKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        raise IRUnimplementedError(
            f"AnnotatedByRelationKind.from_response() not implemented for backend '{backend_type}'"
        )
