from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import (
    CodeUnit,
    CodeUnitRelation,
    RelationDirection,
    RelationKind,
)
from auditzoo.core.ir.model.errors import IRUnimplementedError

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


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

    async def fetch_backend(
        self,
        source_unit: CodeUnit,
        direction: "RelationDirection",
        backend: "CPGBackend",
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        raise IRUnimplementedError(
            f"AnnotatedByRelationKind.to_query() not implemented for backend '{backend.backend_type}'"
        )
