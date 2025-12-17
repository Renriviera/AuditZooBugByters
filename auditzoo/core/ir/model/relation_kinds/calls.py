from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitRelation, RelationKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class Calls(RelationKind):
    """Kind of call relation between code units.

    Represents function/method calls.
    """

    def _to_kwargs(self) -> dict[str, Any]:
        raise IRUnimplementedError("CallRelationKind._to_kwargs() not implemented")

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        raise IRUnimplementedError("CallRelationKind._from_kwargs() not implemented")

    def to_query(
        self, source_unit_id: str, backend_type: str, language: str | None = None
    ) -> str:
        raise IRUnimplementedError(
            f"CallRelationKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> tuple[CodeUnit, CodeUnitRelation] | None:
        raise IRUnimplementedError(
            f"CallRelationKind.from_response() not implemented for backend '{backend_type}'"
        )
