from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitRelation, RelationKind
from auditzoo.core.ir.model.errors import IRUnimplementedError

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


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

    async def fetch_backend(
        self, source_unit_id: str, backend: "CPGBackend"
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        raise IRUnimplementedError(
            f"CallRelationKind.to_query() not implemented for backend '{backend.backend_type}'"
        )

    async def _from_response(
        self, response: Any, backend: "CPGBackend"
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        raise IRUnimplementedError(
            f"CallRelationKind.from_response() not implemented for backend '{backend.backend_type}'"
        )
