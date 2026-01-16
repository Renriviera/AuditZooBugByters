from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


@dataclass(frozen=True)
class Statement(CodeUnitKind):
    """Kind of general statement code unit.

    Represents generic statements in the code.
    """

    async def fetch_backend(self, backend: "CPGBackend") -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"StatementKind.to_query() not implemented for backend '{backend.backend_type}'"
        )

    async def parse(self, raw_str: Any, backend: "CPGBackend") -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"StatementKind.parse() not implemented for backend '{backend.backend_type}'"
        )
