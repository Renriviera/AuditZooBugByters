from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


@dataclass(frozen=True)
class Module(CodeUnitKind):
    """Kind of module/namespace/package code unit.

    Represents logical groupings like Python modules, Java packages,
    C++ namespaces, etc.
    """

    async def to_query(self, backend: CPGBackend) -> str:
        raise IRUnimplementedError(
            f"ModuleKind.to_query() not implemented for backend '{backend.backend_type}'"
        )

    async def from_response(self, response: Any, backend: CPGBackend) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"ModuleKind.to_code_unit() not implemented for backend '{backend.backend_type}'"
        )
