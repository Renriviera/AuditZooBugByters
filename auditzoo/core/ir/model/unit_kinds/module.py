from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class Module(CodeUnitKind):
    """Kind of module/namespace/package code unit.

    Represents logical groupings like Python modules, Java packages,
    C++ namespaces, etc.
    """

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"ModuleKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> CodeUnit | None:
        raise IRUnimplementedError(
            f"ModuleKind.to_code_unit() not implemented for backend '{backend_type}'"
        )
