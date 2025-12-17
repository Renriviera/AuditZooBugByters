from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class Function(CodeUnitKind):
    """Kind of function code unit."""

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"FunctionKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> CodeUnit | None:
        raise IRUnimplementedError(
            f"FunctionKind.to_code_unit() not implemented for backend '{backend_type}'"
        )
