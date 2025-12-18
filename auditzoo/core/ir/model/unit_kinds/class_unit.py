from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class Class(CodeUnitKind):
    """Kind of class/struct/interface code unit.

    Represents class definitions, structs, interfaces, traits, etc.
    """

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"ClassKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"ClassKind.to_code_unit() not implemented for backend '{backend_type}'"
        )
