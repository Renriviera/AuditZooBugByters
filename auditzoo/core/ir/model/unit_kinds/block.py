from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class Block(CodeUnitKind):
    """Kind of code block code unit.

    Represents blocks of code (e.g., function bodies, if blocks, loop bodies).
    """

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"BlockKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"BlockKind.to_code_unit() not implemented for backend '{backend_type}'"
        )
