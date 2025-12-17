from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class Comment(CodeUnitKind):
    """Kind of comment code unit.

    Represents single-line and multi-line comments, documentation strings.
    """

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"CommentKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: dict[str, Any], backend_type: str, language: str | None = None
    ) -> CodeUnit | None:
        raise IRUnimplementedError(
            f"CommentKind.to_code_unit() not implemented for backend '{backend_type}'"
        )
