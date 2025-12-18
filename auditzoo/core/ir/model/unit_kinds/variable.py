from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError


@dataclass(frozen=True)
class LocalVariable(CodeUnitKind):
    """Kind of local variable code unit.

    Represents local variables within function/method scope.
    """

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"LocalVariableKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"LocalVariableKind.to_code_unit() not implemented for backend '{backend_type}'"
        )


@dataclass(frozen=True)
class GlobalVariable(CodeUnitKind):
    """Kind of global variable code unit.

    Represents global/module-level variables.
    """

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"GlobalVariableKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"GlobalVariableKind.to_code_unit() not implemented for backend '{backend_type}'"
        )


@dataclass(frozen=True)
class Parameter(CodeUnitKind):
    """Kind of parameter code unit.

    Represents function/method parameters.
    """

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        raise IRUnimplementedError(
            f"ParameterKind.to_query() not implemented for backend '{backend_type}'"
        )

    def from_response(
        self, response: Any, backend_type: str, language: str | None = None
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"ParameterKind.to_code_unit() not implemented for backend '{backend_type}'"
        )
