from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnimplementedError

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


@dataclass(frozen=True)
class LocalVariable(CodeUnitKind):
    """Kind of local variable code unit.

    Represents local variables within function/method scope.
    """

    async def to_query(self, backend: "CPGBackend") -> str:
        raise IRUnimplementedError(
            f"LocalVariableKind.to_query() not implemented for backend '{backend.backend_type}'"
        )

    async def from_response(
        self, response: Any, backend: "CPGBackend"
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"LocalVariableKind.to_code_unit() not implemented for backend '{backend.backend_type}'"
        )


@dataclass(frozen=True)
class GlobalVariable(CodeUnitKind):
    """Kind of global variable code unit.

    Represents global/module-level variables.
    """

    async def to_query(self, backend: "CPGBackend") -> str:
        raise IRUnimplementedError(
            f"GlobalVariableKind.to_query() not implemented for backend '{backend.backend_type}'"
        )

    async def from_response(
        self, response: Any, backend: "CPGBackend"
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"GlobalVariableKind.to_code_unit() not implemented for backend '{backend.backend_type}'"
        )


@dataclass(frozen=True)
class Parameter(CodeUnitKind):
    """Kind of parameter code unit.

    Represents function/method parameters.
    """

    async def to_query(self, backend: "CPGBackend") -> str:
        raise IRUnimplementedError(
            f"ParameterKind.to_query() not implemented for backend '{backend.backend_type}'"
        )

    async def from_response(
        self, response: Any, backend: "CPGBackend"
    ) -> list[CodeUnit]:
        raise IRUnimplementedError(
            f"ParameterKind.to_code_unit() not implemented for backend '{backend.backend_type}'"
        )
