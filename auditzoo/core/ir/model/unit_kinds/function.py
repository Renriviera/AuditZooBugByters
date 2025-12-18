from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.model.base import CodeLocation, CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRInvalidResponseError, IRUnimplementedError


@dataclass(frozen=True)
class Function(CodeUnitKind):
    """Kind of function code unit."""

    def to_query(self, backend_type: str, language: str | None = None) -> str:
        if backend_type != "joern":
            raise IRUnimplementedError(
                f"FunctionKind.to_query() not implemented for backend '{backend_type}'"
            )

        return 'cpg.method.isExternal(false).nameNot("<global>").dedup.toJson'

    def from_response(
        self,
        response: list[dict[str, Any]],
        backend_type: str,
        language: str | None = None,
    ) -> list[CodeUnit]:
        if backend_type != "joern":
            raise IRUnimplementedError(
                f"FunctionKind.to_code_unit() not implemented for backend '{backend_type}'"
            )

        try:
            units = []
            for raw_function in response:
                if raw_function.get("_label") != "METHOD":
                    continue

                if raw_function.get("name") == "<global>":
                    continue

                unit = CodeUnit.from_cpg(
                    cpg_node_id=f"{raw_function['_id']}",
                    kind=self,
                    code=raw_function["code"],
                    name=raw_function["name"],
                    location=CodeLocation(
                        file_path=raw_function["filename"],
                        line_start=raw_function["lineNumber"],
                        line_end=raw_function["lineNumberEnd"],
                        column_start=raw_function.get("columnNumber", 0),
                    ),
                    signature=raw_function.get("signature"),
                )
                units.append(unit)

            return units
        except Exception as e:
            raise IRInvalidResponseError(
                f"Invalid response format for FunctionKind from backend '{backend_type}': {response} with error {e}"
            ) from e
