from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import (
    CodeUnit,
    CodeUnitRelation,
    RelationDirection,
    RelationKind,
)
from auditzoo.core.ir.model.errors import IRUnimplementedError, IRUnsupportedError
from auditzoo.core.ir.model.unit_kinds.file import File
from auditzoo.core.ir.model.unit_kinds.function import Function

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


@dataclass(frozen=True)
class ContainedIn(RelationKind):
    """Kind of containment relation between code units.

    Represents a code unit being contained within another unit.
    Examples: method contained in class, function contained in module,
    statement contained in function.

    ConatinedInRelation is a single-directional relation, which means that
    it cannot be reversedly traversed to represent "contains" relationship.
    """

    level: str  # e.g., "class", "function", "module", "file"

    def _to_kwargs(self) -> dict[str, Any]:
        return {"level": self.level}

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        return cls(level=kwargs["level"])

    async def fetch_backend(
        self,
        source_unit: CodeUnit,
        direction: "RelationDirection",
        backend: "CPGBackend",
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        if direction != "out":
            raise IRUnsupportedError(
                "ContainedInRelationKind only supports 'out' direction. Try using 'Contains' relation instead."
            )

        if self.level == "file":
            node = File().from_path(source_unit.location.file_path, backend)
            if node is None:
                return []
            else:
                return [(node, CodeUnitRelation(kind=self))]

        raise IRUnimplementedError(
            f"ContainedInRelationKind.to_query() with level '{self.level}' not implemented for backend '{backend.backend_type}'"
        )


@dataclass(frozen=True)
class Contains(RelationKind):
    """Kind of containment relation between code units.

    Represents a code unit containing another unit.
    Examples: class containing method, module containing function,
    file containing module.

    ContainsRelation is a single-directional relation, which means that
    it cannot be reversedly traversed to represent "contained in" relationship.
    """

    level: str  # e.g., "class", "function", "module", "file"

    def _to_kwargs(self) -> dict[str, Any]:
        return {"level": self.level}

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        return cls(level=kwargs["level"])

    async def fetch_backend(
        self,
        source_unit: CodeUnit,
        direction: "RelationDirection",
        backend: "CPGBackend",
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        if direction != "out":
            raise IRUnsupportedError(
                "ContainsRelationKind only supports 'out' direction. Try using 'ContainedIn' relation instead."
            )

        if self.level == "function":
            # File contains all functions defined within it's file path
            query = f"""
                cpg.method
                    .where(_.filenameExact("{str(source_unit.location.file_path)}"))
                    .filter {{ m =>
                        val s = m.lineNumber.getOrElse(Int.MaxValue)
                        val e = m.lineNumberEnd.getOrElse(Int.MinValue)
                        s >= {int(source_unit.location.line_start)} && e <= {int(source_unit.location.line_end)}
                    }}
                    .isExternal(false)
                    .nameNot("<global>")
                    .dedup
                    .toJson
            """.strip()

            response = await backend.query(query)
            units = await Function().parse(raw_data=response, backend=backend)
            return [(unit, CodeUnitRelation(kind=self)) for unit in units]

        raise IRUnimplementedError(
            f"ContainsRelationKind.to_query() with level '{self.level}' not implemented for backend '{backend.backend_type}'"
        )
