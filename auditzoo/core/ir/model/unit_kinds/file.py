from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import CodeLocation, CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnsupportedError

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


@dataclass(frozen=True)
class File(CodeUnitKind):
    """Kind of file/source file code unit.

    Represents a complete source file or compilation unit.
    """

    def from_path(self, file_path: Path, backend: "CPGBackend") -> CodeUnit | None:
        """Create a CodeUnit from a given file path.

        Args:
            file_path: Path to the source file
            backend: CPG backend instance

        Returns:
            CodeUnit representing the file
        """
        absolute_path = Path(backend.source_path) / Path(file_path)
        try:
            code = absolute_path.read_text()
        except (UnicodeDecodeError, PermissionError):
            return None

        line_count = len(code.splitlines()) if code else 1

        return CodeUnit.synthetic(
            synthetic_id=f"file:{file_path}",
            kind=self,
            code=code,
            name=str(file_path),
            location=CodeLocation(
                file_path=file_path,
                line_start=1,
                line_end=line_count,
                column_start=None,
            ),
        )

    async def fetch_backend(self, backend: "CPGBackend") -> list[CodeUnit]:
        # File unit query is agnostic to backend
        project_root = Path(backend.source_path)

        if not project_root.exists():
            return []

        units = []

        # Traverse all files in the project root
        if project_root.is_file():
            # If source_path is a single file
            files = [project_root]
        else:
            # If source_path is a directory, recursively find all files
            files = [f for f in project_root.rglob("*") if f.is_file()]

        for file_path in files:
            # Read file content
            try:
                code = file_path.read_text()
            except (UnicodeDecodeError, PermissionError):
                # Skip files that can't be read as text
                continue

            # Count lines for location (splitlines() handles all line ending types)
            line_count = len(code.splitlines()) if code else 1

            # Create synthetic CodeUnit for this file
            # Use relative path as name for readability
            relative_path = file_path.relative_to(project_root)

            unit = CodeUnit.synthetic(
                synthetic_id=f"file:{relative_path}",
                kind=self,
                code=code,
                name=str(relative_path),
                location=CodeLocation(
                    file_path=relative_path,
                    line_start=1,
                    line_end=line_count,
                    column_start=None,
                ),
            )
            units.append(unit)

        return units

    async def parse(self, raw_data: Any, backend: "CPGBackend") -> list[CodeUnit]:
        raise IRUnsupportedError(
            f"FileKind.parse() is unsupported for backend '{backend.backend_type}'"
        )
