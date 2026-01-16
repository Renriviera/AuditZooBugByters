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

    synthetic_query: str = "z.file"

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
            try:
                relative_path = file_path.relative_to(project_root)
                name = str(relative_path)
            except ValueError:
                # If file is not under project_root, use absolute path
                name = str(file_path)

            unit = CodeUnit.synthetic(
                synthetic_id=f"file:{file_path}",
                kind=self,
                code=code,
                name=name,
                location=CodeLocation(
                    file_path=file_path,
                    line_start=1,
                    line_end=line_count,
                    column_start=None,
                ),
            )
            units.append(unit)

        return units

    async def parse(self, raw_str: Any, backend: "CPGBackend") -> list[CodeUnit]:
        raise IRUnsupportedError(
            f"FileKind.parse() is unsupported for backend '{backend.backend_type}'"
        )
