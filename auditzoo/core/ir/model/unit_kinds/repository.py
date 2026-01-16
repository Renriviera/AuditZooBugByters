from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import CodeLocation, CodeUnit, CodeUnitKind
from auditzoo.core.ir.model.errors import IRUnsupportedError

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


@dataclass(frozen=True)
class Repository(CodeUnitKind):
    """Kind of repository code unit.

    Represents the entire repository structure and layout as a single code unit.
    The code field contains a user-readable text representation of the directory tree,
    while the metadata field contains structured directory information.
    """

    synthetic_query: str = "z.repo"

    def _build_tree_structure(self, root: Path, prefix: str = "") -> tuple[str, dict]:
        """Build a tree representation of the directory structure.

        Args:
            root: Root directory path
            prefix: Prefix for tree formatting

        Returns:
            Tuple of (tree_string, structured_dict)
        """
        structured: dict[str, str | list] = {
            "name": root.name if root.name else str(root),
            "path": str(root),
            "type": "directory" if root.is_dir() else "file",
        }

        if root.is_file():
            return "", structured

        try:
            children = sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name))
        except PermissionError:
            return f"{prefix}[Permission Denied]\n", structured

        # Filter out common directories to ignore
        ignore_dirs = {"__pycache__", "venv", "node_modules"}
        children = [
            c
            for c in children
            if c.name not in ignore_dirs and not c.name.startswith(".")
        ]

        tree_lines = []
        structured["children"] = []

        for i, child in enumerate(children):
            is_last_child = i == len(children) - 1
            connector = "└── " if is_last_child else "├── "
            extension = "    " if is_last_child else "│   "

            if child.is_dir():
                tree_lines.append(f"{prefix}{connector}{child.name}/")
                child_tree, child_struct = self._build_tree_structure(
                    child, prefix + extension
                )
                tree_lines.append(child_tree)
                assert type(structured["children"]) is list
                structured["children"].append(child_struct)
            else:
                # Get file size
                try:
                    size = child.stat().st_size
                    size_str = self._format_size(float(size))
                    tree_lines.append(f"{prefix}{connector}{child.name} ({size_str})")
                except (OSError, PermissionError):
                    tree_lines.append(f"{prefix}{connector}{child.name}")

                assert type(structured["children"]) is list
                structured["children"].append(
                    {
                        "name": child.name,
                        "path": str(child),
                        "type": "file",
                    }
                )

        return "\n".join(tree_lines), structured

    def _format_size(self, size: float) -> str:
        """Format file size in human-readable format.

        Args:
            size: Size in bytes

        Returns:
            Formatted size string
        """
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}TB"

    async def fetch_backend(self, backend: "CPGBackend") -> list[CodeUnit]:
        """Fetch repository structure from the backend.

        Creates a single CodeUnit representing the entire repository structure.
        """
        project_root = Path(backend.source_path)

        if not project_root.exists():
            return []

        # Build tree representation
        root_name = (
            project_root.name if project_root.is_dir() else project_root.parent.name
        )
        tree_header = f"{root_name}/\n"

        if project_root.is_file():
            # Single file - just return info about it
            try:
                size = project_root.stat().st_size
                size_str = self._format_size(float(size))
                tree_text = f"{root_name} ({size_str})"
            except (OSError, PermissionError):
                tree_text = root_name

            structured_info = {
                "name": root_name,
                "path": str(project_root),
                "type": "file",
            }
        else:
            # Directory - build full tree
            tree_body, structured_info = self._build_tree_structure(project_root)
            tree_text = tree_header + tree_body

        # Create synthetic CodeUnit for repository
        unit = CodeUnit.synthetic(
            synthetic_id=f"repo:{project_root}",
            kind=self,
            code=tree_text.strip(),
            name=root_name,
            location=CodeLocation(
                file_path=project_root,
                line_start=-1,
                line_end=-1,
                column_start=None,
            ),
            structure=structured_info,
        )

        return [unit]

    async def parse(self, raw_data: Any, backend: "CPGBackend") -> list[CodeUnit]:
        raise IRUnsupportedError(
            f"RepositoryKind.parse() is unsupported for backend '{backend.backend_type}'"
        )
