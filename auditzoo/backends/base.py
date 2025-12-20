"""Base utilities for IR backends.

Common configuration, error handling, and utilities shared by all backends.
"""

import os
from dataclasses import dataclass

from auditzoo.core.ir.backend_api import BackendConfigError


@dataclass
class BackendConfig:
    """Base configuration for backends."""

    backend_type: str  # "joern" or "treesitter"
    language: str  # language for the project of interest
    source_path: str  # Path to source code to parse
    analysis_path: str  # Path to store analysis artifacts
    project_name: str  # Name of the project

    def __init__(
        self,
        backend_type: str,
        source_path: str,
        language: str,
        analysis_path: str | None = None,
        project_name: str | None = None,
    ):
        self.backend_type = backend_type
        self.source_path = os.path.abspath(os.path.expanduser(source_path))
        self.language = language
        self.analysis_path = self._get_analysis_path(self.source_path, analysis_path)
        self.project_name = (
            project_name
            if project_name is not None
            else os.path.basename(self.source_path.rstrip("/"))
        )

    @staticmethod
    def _get_analysis_path(source_path: str, analysis_path: str | None = None) -> str:
        """Get the path for storing analysis artifacts.

        Args:
            source_path: Path to the source code
            analysis_path: Optional custom analysis path
        Returns:
            Path to store analysis artifacts
        """
        if analysis_path:
            return os.path.abspath(os.path.expanduser(analysis_path))

        # If source_path is a file, use its parent directory, else use source_path
        if os.path.isfile(source_path):
            return os.path.abspath(
                os.path.join(os.path.dirname(source_path), ".auditzoo")
            )
        else:
            return os.path.abspath(os.path.join(source_path, ".auditzoo"))


@dataclass
class JoernConfig(BackendConfig):
    """Configuration for Joern backend."""

    joern_path: str  # Path to Joern installation
    host: str = "localhost"
    port: int = 8080

    def __init__(
        self,
        source_path: str,
        language: str | None = None,
        analysis_path: str | None = None,
        project_name: str | None = None,
        joern_path: str | None = None,
        **kwargs,
    ):
        super().__init__(
            backend_type="joern",
            source_path=source_path,
            language=language if language is not None else "auto",
            analysis_path=analysis_path,
            project_name=project_name,
        )
        if self.language is None:
            raise BackendConfigError("Language must be specified for Joern backend")

        joern_path = kwargs.get("joern_path")
        if joern_path is None:
            joern_path = os.path.join(
                os.environ.get("CONDA_PREFIX", "/opt"), "opt/joern"
            )
        self.joern_path = joern_path

        self.host = kwargs.get("host", "localhost")
        self.port = kwargs.get("port", 8080)


@dataclass
class TreeSitterConfig(BackendConfig):
    """Configuration for TreeSitter backend."""

    grammar_path: str | None = None

    def __init__(
        self,
        source_path: str,
        language: str,
        analysis_path: str | None = None,
        project_name: str | None = None,
        **kwargs,
    ):
        super().__init__(
            backend_type="treesitter",
            source_path=source_path,
            language=language,
            analysis_path=analysis_path,
            project_name=project_name,
        )
        self.grammar_path = kwargs.get("grammar_path")
