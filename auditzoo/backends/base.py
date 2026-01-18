"""Base utilities for IR backends.

Common configuration, error handling, and utilities shared by all backends.
"""

import os
from dataclasses import dataclass

from auditzoo.core.ir.backend_api import BackendConfig, BackendConfigError


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
