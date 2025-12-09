"""Base utilities for IR backends.

Common configuration, error handling, and utilities shared by all backends.
"""

from dataclasses import dataclass


@dataclass
class BackendConfig:
    """Base configuration for backends."""

    backend_type: str  # "lsp", "joern", "treesitter"
    language: str


@dataclass
class JoernConfig(BackendConfig):
    """Configuration for Joern backend."""

    joern_path: str  # Path to Joern installation
    db_path: str | None = None  # Path to CPG database
    host: str = "localhost"
    port: int = 8080

    def __init__(self, language: str, joern_path: str, **kwargs):
        super().__init__(backend_type="joern", language=language)
        self.joern_path = joern_path
        self.db_path = kwargs.get("db_path")
        self.host = kwargs.get("host", "localhost")
        self.port = kwargs.get("port", 8080)


@dataclass
class TreeSitterConfig(BackendConfig):
    """Configuration for TreeSitter backend."""

    grammar_path: str | None = None

    def __init__(self, language: str, **kwargs):
        super().__init__(backend_type="treesitter", language=language)
        self.grammar_path = kwargs.get("grammar_path")


class BackendError(Exception):
    """Base exception for backend errors."""

    pass


class BackendConnectionError(BackendError):
    """Error connecting to backend."""

    pass


class BackendQueryError(BackendError):
    """Error executing a query."""

    pass
