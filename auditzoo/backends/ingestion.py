"""Backend ingestion and IR view construction.

This module provides utilities for choosing and configuring backends,
and building IR views during the preprocessing phase.
"""

from auditzoo.backends.base import (
    BackendConfig,
    JoernConfig,
    TreeSitterConfig,
)
from auditzoo.backends.joern.backend import JoernBackend
from auditzoo.core.ir.backend_api import BackendUnsupportedLanguageError, CPGBackend


async def create_backend(config: BackendConfig) -> CPGBackend:
    """Create and initialize a backend.

    Args:
        config: Backend configuration

    Returns:
        Initialized backend instance

    Raises:
        ValueError: If backend type is unknown
    """
    if config.backend_type == "joern":
        if not isinstance(config, JoernConfig):
            raise TypeError("Expected JoernConfig for Joern backend")
        backend = JoernBackend(config)
        await backend.connect()
        return backend

    elif config.backend_type == "treesitter":
        raise NotImplementedError("TreeSitter backend not yet implemented")

    else:
        raise ValueError(f"Unknown backend type: {config.backend_type}")


def auto_detect_backend(
    source_path: str,
    language: str | None = None,
    analysis_path: str | None = None,
    project_name: str | None = None,
    prefer: str | None = None,
) -> BackendConfig:
    """Auto-detect the best backend for a project.

    Args:
        source_path: Path to the project of interest
        language: Programming language, automatically detected if None
        analysis_path: Path to store analysis artifacts
        project_name: Name of the project
        prefer: Preferred backend type if available

    Returns:
        Backend configuration
    """
    if prefer == "joern" or language is None:
        return JoernConfig(
            source_path=source_path,
            language=language,
            analysis_path=analysis_path,
            project_name=project_name,
        )
    else:
        if language is None:
            raise BackendUnsupportedLanguageError(
                "Language must be specified for TreeSitter backend."
            )
        return TreeSitterConfig(
            source_path=source_path,
            language=language,
            analysis_path=analysis_path,
            project_name=project_name,
        )
