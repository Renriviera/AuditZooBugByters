"""Backend ingestion and IR view construction.

This module provides utilities for choosing and configuring backends,
and building IR views during the preprocessing phase.
"""

from auditzoo.backends.base import BackendConfig, JoernConfig, TreeSitterConfig
from auditzoo.core.ir.backend_api import CPGBackend
from auditzoo.core.ir.model import ProgramId
from auditzoo.core.ir.view import IRView


async def create_ir_view(config: BackendConfig) -> IRView:
    """Create an IR view with the appropriate backend.

    Args:
        config: Backend configuration

    Returns:
        An IRView wrapping the configured backend

    Raises:
        ValueError: If backend type is unknown
    """
    backend = await create_backend(config)
    return IRView(backend, ProgramId("unknown"))


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
        from auditzoo.backends.joern.backend import JoernBackend

        assert isinstance(config, JoernConfig), "Expected JoernConfig for joern backend"
        backend = JoernBackend(config)
        await backend.connect()
        return backend

    elif config.backend_type == "treesitter":
        # Placeholder for TreeSitter backend
        # from auditzoo.backends.treesitter.backend import TreeSitterBackend
        # backend = TreeSitterBackend(config)
        # return backend
        raise NotImplementedError("TreeSitter backend not yet implemented")

    else:
        raise ValueError(f"Unknown backend type: {config.backend_type}")


def auto_detect_backend(
    project_path: str, language: str, prefer: str | None = None
) -> BackendConfig:
    """Auto-detect the best backend for a project.

    Args:
        project_path: Path to the project
        language: Programming language
        prefer: Preferred backend type if available

    Returns:
        Backend configuration

    This is a simple heuristic-based detection. A real implementation
    would check for:
    - Existing Joern CPG databases
    - Available LSP servers
    - TreeSitter grammar availability
    """
    # Simple heuristic: prefer Joern if available, otherwise TreeSitter
    if prefer == "joern":
        return JoernConfig(
            language=language,
            joern_path="/usr/local/bin/joern",  # Default path
            db_path=None,
        )
    else:
        # Default to TreeSitter
        return TreeSitterConfig(language=language)
