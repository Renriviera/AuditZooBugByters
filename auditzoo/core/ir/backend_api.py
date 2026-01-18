"""CPG Backend interface.

This module defines the interface that all CPG backends (Joern, TreeSitter)
must implement. The interface is CPG-centric, providing direct query access
alongside convenience methods.
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from auditzoo.core.ir.facts.base import RelationFact, UnitFact
from auditzoo.core.ir.model import CodeUnit, CodeUnitKind, CodeUnitRelation
from auditzoo.core.ir.model.base import CodeLocation, RelationDirection, RelationKind


class CPGBackend(ABC):
    """Abstract interface for CPG backends.

    All backends (Joern, TreeSitter) must implement this interface.
    The interface is CPG-centered: direct query access is the primary method,
    with convenience methods built on top of CPG queries.
    """

    @property
    @abstractmethod
    def backend_type(self) -> str:
        """The backend type."""
        pass

    @property
    @abstractmethod
    def language(self) -> str | None:
        """
        The langauge of the project under analysis.

        Returns:
            The project's language, or None if the backend is not connected.
        """
        pass

    @property
    @abstractmethod
    def source_path(self) -> str:
        """The source path of the project under analysis."""
        pass

    # ===== Core CPG Query Interface =====

    @abstractmethod
    async def query(self, query: str, response_ty: str = "json") -> Any:
        """Execute a backend query and return results.

        Args:
            query: CPG query string (Scala/Joern syntax)
            response_ty: Expected response type ("json", "str", etc.)

        Returns:
            Query results (typically JSON-decoded dict/list)

        Raises:
            BackendError: If query execution fails
            UnsupportedOperationError: If backend doesn't support this query
        """
        pass

    # ===== Tag Management =====

    @abstractmethod
    async def get_relation_tags(self) -> list[RelationFact]:
        """Get relation facts attached to the CPG.

        Returns:
            List of RelationFact objects

        Raises:
            BackendError: If tag retrieval fails
        """
        pass

    @abstractmethod
    async def get_unit_tags(self, unit: CodeUnit) -> list[UnitFact]:
        """Get tags attached to a code unit.

        Args:
            unit: CodeUnit to get tags for

        Returns:
            List of UnitFact objects

        Raises:
            BackendError: If tag retrieval fails
        """
        pass

    @abstractmethod
    async def set_unit_tag(self, unit: CodeUnit, fact: UnitFact) -> None:
        """Add a tag to a code unit.

        Args:
            unit: CodeUnit to add tag to
            fact: UnitFact object representing the tag

        Raises:
            BackendError: If tag addition fails
        """
        pass

    @abstractmethod
    async def set_relation_tag(self, fact: RelationFact) -> None:
        """Add a tag to a relation.

        Args:
            fact: RelationFact object representing the tag

        Raises:
            BackendError: If tag addition fails
        """
        pass

    # ===== Code Unit and Relation Management =====

    @abstractmethod
    async def get_code_unit_by_location(
        self, location: CodeLocation
    ) -> CodeUnit | None:
        """Get a code unit by its source location.

        Args:
            path: Source file path
            location: CodeLocation object specifying start and end lines

        Returns:
            CodeUnit object or None if not found

        Raises:
            BackendError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_code_unit(self, cpg_node_id: str) -> CodeUnit | None:
        """Get a specific code unit by its CPG node ID.

        Args:
            cpg_node_id: CPG node ID of the code unit

        Returns:
            CodeUnit object or None if not found

        Raises:
            BackendError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_code_units(self, kind: CodeUnitKind) -> list[CodeUnit]:
        """Get all code units of a specific type.

        Args:
            kind: Type/kind of code unit (e.g., function, class)

        Returns:
            List of CodeUnit objects

        Raises:
            BackendError: If retrieval fails
        """
        pass

    @abstractmethod
    async def get_relations(
        self, source_unit: CodeUnit, kind: RelationKind, direction: RelationDirection
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        """Get all relations of a specific kind from a source code unit.

        Args:
            source_unit: Source CodeUnit
            kind: Kind of relation to retrieve (e.g., CALLS, INHERITS)
            direction: Direction of the relation (OUTGOING or INCOMING)

        Returns:
            List of (target_unit, relation) tuples

        Raises:
            BackendError: If retrieval fails
        """
        pass

    # ===== Connection Management =====

    @abstractmethod
    async def connect(self) -> None:
        """Connect to the backend and initialize.

        Raises:
            BackendError: If connection fails
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the backend and cleanup.

        Raises:
            BackendError: If disconnection fails
        """
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if backend is connected.

        Returns:
            True if connected
        """
        pass

    @abstractmethod
    async def reload(self) -> None:
        """Reload or refresh the backend state.

        Raises:
            BackendError: If reload fails
        """
        pass

    # ===== Async Context Manager Support =====

    async def __aenter__(self):
        """Context manager entry.

        Automatically connects to the backend when entering the context.

        Returns:
            Self for use in async with statement

        Example:
            async with backend:
                results = await backend.query("cpg.method.name.l")
        """
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit.

        Automatically disconnects when exiting the context.
        Ensures cleanup even if an exception occurs.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred
        """
        await self.disconnect()


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


class BackendError(Exception):
    """Base exception for backend errors."""

    pass


class BackendConfigError(BackendError):
    """Error in backend configuration."""

    pass


class BackendConnectionError(BackendError):
    """Error connecting to backend."""

    pass


class BackendQueryError(BackendError):
    """Error executing a query."""

    pass


class BackendUnsupportedLanguageError(BackendError):
    """Error for unsupported programming languages."""

    pass


class BackendUnimplementedError(BackendError):
    """Error for unimplemented backend features."""

    pass


class BackendResponseError(BackendError):
    """Error for invalid or unexpected backend responses."""

    pass
