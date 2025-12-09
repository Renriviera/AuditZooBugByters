"""CPG Backend interface.

This module defines the interface that all CPG backends (Joern, TreeSitter)
must implement. The interface is CPG-centric, providing direct query access
alongside convenience methods.
"""

from abc import ABC, abstractmethod
from typing import Any

from auditzoo.core.ir.model import Function, ProgramId


class CPGBackend(ABC):
    """Abstract interface for CPG backends.

    All backends (Joern, TreeSitter) must implement this interface.
    The interface is CPG-centered: direct query access is the primary method,
    with convenience methods built on top of CPG queries.
    """

    # ===== Core CPG Query Interface =====

    @abstractmethod
    async def cpg_query(self, query: str) -> Any:
        """Execute a CPG query and return results.

        Args:
            query: CPG query string (Scala/Joern syntax)

        Returns:
            Query results (typically JSON-decoded dict/list)

        Raises:
            BackendError: If query execution fails
            UnsupportedOperationError: If backend doesn't support this query
        """
        pass

    @abstractmethod
    def supports_feature(self, feature: str) -> bool:
        """Check if backend supports a specific feature.

        Args:
            feature: Feature name (e.g., "dataflow", "controlflow", "taint")

        Returns:
            True if feature is supported
        """
        pass

    # ===== Tag Management =====

    @abstractmethod
    async def add_tag(self, cpg_node_id: str, tag_name: str, tag_data: dict) -> None:
        """Add a tag to a CPG node.

        Args:
            cpg_node_id: CPG node ID
            tag_name: Tag name (typically fact type)
            tag_data: Tag data (JSON-compatible dict)

        Raises:
            BackendError: If tag addition fails
        """
        pass

    @abstractmethod
    async def get_tags(
        self, cpg_node_id: str, tag_name: str | None = None
    ) -> list[dict]:
        """Get tags attached to a CPG node.

        Args:
            cpg_node_id: CPG node ID
            tag_name: Optional tag name filter

        Returns:
            List of tag data dicts

        Raises:
            BackendError: If tag retrieval fails
        """
        pass

    @abstractmethod
    async def query_by_tag(self, tag_name: str) -> list[str]:
        """Find CPG node IDs that have a specific tag.

        Args:
            tag_name: Tag name to search for

        Returns:
            List of CPG node IDs

        Raises:
            BackendError: If query fails
        """
        pass

    @abstractmethod
    async def get_all_tags(self, tag_name: str | None = None) -> dict[str, list[dict]]:
        """Get all tags in the CPG.

        Args:
            tag_name: Optional tag name filter

        Returns:
            Dict mapping CPG node IDs to lists of tag data

        Raises:
            BackendError: If retrieval fails
        """
        pass

    # ===== Convenience Methods =====
    # These are built on top of cpg_query() but provide simpler interfaces

    @abstractmethod
    async def get_program_info(self, program_id: ProgramId) -> dict[str, Any]:
        """Get program metadata.

        Args:
            program_id: Program identifier

        Returns:
            Program metadata dict
        """
        pass

    @abstractmethod
    async def get_functions(self, program_id: ProgramId) -> list[Function]:
        """Get all functions/methods in the program.

        Args:
            program_id: Program identifier

        Returns:
            List of Function objects with CPG node IDs
        """
        pass

    @abstractmethod
    async def get_function_by_name(
        self, program_id: ProgramId, function_name: str
    ) -> Function | None:
        """Get a specific function by name.

        Args:
            program_id: Program identifier
            function_name: Function/method name

        Returns:
            Function object or None if not found
        """
        pass

    @abstractmethod
    async def get_cfg_nodes(self, function_cpg_id: str) -> list[dict[str, Any]]:
        """Get CFG nodes for a function.

        Args:
            function_cpg_id: CPG node ID of the function

        Returns:
            List of CFG node dicts with fields:
                - id: CPG node ID
                - code: Source code
                - line: Line number
                - successors: List of successor node IDs
        """
        pass

    @abstractmethod
    async def get_call_graph(self, program_id: ProgramId) -> list[dict[str, Any]]:
        """Get call graph edges.

        Args:
            program_id: Program identifier

        Returns:
            List of call edge dicts with fields:
                - caller_id: CPG node ID of caller method
                - callee_id: CPG node ID of callee method
                - call_site_id: CPG node ID of call site
        """
        pass

    @abstractmethod
    async def get_ast_nodes(
        self, function_cpg_id: str, node_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Get AST nodes for a function.

        Args:
            function_cpg_id: CPG node ID of the function
            node_type: Optional filter by AST node type

        Returns:
            List of AST node dicts with fields:
                - id: CPG node ID
                - type: AST node type
                - code: Source code
                - line: Line number
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


class BackendError(Exception):
    """General backend error."""

    pass


class UnsupportedOperationError(BackendError):
    """Operation not supported by this backend."""

    pass
