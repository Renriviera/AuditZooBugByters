"""Joern IR Backend implementation.

This module implements the IRBackend interface using Joern CPG queries.
"""

from typing import Any

from auditzoo.backends.base import JoernConfig
from auditzoo.backends.joern.client import JoernClient
from auditzoo.core.ir.backend_api import CPGBackend
from auditzoo.core.ir.model import Function, ProgramId


class JoernBackend(CPGBackend):
    """IR backend using Joern CPG.

    This backend queries Joern's Code Property Graph to provide
    IR-level information about programs.
    """

    def __init__(self, config: JoernConfig):
        """Initialize Joern backend.

        Args:
            config: Joern configuration
        """
        self.config = config
        self.client = JoernClient(
            joern_path=config.joern_path, host=config.host, port=config.port
        )
        self._connected = False

    # ===== Connection Management =====

    async def connect(self) -> None:
        """Connect to Joern and load the CPG."""
        await self.client.connect(self.config.db_path)
        self._connected = True

    async def disconnect(self) -> None:
        """Disconnect from Joern."""
        await self.client.disconnect()
        self._connected = False

    def is_connected(self) -> bool:
        """Check if backend is connected."""
        return self._connected

    # ===== Core CPG Query Interface =====

    async def cpg_query(self, query: str) -> Any:
        """Execute a CPG query and return results.

        Args:
            query: CPG query string (Scala/Joern syntax)

        Returns:
            Query results (typically JSON-decoded dict/list)
        """
        raise AssertionError("unimplemented")

    def supports_feature(self, feature: str) -> bool:
        """Check if backend supports a specific feature.

        Args:
            feature: Feature name (e.g., "dataflow", "controlflow", "taint")

        Returns:
            True if feature is supported
        """
        raise AssertionError("unimplemented")

    # ===== Tag Management =====

    async def add_tag(self, cpg_node_id: str, tag_name: str, tag_data: dict) -> None:
        """Add a tag to a CPG node.

        Args:
            cpg_node_id: CPG node ID
            tag_name: Tag name (typically fact type)
            tag_data: Tag data (JSON-compatible dict)
        """
        raise AssertionError("unimplemented")

    async def get_tags(
        self, cpg_node_id: str, tag_name: str | None = None
    ) -> list[dict]:
        """Get tags attached to a CPG node.

        Args:
            cpg_node_id: CPG node ID
            tag_name: Optional tag name filter

        Returns:
            List of tag data dicts
        """
        raise AssertionError("unimplemented")

    async def query_by_tag(self, tag_name: str) -> list[str]:
        """Find CPG node IDs that have a specific tag.

        Args:
            tag_name: Tag name to search for

        Returns:
            List of CPG node IDs
        """
        raise AssertionError("unimplemented")

    async def get_all_tags(self, tag_name: str | None = None) -> dict[str, list[dict]]:
        """Get all tags in the CPG.

        Args:
            tag_name: Optional tag name filter

        Returns:
            Dict mapping CPG node IDs to lists of tag data
        """
        raise AssertionError("unimplemented")

    # ===== Convenience Methods =====

    async def get_program_info(self, program_id: ProgramId) -> dict[str, Any]:
        """Get program metadata.

        Args:
            program_id: Program identifier

        Returns:
            Program metadata dict
        """
        raise AssertionError("unimplemented")

    async def get_functions(self, program_id: ProgramId) -> list[Function]:
        """Get all functions/methods in the program.

        Args:
            program_id: Program identifier

        Returns:
            List of Function objects with CPG node IDs
        """
        raise AssertionError("unimplemented")

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
        raise AssertionError("unimplemented")

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
        raise AssertionError("unimplemented")

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
        raise AssertionError("unimplemented")

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
        raise AssertionError("unimplemented")
