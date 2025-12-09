"""Joern CPG client.

Low-level wrapper for interacting with Joern and querying the CPG.
"""

import subprocess  # nosec B404 - subprocess needed for Joern interaction
from typing import Any

from auditzoo.backends.base import BackendConnectionError


class JoernClient:
    """Client for interacting with Joern CPG.

    This client handles:
    - Starting/stopping Joern server
    - Running CPG queries
    - Mapping query results to Python objects
    """

    def __init__(self, joern_path: str, host: str = "localhost", port: int = 8080):
        """Initialize Joern client.

        Args:
            joern_path: Path to Joern installation
            host: Joern server host
            port: Joern server port
        """
        self.joern_path = joern_path
        self.host = host
        self.port = port
        self._process: subprocess.Popen | None = None
        self._connected = False

    async def connect(self, cpg_path: str | None = None):
        """Connect to Joern server or start a new one.

        Args:
            cpg_path: Path to existing CPG database
        """
        # In a real implementation, this would:
        # 1. Check if a Joern server is already running
        # 2. If not, start one with the given CPG
        # 3. Wait for it to be ready
        # For now, this is a placeholder
        self._connected = True

    async def disconnect(self):
        """Disconnect from Joern server."""
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
        self._connected = False

    async def query(self, query_str: str) -> list[dict[str, Any]]:
        """Execute a CPG query.

        Args:
            query_str: Joern query string (e.g., "cpg.method.name.l")

        Returns:
            List of query results as dictionaries

        Raises:
            BackendConnectionError: If not connected
            BackendQueryError: If query fails
        """
        if not self._connected:
            raise BackendConnectionError("Not connected to Joern")

        # In a real implementation, this would:
        # 1. Send the query to the Joern server via HTTP/REST API
        # 2. Parse the JSON response
        # 3. Return the results
        # For now, return a placeholder
        return []

    async def get_methods(self) -> list[dict[str, Any]]:
        """Get all methods in the CPG.

        Returns:
            List of method dictionaries with name, signature, file, line, etc.
        """
        return await self.query("cpg.method.toJson")

    async def get_cfg(self, method_name: str) -> dict[str, Any]:
        """Get CFG for a specific method.

        Args:
            method_name: Name of the method

        Returns:
            CFG structure as a dictionary
        """
        query = f'cpg.method.name("{method_name}").controlStructure.toJson'
        return await self.query(query)  # type: ignore[return-value]

    async def get_call_graph(self) -> list[dict[str, Any]]:
        """Get the call graph.

        Returns:
            List of caller-callee relationships
        """
        return await self.query("cpg.call.toJson")

    async def get_data_flow(
        self, source: str, sink: str | None = None
    ) -> list[dict[str, Any]]:
        """Get data flow from source to sink.

        Args:
            source: Source location or variable
            sink: Optional sink location

        Returns:
            Data flow paths
        """
        # Placeholder for data flow query
        return []

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._connected:
            # In async context, we can't await here
            # In a real implementation, use async context manager
            pass
