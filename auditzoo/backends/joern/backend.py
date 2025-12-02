"""Joern IR Backend implementation.

This module implements the IRBackend interface using Joern CPG queries.
"""

from typing import List, Optional, Dict
from auditzoo.core.ir.backend_api import IRBackend
from auditzoo.core.ir.model import (
    ProgramId,
    FunctionId,
    NodeId,
    BasicBlockId,
    Program,
    Function,
    BasicBlock,
    IRNode,
    NodeKind,
)
from auditzoo.backends.joern.client import JoernClient
from auditzoo.backends.base import JoernConfig


class JoernBackend(IRBackend):
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

    async def connect(self):
        """Connect to Joern and load the CPG."""
        await self.client.connect(self.config.db_path)
        self._connected = True

    async def disconnect(self):
        """Disconnect from Joern."""
        await self.client.disconnect()
        self._connected = False

    async def get_program(self, program_id: ProgramId) -> Optional[Program]:
        """Get program metadata from Joern."""
        # In a real implementation, query CPG for program metadata
        return Program(
            id=program_id,
            name=program_id.id,
            root_path=self.config.db_path or "",
            language=self.config.language,
        )

    async def get_functions(self, program_id: ProgramId) -> List[Function]:
        """Get all functions from Joern CPG."""
        methods = await self.client.get_methods()

        functions = []
        for method in methods:
            func_id = FunctionId(
                program_id=program_id,
                name=method.get("name", "unknown"),
                file=method.get("filename"),
                line=method.get("lineNumber"),
            )

            function = Function(
                id=func_id,
                name=method.get("name", "unknown"),
                file=method.get("filename"),
                start_line=method.get("lineNumber"),
                end_line=method.get("lineNumberEnd"),
                language=self.config.language,
            )
            functions.append(function)

        return functions

    async def get_function(self, function_id: FunctionId) -> Optional[Function]:
        """Get a specific function from Joern."""
        # In a real implementation, query CPG for this specific method
        return Function(
            id=function_id,
            name=function_id.name,
            file=function_id.file,
            start_line=function_id.line,
            language=self.config.language,
        )

    async def get_cfg(self, function_id: FunctionId) -> List[BasicBlock]:
        """Get CFG for a function from Joern."""
        cfg_data = await self.client.get_cfg(function_id.name)

        # In a real implementation, parse Joern's CFG representation
        # and construct BasicBlock objects
        # For now, return a minimal placeholder
        blocks = []

        # Create a simple single-block CFG as placeholder
        block_id = BasicBlockId(function_id=function_id, block_index=0)
        block = BasicBlock(id=block_id, nodes=[])
        blocks.append(block)

        return blocks

    async def get_basic_block(self, block_id: BasicBlockId) -> Optional[BasicBlock]:
        """Get a specific basic block."""
        # Placeholder implementation
        return BasicBlock(id=block_id, nodes=[])

    async def get_nodes(self, function_id: FunctionId) -> List[IRNode]:
        """Get all nodes in a function from Joern."""
        # In a real implementation, query CPG for AST nodes in the method
        # For now, return empty list
        return []

    async def get_node(self, node_id: NodeId) -> Optional[IRNode]:
        """Get a specific node."""
        # Placeholder implementation
        return IRNode(id=node_id, kind=NodeKind.UNKNOWN, code="")

    async def get_callers(self, function_id: FunctionId) -> List[FunctionId]:
        """Get callers of a function from Joern."""
        # In a real implementation, query CPG for incoming call edges
        return []

    async def get_callees(self, function_id: FunctionId) -> List[FunctionId]:
        """Get callees of a function from Joern."""
        # In a real implementation, query CPG for outgoing call edges
        return []

    async def get_call_graph(
        self, program_id: ProgramId
    ) -> Dict[FunctionId, List[FunctionId]]:
        """Get the call graph from Joern."""
        call_data = await self.client.get_call_graph()

        # In a real implementation, parse Joern's call graph
        # and construct the mapping
        call_graph = {}

        return call_graph
