"""IR View abstraction with caching.

This module provides the IRView class that wraps any IRBackend and adds
caching and convenience methods.
"""

from typing import List, Optional, Dict, Any
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
)


class IRView:
    """Cached view over an IR backend.

    Provides convenient access to program information with automatic caching
    to avoid redundant queries to the underlying backend.
    """

    def __init__(self, backend: IRBackend):
        self.backend = backend
        self._program_cache: Dict[ProgramId, Optional[Program]] = {}
        self._functions_cache: Dict[ProgramId, List[Function]] = {}
        self._function_cache: Dict[FunctionId, Optional[Function]] = {}
        self._cfg_cache: Dict[FunctionId, List[BasicBlock]] = {}
        self._nodes_cache: Dict[FunctionId, List[IRNode]] = {}
        self._node_cache: Dict[NodeId, Optional[IRNode]] = {}
        self._block_cache: Dict[BasicBlockId, Optional[BasicBlock]] = {}
        self._callers_cache: Dict[FunctionId, List[FunctionId]] = {}
        self._callees_cache: Dict[FunctionId, List[FunctionId]] = {}
        self._call_graph_cache: Dict[ProgramId, Dict[FunctionId, List[FunctionId]]] = {}

    async def get_program(self, program_id: ProgramId) -> Optional[Program]:
        """Get program metadata (cached)."""
        if program_id not in self._program_cache:
            self._program_cache[program_id] = await self.backend.get_program(program_id)
        return self._program_cache[program_id]

    async def get_functions(self, program_id: ProgramId) -> List[Function]:
        """Get all functions in the program (cached)."""
        if program_id not in self._functions_cache:
            self._functions_cache[program_id] = await self.backend.get_functions(
                program_id
            )
        return self._functions_cache[program_id]

    async def get_function(self, function_id: FunctionId) -> Optional[Function]:
        """Get a specific function (cached)."""
        if function_id not in self._function_cache:
            self._function_cache[function_id] = await self.backend.get_function(
                function_id
            )
        return self._function_cache[function_id]

    async def get_cfg(self, function_id: FunctionId) -> List[BasicBlock]:
        """Get the control flow graph for a function (cached)."""
        if function_id not in self._cfg_cache:
            self._cfg_cache[function_id] = await self.backend.get_cfg(function_id)
        return self._cfg_cache[function_id]

    async def get_basic_block(self, block_id: BasicBlockId) -> Optional[BasicBlock]:
        """Get a specific basic block (cached)."""
        if block_id not in self._block_cache:
            self._block_cache[block_id] = await self.backend.get_basic_block(block_id)
        return self._block_cache[block_id]

    async def get_nodes(self, function_id: FunctionId) -> List[IRNode]:
        """Get all nodes in a function (cached)."""
        if function_id not in self._nodes_cache:
            self._nodes_cache[function_id] = await self.backend.get_nodes(function_id)
        return self._nodes_cache[function_id]

    async def get_node(self, node_id: NodeId) -> Optional[IRNode]:
        """Get a specific node (cached)."""
        if node_id not in self._node_cache:
            self._node_cache[node_id] = await self.backend.get_node(node_id)
        return self._node_cache[node_id]

    async def get_callers(self, function_id: FunctionId) -> List[FunctionId]:
        """Get functions that call this function (cached)."""
        if function_id not in self._callers_cache:
            self._callers_cache[function_id] = await self.backend.get_callers(
                function_id
            )
        return self._callers_cache[function_id]

    async def get_callees(self, function_id: FunctionId) -> List[FunctionId]:
        """Get functions called by this function (cached)."""
        if function_id not in self._callees_cache:
            self._callees_cache[function_id] = await self.backend.get_callees(
                function_id
            )
        return self._callees_cache[function_id]

    async def get_call_graph(
        self, program_id: ProgramId
    ) -> Dict[FunctionId, List[FunctionId]]:
        """Get the call graph for the program (cached)."""
        if program_id not in self._call_graph_cache:
            self._call_graph_cache[program_id] = await self.backend.get_call_graph(
                program_id
            )
        return self._call_graph_cache[program_id]

    def invalidate_cache(self):
        """Clear all caches."""
        self._program_cache.clear()
        self._functions_cache.clear()
        self._function_cache.clear()
        self._cfg_cache.clear()
        self._nodes_cache.clear()
        self._node_cache.clear()
        self._block_cache.clear()
        self._callers_cache.clear()
        self._callees_cache.clear()
        self._call_graph_cache.clear()
