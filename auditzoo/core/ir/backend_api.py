"""IR Backend interface.

This module defines the interface that all IR backends (LSP, Joern, TreeSitter)
must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
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


class IRBackend(ABC):
    """Abstract interface for IR backends.

    All backends (LSP, Joern, TreeSitter) must implement this interface
    to provide program information in the canonical IR format.
    """

    @abstractmethod
    async def get_program(self, program_id: ProgramId) -> Optional[Program]:
        """Get program metadata."""
        pass

    @abstractmethod
    async def get_functions(self, program_id: ProgramId) -> List[Function]:
        """Get all functions in the program."""
        pass

    @abstractmethod
    async def get_function(self, function_id: FunctionId) -> Optional[Function]:
        """Get a specific function."""
        pass

    @abstractmethod
    async def get_cfg(self, function_id: FunctionId) -> List[BasicBlock]:
        """Get the control flow graph for a function."""
        pass

    @abstractmethod
    async def get_basic_block(self, block_id: BasicBlockId) -> Optional[BasicBlock]:
        """Get a specific basic block."""
        pass

    @abstractmethod
    async def get_nodes(self, function_id: FunctionId) -> List[IRNode]:
        """Get all nodes in a function."""
        pass

    @abstractmethod
    async def get_node(self, node_id: NodeId) -> Optional[IRNode]:
        """Get a specific node."""
        pass

    @abstractmethod
    async def get_callers(self, function_id: FunctionId) -> List[FunctionId]:
        """Get functions that call this function."""
        pass

    @abstractmethod
    async def get_callees(self, function_id: FunctionId) -> List[FunctionId]:
        """Get functions called by this function."""
        pass

    @abstractmethod
    async def get_call_graph(
        self, program_id: ProgramId
    ) -> Dict[FunctionId, List[FunctionId]]:
        """Get the call graph for the program.

        Returns a dict mapping function IDs to lists of callees.
        """
        pass
