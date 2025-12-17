"""AnalysisContext for analysis agents.

This module provides the context object that analysis agents use to interact
with the infrastructure (IR and facts).
"""

from typing import Any

from auditzoo.core.agents.ir_store import IRStoreAgent
from auditzoo.core.ir.facts import RelationFact, UnitFact
from auditzoo.core.ir.view import IRView
from auditzoo.core.protocol.ir_messages import (
    GetFactsRequest,
    GetIRVersionRequest,
    UpdateFactsRequest,
)


class AnalysisContext:
    """Context for analysis agents to interact with infrastructure.

    Provides methods for:
    - Accessing IR views
    - Getting and updating facts
    - Logging

    Agents communicate directly via AutoGen-Core message passing.
    No task routing or dependency management - agents call each other directly by ID.
    """

    def __init__(self, ir_store: IRStoreAgent):
        """Initialize analysis context.

        Args:
            ir_store: IRStoreAgent instance for accessing IR and facts
        """
        self.ir_store = ir_store

    async def get_ir_view(self, program_id: str) -> IRView | None:
        """Get the IR view for a program.

        Args:
            program_id: Program to get IR view for

        Returns:
            IRView instance or None if not found
        """
        return self.ir_store.get_ir_view(program_id)

    async def get_ir_version(self, program_id: str) -> int:
        """Get the current IR version for a program.

        Args:
            program_id: Program to get version for

        Returns:
            Version number
        """
        _request = GetIRVersionRequest(program_id=program_id)
        raise NotImplementedError("GetIRVersionRequest handling not yet implemented")

    async def get_facts(
        self,
        program_id: str,
        fact_types: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[UnitFact | RelationFact]:
        """Get facts for a program.

        Args:
            program_id: Target program
            fact_types: Optional filter by fact names (e.g., ["vulnerability", "taint"])
            filters: Optional additional filters (fact-specific attributes)

        Returns:
            List of matching facts (both UnitFact and RelationFact)
        """
        _request = GetFactsRequest(
            program_id=program_id, fact_types=fact_types, filters=filters or {}
        )
        raise NotImplementedError("GetFactsRequest handling not yet implemented")

    async def update_facts(
        self,
        program_id: str,
        facts: list[UnitFact | RelationFact],
        replace: bool = False,
    ) -> bool:
        """Update facts for a program.

        Args:
            program_id: Target program
            facts: Facts to add or update (UnitFact or RelationFact)
            replace: If True, replace existing facts of same name; if False, append

        Returns:
            True if successful, False otherwise
        """
        _request = UpdateFactsRequest(
            program_id=program_id, facts=facts, replace=replace
        )
        raise NotImplementedError("UpdateFactsRequest handling not yet implemented")
