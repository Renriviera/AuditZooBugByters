"""Joern IR Backend implementation.

This module implements the IRBackend interface using Joern CPG queries.
"""

from pathlib import Path
from typing import Any

from auditzoo.backends.base import JoernConfig
from auditzoo.backends.joern.client import JoernClient
from auditzoo.core.ir.backend_api import CPGBackend
from auditzoo.core.ir.facts.base import RelationFact, UnitFact
from auditzoo.core.ir.model import CodeUnit, CodeUnitKind, CodeUnitRelation
from auditzoo.core.ir.model.base import RelationDirection, RelationKind


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
        await self.client.connect(
            language=self.config.language,
            source_path=self.config.source_path,
            analysis_path=self.config.analysis_path,
        )
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
        raise NotImplementedError()

    # ===== Tag Management =====

    def get_relation_tags(self) -> list[RelationFact]:
        """Get relation facts attached to the CPG.

        Returns:
            List of RelationFact objects
        """
        raise NotImplementedError()

    def get_unit_tags(self, unit: CodeUnit) -> list[UnitFact]:
        """Get tags attached to a code unit.

        Args:
            unit: CodeUnit to get tags for

        Returns:
            List of UnitFact objects
        """
        raise NotImplementedError()

    def set_unit_tag(self, unit: CodeUnit, fact: UnitFact) -> None:
        """Add a tag to a code unit.

        Args:
            unit: CodeUnit to add tag to
            fact: UnitFact object representing the tag
        """
        raise NotImplementedError()

    def set_relation_tag(self, fact: RelationFact) -> None:
        """Add a tag to a relation.

        Args:
            fact: RelationFact object representing the tag
        """
        raise NotImplementedError()

    # ===== Code Unit and Relation Management =====

    def get_code_unit_by_location(
        self, path: Path, start_line: int, end_line: int
    ) -> CodeUnit | None:
        """Get a code unit by its source location.

        Args:
            path: Source file path
            start_line: Starting line number
            end_line: Ending line number

        Returns:
            CodeUnit object or None if not found
        """
        raise NotImplementedError()

    def get_code_unit(self, cpg_node_id: str) -> CodeUnit | None:
        """Get a specific code unit by its CPG node ID.

        Args:
            cpg_node_id: CPG node ID of the code unit

        Returns:
            CodeUnit object or None if not found
        """
        raise NotImplementedError()

    def get_code_units(self, kind: CodeUnitKind) -> list[CodeUnit]:
        """Get all code units of a specific type.

        Args:
            kind: Type/kind of code unit (e.g., function, class)

        Returns:
            List of CodeUnit objects
        """
        raise NotImplementedError()

    def get_relations(
        self, source_unit: CodeUnit, kind: RelationKind, direction: RelationDirection
    ) -> list[tuple[CodeUnit, CodeUnitRelation, dict[str, Any]]]:
        """Get all relations of a specific kind from a source code unit.

        Args:
            source_unit: Source CodeUnit
            kind: Kind of relation to retrieve (e.g., CALLS, INHERITS)
            direction: Direction of the relation (OUTGOING or INCOMING)

        Returns:
            List of (target_unit, relation, metadata) tuples
        """
        raise NotImplementedError()
