"""Joern IR Backend implementation.

This module implements the IRBackend interface using Joern CPG queries.
"""

from pathlib import Path
from typing import Any

from auditzoo.backends.base import JoernConfig
from auditzoo.backends.joern.client import JoernClient
from auditzoo.backends.joern.utils import parse_joern_response
from auditzoo.core.ir.backend_api import (
    BackendResponseError,
    BackendUnimplementedError,
    CPGBackend,
)
from auditzoo.core.ir.facts.base import RelationFact, UnitFact
from auditzoo.core.ir.model import CodeUnit, CodeUnitKind, CodeUnitRelation
from auditzoo.core.ir.model.base import CodeLocation, RelationDirection, RelationKind


class JoernBackend(CPGBackend):
    """IR backend using Joern CPG.

    This backend queries Joern's Code Property Graph to provide
    IR-level information about programs.
    """

    _language: str | None = None

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

    @property
    def backend_type(self) -> str:
        return "joern"

    @property
    def language(self) -> str | None:
        return self._language

    @property
    def source_path(self) -> str:
        return self.config.source_path

    # ===== Connection Management =====

    async def connect(self) -> None:
        """Connect to Joern and load the CPG."""
        await self.client.connect(
            language=self.config.language,
            source_path=self.config.source_path,
            analysis_path=self.config.analysis_path,
            project_name=self.config.project_name,
        )
        self._connected = True

        await self._load_pre_defined_scripts()

    async def disconnect(self) -> None:
        """Disconnect from Joern."""
        # Clean cache and close connection
        self._language = None

        # Commit any pending changes and save the CPG
        await self.query_raw("run.commit")
        await self.query_raw("save")

        await self.client.disconnect()
        self._connected = False

    def is_connected(self) -> bool:
        """Check if backend is connected."""
        return self._connected

    async def reload(self) -> None:
        """Reload the CPG from disk."""
        if not self.is_connected() or self.client.workspace_dir is None:
            raise BackendResponseError("Cannot reload CPG: not connected to Joern.")

        current_project = await self.query("project.name", "str")
        await self.query_raw(f'close("{current_project}")')

        await self.client.load_project(
            source_path=self.config.source_path,
            project_name=self.config.project_name,
            language=self.config.language,
        )

        # Reload pre-defined scripts after reloading CPG
        await self._load_pre_defined_scripts()

    async def _load_pre_defined_scripts(self) -> None:
        """Load pre-defined Scala scripts into Joern."""
        scripts_dir = Path(__file__).parent / "scripts"
        pre_define_script = scripts_dir / "pre_define.sc"

        if not pre_define_script.exists():
            raise BackendResponseError(
                f"Pre-defined script not found: {pre_define_script}"
            )

        script_content = pre_define_script.read_text()
        await self.query_raw(script_content)

    # ===== Core CPG Query Interface =====

    async def query_raw(self, query: str) -> str:
        """Execute a CPG query and return results.

        Args:
            query: CPG query string (Scala/Joern syntax)

        Returns:
            Query results (typically JSON-decoded dict/list)
        """
        return await self.client.query(query)

    async def query(self, query: str, response_ty: str = "json") -> Any:
        """Execute a CPG query and return results as a dict.

        Args:
            query: CPG query string (Scala/Joern syntax)

        Returns:
            Query results as a dictionary
        """
        result = await self.query_raw(query)
        return parse_joern_response(result, response_ty=response_ty)

    # ===== Metadata Management =====

    async def get_language(self) -> str | None:
        """Get the programming language of the loaded CPG.

        Returns:
            Programming language as a string, or None if unknown
        """
        if self._language is None:
            query = "cpg.metaData.language.toJson"
            result = await self.query(query)
            if not result or not isinstance(result, list) or len(result) == 0:
                raise BackendResponseError(
                    "Failed to retrieve language from Joern CPG metadata."
                )

            self._language = result[0]

        return self._language

    # ===== Tag Management =====

    async def get_relation_tags(self) -> list[RelationFact]:
        """Get relation facts attached to the CPG.

        Returns:
            List of RelationFact objects
        """
        raise NotImplementedError()

    async def get_unit_tags(self, unit: CodeUnit) -> list[UnitFact]:
        """Get tags attached to a code unit.

        Args:
            unit: CodeUnit to get tags for

        Returns:
            List of UnitFact objects
        """
        raise NotImplementedError()

    async def set_unit_tag(self, unit: CodeUnit, fact: UnitFact) -> None:
        """Add a tag to a code unit.

        Args:
            unit: CodeUnit to add tag to
            fact: UnitFact object representing the tag
        """
        raise NotImplementedError()

    async def set_relation_tag(self, fact: RelationFact) -> None:
        """Add a tag to a relation.

        Args:
            fact: RelationFact object representing the tag
        """
        raise NotImplementedError()

    # ===== Code Unit and Relation Management =====

    async def get_code_unit_by_location(
        self, location: CodeLocation
    ) -> CodeUnit | None:
        """Get a code unit by its source location.

        Args:
            location: CodeLocation object specifying start and end lines

        Returns:
            CodeUnit object or None if not found
        """
        if location.column_start is not None:
            raise BackendUnimplementedError(
                "get_code_unit_by_location with column_start is not implemented for Joern backend."
            )

        unit_id = await self.query(
            f'minimalCoveringNodeInfo("{location.file_path}", {location.line_start}, {location.line_end})',
            response_ty="int",
        )

        if unit_id is None:
            return None

        return await self.get_code_unit(cpg_node_id=str(unit_id))

    async def get_code_unit(self, cpg_node_id: str) -> CodeUnit | None:
        """Get a specific code unit by its CPG node ID.

        Args:
            cpg_node_id: CPG node ID of the code unit

        Returns:
            CodeUnit object or None if not found
        """
        query = f"cpg.all.id({cpg_node_id}L).toJson"
        response = await self.query(query)
        units = await CodeUnitKind.create_from_response(
            response=response,
            backend=self,
        )

        if not units or not isinstance(units, list) or len(units) == 0:
            return None

        return units[0]

    async def get_code_units(self, kind: CodeUnitKind) -> list[CodeUnit]:
        """Get all code units of a specific type.

        Args:
            kind: Type/kind of code unit (e.g., function, class)

        Returns:
            List of CodeUnit objects
        """
        units = await kind.fetch_backend(backend=self)

        return units

    async def get_relations(
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
