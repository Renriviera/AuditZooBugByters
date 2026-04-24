"""Joern IR Backend implementation.

This module implements the IRBackend interface using Joern CPG queries.
"""

import asyncio
import json
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
from auditzoo.core.ir.facts.base import RelationFact, UnitFact, deserialize_fact
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
            joern_path=config.joern_path,
            host=config.host,
            port=config.port,
            jvm_stack_size=config.jvm_stack_size,
            jvm_extra_opts=config.jvm_extra_opts or [],
        )
        self._connected = False
        # ``pre_define.sc`` is loaded lazily the first time a caller reaches
        # for a helper that actually needs it (``get_code_unit_by_location``
        # today).  Loading it from ``connect`` makes ``cpg_build_s`` dominated
        # by Scala-compile-against-the-fresh-CPG cost (~85% of build time on
        # the CWE-78 sweep, up to ~450s for bikeshed-sized CPGs) even for
        # pipelines that never invoke the helper at all.  Guarded by a lock
        # so concurrent first-time callers only trigger the load once.
        self._pre_define_loaded: bool = False
        self._pre_define_lock: asyncio.Lock = asyncio.Lock()

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
        """Connect to Joern and load the CPG.

        ``pre_define.sc`` is *not* loaded here; it is deferred until the
        first caller actually needs one of its helpers.  See
        ``_ensure_pre_defined_loaded`` for the rationale.
        """
        await self.client.connect(
            language=self.config.language,
            source_path=self.config.source_path,
            analysis_path=self.config.analysis_path,
            project_name=self.config.project_name,
            force_create_cpg=self.config.force_create_cpg,
            run_overlays=self.config.run_overlays,
            cache_enabled=bool(self.config.cpg_cache_key),
        )
        self._connected = True
        # Fresh JVM session: every previously-defined helper is gone.
        self._pre_define_loaded = False

    @property
    def last_connect_timings(self) -> dict[str, float | bool]:
        """Per-phase CPG build timings from the most recent ``connect``."""
        return dict(self.client.last_connect_timings)

    @property
    def last_connect_rss(self) -> dict[str, int]:
        """Per-phase JVM RSS samples from the most recent ``connect``."""
        return dict(self.client.last_connect_rss)

    @property
    def gc_log_path(self) -> str | None:
        """Directory where the Joern JVM is writing GC logs, or ``None``."""
        return self.client.gc_log_path

    async def disconnect(self) -> None:
        """Disconnect from Joern."""
        # Clean cache and close connection
        self._language = None

        # Get current project name
        current_project = await self.query("project.name", "str")

        # Commit any pending changes and save the CPG
        await self.query_raw("run.commit")
        await self.query_raw("save")
        await self.query_raw(f'close("{current_project}")')

        await self.client.disconnect()
        self._connected = False
        self._pre_define_loaded = False

    def is_connected(self) -> bool:
        """Check if backend is connected."""
        return self._connected

    async def reload(self) -> None:
        """Reload the CPG from disk.

        Note: this action will discard any facts stored in the current session.
        And create a fresh session with the CPG re-analyzed from code.
        """
        if not self.is_connected() or self.client.workspace_dir is None:
            raise BackendResponseError("Cannot reload CPG: not connected to Joern.")

        current_project = await self.query("project.name", "str")
        await self.query_raw("run.commit")
        await self.query_raw("save")
        await self.query_raw(f'close("{current_project}")')

        await self.client.load_project(
            source_path=self.config.source_path,
            project_name=self.config.project_name,
            language=self.config.language,
            force_create_cpg=True,
            run_overlays=self.config.run_overlays,
        )

        # A fresh CPG means the REPL's previously-compiled helpers were
        # tied to the old session and are no longer valid; the next caller
        # that needs them will trigger a re-load lazily.
        self._pre_define_loaded = False

    async def _ensure_pre_defined_loaded(self) -> None:
        """Idempotently load ``pre_define.sc`` on first demand.

        Shipping the helper through ``query_raw`` forces Scala to
        type-check + compile it against the freshly-imported CPG's
        classpath, which is by far the dominant cost in ``connect`` on
        medium-to-large repos (see ``FORK_FIXES.md``).  The cwe78_study
        arms never hit the helper, so for that workload paying this cost
        inside ``connect`` is pure overhead.  Load it lazily and cache
        the result; a ``disconnect`` / ``reload`` / new ``connect``
        invalidates the cache because the JVM session's defined symbols
        are gone.

        The lock makes concurrent first-time callers serialise through a
        single load rather than firing N duplicate compilations.
        """
        if self._pre_define_loaded:
            return
        async with self._pre_define_lock:
            if self._pre_define_loaded:
                return
            await self._load_pre_defined_scripts()
            self._pre_define_loaded = True

    async def _load_pre_defined_scripts(self) -> None:
        """Unconditionally ship ``pre_define.sc`` to the Joern REPL.

        Callers should almost always go through
        ``_ensure_pre_defined_loaded`` instead; this method exists as a
        direct hook for tests and for any caller that explicitly wants
        to force a re-load.
        """
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
        query = 'cpg.tag.filter(_.name.startsWith("relationfact:")).toJson'
        response = await self.query(query)

        return [
            deserialize_fact(json.loads(response["fact"]))  # type: ignore
            for response in response
            if "fact" in response
        ]

    async def get_unit_tags(self, unit: CodeUnit) -> list[UnitFact]:
        """Get tags attached to a code unit.

        Args:
            unit: CodeUnit to get tags for

        Returns:
            List of UnitFact objects
        """
        if unit.is_synthetic:
            query = 'cpg.tag.filter(_.name.startsWith("unitfact:")).toJson'
        else:
            query = (
                f'cpg.tag.id({unit.id}L).filter(_.name.startsWith("unitfact:")).toJson'
            )
        response = await self.query(query)

        return [
            deserialize_fact(json.loads(response["fact"]))  # type: ignore
            for response in response
            if "fact" in response and response["unit_id"] == unit.id
        ]

    async def set_unit_tag(self, unit: CodeUnit, fact: UnitFact) -> None:
        """Add a tag to a code unit.

        Args:
            unit: CodeUnit to add tag to
            fact: UnitFact object representing the tag
        """
        tag = {
            "unit_id": unit.id,
            "fact": fact.to_dict(),
        }
        value = json.dumps(json.dumps(tag))  # Double JSON encode to escape quotes
        key = fact.id()

        query = f'cpg.metaData.newTagNodePair({key}, "{value}").store()'
        await self.query_raw(query)
        await self.query_raw("run.commit")

    async def set_relation_tag(self, fact: RelationFact) -> None:
        """Add a tag to a relation.

        Args:
            fact: RelationFact object representing the tag
        """
        tag = {
            "fact": fact.to_dict(),
        }
        value = json.dumps(json.dumps(tag))  # Double JSON encode to escape quotes
        key = fact.id()

        query = f'cpg.metaData.newTagNodePair({key}, "{value}").store()'
        await self.query_raw(query)
        await self.query_raw("run.commit")

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

        # ``minimalCoveringNodeInfo`` is defined in ``pre_define.sc``; make
        # sure it is available in the REPL before we reference it.
        await self._ensure_pre_defined_loaded()

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
        units = await CodeUnitKind.parse_units(
            raw_data=response,
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
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        """Get all relations of a specific kind from a source code unit.

        Args:
            source_unit: Source CodeUnit
            kind: Kind of relation to retrieve (e.g., CALLS, INHERITS)
            direction: Direction of the relation (OUTGOING or INCOMING)

        Returns:
            List of (target_unit, relation) tuples
        """
        return await kind.fetch_backend(
            source_unit=source_unit, direction=direction, backend=self
        )
