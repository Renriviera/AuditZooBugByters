"""CPG IR View - Graph-based view over CPG backends using NetworkX.

This module provides IRView, which maintains an in-memory graph of CodeUnits
with relations between them. It provides efficient querying, relation traversal,
and tag management.

For the graph representation, we use NetworkX's MultiDiGraph to represent
directed relations (e.g., function calls, inheritance, data flow) between CodeUnits.
Nodes represent CPG-backed CodeUnits, and edges represent relations with
associated information (within relation,  call sites, confidence scores, etc.).
The key of each edge is the CodeUnitRelation type.

Note that IRView provides low-level graph operations (e.g., get the neighbors of a node).
Higher-level analyses (e.g., caller/callee analysis, data flow analysis, taint analysis)
are built on top of this core graph abstraction and provided in a separate agent layer.
"""

from collections import defaultdict
from collections.abc import Callable
from typing import Any, Literal

import networkx as nx

from auditzoo.core.ir.backend_api import CPGBackend
from auditzoo.core.ir.facts import (
    RelationFact,
    UnitFact,
)
from auditzoo.core.ir.model import (
    CodeUnit,
    CodeUnitKind,
    CodeUnitRelation,
    IRBackendError,
    IRValueError,
    RelationDirection,
    RelationKind,
    RKRegistry,
    UKRegistry,
)
from auditzoo.core.ir.model.base import CodeLocation


class IRView:
    """Graph-based view over a CPG backend using NetworkX.

    IRView maintains an in-memory directed graph where:
    - Nodes: CodeUnit objects (identified by their `id`)
    - Edges: Relations between CodeUnits (with CodeUnitRelation attributes)
    - Node attributes: CodeUnit object and Facts
    - Edge attributes: CodeUnitRelation

    This provides:
    - Efficient graph traversal
    - Fact management on CodeUnits (annotations from analyses)
    - Lazy loading from backend
    - Built-in graph algorithms via NetworkX

    Lifecycle Management:
        IRView manages backend lifecycle by default. Use async context manager pattern.
    """

    def __init__(self, backend: CPGBackend, owns_backend: bool = True):
        """Initialize IR view.

        Args:
            backend: CPG backend instance (should already be connected)
            owns_backend: If True, IRView will manage backend lifecycle (connect/disconnect).
                         Set to False if you want to manage backend lifecycle manually.
        """
        self.backend = backend
        self._owns_backend = owns_backend

        # === Core Graph ===
        # MultiDiGraph for directed relations (calls, references, inheritance, etc.)
        self._graph = nx.MultiDiGraph()

        # Group CodeUnit IDs by kind for O(1) "get all functions"-like queries
        self._type_index: dict[CodeUnitKind, set[str]] = defaultdict(set)

        # === Fact Storage ===
        self._relation_facts: list[RelationFact] = []

        # === Loading State ===
        # Track which units have been loaded from backend
        self._loaded_units: set[str] = set()
        # Track which (unit_id, direction, relation) tuples have been loaded
        self._loaded_relations: set[tuple[str, RelationDirection, RelationKind]] = set()
        # Track which unit kinds have been loaded (entirely) from backend
        self._loaded_unit_kinds: set[CodeUnitKind] = set()
        # Track which relation kinds have been loaded (entirely) from backend
        self._loaded_relation_kinds: set[RelationKind] = set()

        # Check whether backend is connected
        if not self.backend.is_connected():
            raise IRBackendError("Backend must be connected before initializing IRView")

    @classmethod
    async def create(cls, backend: CPGBackend) -> "IRView":
        """Async factory method to create and initialize an IRView.

        This handles connecting the backend before creating the view.

        Args:
            backend: CPG backend instance

        Returns:
            Initialized IRView instance
        """
        if not backend.is_connected():
            await backend.connect()

        view = cls(backend, owns_backend=True)
        await view.preload_from_backend()
        return view

    async def __aenter__(self) -> "IRView":
        """Context manager entry.

        Returns:
            Self for use in async with statement

        Note:
            If you used IRView.create(), the backend is already connected.
            If you passed a backend to __init__(), ensure it's connected before entering.
        """
        # Backend should already be connected (either by create() or by user)
        # We just return self for the context
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit.

        Performs cleanup:
        - Syncs facts to backend
        - Clears graph and indexes
        - Disconnects backend if owned by IRView

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred
        """
        # Always cleanup the view
        await self.cleanup(sync_to_backend=True)

        # Disconnect backend if we own it
        if self._owns_backend:
            await self.backend.disconnect()

    # ============================================
    # Backend Queries
    # ============================================
    async def query(self, query: str, response_ty: str = "json") -> Any:
        """Execute a raw query against the backend.

        Args:
            query: Query string (CPG query language)
            response_ty: Expected response type ("json", "str", etc.)

        Returns:
            Backend-specific query results
        """
        return await self.backend.query(query, response_ty=response_ty)

    # ============================================
    # UNIT MANAGEMENT
    # ============================================

    def _add_unit(self, unit: CodeUnit) -> None:
        """Add a CodeUnit to the graph as a node.

        Args:
            unit: CodeUnit to add

        Raises:
            IRValueError: If unit is not CPG-backed
        """
        # Add node with unit and empty unit facts storage
        self._graph.add_node(
            unit.id,
            unit=unit,
            unit_facts=[],  # List of UnitFact objects attached to this unit
        )

        # Update kind index for fast lookup
        self._type_index[unit.kind].add(unit.id)

    async def fetch_unit(self, location: CodeLocation) -> CodeUnit | None:
        """Fetch a CodeUnit by its source location.

        Args:
            location: CodeLocation object specifying start and end lines

        Returns:
            The minimal CodeUnit covering the specified location, or None if not found
        """
        unit = await self.backend.get_code_unit_by_location(location)
        if unit and unit.id not in self._graph:
            self._add_unit(unit)
        return unit

    async def get_unit(
        self, unit_id: str, fetch_backend: bool = True
    ) -> CodeUnit | None:
        """Get CodeUnit by ID.

        Args:
            unit_id: CodeUnit ID to look up
            fetch_backend: If True, attempt to load from backend if not in graph

        Returns:
            CodeUnit if found, None otherwise
        """
        if unit_id in self._graph:
            unit = self._graph.nodes[unit_id]["unit"]
            if not isinstance(unit, CodeUnit):
                raise IRValueError(f"Node {unit_id} is not a valid CodeUnit")
            return unit

        if CodeUnit.is_synthetic_id(unit_id):
            # Synthetic units cannot be fetched from backend via ID
            raise IRValueError(
                f"Synthetic CodeUnit {unit_id} not found in graph and cannot be fetched from backend"
            )

        if fetch_backend and unit_id not in self._loaded_units:
            unit = await self.backend.get_code_unit(unit_id)
            self._loaded_units.add(unit_id)
            if unit:
                self._add_unit(unit)
                return unit

        return None

    async def has_unit(self, unit_id: str, fetch_backend: bool = True) -> bool:
        """Check if a CodeUnit exists in the graph.

        Args:
            unit_id: CodeUnit ID to check
            fetch_backend: If True, attempt to load from backend if not in graph

        Returns:
            True if unit exists in graph
        """
        return await self.get_unit(unit_id, fetch_backend) is not None

    async def get_all_units_by_kind(
        self, kind: CodeUnitKind, fetch_backend: bool = True
    ) -> list[CodeUnit]:
        """Get all CodeUnits of a specific type.

        Args:
            kind: CodeUnitKind to filter by
            fetch_backend: If True, attempt to load from backend if not in graph

        Returns:
            List of matching CodeUnits
        """
        if fetch_backend and kind not in self._loaded_unit_kinds:
            # Load from backend if not already loaded
            units = await self.backend.get_code_units(kind)
            for unit in units:
                self._add_unit(unit)
            self._loaded_unit_kinds.add(kind)

        return [
            self._graph.nodes[node_id]["unit"] for node_id in self._type_index[kind]
        ]

    def get_all_units(self) -> list[CodeUnit]:
        """Get all CodeUnits in the graph. Note that this does NOT fetch from backend.

        Returns:
            List of all CodeUnits
        """
        return [self._graph.nodes[node_id]["unit"] for node_id in self._graph.nodes]

    # ============================================
    # RELATION MANAGEMENT
    # ============================================

    async def _add_relation(
        self,
        source_id: str,
        target_id: str,
        relation: CodeUnitRelation,
    ) -> None:
        """Add a relation (edge) between two CodeUnits.

        Args:
            source_id: Source CodeUnit ID
            target_id: Target CodeUnit ID
            relation: Type of relation (CALLS, INHERITS, etc.) - the key

        Note:
            For MultiDiGraph, we will use relation_type as the key, which means
            we need to ensure uniqueness if multiple edges of the same type exist,
            e.g., multiple calls from one function to another at different call sites.
            This can be done by setting a different description for the CodeUnitRelation.

        Example:
            view.add_relation(
                "func_123",
                "func_456",
                CodeUnitRelation(RelationKind.CALLS),
                call_site_id="call_789"
            )
        """
        if not await self.has_unit(source_id):
            raise IRValueError(f"Source unit {source_id} not found in graph")

        if not await self.has_unit(target_id):
            raise IRValueError(f"Target unit {target_id} not found in graph")

        self._graph.add_edge(source_id, target_id, key=relation)

    async def get_all_relations_by_kind(
        self,
        kind: RelationKind,
        fetch_backend: bool = True,
    ) -> list[tuple[CodeUnit, CodeUnit, CodeUnitRelation]]:
        """Get all relations of a specific type (for units that exist in the graph).

        Args:
            kind: RelationKind to filter by
            fetch_backend: If True, attempt to load from backend if not in graph

        Returns:
            List of (source_unit, target_unit) tuples
        """
        if fetch_backend and kind not in self._loaded_relation_kinds:
            # Load all relations of this type from backend
            for source_id in self._graph.nodes:
                source_unit = self._graph.nodes[source_id]["unit"]

                # We only need to do one direction, since we track all nodes
                relations = await self.backend.get_relations(source_unit, kind, "out")

                for target_unit, relation in relations:
                    if not await self.has_unit(target_unit.id, fetch_backend=True):
                        raise IRValueError(
                            f"Related unit {target_unit.id} not found in backend"
                        )
                    await self._add_relation(source_id, target_unit.id, relation)

            self._loaded_relation_kinds.add(kind)

        # Collect results - MultiDiGraph returns (source, target, key, data)
        result = []
        for source_id, target_id, key, _ in self._graph.edges(data=True, keys=True):
            if key.kind == kind:
                source_unit = self._graph.nodes[source_id]["unit"]
                target_unit = self._graph.nodes[target_id]["unit"]
                result.append((source_unit, target_unit, key))

        return result

    async def get_related_units(
        self,
        unit: CodeUnit,
        kind: RelationKind,
        direction: Literal["both"] | RelationDirection,
        fetch_backend: bool = True,
    ) -> list[tuple[CodeUnit, str, dict[str, Any]]]:
        """Get units related to this unit by a specific relation.

        Args:
            unit: Source CodeUnit
            kind: Type of relation to follow
            direction: "out" (successors), "in" (predecessors), or "both"
            fetch_backend: If True, attempt to load from backend if not in graph

        Returns:
            List of (related_unit, relation, direction) tuples
            edge attributes like call_site_id, confidence, etc.

        Raises:
            IRValueError: If direction is invalid or related unit not found

        Example:
            # Get all functions called by foo
            callees = view.get_related_units(foo, CodeUnitRelation(RelationKind.CALLS), "out")

            # Get all functions that call foo
            callers = view.get_related_units(foo, RelationKind.CALLS, "in")
        """
        if not await self.has_unit(unit.id, fetch_backend):
            raise IRValueError(f"CodeUnit {unit.id} not found in graph")

        # Check valid direction
        if direction not in ("in", "out", "both"):
            raise IRValueError("direction must be 'in', 'out', or 'both'")
        if direction == "both":
            # Combine results from both directions
            out_related = await self.get_related_units(unit, kind, "out", fetch_backend)
            in_related = await self.get_related_units(unit, kind, "in", fetch_backend)
            return out_related + in_related

        if (
            fetch_backend
            and kind not in self._loaded_relation_kinds
            and (unit.id, direction, kind) not in self._loaded_relations
        ):
            # Load relations from backend
            relations = await self.backend.get_relations(unit, kind, direction)
            for target_unit, relation in relations:
                # Ensure target unit exists
                if not await self.has_unit(target_unit.id, fetch_backend=True):
                    raise IRValueError(
                        f"Related unit {target_unit.id} not found in backend"
                    )

                # Add relation
                if direction == "out":
                    await self._add_relation(unit.id, target_unit.id, relation)
                else:
                    await self._add_relation(target_unit.id, unit.id, relation)

            self._loaded_relations.add((unit.id, direction, kind))

        related = []
        if direction == "out":
            # Outgoing edges (e.g., who this calls) - MultiDiGraph returns (source, target, key, data)
            for _, target, key, data in self._graph.out_edges(
                unit.id, data=True, keys=True
            ):
                if key.kind == kind:
                    related.append((self._graph.nodes[target]["unit"], "out", data))
        else:
            # Incoming edges (e.g., who calls this) - MultiDiGraph returns (source, target, key, data)
            for source, _, key, data in self._graph.in_edges(
                unit.id, data=True, keys=True
            ):  # pyright: ignore[reportCallIssue]
                if key.kind == kind:
                    related.append((self._graph.nodes[source]["unit"], "in", data))

        return related

    def get_all_relations(
        self,
    ) -> list[tuple[CodeUnit, CodeUnit, CodeUnitRelation, dict[str, Any]]]:
        """Get all relations in the graph. Note that this does NOT fetch from backend.

        Returns:
            List of (source_unit, target_unit, relation) tuples
        """
        result = []
        for source_id, target_id, key, _ in self._graph.edges(data=True, keys=True):
            source_unit = self._graph.nodes[source_id]["unit"]
            target_unit = self._graph.nodes[target_id]["unit"]
            result.append((source_unit, target_unit, key))
            result.append((source_unit, target_unit, key))

        return result  # type: ignore

    # ============================================
    # GRAPH QUERIES (No BACKEND FETCH)
    # ============================================

    def filter_graph(
        self,
        filter: Callable[[CodeUnit, CodeUnit, CodeUnitRelation, dict[str, Any]], bool],
    ) -> nx.MultiDiGraph:
        """Create a subgraph containing only edges of the specified relation type.
        Note that this function will *NOT* fetch from backend.

        Args:
            relation_type: Type of relation to filter by

        Returns:
            NetworkX MultiDiGraph containing only edges matching the relation type
        """
        # For MultiDiGraph, edges() returns (u, v, key, data) when keys=True
        edges = [
            (u, v, key)
            for u, v, key, d in self._graph.edges(data=True, keys=True)
            if filter(
                self._graph.nodes[u]["unit"], self._graph.nodes[v]["unit"], key, d
            )
        ]
        return self._graph.edge_subgraph(edges)  # pyright: ignore

    def get_reachable_units(
        self,
        unit: CodeUnit,
        filter: Callable[[CodeUnit, CodeUnit, CodeUnitRelation, dict[str, Any]], bool],
        max_depth: int | None = None,
    ) -> set[CodeUnit]:
        """Get all transitively reachable units using NetworkX graph traversal.
        Note that this function will *NOT* fetch from backend.

        Args:
            unit: Starting unit
            filter: Callable to determine which relations to follow
            max_depth: Maximum depth to traverse (None for unlimited)

        Returns:
            Set of all reachable CodeUnits following the specified relation type
        """
        if not unit.id or unit.id not in self._graph:
            return set()

        # Create subgraph with only the specified relation type
        subgraph = self.filter_graph(filter)

        # Use NetworkX to get all reachable nodes
        if max_depth is None:
            # All reachable descendants
            reachable_ids = nx.descendants(subgraph, unit.id)
        else:
            # Limited depth traversal
            reachable_ids = set()
            nodes_at_depth = nx.single_source_shortest_path_length(
                subgraph, unit.id, cutoff=max_depth
            )
            reachable_ids.update(nodes_at_depth.keys())
            reachable_ids.discard(unit.id)  # Remove the starting node

        # Convert IDs to CodeUnits
        result = set()
        for node_id in reachable_ids:
            if node_id in self._graph:
                result.add(self._graph.nodes[node_id]["unit"])

        return result

    def find_shortest_path(
        self,
        from_unit: CodeUnit,
        to_unit: CodeUnit,
        filter: Callable[[CodeUnit, CodeUnit, CodeUnitRelation, dict[str, Any]], bool],
    ) -> list[CodeUnit] | None:
        """Find shortest path from one unit to another following a specific relation type.
        Note that this function will *NOT* fetch from backend.

        Args:
            from_unit: Starting unit
            to_unit: Target unit
            filter: Callable to determine which relations to follow

        Returns:
            List of CodeUnits representing the path, or None if no path exists
        """
        if not from_unit.id or not to_unit.id:
            return None

        # Create subgraph with only the specified relation type
        subgraph = self.filter_graph(filter)
        try:
            path_ids = nx.shortest_path(subgraph, from_unit.id, to_unit.id)
            return [self._graph.nodes[nid]["unit"] for nid in path_ids]
        except nx.NetworkXNoPath:
            return None

    # ============================================
    # FACT MANAGEMENT
    # ============================================

    async def add_unit_fact(
        self, unit: CodeUnit, fact: UnitFact, fetch_backend: bool = True
    ) -> None:
        """Add a unit fact to a CodeUnit.

        Unit facts are stored as node attributes in the graph.
        For persistence to backend, call sync_unit_facts_to_backend().

        Args:
            unit: CodeUnit to attach fact to
            fact: UnitFact instance to add
            fetch_backend: If True, attempt to load unit from backend if not in graph

        Raises:
            ValueError: If unit not in graph

        Example:
            from auditzoo.core.ir.facts import SummaryFact

            unit = view.get_function_by_signature("foo()")
            fact = SummaryFact(
                name="vulnerability",
                summary="Potential SQL injection",
                details={"severity": "high", "confidence": 0.85}
            )
            view.add_unit_fact(unit, fact)
        """
        if not await self.has_unit(unit.id, fetch_backend):
            raise IRValueError(f"CodeUnit {unit.id} not found in graph")

        # Unit facts stored in node attributes
        self._graph.nodes[unit.id]["unit_facts"].append(fact)

    async def add_relation_fact(
        self, fact: RelationFact, fetch_backend: bool = True
    ) -> None:
        """Add a relation fact connecting two CodeUnits.

        Relation facts are stored at the graph level (global).
        The fact's graph_updater function is called to update the NetworkX graph.
        For persistence to backend, call sync_relation_facts_to_backend().

        Args:
            fact: RelationFact instance to add
            fetch_backend: If True, attempt to load units from backend if not in graph

        Example:
            from auditzoo.core.ir.facts import CallFact

            fact = CallFact(
                source_node_id="caller_func_id",
                target_node_id="callee_func_id",
                call_site_node_id="call_site_id",
                call_context="dynamic dispatch",
            )
            view.add_relation_fact(fact)
            # This automatically creates an edge in the graph!
        """
        if not await self.has_unit(fact.source_node_id, fetch_backend):
            raise IRValueError(
                f"Source CodeUnit {fact.source_node_id} not found in graph"
            )

        if not await self.has_unit(fact.target_node_id, fetch_backend):
            raise IRValueError(
                f"Target CodeUnit {fact.target_node_id} not found in graph"
            )

        # Store relation fact globally
        self._relation_facts.append(fact)

        # Update graph using the fact's graph updater
        fact.apply_graph_update(self._graph)

    async def get_unit_facts(
        self,
        unit: CodeUnit,
        fact_cls: type[UnitFact] | None = None,
        fetch_backend: bool = True,
    ) -> list[UnitFact]:
        """Get unit facts attached to a CodeUnit.

        Args:
            unit: CodeUnit to get facts for
            fact_cls: If provided, filter to only this UnitFact subclass

        Returns:
            List of UnitFact objects

        Example:
            # Get all unit facts
            all_facts = view.get_unit_facts(unit)
        """
        if not await self.has_unit(unit.id, fetch_backend):
            raise IRValueError(f"CodeUnit {unit.id} not found in graph")

        unit_facts = self._graph.nodes[unit.id]["unit_facts"]
        if fact_cls:
            unit_facts = [fact for fact in unit_facts if isinstance(fact, fact_cls)]

        return list(unit_facts)

    def get_relation_facts(
        self, fact_cls: type[RelationFact] | None = None
    ) -> list[RelationFact]:
        """Get relation facts from the graph.

        Args:
            fact_cls: If provided, filter to only this RelationFact subclass

        Returns:
            List of RelationFact objects

        Example:
            # Get all relation facts
            all_relations = view.get_relation_facts()
        """
        if fact_cls:
            return [fact for fact in self._relation_facts if isinstance(fact, fact_cls)]
        else:
            return list(self._relation_facts)

    # ============================================
    # SYNC BACKEND
    # ============================================

    async def preload_from_backend(self) -> None:
        """Preload common units and relations from the backend into the IRView.
        This can be used to eagerly load frequently accessed data.
        """

        await self.get_all_units_by_kind(UKRegistry.Function(), fetch_backend=True)
        await self.get_all_relations_by_kind(RKRegistry.Calls(), fetch_backend=True)
        await self.get_all_relations_by_kind(
            RKRegistry.AnnotatedBy(), fetch_backend=True
        )

        for unit in self.get_all_units():
            await self.load_unit_facts_from_backend(unit)
        await self.load_relation_facts_from_backend()

    async def load_unit_facts_from_backend(self, unit: CodeUnit) -> None:
        """Load unit facts for a CodeUnit from the backend.

        This queries the backend for tags and deserializes them into UnitFact objects.

        Args:
            unit: CodeUnit to load facts for
        """
        # Get all tags from backend for this CPG node
        facts = await self.backend.get_unit_tags(unit)

        for fact in facts:
            await self.add_unit_fact(unit, fact)

    async def load_relation_facts_from_backend(self) -> None:
        """Load all relation facts from the backend.

        This queries the backend for global tags and deserializes them into RelationFact objects.
        """
        # Get all global tags from backend
        facts = await self.backend.get_relation_tags()

        for fact in facts:
            await self.add_relation_fact(fact)

    async def sync_backend(self) -> None:
        """Sync all facts in the IRView down to the CPG backend for persistence."""
        # Sync unit facts
        for node_id in self._graph.nodes:
            unit = self._graph.nodes[node_id]["unit"]
            await self.store_unit_facts_to_backend(unit)

        # Sync relation facts
        await self.store_relation_facts_to_backend()

    async def store_unit_facts_to_backend(self, unit: CodeUnit) -> None:
        """Sync all unit facts for a CodeUnit to the CPG backend for persistence.

        Unit facts are stored as per-node tags in the backend.

        Args:
            unit: CodeUnit whose unit facts to sync
        """
        facts = await self.get_unit_facts(unit, fetch_backend=False)
        for fact in facts:
            # Serialize fact and store as backend tag
            await self.backend.set_unit_tag(unit, fact)

    async def store_relation_facts_to_backend(self) -> None:
        """Sync all relation facts to the CPG backend for persistence.

        Relation facts are stored as global tags (on a special "_global" node)
        because they reference two node_ids and aren't specific to one unit.
        """
        for fact in self._relation_facts:
            # Serialize fact and store as global backend tag
            await self.backend.set_relation_tag(fact)

    # ============================================
    # CACHE MANAGEMENT
    # ============================================

    def get_graph_stats(self) -> dict[str, Any]:
        """Get statistics about the graph.

        Returns:
            Dictionary with graph statistics including:
            - num_nodes: Total number of CodeUnits
            - num_edges: Total number of relations
            - num_unit_facts: Total number of unit facts attached
            - num_relation_facts: Total number of relation facts
            - nodes_by_kind: Count of nodes per CodeUnitKind
            - edges_by_kind: Count of edges per RelationKind
            - loaded_unit_kinds: Set of loaded unit kinds
            - loaded_relation_kinds: Set of loaded relation kinds
        """
        # Count nodes by kind
        nodes_by_kind = {
            str(kind): len(node_ids) for kind, node_ids in self._type_index.items()
        }

        # Count edges by relation kind
        edges_by_kind: dict[str, int] = defaultdict(int)
        for _, _, key, _ in self._graph.edges(data=True, keys=True):
            edges_by_kind[str(key.kind)] += 1

        # Count total unit facts
        total_unit_facts = sum(
            len(data["unit_facts"]) for _, data in self._graph.nodes(data=True)
        )

        return {
            "num_nodes": self._graph.number_of_nodes(),
            "num_edges": self._graph.number_of_edges(),
            "num_unit_facts": total_unit_facts,
            "num_relation_facts": len(self._relation_facts),
            "nodes_by_kind": nodes_by_kind,
            "edges_by_kind": dict(edges_by_kind),
            "loaded_unit_kinds": [str(kind) for kind in self._loaded_unit_kinds],
            "loaded_relation_kinds": [
                str(kind) for kind in self._loaded_relation_kinds
            ],
        }

    async def reload(self) -> None:
        """Clear all cached data and reload from backend."""
        # Clear all data structures
        self._graph.clear()
        self._type_index.clear()
        self._relation_facts.clear()
        self._loaded_units.clear()
        self._loaded_relations.clear()
        self._loaded_unit_kinds.clear()
        self._loaded_relation_kinds.clear()

        # Reload backend data
        await self.backend.reload()

        # Preload from backend
        await self.preload_from_backend()

    async def cleanup(self, sync_to_backend: bool = False) -> None:
        """Explicit cleanup method for IRView.

        This provides more control than relying on __del__().
        Use this when you want deterministic cleanup.

        Note: This does NOT disconnect the backend. Use the async context manager
        or manually call backend.disconnect() if needed.

        Args:
            sync_to_backend: If True, sync all facts to backend before cleanup

        Example:
            # Manual cleanup (not recommended, use async context manager instead)
            view = IRView(backend, owns_backend=False)
            try:
                # ... use view ...
            finally:
                await view.cleanup(sync_to_backend=True)
                # Backend is still connected, disconnect manually if needed
        """
        if sync_to_backend:
            await self.sync_backend()

        # Clear all data structures
        self._graph.clear()
        self._type_index.clear()
        self._relation_facts.clear()
        self._loaded_units.clear()
        self._loaded_relations.clear()
        self._loaded_unit_kinds.clear()
        self._loaded_relation_kinds.clear()
