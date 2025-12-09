"""CPG IR View - Cached wrapper around CPG backends.

This module provides IRView, which wraps a CPGBackend and adds caching
and convenience methods. IRView is what analysis agents interact with.
"""

from typing import Any

from auditzoo.contracts.facts import Fact
from auditzoo.core.ir.backend_api import CPGBackend
from auditzoo.core.ir.model import Function, ProgramId


class IRView:
    """Cached view over a CPG backend.

    Provides:
    - Direct CPG query access
    - Convenience methods for common operations
    - Tag management for facts
    - Caching to reduce backend calls
    """

    def __init__(self, backend: CPGBackend, program_id: ProgramId):
        """Initialize IR view.

        Args:
            backend: CPG backend instance
            program_id: Program this view represents
        """
        self.backend = backend
        self.program_id = program_id
        self._cache: dict[str, Any] = {}

    # ===== Direct CPG Query Access =====

    async def cpg_query(self, query: str, cache_key: str | None = None) -> Any:
        """Execute a CPG query.

        Args:
            query: CPG query string
            cache_key: Optional cache key for result caching

        Returns:
            Query results
        """
        if cache_key and cache_key in self._cache:
            return self._cache[cache_key]

        result = await self.backend.cpg_query(query)

        if cache_key:
            self._cache[cache_key] = result

        return result

    def supports_feature(self, feature: str) -> bool:
        """Check if backend supports a feature.

        Args:
            feature: Feature name (e.g., "dataflow", "controlflow")

        Returns:
            True if supported
        """
        return self.backend.supports_feature(feature)

    # ===== Tag/Fact Management =====

    async def add_fact(self, fact: Fact, cpg_node_id: str | None = None) -> None:
        """Add a fact as a CPG tag.

        Args:
            fact: Fact to store
            cpg_node_id: Optional specific CPG node to attach to
                        (if None, uses first node referenced in fact)
        """
        tag_data = fact.to_tag()
        tag_name = fact.fact_type.value

        # If no specific node ID, try to extract from fact
        if cpg_node_id is None:
            cpg_node_id = self._extract_primary_node_id(fact)

        if cpg_node_id:
            await self.backend.add_tag(cpg_node_id, tag_name, tag_data)
        else:
            # Store as global tag (implementation-dependent)
            await self.backend.add_tag("_global", tag_name, tag_data)

    async def get_facts(
        self, fact_type: str | None = None, cpg_node_id: str | None = None
    ) -> list[Fact]:
        """Get facts from CPG tags.

        Args:
            fact_type: Optional filter by fact type
            cpg_node_id: Optional filter by CPG node

        Returns:
            List of deserialized facts
        """
        if cpg_node_id:
            # Get tags from specific node
            tags = await self.backend.get_tags(cpg_node_id, fact_type)
        else:
            # Get all tags
            all_tags = await self.backend.get_all_tags(fact_type)
            tags = []
            for node_tags in all_tags.values():
                tags.extend(node_tags)

        # Deserialize tags to facts
        facts = []
        for tag_data in tags:
            fact = self._deserialize_fact(tag_data)
            if fact:
                facts.append(fact)

        return facts

    async def query_nodes_by_fact(self, fact_type: str) -> list[str]:
        """Find CPG nodes that have facts of a specific type.

        Args:
            fact_type: Fact type to search for

        Returns:
            List of CPG node IDs
        """
        return await self.backend.query_by_tag(fact_type)

    # ===== Convenience Methods =====

    async def get_program_info(self) -> dict[str, Any]:
        """Get program metadata.

        Returns:
            Program info dict
        """
        cache_key = "program_info"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[no-any-return]

        info = await self.backend.get_program_info(self.program_id)
        self._cache[cache_key] = info
        return info

    async def get_functions(self) -> list[Function]:
        """Get all functions in the program.

        Returns:
            List of Function objects
        """
        cache_key = "functions"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[no-any-return]

        functions = await self.backend.get_functions(self.program_id)
        self._cache[cache_key] = functions
        return functions

    async def get_function_by_name(self, function_name: str) -> Function | None:
        """Get a specific function by name.

        Args:
            function_name: Function name

        Returns:
            Function object or None
        """
        # Check cache first
        functions = await self.get_functions()
        for func in functions:
            if func.name == function_name:
                return func

        # Fallback to backend query
        return await self.backend.get_function_by_name(self.program_id, function_name)

    async def get_cfg_nodes(self, function: Function) -> list[dict[str, Any]]:
        """Get CFG nodes for a function.

        Args:
            function: Function object

        Returns:
            List of CFG node dicts
        """
        cache_key = f"cfg_{function.cpg_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[no-any-return]

        cfg_nodes = await self.backend.get_cfg_nodes(function.cpg_id)
        self._cache[cache_key] = cfg_nodes
        return cfg_nodes

    async def get_call_graph(self) -> list[dict[str, Any]]:
        """Get call graph for the program.

        Returns:
            List of call edge dicts
        """
        cache_key = "call_graph"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[no-any-return]

        call_graph = await self.backend.get_call_graph(self.program_id)
        self._cache[cache_key] = call_graph
        return call_graph

    async def get_ast_nodes(
        self, function: Function, node_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Get AST nodes for a function.

        Args:
            function: Function object
            node_type: Optional filter by node type

        Returns:
            List of AST node dicts
        """
        cache_key = f"ast_{function.cpg_id}"
        if node_type:
            cache_key += f"_{node_type}"

        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[no-any-return]

        ast_nodes = await self.backend.get_ast_nodes(function.cpg_id, node_type)
        self._cache[cache_key] = ast_nodes
        return ast_nodes

    # ===== Cache Management =====

    def clear_cache(self, key: str | None = None) -> None:
        """Clear cache.

        Args:
            key: Optional specific key to clear (clears all if None)
        """
        if key:
            self._cache.pop(key, None)
        else:
            self._cache.clear()

    def invalidate_cache(self):
        """Clear all caches (legacy compatibility)."""
        self.clear_cache()

    def invalidate_on_update(self) -> None:
        """Invalidate cache after program updates."""
        # Keep program info, clear derived data
        self._cache = {k: v for k, v in self._cache.items() if k == "program_info"}

    # ===== Helper Methods =====

    def _extract_primary_node_id(self, fact: Fact) -> str | None:
        """Extract primary CPG node ID from a fact.

        Args:
            fact: Fact object

        Returns:
            CPG node ID or None
        """
        # Try to find a CPG node ID field in the fact
        for attr_name in dir(fact):
            if attr_name.startswith("cpg_") and attr_name.endswith("_id"):
                node_id = getattr(fact, attr_name, None)
                if node_id and isinstance(node_id, str):
                    return node_id  # type: ignore[no-any-return]
        return None

    def _deserialize_fact(self, tag_data: dict) -> Fact | None:
        """Deserialize a fact from tag data.

        Args:
            tag_data: Tag data dict

        Returns:
            Fact object or None if deserialization fails
        """
        from auditzoo.contracts.facts import (
            CallGraphFact,
            IssueFact,
            PointsToFact,
            RangeFact,
            SliceFact,
            TaintFact,
        )

        fact_type = tag_data.get("type")
        if fact_type is None:
            # Log error in production
            return None

        fact_class_map = {
            "points_to": PointsToFact,
            "range": RangeFact,
            "taint": TaintFact,
            "slice": SliceFact,
            "issue": IssueFact,
            "call_graph": CallGraphFact,
        }

        fact_class = fact_class_map.get(fact_type)
        if fact_class:
            try:
                return fact_class.from_tag(tag_data)  # type: ignore[no-any-return,attr-defined]
            except Exception:
                # Log error in production
                return None

        return None
