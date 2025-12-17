# AuditZoo – Architecture Specification

## Overview

AuditZoo is a **CPG-centered, agent-based program analysis framework** built on Joern and AutoGen-Core.

**Core Design:**
- CPG as source of truth for program structure
- NetworkX graph of CodeUnits for in-memory analysis
- Facts system for analysis results (UnitFact and RelationFact)
- AutoGen-Core for agent orchestration

---

## Architecture

### Two Phases

1. **Preprocessing**
   - Generate CPG from source code using Joern
   - No agents involved - pure library code

2. **Analysis**
   - Load CPG into IRView (NetworkX graph of CodeUnits)
   - Run analysis agents via AutoGen-Core
   - Store results as Facts (in-memory + persisted to CPG tags)

### Package Structure

```
auditzoo/
├── core/
│   ├── ir/           # CodeUnit model, IRView, facts, backend API
│   ├── agents/       # Infrastructure agents (ir_store, plugin_registry)
│   ├── protocol/     # Message types and envelopes
│   └── runtime/      # AutoGen-Core runtime integration
├── backends/
│   ├── joern/        # Joern CPG backend
│   └── ingestion.py  # Backend setup
├── sdk/
│   ├── base_agent.py # Base class for analysis agents
│   ├── context.py    # Analysis context helper
│   └── registry.py   # Agent registration
└── analyses/
    ├── primitives/   # Low-level analyses (slicing, taint)
    └── detectors/    # High-level detectors
```

---

## Core IR Design

### CodeUnit

A flexible unit of code at any granularity (file, class, function, statement):

```python
@dataclass
class CodeUnit:
    id: str                    # Unique identifier (CPG node ID or synthetic)
    unit_type: CodeUnitType    # Kind (FUNCTION, CLASS, FILE, etc.)
    code: str                  # Source code text
    signature: str             # Human-readable name
    location: CodeLocation     # File path and line numbers
    cpg_node_id: Optional[str] # Link to CPG node (if CPG-backed)
```

**Identity:**
- Hashable by `id` (can use in sets, dicts, graphs)
- Equality based on `id`
- Factory methods: `CodeUnit.from_cpg()`, `CodeUnit.synthetic()`

### IRView

NetworkX directed graph of CodeUnits:

```python
class IRView:
    _graph: nx.DiGraph        # Nodes=CodeUnits, Edges=Relations
    _relation_facts: list      # Global relation facts
    _kind_index: dict          # Fast lookup by CodeUnitKind
```

**Node attributes:**
- `unit`: CodeUnit object
- `unit_facts`: List of UnitFact objects

**Edge attributes:**
- `relation_kind`: RelationKind enum (CALLS, INHERITS, etc.)
- Custom metadata (call_site_id, confidence, etc.)

**Key Operations:**
- `get_all_functions()` - Load functions from backend
- `load_call_graph()` - Build call edges
- `get_callers(unit)` / `get_callees(unit)` - Graph traversal
- `get_transitive_callees(unit, max_depth)` - Use NetworkX algorithms
- `add_unit_fact(unit, fact)` - Attach fact to node
- `add_relation_fact(fact)` - Add relation + update graph

### Facts System

Two types of facts:

**1. UnitFact** - Attached to single CodeUnit (stored per-node):
```python
@dataclass
class UnitFact(ABC):
    name: str                  # Fact type (e.g., "vulnerability", "taint")
    metadata: dict[str, Any]

# Predefined:
SummaryFact(name, summary, details)     # General analysis results
CustomUnitFact(name, data)              # Domain-specific
```

**2. RelationFact** - Connects two CodeUnits (stored globally):
```python
@dataclass
class RelationFact(ABC):
    name: str                  # Relation type (e.g., "call", "dataflow")
    source_node_id: str
    target_node_id: str
    graph_updater: GraphUpdater  # Serializable graph update spec

# Predefined:
CallFact(source, target, context, confidence)
CustomRelationFact(name, source, target, data, graph_updater)
```

**Graph Updater:**
```python
@dataclass
class GraphUpdater:
    operation: GraphUpdateOp   # ADD_EDGE, REMOVE_EDGE, UPDATE_EDGE
    relation_kind: str         # "CALLS", "INHERITS", etc.
    edge_attrs: dict           # Edge metadata
```

**Serialization:**
- Unit facts → per-node CPG tags
- Relation facts → global CPG tags (on "_global" node)
- Everything is JSON-serializable

---

## Backend API

### CPGBackend Interface

```python
class CPGBackend(ABC):
    async def connect() -> None
    async def disconnect() -> None

    # Core query
    async def cpg_query(query: str) -> Any

    # Tag management
    async def add_tag(cpg_node_id: str, tag_name: str, tag_data: dict)
    async def get_tags(cpg_node_id: str, tag_name: str | None) -> list[dict]

    # Convenience methods
    async def get_functions(program_id: ProgramId) -> list[Function]
    async def get_call_graph(program_id: ProgramId) -> list[dict]
    async def get_cfg_nodes(function_cpg_id: str) -> list[dict]

    # Context manager support
    async def __aenter__() / __aexit__()
```

### Joern Backend

Connects to Joern server via HTTP client:
- Manages Joern server lifecycle
- Executes CPG queries
- Converts Joern responses to CodeUnits
- Handles tag serialization

---

## Agent System

### Infrastructure Agents

**IRStoreAgent**
- Manages IRView instances
- Provides IR access to analysis agents
- Handles loading/caching

**PluginRegistryAgent**
- Registers analysis agents
- Routes requests by agent ID (no capabilities system)

### Analysis Agents

Base class:
```python
class BaseAnalysisAgent(RoutedAgent):
    def __init__(self, agent_id: str, ir_store: IRStoreAgent):
        super().__init__(agent_id)
        self.ir_store = ir_store

    async def analyze(self, program_id: str) -> list[Fact]:
        # Get IR view
        ir_view = await self.ir_store.get_ir_view(program_id)

        # Perform analysis
        ...

        # Return facts
        return facts
```

**No capabilities system** - agents are called directly by ID.

---

## Usage Examples

### Basic Analysis

```python
from auditzoo.backends.joern.backend import JoernBackend
from auditzoo.core.ir.view import IRView
from auditzoo.core.ir.facts import SummaryFact

# Setup backend
config = JoernConfig(language="c", source_path="./src")
async with JoernBackend(config) as backend:
    # Create view
    view = IRView(backend)

    # Load program
    functions = await view.get_all_functions()
    await view.load_call_graph()

    # Analyze
    for func in functions:
        if is_vulnerable(func):
            view.add_unit_fact(func, SummaryFact(
                name="vulnerability",
                summary="Buffer overflow",
                details={"severity": "high"}
            ))

    # Persist
    for func in functions:
        await view.sync_unit_facts_to_backend(func)
```

### Custom Relation Fact

```python
from auditzoo.core.ir.facts import CustomRelationFact, GraphUpdater, GraphUpdateOp

# Add dataflow relation
view.add_relation_fact(CustomRelationFact(
    name="dataflow",
    source_node_id="var_x_id",
    target_node_id="var_y_id",
    data={"taint": True, "sanitized": False},
    graph_updater=GraphUpdater(
        operation=GraphUpdateOp.ADD_EDGE,
        relation_kind="REFERENCES",
        edge_attrs={"taint": True}
    )
))

# This automatically creates an edge in the graph!
# Query later:
related = view.get_related_units(var_x, RelationKind.REFERENCES, "out")
```

---

## Design Principles

1. **CPG as source of truth** - Don't abstract it away, expose it
2. **NetworkX for flexibility** - Graph algorithms built-in
3. **Facts not capabilities** - Simple, serializable annotations
4. **Agent by ID** - No complex capability routing
5. **No over-engineering** - Keep it simple and focused

---

## Development Status

**Completed:**
- ✅ CodeUnit model with mandatory IDs and hash/eq
- ✅ IRView with NetworkX graph
- ✅ UnitFact and RelationFact system
- ✅ Serializable GraphUpdater
- ✅ Async context managers for backends
- ✅ Facts moved to core/ir/

**In Progress:**
- ⚠️ Joern backend full implementation
- ⚠️ Analysis agent examples
- ⚠️ AutoGen-Core integration updates

**Not Started:**
- ❌ TreeSitter backend
- ❌ Comprehensive test suite
