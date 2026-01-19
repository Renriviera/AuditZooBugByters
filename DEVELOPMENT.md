# AuditZoo Development Guide

This document describes the architecture and internals of AuditZoo for contributors and developers who want to extend or modify the framework.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Protocol System](#protocol-system)
- [IR Model](#ir-model)
- [Backend System](#backend-system)
- [Analysis Agents](#analysis-agents)
- [Schema Patterns with to_schema and typed_dict](#schema-patterns-with-to_schema-and-typed_dict)
- [Advanced Topics](#advanced-topics)
- [Contributing](#contributing)

## Architecture Overview

AuditZoo follows a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│              User Code / Analysis Scripts               │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                  AnalysisRuntime                        │
│  (Orchestrates backend, IR, agents, messaging)          │
└───────────┬───────────────────────────┬─────────────────┘
            │                           │
┌───────────▼──────────┐    ┌───────────▼──────────────┐
│   Agent Layer        │    │      IR Layer            │
│  - IRStorageAgent    │◄───┤  - IRView (graph)        │
│  - BaseAnalysisAgent │    │  - CodeUnit, Relations   │
│  - Custom Agents     │    │  - Facts                 │
└───────────┬──────────┘    └───────────┬──────────────┘
            │                           │
┌───────────▼───────────────────────────▼──────────────┐
│                  Protocol Layer                      │
│            Request/Response messaging                │
└───────────┬──────────────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────┐
│              Backend Layer                           │
│  - CPGBackend (abstract interface)                   │
│  - JoernBackend, TreeSitterBackend, etc.             │
└──────────────────────────────────────────────────────┘
```

### Design Principles

1. **Agent-based**: Analysis tasks are performed by lightweight agents that communicate via messages
2. **Protocol-driven**: All communication uses structured Request/Response messages
3. **Backend-agnostic**: IR model abstracts away backend specifics (Joern, TreeSitter, CodeQL)
4. **Extensible**: Easy to add new code unit kinds, relation kinds, facts, and analysis agents
5. **Composable**: Agents can call other agents to build complex analyses
6. **Defensive error handling**: All exceptions in agents are caught and returned as `Response.fail()`

## Core Components

### 1. AnalysisRuntime (`auditzoo/core/runtime/`)

The `AnalysisRuntime` is the central orchestrator that:
- Creates and manages the backend connection
- Initializes the IR view (graph representation)
- Sets up the AutoGen-Core runtime for agent messaging
- Registers agents (both built-in and custom)
- Routes messages between agents

**Key files:**
- [`runtime.py`](auditzoo/core/runtime/runtime.py) - Main runtime implementation

**Lifecycle:**
```python
# Initialization
config = auto_detect_backend("./project")
runtime = AnalysisRuntime(config)
await runtime.initialize()  # Creates backend, IRView, registers IRStorageAgent

# Registration
await runtime.register_agent(MyAgent, "my_agent", lambda: MyAgent())

# Execution
runtime.start()
response = await runtime.send_message(request, target_agent_id)

# Cleanup
await runtime.stop()  # Disconnects backend, syncs facts, stops agents
```

### 2. IR Layer (`auditzoo/core/ir/`)

The IR (Intermediate Representation) layer provides a unified graph-based view of code across different backends.

**Key components:**

#### IRView (`ir/view.py`)
- In-memory graph representation using NetworkX
- Manages CodeUnits (nodes) and Relations (edges)
- Handles Facts (analysis results attached to units/relations)
- Provides CRUD operations and graph queries

#### CodeUnit (`ir/model/base.py`)
- Represents code at any granularity (file, class, function, statement, etc.)
- Each unit has: `id`, `kind`, `code`, `name`, `location`
- Can be CPG-backed (from Joern/TreeSitter) or synthetic (created by analyses)
- Identity based on `id` field (hashable, usable in sets/dicts)
- **All CodeUnits and nested structures must be dataclasses**

**Philosophy**: CodeUnits are like "editor views" of code snippets at different granularities. Relations represent how developers navigate code structure.

#### CodeUnitKind (`ir/model/base.py`)
- Abstract base class for different kinds of code units
- Subclasses define how to fetch and parse units from backends
- Auto-registers via `__init_subclass__` mechanism
- **Must be frozen dataclasses**: `@dataclass(frozen=True)`

**Built-in kinds** (`ir/model/unit_kinds/`):
- `Function` - Functions/methods
- `ClassUnit` - Classes/structs
- `File` - Source files
- `Module` - Modules/packages
- `Statement` - Individual statements
- `Expression` - Expressions
- `Variable` - Variables/parameters
- `Comment` - Comments
- `Repository` - Repository root

#### RelationKind (`ir/model/base.py`)
- Abstract base class for relationships between units
- Subclasses define how to fetch relations from backends
- Can have additional fields (e.g., `Contains` has a `level` field)
- Auto-registers via `__init_subclass__`
- **Must be frozen dataclasses**: `@dataclass(frozen=True)`

**Built-in kinds** (`ir/model/relation_kinds/`):
- `Calls` - Function/method calls
- `Contains` - Containment (function contains statement, file contains class, etc.)
- `AnnotatedBy` - Annotations/decorators

#### Facts (`ir/facts/`)
Facts are analysis results attached to CodeUnits or Relations without modifying the core model.

- **UnitFact**: Attached to a single CodeUnit (e.g., taint status, complexity metrics)
- **RelationFact**: Connects two CodeUnits with analysis findings (e.g., data flow paths)
- **Must be dataclasses** for proper serialization

Facts support:
- Serialization to backend for persistence
- Custom update operations via `GraphUpdater`
- Type-safe registration via `__init_subclass__`

**Fact registries:**
- `UFRegistry` - All UnitFact types
- `RFRegistry` - All RelationFact types

### 3. Protocol Layer (`auditzoo/core/protocol/`)

All agent communication uses structured messages defined in the protocol layer.

**Protocol basics:**
- **Single Request and Response classes** (sealed; no subclasses)
- **Flexible payloads**: `payload` is `dict[str, Any]`
- **Optional validation**: `response_schema` can validate `Response.data`

#### Request Class ([`protocol/requests.py`](auditzoo/core/protocol/requests.py))

```python
@dataclass
class Request:
    type: str                           # Dot-notation type (e.g., "ir.get_unit", "task.analysis")
    payload: dict[str, Any]             # Request data (JSON-serializable recommended)
    request_id: str                     # Auto-generated UUID
    metadata: dict[str, Any]            # Optional metadata
    response_schema: dict[str, Any]     # Optional JSON schema for response validation
```

**Request Type Conventions:**

1. **IR Operations** (prefix: `ir.`)
   - Direct IR operations (CRUD on units/relations)
   - Handled by `IRStorageAgent`
   - Examples: `ir.get_unit`, `ir.get_related_units`, `ir.get_graph_stats`

2. **Analysis Tasks** (prefix: `task.`)
   - Long-running analysis tasks
   - Handled by custom analysis agents
   - Examples: `task.taint_analysis`, `task.find_callers`

3. **Queries** (prefix: `query.`)
   - Fast lookups and searches
   - Handled by `IRStorageAgent` or query processors
   - Examples: `query.search`, `query.pattern_match`

**Payload example**:
```python
from dataclasses import dataclass, asdict

@dataclass
class TaintParams:
    source: str
    sink: str

params = TaintParams(source="user_input", sink="sql_query")
request = Request(
    type="task.taint_analysis",
    payload=asdict(params)
)
```

**Agent-specific request helpers**:
Request is sealed, so define small helper functions to construct agent-specific
requests instead of subclassing. This keeps call sites consistent and documents
payload shape in one place (see `auditzoo/agents/utility/human_interaction_agent.py`).

```python
from auditzoo.core.protocol.requests import Request
from auditzoo.core.protocol.utils import to_schema, typed_dict

def my_agent_request(query: str, **kwargs) -> Request:
    return Request(
        type="task.my_agent",
        payload={"query": query},
        response_schema=to_schema(typed_dict(results=list[str])),
        **kwargs,
    )
```

#### Response Class ([`protocol/responses.py`](auditzoo/core/protocol/responses.py))

```python
@dataclass
class Response:
    success: bool
    data: Any = None              # Any type
    error: str | None = None
    metadata: dict = {}

# Convenience constructors
Response.ok(data=[...])
Response.fail(error="Error message")

# Unwrapping
result = response.unwrap()        # Raises if failed
result = response.unwrap_or(default=[])
```

**Note**: `Response.data` can be any type (list, dataclass, primitive, etc.).

### 4. Agent System (`auditzoo/core/agents/`)

#### BaseAgent ([`agents/base.py`](auditzoo/core/agents/base.py))

All agents inherit from BaseAgent which provides:
- Message handling infrastructure via `handle_message` (decorated with `@message_handler`)
- Optional response validation against JSON schemas
- Exception handling that catches ALL exceptions and returns `Response.fail()`

**Architecture:**
```python
class BaseAgent(RoutedAgent, ABC):
    @message_handler
    async def handle_message(self, message: Request, ctx: MessageContext) -> Response:
        try:
            response = await self._handle_request(message, ctx)
            if message.response_schema != {}:
                # Validate response if schema provided
                response.validate(message.response_schema)
            return response
        except Exception as e:
            # ALL exceptions are caught and returned as Response.fail
            return Response.fail(f"Exception in handling request: {e}")

    @abstractmethod
    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        pass
```

**Key Points:**
- `handle_message`: Entry point with `@message_handler`, handles validation and exceptions
- `_handle_request`: Abstract method for subclasses to implement (NO `@message_handler`)
- ANY exception in an agent is caught and returned as `Response.fail()`
- Override `register_all()` to register sub-agents; the runtime calls it.

#### IRStorageAgent ([`agents/ir_storage_agent.py`](auditzoo/core/agents/ir_storage_agent.py))
- Built-in agent that manages the IR graph
- Handles all `ir.*` requests
- Automatically registered by `AnalysisRuntime`

**Common operations:**
- `ir.query`, `ir.fetch_unit`, `ir.get_unit`, `ir.has_unit`
- `ir.get_all_units_by_kind`, `ir.get_all_units`
- `ir.get_all_relations_by_kind`, `ir.get_all_relations`, `ir.get_related_units`
- `ir.get_graph_stats`, `ir.load_facts`, `ir.preload_from_backend`, `ir.sync_backend`, `ir.reload`, `ir.cleanup`

**Not implemented (returns failure today):**
- `ir.filter_graph`, `ir.get_reachable_units`, `ir.find_shortest_path`
- `ir.add_unit_fact`, `ir.add_relation_fact`, `ir.get_unit_facts`, `ir.get_relation_facts`

#### BaseAnalysisAgent ([`agents/base_analysis_agent.py`](auditzoo/core/agents/base_analysis_agent.py))
- Base class for all custom analysis agents
- Provides syntactic sugar methods for IR access:
  - `get_functions(ctx)` - Get all functions
  - `get_files(ctx)` - Get all files
  - `get_callers(func_id, ctx)` - Get callers of a function
  - `get_callees(func_id, ctx)` - Get callees of a function
  - `get_unit(unit_id, ctx)` - Get a specific unit
  - `query_ir(query, response_ty, ctx)` - Execute raw backend queries

**Creating custom agents:**
```python
from auditzoo.core.protocol.utils import to_schema, typed_dict

# Define response schema in your agent file (recommended)
MY_TASK_RESPONSE_SCHEMA = to_schema(typed_dict(
    results=list[str],
    confidence=float,
))

class MyAgent(BaseAnalysisAgent):
    def __init__(self):
        super().__init__("My agent description")

    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        if message.type != "task.my_task":
            return Response.fail("Unknown task type")

        # Use sugar methods
        functions = await self.get_functions(ctx)
        # ... analysis logic ...

        return Response.ok(data={"results": [...], "confidence": 0.95})
```

**Important Notes**:
- Implement `_handle_request`, NOT `handle_task`
- Do NOT use `@message_handler` on `_handle_request` (handled by BaseAgent)
- Define response schemas as module constants for callers to import
- BaseAnalysisAgent does NOT implement `_handle_request` - it remains abstract

## Schema Patterns with to_schema and typed_dict

AuditZoo uses `to_schema` and `typed_dict` helpers to generate JSON schemas for response validation.

Schema validation is optional.

### Basic Pattern

```python
from auditzoo.core.protocol.utils import to_schema, typed_dict
from typing_extensions import NotRequired

RESPONSE_SCHEMA = to_schema(typed_dict(
    required_field=str,
    optional_field=NotRequired[int],
    nested_list=list[dict[str, str]],
))

# Use in request
request = Request(
    type="task.my_task",
    payload={...},
    response_schema=RESPONSE_SCHEMA,
)
```

### Complex Nested Schemas

```python
from dataclasses import dataclass
from auditzoo.core.protocol.utils import to_schema, typed_dict
from typing_extensions import NotRequired

# When response contains dataclasses, use dataclass types directly
@dataclass
class FunctionInfo:
    name: str
    callers: list[str]

RESPONSE_SCHEMA = to_schema(typed_dict(
    results=list[FunctionInfo],
    message=NotRequired[str],
))
```

### Best Practices

1. **Define schemas in callee agent files**:
```python
# In my_agent.py (where handler is implemented)
MY_RESPONSE_SCHEMA = to_schema(typed_dict(...))

class MyAgent(BaseAnalysisAgent):
    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        # Implementation
        pass
```

2. **Import schemas in caller code**:
```python
# In caller code
from my_agent import MY_RESPONSE_SCHEMA

request = Request(
    type="task.my_task",
    payload={...},
    response_schema=MY_RESPONSE_SCHEMA,
)
```

3. **Use NotRequired for optional fields**:
```python
to_schema(typed_dict(
    required=str,
    optional=NotRequired[int],
))
```

4. **All nested structures must be dataclasses**:
```python
@dataclass
class NestedData:
    field: str

RESPONSE_SCHEMA = to_schema(typed_dict(
    nested=NestedData,
))
```

### Real-World Example

See [`auditzoo/core/agents/ir_storage_agent.py`](auditzoo/core/agents/ir_storage_agent.py) for complete examples:

```python
REQUEST_SCHEMAS = {
    "get_unit": to_schema(typed_dict(
        unit_id=str,
        fetch_backend=NotRequired[bool],
    )),
    "get_related_units": to_schema(typed_dict(
        unit_id=str,
        kind=RelationKind,
        direction=str,
        fetch_backend=NotRequired[bool],
    )),
}
```

## Backend System

### Backend Interface (`auditzoo/core/ir/backend_api.py`)

All backends implement the `CPGBackend` abstract interface:

```python
class CPGBackend(ABC):
    @abstractmethod
    async def connect(self) -> None:
        """Connect to backend"""

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from backend"""

    @abstractmethod
    def is_connected(self) -> bool:
        """Check connection status"""

    @abstractmethod
    async def query(self, query: str) -> Any:
        """Execute a backend-specific query"""
```

### Current Backends

**JoernBackend** (`auditzoo/backends/joern/`)
- Uses Joern's CPG for C/C++/Java/Python/JavaScript/Go
- Communicates via `cpgqls-client` (WebSocket-based query API)
- Supports Joern query language for complex graph queries

**TreeSitterBackend** (`auditzoo/backends/treesitter/`)
- Lightweight AST-based backend (work in progress)
- For languages not supported by Joern or when CPG is overkill

**Future**: CodeQL backend, custom backends

### Backend Auto-detection (`auditzoo/backends/ingestion.py`)

```python
config = auto_detect_backend(
    source_path="./project",
    language=None,         # Auto-detected if None
    prefer="joern"         # Preferred backend
)

# Returns BackendConfig (JoernConfig, TreeSitterConfig, etc.)
```

## Analysis Agents

Analysis agents live in `auditzoo/agents/` and implement specific analysis tasks.

### Adding New Agents

**Singleton agents**: Place directly under `auditzoo/agents/{category}/` (e.g., `auditzoo/agents/utility/my_agent.py`)

**Multi-agent systems with a single exposed agent**: Override `register_all()` to register internal agents so the runtime can register them implicitly.

```python
# auditzoo/agents/myanalysis/system/main_agent.py
class MainAgent(BaseAnalysisAgent):
    @classmethod
    async def register_all(cls, runtime: AgentRuntime, type: str, factory, **kwargs):
        # Register internal agents first
        await HelperAgent1.register_all(runtime, "helper1", lambda: HelperAgent1())
        await HelperAgent2.register_all(runtime, "helper2", lambda: HelperAgent2())

        # Register self
        return await super().register_all(runtime, type, factory, **kwargs)
```

See [auditzoo/agents/README.md](auditzoo/agents/README.md) for available agents.

## Advanced Topics

### Extending the IR Model: Supporting Different IR Operations

For advanced use cases, you may need to support different IR operations that go beyond the built-in code unit and relation kinds. AuditZoo provides extensibility points for this.

#### Custom CodeUnitKind

To add a new kind of code unit (e.g., for a new IR node type):

```python
from dataclasses import dataclass
from auditzoo.core.ir.model.base import CodeUnitKind, CodeUnit, CodeLocation

@dataclass(frozen=True)
class CustomIRNode(CodeUnitKind):
    """Custom IR node kind for specialized analysis."""

    # Add any kind-specific fields here
    custom_field: str = "default_value"

    async def fetch_backend(self, backend: CPGBackend) -> list[CodeUnit]:
        """Define how to fetch these units from the backend."""
        if backend.backend_type != "joern":
            raise IRUnimplementedError(
                f"CustomIRNode not implemented for {backend.backend_type}"
            )

        # Write backend-specific query
        query = "cpg.myCustomNode.toJson"
        response = await backend.query(query)
        return await self.parse(response, backend)

    async def parse(self, raw_data: Any, backend: CPGBackend) -> list[CodeUnit]:
        """Parse backend response into CodeUnit instances."""
        units = []
        for raw in raw_data:
            unit = CodeUnit.from_cpg(
                cpg_node_id=str(raw["_id"]),
                kind=self,
                code=raw["code"],
                name=raw["name"],
                location=CodeLocation(
                    file_path=raw["filename"],
                    line_start=raw["lineNumber"],
                    line_end=raw["lineNumberEnd"],
                ),
                # Add custom metadata
                custom_metadata=raw.get("customField")
            )
            units.append(unit)
        return units
```

**Auto-registration**: The `__init_subclass__` mechanism in `CodeUnitKind` automatically registers your new kind. Access it via:

```python
from auditzoo.core.ir.model import UKRegistry

# Create instance
custom_kind = UKRegistry.CustomIRNode(custom_field="value")

# Use in queries
units = await ir_view.get_all_units_by_kind(custom_kind)
```

#### Custom RelationKind

To add a new kind of relation (e.g., for a new edge type in your IR):

```python
from dataclasses import dataclass
from auditzoo.core.ir.model.base import RelationKind, CodeUnit, CodeUnitRelation

@dataclass(frozen=True)
class CustomRelation(RelationKind):
    """Custom relation kind for specialized IR edges."""

    # Add relation-specific fields
    relation_attribute: str = "default"

    def _to_kwargs(self) -> dict[str, Any]:
        """Serialize instance fields for storage."""
        return {"relation_attribute": self.relation_attribute}

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        """Deserialize instance from storage."""
        return cls(relation_attribute=kwargs.get("relation_attribute", "default"))

    async def fetch_backend(
        self,
        source_unit: CodeUnit,
        direction: RelationDirection,
        backend: CPGBackend,
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        """Fetch relations from backend."""
        if backend.backend_type != "joern":
            raise IRUnimplementedError(
                f"CustomRelation not implemented for {backend.backend_type}"
            )

        # Write direction-specific queries
        if direction == "out":
            query = f"cpg.node.id({source_unit.id}L).myCustomEdge.l.toJson"
        else:
            query = f"cpg.node.id({source_unit.id}L).myCustomEdgeIn.l.toJson"

        response = await backend.query(query)

        results = []
        for raw in response:
            # Parse target unit
            target_unit = await CodeUnitKind.parse_units(raw, backend)

            # Create relation with metadata
            relation = CodeUnitRelation(
                kind=self,
                edge_id=raw.get("edge_id"),
                confidence=raw.get("confidence", 1.0),
            )
            results.append((target_unit[0], relation))

        return results
```

**Auto-registration**: Your `RelationKind` is automatically registered via `__init_subclass__`. Access via:

```python
from auditzoo.core.ir.model import RKRegistry

# Create instance
custom_rel = RKRegistry.CustomRelation(relation_attribute="value")

# Use in queries
neighbors = await ir_view.get_related_units(
    unit_id="123",
    kind=custom_rel,
    direction="out"
)
```

#### Best Practices for IR Extensions

1. **Inherit from base classes**: Always inherit from `CodeUnitKind` or `RelationKind`
2. **Use `@dataclass(frozen=True)`**: Kinds should be immutable
3. **Implement backend-specific logic**: Handle different backends in `fetch_backend()` and `parse()`
4. **Add proper error handling**: Raise `IRUnimplementedError` for unsupported backends
5. **Document your extensions**: Add docstrings explaining the purpose and usage
6. **Test with multiple backends**: Ensure your extensions work across different backend types

### Facts and Analysis Results

Facts are the recommended way to attach analysis results to the IR without modifying the core model.

#### Creating a UnitFact

```python
from auditzoo.core.ir.facts import UnitFact
from dataclasses import dataclass

@dataclass
class TaintStatus(UnitFact):
    """Indicates if a code unit is tainted."""
    is_tainted: bool
    source: str | None = None

    def to_backend(self) -> dict:
        """Serialize for backend storage."""
        return {
            "is_tainted": self.is_tainted,
            "source": self.source,
        }

    @classmethod
    def from_backend(cls, data: dict) -> "TaintStatus":
        """Deserialize from backend."""
        return cls(
            is_tainted=data["is_tainted"],
            source=data.get("source")
        )

# Attach to unit
await ir_view.add_unit_fact(unit_id="func_123", fact=TaintStatus(is_tainted=True, source="user_input"))

# Retrieve
facts = await ir_view.get_unit_facts(unit_id="func_123", fact_type=UFRegistry.TaintStatus)
```

#### Creating a RelationFact

```python
from auditzoo.core.ir.facts import RelationFact
from dataclasses import dataclass

@dataclass
class DataFlowPath(RelationFact):
    """Represents a data flow path between units."""
    confidence: float
    intermediate_nodes: list[str]

    def to_backend(self) -> dict:
        return {
            "confidence": self.confidence,
            "intermediate_nodes": self.intermediate_nodes,
        }

    @classmethod
    def from_backend(cls, data: dict) -> "DataFlowPath":
        return cls(
            confidence=data["confidence"],
            intermediate_nodes=data["intermediate_nodes"]
        )

# Attach between units
await ir_view.add_relation_fact(
    source_id="func_123",
    target_id="func_456",
    fact=DataFlowPath(confidence=0.95, intermediate_nodes=["var_x", "var_y"])
)
```

### Multi-Agent Collaboration

Agents can send messages to other agents to build complex workflows:

```python
from taint_analyzer import TAINT_RESPONSE_SCHEMA
from vuln_scanner import VULN_RESPONSE_SCHEMA

class OrchestratorAgent(BaseAnalysisAgent):
    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        # Send sub-task to another agent with validation
        taint_response = await self.send_message(
            Request(
                type="task.taint_analysis",
                payload={...},
                response_schema=TAINT_RESPONSE_SCHEMA
            ),
            AgentId("taint_analyzer", "default")
        )

        vuln_response = await self.send_message(
            Request(
                type="task.vuln_scan",
                payload={...},
                response_schema=VULN_RESPONSE_SCHEMA
            ),
            AgentId("vuln_scanner", "default")
        )

        # Combine results
        combined = self._combine_results(taint_response.data, vuln_response.data)
        return Response.ok(data=combined)
```

## Contributing

We welcome contributions! AuditZoo is at a very early stage, and there are many opportunities to improve and extend the framework.

### Contribution Guidelines

#### PR Requirements

**IMPORTANT**: When submitting pull requests:

1. **Separate core changes from application changes**
   - PRs should NOT mix changes in `auditzoo/core/` with changes in other directories
   - Core infrastructure changes should be in separate PRs from analysis implementations
   - This keeps core changes reviewable and ensures stability

2. **Good PR structure:**
   - ✅ PR 1: Add new `CodeUnitKind` in `core/ir/model/unit_kinds/`
   - ✅ PR 2: Implement new analysis agent in `auditzoo/agents/`
   - ❌ Single PR: Both of the above

3. **Code quality:**
   - Follow existing code style (Black, Ruff, isort)
   - Add type hints
   - Write tests for new functionality
   - Update documentation

4. **Testing:**
   - Run tests: `pytest tests/`
   - Check types: `mypy auditzoo/`
   - Format code: `black auditzoo/ && isort auditzoo/`
   - Lint: `ruff check auditzoo/`

### Development Setup

```bash
# Clone repository
git clone https://github.com/Biscope-AI/auditzoo.git
cd auditzoo

# Install in development mode with dev dependencies
bash install-dev.sh

# Or manually:
conda create -n auditzoo-dev python=3.10 openjdk=17 -y
conda activate auditzoo-dev
pip install -r requirements-dev.txt
pip install -e .

# Set up pre-commit hooks
pre-commit install
```

### Areas for Contribution

1. **New Analysis Agents**: Implement analyses in `auditzoo/agents/`
2. **Backend Support**: Add support for new backends (CodeQL, LLVM, etc.)
3. **IR Extensions**: Add new `CodeUnitKind` or `RelationKind` for your domain
4. **Documentation**: Improve docs, add examples, write tutorials
5. **Testing**: Expand test coverage, add integration tests
6. **Performance**: Optimize IR graph operations, query performance

### Questions?

- Open an issue on [GitHub](https://github.com/Biscope-AI/auditzoo/issues)
- Reach out to the maintainers
- Check the examples in `examples/`

---

**Happy hacking!** 🚀
