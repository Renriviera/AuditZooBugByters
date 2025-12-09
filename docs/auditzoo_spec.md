# AuditZoo – CPG-Centered Architecture Specification

## 0. Purpose and Vision

AuditZoo is a **CPG-centered, agent-based program analysis framework** built on Joern and AutoGen-Core.

High-level goals:

* Use **Joern's Code Property Graph (CPG)** as the foundational IR for all supported languages
* Store all **derived analysis information** (facts, issues, annotations) as **CPG Tags** for persistent storage
* Let multiple teams build their own **analysis agents** ("the Zoo"), both primitive (e.g., points-to, slicing) and high-level (e.g., buffer-overflow detectors, access-control checkers)
* Make it easy to **add, combine, and reuse** analyses without race conditions or tight coupling
* Allow the system to **spawn new agent instances dynamically**, based on a type-id/instance-id naming convention
* **TreeSitter as fallback**: For languages not supported by Joern, provide a minimal CPG-compatible interface via TreeSitter

**Key Design Decision**: The IR is not an abstraction layer – it's a **wrapper around Joern's CPG** that provides both convenience methods and direct CPG query access. All facts are stored as CPG Tags, making the CPG the single on-disk storage format.

---

## 1. Architecture Overview

### 1.1 Two Phases

1. **Preprocessing (no agents)**
   * Use Joern to generate CPG from source code
   * For unsupported languages, use TreeSitter to build a minimal CPG-compatible representation
   * Create IR view objects that wrap the CPG
   * This phase is library code, not agents

2. **Analysis (agents via AutoGen-Core)**
   * Start an AutoGen-Core runtime
   * Register core infrastructure agents and analysis agents
   * Send messages to perform analyses, store facts, and produce issue reports
   * All facts are serialized as CPG Tags and persisted to the CPG database

### 1.2 Package Structure

* `auditzoo.core` – runtime plumbing, CPG IR wrapper, infrastructure agents, protocols
* `auditzoo.backends` – Joern integration and TreeSitter fallback
  * `joern/` – Primary backend using Joern CPG
  * `treesitter/` – Fallback that emulates Joern server for unsupported languages
  * **No LSP backend**
* `auditzoo.contracts` – shared semantic schemas (facts that serialize to CPG Tags)
* `auditzoo.sdk` – what analysis authors use to implement and register agents
* `auditzoo.analyses` – built-in analyses
  * `auditzoo.analyses.primitives` – low-level analyses (slicing, taint, etc.)
  * `auditzoo.analyses.detectors` – high-level issue detectors

---

## 2. CPG-Centered IR Design

### 2.1 IR as CPG Wrapper

The IR is **not** a language-neutral abstraction. It is a **thin wrapper** around Joern's CPG that:

1. **Exposes CPG directly** – Analyses can execute arbitrary CPG queries
2. **Provides convenience methods** – Common operations (get functions, get CFG) are pre-built
3. **Manages custom facts as CPG Tags** – All semantic information is serialized and stored as Tags
4. **Handles both Joern and TreeSitter** – Unified interface, but TreeSitter provides limited functionality

### 2.2 CPG Query Access

All analyses have direct access to CPG queries:

```python
# Direct CPG query
result = await ir_view.cpg_query("""
    cpg.method.name("authenticate").callIn.map { call =>
        Map("caller" -> call.method.name, "location" -> call.location)
    }.toJson
""")

# Convenience method (wraps common CPG query)
functions = await ir_view.get_functions(program_id)
```

### 2.3 Custom Facts as CPG Tags

**All facts are stored as CPG Tags**. This provides:

* **Persistent storage**: Facts survive across sessions
* **Single source of truth**: CPG database contains both structure and analysis results
* **Query integration**: Can query CPG nodes by tags

Fact classes must implement:

```python
@dataclass
class Fact(ABC):
    """Base class for all facts - must be serializable to CPG Tag."""

    @abstractmethod
    def to_tag(self) -> dict:
        """Serialize fact to CPG Tag format (JSON-compatible dict)."""
        pass

    @classmethod
    @abstractmethod
    def from_tag(cls, tag_data: dict) -> "Fact":
        """Deserialize fact from CPG Tag data."""
        pass
```

Example:

```python
@dataclass
class TaintFact(Fact):
    cpg_source_id: str  # CPG node ID
    cpg_sink_id: str    # CPG node ID
    path_node_ids: List[str]  # CPG node IDs along path
    taint_kind: str

    def to_tag(self) -> dict:
        return {
            "type": "taint",
            "source": self.cpg_source_id,
            "sink": self.cpg_sink_id,
            "path": self.path_node_ids,
            "kind": self.taint_kind
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "TaintFact":
        return cls(
            cpg_source_id=tag_data["source"],
            cpg_sink_id=tag_data["sink"],
            path_node_ids=tag_data["path"],
            taint_kind=tag_data["kind"]
        )
```

The IR provides methods to:
* Attach tags to CPG nodes
* Query nodes by tags
* List all tags of a specific type

### 2.4 Language Support Strategy

**Joern-supported languages** (C/C++, Java, JavaScript/TypeScript, Python, Go, Kotlin):
* Full CPG available
* All analyses work
* Tags stored in Joern database

**TreeSitter-supported languages** (anything else):
* TreeSitter builds AST
* Minimal CPG emulation:
  * Methods/functions
  * Call graph (basic)
  * AST nodes as CPG nodes
  * In-memory tag storage (can export to JSON)
  * **No**: dataflow, control flow, complex semantic queries
* Analyses must degrade gracefully

---

## 3. Core Modules

### 3.1 `core/ir/` – CPG IR Wrapper

* `model.py`
  * `CPGView` – Main interface to CPG
  * Minimal identifier types (ProgramId, FunctionId) for convenience
  * CPG node references (strings of CPG node IDs)

* `backend_api.py`
  * `CPGBackend` interface (replaces IRBackend)
  * Methods for CPG queries
  * Methods for tag management (add_tag, get_tags, query_by_tag)
  * Both Joern and TreeSitter implement this

* `view.py`
  * `IRView` – Wraps CPGBackend, provides caching
  * Direct `cpg_query()` method
  * Convenience methods for common operations
  * Tag management methods

### 3.2 `backends/` – Joern and TreeSitter

#### `backends/joern/`

* `client.py`
  * Low-level Joern client
  * CPG query execution
  * CPG database management
  * Tag operations (add/query/list tags)

* `backend.py`
  * `JoernBackend` – Implements CPGBackend
  * Direct CPG query passthrough
  * Convenience method implementations using CPG queries
  * Tag serialization to CPG database

#### `backends/treesitter/`

* `parser.py`
  * TreeSitter parsing per language
  * AST to minimal CPG conversion

* `backend.py`
  * `TreeSitterBackend` – Implements CPGBackend
  * Emulates Joern query interface
  * Limited functionality (methods, calls, AST only)
  * Returns errors for unsupported operations
  * In-memory tag storage

* `cpg_emulator.py`
  * In-memory CPG-like structure
  * Responds to basic CPG queries
  * Maps TreeSitter AST to CPG nodes
  * In-memory tag store

#### `backends/ingestion.py`

* Auto-detection: Joern vs TreeSitter
* CPG creation and loading
* IRView construction

**No LSP backend** – Completely removed from design

### 3.3 `contracts/facts.py` – CPG Tag-Serializable Facts

All fact types must:
1. Reference CPG nodes by ID
2. Implement `to_tag()` and `from_tag()` for serialization
3. Use JSON-compatible types only

```python
class Fact(ABC):
    """Base class for all facts."""

    @abstractmethod
    def to_tag(self) -> dict:
        """Serialize to CPG Tag (JSON-compatible dict)."""
        pass

    @classmethod
    @abstractmethod
    def from_tag(cls, tag_data: dict) -> "Fact":
        """Deserialize from CPG Tag."""
        pass


@dataclass
class PointsToFact(Fact):
    cpg_pointer_id: str  # CPG node ID
    cpg_target_ids: List[str]  # CPG node IDs
    context: Optional[str] = None

    def to_tag(self) -> dict:
        return {
            "type": "points_to",
            "pointer": self.cpg_pointer_id,
            "targets": self.cpg_target_ids,
            "context": self.context
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "PointsToFact":
        return cls(
            cpg_pointer_id=tag_data["pointer"],
            cpg_target_ids=tag_data["targets"],
            context=tag_data.get("context")
        )
```

### 3.4 Core Agents

* `ir_store.py` – IRStoreAgent
  * Stores CPGView objects (which wrap CPG with tags)
  * Fact operations translate to tag operations
  * All facts persisted to CPG

* `task_router.py` – TaskRouterAgent (unchanged)
* `plugin_registry.py` – PluginRegistryAgent (unchanged)
* `dependency_mgr.py` – DependencyManagerAgent (unchanged)

All agents interact with CPG through IRView, not directly.

---

## 4. Analysis Agent Interface

### 4.1 SDK

`AnalysisContext` now provides:

```python
# Get CPG view
cpg_view = await context.get_cpg_view(program_id)

# Direct CPG query
result = await cpg_view.cpg_query("...")

# Convenience methods
functions = await cpg_view.get_functions()

# Facts (stored as CPG tags)
facts = await context.get_facts(program_id, fact_types=[...])
await context.add_facts(program_id, [fact1, fact2])  # Serializes to tags
```

### 4.2 Writing Analyses

Analyses can:

1. **Use convenience methods** for common operations
2. **Write CPG queries** for complex analysis
3. **Store custom facts** that serialize to CPG tags
4. **Check backend capabilities** and degrade gracefully

Example:

```python
async def handle_task(self, task: TaskEnvelope, context: AnalysisContext):
    cpg_view = await context.get_cpg_view(task.program_id)

    # Check if backend supports dataflow
    if cpg_view.supports_dataflow():
        # Use CPG dataflow queries
        result = await cpg_view.cpg_query("""
            cpg.method.name("foo").parameter.reachableBy(...)
        """)
    else:
        # Fallback for TreeSitter
        # Use only AST-based analysis
        functions = await cpg_view.get_functions()

    # Create fact and store as CPG tag
    fact = TaintFact(
        cpg_source_id="node123",
        cpg_sink_id="node456",
        path_node_ids=["node123", "node200", "node456"],
        taint_kind="sql_injection"
    )
    await context.add_facts(task.program_id, [fact])
```

---

## 5. CPG Tag Storage

### 5.1 Joern Tag Storage

Joern supports custom tags on CPG nodes. AuditZoo uses this to store facts:

```scala
// Add tag to CPG node
cpg.method.name("foo").newTagNode("taint", """{"type": "taint", ...}""")

// Query by tag
cpg.method.tag.nameExact("taint").node
```

The JoernBackend handles:
* Serializing facts to JSON
* Storing as tags with fact type as tag name
* Querying and deserializing tags back to facts

### 5.2 TreeSitter Tag Storage

TreeSitter backend maintains in-memory tag store:

```python
# In-memory mapping: node_id -> list of tags
tags: Dict[str, List[dict]] = {}
```

Can export to JSON for persistence.

---

## 6. Implementation Priorities

1. **Core IR redesign**
   * New CPGBackend interface with tag management
   * CPGView wrapper with direct query access
   * CPG node-based identifiers

2. **Fact serialization framework**
   * Update Fact base class with to_tag/from_tag
   * Update all fact types
   * IRStoreAgent manages tags

3. **Joern backend**
   * Full CPG query support
   * Tag storage via Joern API
   * Multi-language support

4. **TreeSitter fallback**
   * CPG emulation layer
   * Basic query support
   * In-memory tag storage
   * Graceful degradation

5. **Remove LSP**
   * Delete all LSP code
   * Remove from documentation

6. **Update agents and SDK**
   * IRStoreAgent handles tags
   * AnalysisContext exposes CPG
   * Update example analyses

---

## 7. Design Principles

1. **CPG is the IR** – Don't abstract away from CPG, embrace it
2. **Direct query access** – Analyses should write CPG queries when needed
3. **Joern first** – Optimize for Joern-supported languages
4. **Graceful degradation** – TreeSitter provides minimal functionality
5. **Facts are Tags** – All facts serialize to CPG tags for persistent storage
6. **Single on-disk format** – CPG database is the only storage (no separate fact DB)
7. **No LSP** – Removed completely

---

## 8. Coding Agent Instructions

When implementing this design:

1. **Replace IRBackend with CPGBackend**
   * Add `cpg_query()` method as primary interface
   * Add `add_tag()`, `get_tags()`, `query_by_tag()` methods
   * Keep convenience methods but implement them via CPG queries

2. **Update IR model**
   * Remove custom node types (use CPG node IDs directly)
   * Keep minimal identifiers (ProgramId, FunctionId) for convenience
   * Add CPG node reference type (string IDs)

3. **Implement fact serialization**
   * Update Fact base class with `to_tag()` and `from_tag()` abstract methods
   * Update all fact types to serialize/deserialize to JSON-compatible dicts
   * Ensure all facts reference CPG nodes by ID strings

4. **Implement Joern backend**
   * Direct CPG query passthrough
   * All convenience methods via CPG queries
   * Tag storage via Joern tag API

5. **Implement TreeSitter emulation**
   * Minimal CPG structure
   * Basic query parser
   * In-memory tag storage
   * Clear error messages for unsupported operations

6. **Delete all LSP code**
   * Remove `backends/lsp/` entirely
   * Remove LSP from ingestion
   * Remove LSP from documentation

7. **Update agents**
   * IRStoreAgent stores/retrieves facts as tags
   * Keep other agents unchanged

8. **Delete old docs**
   * Remove all migration guides
   * Remove LSP references
   * Keep only CPG-centered documentation

This spec defines a CPG-centered architecture where the CPG database is the single source of truth for both program structure and analysis results (stored as tags).
