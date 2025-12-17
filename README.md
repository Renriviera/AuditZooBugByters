# AuditZoo

**CPG-centered, agent-based program analysis framework built on Joern and AutoGen-Core**

AuditZoo is a unified infrastructure for building and composing program analyses. It uses Joern's Code Property Graph (CPG) as the foundation and represents programs as a graph of `CodeUnit` objects with analysis results attached as `Facts`.

## Key Features

- **CPG-Centered**: Built on Joern's Code Property Graph
- **Graph-Based IR**: NetworkX graph of CodeUnits for flexible queries
- **Fact System**: Unit facts (per-node) and Relation facts (graph-level) for analysis results
- **Direct Query Access**: Write CPG queries directly for maximum flexibility
- **Analysis Agents**: Composable analyses using AutoGen-Core
- **Multi-Language**: Supports all Joern languages (C/C++, Java, JavaScript/TypeScript, Python, Go, Kotlin)

## Architecture

AuditZoo has two phases:

1. **Preprocessing**: Generate CPG from source code using Joern
2. **Analysis**: Run analysis agents that query CPG via IRView (NetworkX graph of CodeUnits)

**Design Philosophy**: The CPG is the source of truth for program structure. Analysis results are stored as Facts (both in-memory on CodeUnits and persisted to CPG tags).

See [docs/auditzoo_spec.md](docs/auditzoo_spec.md) for detailed architecture.

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/BiScope-AI/auditzoo
cd auditzoo

# Run automated installation
./install.sh

# Activate environment
conda activate auditzoo
```

**📋 Full installation guide**: [INSTALL.md](INSTALL.md)

### Basic Usage

```python
import asyncio
from auditzoo.backends.base import JoernConfig
from auditzoo.backends.joern.backend import JoernBackend
from auditzoo.core.ir.view import IRView
from auditzoo.core.ir.facts import SummaryFact, CallFact

async def main():
    # Configure Joern backend
    config = JoernConfig(
        language="c",
        source_path="./my_project",
        analysis_path="./analysis",
        joern_path="/opt/joern"
    )

    # Create backend and connect
    async with JoernBackend(config) as backend:
        # Create IR view (graph of CodeUnits)
        view = IRView(backend)

        # Load functions into graph
        functions = await view.get_all_functions()
        print(f"Loaded {len(functions)} functions")

        # Load call graph
        await view.load_call_graph()

        # Query the graph
        foo = view.get_function_by_signature("foo()")
        if foo:
            callers = view.get_callers(foo)
            callees = view.get_callees(foo)
            print(f"foo() has {len(callers)} callers and {len(callees)} callees")

        # Add analysis results as facts
        view.add_unit_fact(foo, SummaryFact(
            name="vulnerability",
            summary="Buffer overflow detected",
            details={"severity": "high", "cwe": "CWE-120"}
        ))

        # Add additional call edges
        view.add_relation_fact(CallFact(
            source_node_id="caller_id",
            target_node_id="callee_id",
            call_context="dynamic dispatch",
            confidence=0.8
        ))

        # Find all vulnerable units
        vulnerable = view.find_units_with_unit_fact("vulnerability")
        print(f"Found {len(vulnerable)} vulnerable functions")

asyncio.run(main())
```

## Core Concepts

### CodeUnit
A flexible unit of code at any granularity (file, class, function, statement). Each has:
- `id`: Unique identifier
- `unit_type`: Kind (FUNCTION, CLASS, FILE, etc.)
- `code`: Source code text
- `signature`: Human-readable name
- `location`: Source file and line numbers
- `cpg_node_id`: Link to CPG node (optional)

### IRView
NetworkX graph of CodeUnits with:
- **Nodes**: CodeUnits
- **Edges**: Relations (calls, data flow, inheritance)
- **Unit Facts**: Attached to individual nodes
- **Relation Facts**: Stored globally, connect two nodes

### Facts
Two types of facts for analysis results:

**Unit Facts** (attached to single CodeUnit):
- `SummaryFact`: General analysis results
- `CustomUnitFact`: Domain-specific annotations

**Relation Facts** (connect two CodeUnits):
- `CallFact`: Function call relationships
- `CustomRelationFact`: Custom relationships (dataflow, inheritance)

## Language Support

| Language | Backend | Features |
|----------|---------|----------|
| C/C++ | Joern | ✅ Full (CFG, dataflow, taint, call graph) |
| Java | Joern | ✅ Full |
| JavaScript/TypeScript | Joern | ✅ Full |
| Python | Joern | ✅ Full |
| Go | Joern | ✅ Full |
| Kotlin | Joern | ✅ Full |

## Project Structure

```
auditzoo/
├── core/
│   ├── ir/              # IR model, view, backend API, facts
│   ├── agents/          # Core infrastructure agents
│   ├── protocol/        # Message types and envelopes
│   └── runtime/         # AutoGen-Core runtime integration
├── backends/
│   ├── joern/           # Joern CPG backend
│   └── ingestion.py     # Backend setup
├── sdk/
│   ├── base_agent.py    # Base class for analysis agents
│   ├── context.py       # Analysis context helper
│   └── registry.py      # Agent registration
└── analyses/
    ├── primitives/      # Primitive analyses (slicing, taint, etc.)
    └── detectors/       # High-level detectors (buffer overflow, etc.)
```

## Documentation

- **[INSTALL.md](INSTALL.md)** - Installation guide
- **[DEVELOP.md](DEVELOP.md)** - Development setup
- **[docs/auditzoo_spec.md](docs/auditzoo_spec.md)** - Architecture specification

## Development Status

**Current Status:**
- ✅ CodeUnit model with mandatory IDs
- ✅ IRView with NetworkX graph
- ✅ Unit facts and Relation facts system
- ✅ Serializable graph updaters
- ✅ AutoGen-Core integration
- ⚠️ Joern backend (partial implementation)
- ⚠️ Analysis agents (under development)

## Contributing

We welcome contributions! See [DEVELOP.md](DEVELOP.md) for development setup.

Quick development setup:
```bash
git clone https://github.com/BiScope-AI/auditzoo
cd auditzoo
./install-dev.sh
conda activate auditzoo-dev
```

## License

[To be determined]

## Acknowledgments

- **Joern**: https://joern.io - Code Property Graph framework
- **AutoGen-Core**: https://github.com/microsoft/autogen - Multi-agent framework
- **NetworkX**: https://networkx.org - Graph library
