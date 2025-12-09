# AuditZoo

**CPG-centered, agent-based program analysis framework built on Joern and AutoGen-Core**

AuditZoo is a unified infrastructure for building and composing program analyses. It uses Joern's Code Property Graph (CPG) as the foundation and stores all analysis results as CPG Tags for persistent, queryable storage.

## Key Features

- **CPG-Centered**: Built on Joern's Code Property Graph - no abstraction layers
- **Direct Query Access**: Write CPG queries directly for maximum flexibility
- **Persistent Facts**: All analysis results stored as CPG Tags
- **Analysis Agents**: Composable primitives and detectors using AutoGen-Core
- **Multi-Language**: Supports all Joern languages (C/C++, Java, JavaScript/TypeScript, Python, Go, Kotlin)
- **TreeSitter Fallback**: Minimal support for languages not supported by Joern

## Architecture

AuditZoo has two phases:

1. **Preprocessing**: Generate CPG from source code using Joern (or TreeSitter for unsupported languages)
2. **Analysis**: Run analysis agents that query CPG and store facts as tags

**Design Philosophy**: The CPG database is the single source of truth for both program structure and analysis results. No separate fact database - everything is CPG tags.

See [docs/auditzoo_spec.md](docs/auditzoo_spec.md) for detailed architecture.

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/auditzoo
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
import os
from auditzoo.core.ir.model import ProgramId
from auditzoo.backends.base import JoernConfig
from auditzoo.backends.joern.backend import JoernBackend
from auditzoo.core.ir.view import IRView

async def main():
    # Configure Joern backend
    config = JoernConfig(
        language="c",
        joern_path=os.path.join(os.environ.get('CONDA_PREFIX', '/opt'), 'opt/joern'),
        db_path="./project.cpg"
    )

    # Create backend and connect
    backend = JoernBackend(config)
    await backend.connect()

    # Create IR view
    program_id = ProgramId("my_project")
    ir_view = IRView(backend, program_id)

    # Get all functions
    functions = await ir_view.get_functions()
    for func in functions:
        print(f"Function: {func.name} at {func.file}:{func.start_line}")

    # Direct CPG query
    result = await ir_view.cpg_query("""
        cpg.method.name("main").callOut.map { call =>
            Map("name" -> call.name, "location" -> call.location)
        }.toJson
    """)
    print(f"Calls from main: {result}")

    await backend.disconnect()

asyncio.run(main())
```

## Language Support

| Language | Backend | Features |
|----------|---------|----------|
| C/C++ | Joern | ✅ Full (CFG, dataflow, taint, call graph) |
| Java | Joern | ✅ Full |
| JavaScript/TypeScript | Joern | ✅ Full |
| Python | Joern | ✅ Full |
| Go | Joern | ✅ Full |
| Kotlin | Joern | ✅ Full |
| Rust | TreeSitter | ⚠️ Limited (AST, basic call graph only) |
| Ruby | TreeSitter | ⚠️ Limited |
| Others | TreeSitter | ⚠️ Limited (if grammar available) |

## Project Structure

```
auditzoo/
├── core/
│   ├── ir/              # CPG wrapper (model, backend API, view)
│   ├── agents/          # Core infrastructure agents
│   ├── protocol/        # Message types and envelopes
│   └── runtime/         # AutoGen-Core runtime integration
├── backends/
│   ├── joern/           # Joern CPG backend (primary)
│   ├── treesitter/      # TreeSitter fallback backend
│   └── ingestion.py     # Backend selection and CPG creation
├── contracts/
│   ├── facts.py         # Fact types (serialize to CPG tags)
│   └── capabilities.py  # Agent capability schemas
├── sdk/
│   ├── base_agent.py    # Base class for analysis agents
│   ├── context.py       # Analysis context helper
│   └── registry.py      # Agent registration
└── analyses/
    ├── primitives/      # Primitive analyses (slicing, taint, etc.)
    └── detectors/       # High-level detectors (buffer overflow, etc.)
```

## Documentation

- **[INSTALL.md](INSTALL.md)** - Installation guide for users
- **[DEVELOP.md](DEVELOP.md)** - Development setup and contributing
- **[docs/auditzoo_spec.md](docs/auditzoo_spec.md)** - Complete architecture specification

## Development Status

**Current Status:**
- ✅ CPG-centered architecture designed
- ✅ Core IR components (CPGBackend, IRView, tag management)
- ✅ Fact serialization framework
- ✅ AutoGen-Core integration (agents, runtime)
- ⚠️ Joern backend (partial - needs full implementation)
- ❌ TreeSitter backend (not started)
- ✅ Example analysis structure

**Next Steps:**
1. Complete Joern backend with full CPG query support
2. Implement TreeSitter CPG emulator
3. Update core agents for new IR
4. Add more example analyses
5. Write comprehensive documentation

## Contributing

We welcome contributions! See [DEVELOP.md](DEVELOP.md) for development setup and guidelines.

Quick development setup:
```bash
git clone https://github.com/your-username/auditzoo
cd auditzoo
./install-dev.sh
conda activate auditzoo-dev
```

## License

[To be determined]

## Acknowledgments

- **Joern**: https://joern.io - Code Property Graph framework
- **AutoGen-Core**: https://github.com/microsoft/autogen - Multi-agent framework
- **TreeSitter**: https://tree-sitter.github.io - Parsing library
