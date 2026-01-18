# AuditZoo

AuditZoo is a CPG-centered, agent-based program analysis framework built on Joern and AutoGen-Core. It provides a unified infrastructure for building and composing program analyses using lightweight agents that communicate through a flexible protocol.

## Installation

### Prerequisites
- Python 3.10+
- Conda (Miniconda or Anaconda)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Biscope-AI/auditzoo.git
cd auditzoo

# Run the installation script (installs AuditZoo + Joern in a conda environment)
bash install.sh

# Activate the environment
conda activate auditzoo
```

The installation script will:
- Create a conda environment with Python 3.10 and Java 17
- Install AuditZoo and its dependencies
- Download and install Joern
- Configure environment variables

## Usage

### Basic Example

```python
import asyncio
from auditzoo import AnalysisRuntime, UKRegistry, auto_detect_backend, Request

async def main():
    # Auto-detect backend configuration
    config = auto_detect_backend("./my_project")

    # Initialize runtime (connects to backend, loads IR)
    async with AnalysisRuntime(config) as runtime:
        # Send IR queries
        response = await runtime.send_message(
            Request(type="ir.get_all_units_by_kind", payload={"kind": UKRegistry.Function()}),
            runtime.ir_agent_id
        )

        functions = response.unwrap()["units"]
        print(f"Found {len(functions)} functions")

asyncio.run(main())
```

### Creating Custom Analysis Agents

AuditZoo allows you to create custom analysis agents that can query the IR and perform complex analyses:

```python
from autogen_core import MessageContext, AgentId
from auditzoo import BaseAnalysisAgent, Request, Response

class MyAnalysisAgent(BaseAnalysisAgent):
    def __init__(self):
        super().__init__("My custom analysis agent")

    async def _handle_request(self, message: Request, ctx: MessageContext) -> Response:
        if message.type != "task.my_analysis":
            return Response.fail("Unknown task type")

        # Use sugar methods to access IR
        functions = await self.get_functions(ctx)

        # Perform analysis...
        results = []
        for func in functions:
            callers = await self.get_callers(func.id, ctx)
            # ... analyze ...

        return Response.ok(data={"results": results})

# Register and use the agent
async with AnalysisRuntime(config) as runtime:
    await runtime.register_agent(
        agent_type=MyAnalysisAgent,
        agent_name="my_analyzer",
        agent_factory=lambda: MyAnalysisAgent()
    )
    runtime.start()

    # Send task to your agent
    response = await runtime.send_message(
        Request(type="task.my_analysis", payload={}),
        AgentId("my_analyzer", "default")
    )
```

See [examples/find_callers.py](examples/find_callers.py) for a complete working example.

## Key Concepts

- **Runtime**: Manages backend connections, IR storage, and agent lifecycle
- **Agents**: Lightweight workers that handle specific analysis tasks
  - `IRStorageAgent`: Manages the IR graph (CRUD operations)
  - `BaseAnalysisAgent`: Base class for custom analysis agents
- **Protocol**: Request/Response messaging for agent communication
  - `Request`: Universal message class for all agent communication
    - IR operations: type="ir.*" (get units, relations, facts)
    - Analysis tasks: type="task.*" (performed by custom agents)
    - Queries: type="query.*" (quick searches and lookups)
  - Payload: Flexible dict for custom data structures
  - Optional response_schema for runtime validation
- **IR Model**: Code representation built on Code Property Graphs
  - `CodeUnit`: Represents code at any granularity (file, function, statement, etc.)
  - `CodeUnitRelation`: Relationships between units (calls, contains, etc.)
  - `Facts`: Analysis results attached to units or relations

## Development

> **Note**: If you want to contribute to or extend AuditZoo, please refer to [DEVELOPMENT.md](DEVELOPMENT.md) for detailed architecture documentation and development guidelines.

## Project Status

AuditZoo is at a very early stage of development. We welcome contributions and feedback!

Feel free to open pull requests, but please note:
- **IMPORTANT**: Any PR should NOT mix changes in `core/` and changes in other places. Keep core infrastructure changes separate from analysis implementations.

## License

AuditZoo is licensed under the [GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)](LICENSE).

This means:
- ✅ You can freely use, modify, and distribute this software
- ✅ Perfect for academic research and open-source projects
- ⚠️ If you run a modified version as a network service (e.g., SaaS, web application), you **must** make your source code available to users
- ⚠️ Any modifications or derivative works must also be licensed under AGPL-3.0

For commercial licensing options or if AGPL doesn't fit your use case, please contact us.

## Citation

If you use AuditZoo in your research, please cite:

```bibtex
@software{auditzoo,
  author = {Zhang, Zhuo},
  title = {AuditZoo: CPG-centered Agent-based Program Analysis Framework},
  year = {2025},
  url = {https://github.com/Biscope-AI/auditzoo}
}
```
