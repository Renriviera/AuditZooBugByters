#!/usr/bin/env python3
"""Example: Find all callers of a specific function.

This example demonstrates:
1. Creating a custom analysis agent (CallerFinderAgent)
2. Using AnalysisRuntime to orchestrate backend and agents
3. Sending task requests and processing responses
4. Formatting and displaying results

Usage:
    python examples/find_callers.py <project_path> <function_name>

Example:
    python examples/find_callers.py ./my_project malloc
"""

import asyncio
import sys
from pathlib import Path
from typing import Any

from autogen_core import AgentId, MessageContext, message_handler

from auditzoo.backends.base import JoernConfig
from auditzoo.backends.ingestion import auto_detect_backend
from auditzoo.core.agents import BaseAnalysisAgent
from auditzoo.core.protocol.requests import TaskRequest
from auditzoo.core.protocol.responses import Response
from auditzoo.core.runtime import AnalysisRuntime


class CallerFinderAgent(BaseAnalysisAgent):
    """Analysis agent that finds all callers of a given function.

    This agent:
    1. Receives a task request with function name
    2. Searches for all functions with matching name
    3. For each match, finds all callers using IR relations
    4. Returns results with caller information
    """

    def __init__(self) -> None:
        """Initialize CallerFinderAgent.

        Note: ir_storage_agent_id is injected by runtime during registration.

        Args:
            description: Agent description
        """
        super().__init__("Finds all callers of a given function")

    @message_handler
    async def handle_task(self, message: TaskRequest, ctx: MessageContext) -> Response:
        """Handle find_callers task requests.

        Args:
            message: TaskRequest with type="find_callers" and payload containing:
                - function_name: str - Name of function to find callers for
            ctx: Message context from AutoGen

        Returns:
            Response with caller information or error
        """
        # Only handle find_callers tasks
        if message.type != "task.find_callers":
            return Response(success=False, error=f"Unknown task type: {message.type}")

        # Extract function name from request
        function_name = message.payload.get("function_name")
        if not function_name:
            return Response(success=False, error="Missing 'function_name' in payload")

        try:
            # Step 1: Get all functions from IR
            all_functions = await self.get_functions(ctx)

            # Step 2: Find functions matching the name
            matching_functions = [
                func for func in all_functions if function_name in func.name
            ]

            if not matching_functions:
                return Response(
                    success=True,
                    data={
                        "function_name": function_name,
                        "matches": [],
                        "message": f"No functions found matching '{function_name}'",
                    },
                )

            # Step 3: For each matching function, find its callers
            results = []
            for func in matching_functions:
                func_id = func.id

                # Get callers using BaseAnalysisAgent sugar method
                callers = await self.get_callers(func_id, ctx)
                caller_infos = []

                for caller, relation in callers:
                    caller_infos.append(
                        {
                            "caller_name": caller.name,
                            "callsite": relation.metadata.get("callsite_code"),
                        }
                    )

                results.append(
                    {
                        "function_name": func.name,
                        "callers": caller_infos,
                    }
                )

            return Response(success=True, data={"results": results})

        except Exception as e:
            return Response(success=False, error=f"Analysis failed: {e}")


def format_results(response_data: dict[str, Any] | None) -> None:
    """Format and print analysis results in a readable way.

    Args:
        response_data: Response data from CallerFinderAgent with format:
            {
                "results": [
                    {
                        "function_name": "malloc",
                        "callers": [
                            {"caller_name": "foo", "callsite": "ptr = malloc(10);"},
                            ...
                        ]
                    },
                    ...
                ]
            }
    """
    if not response_data:
        print("\nNo data returned from analysis.")
        return

    # Handle case where no matches were found
    if "message" in response_data:
        print(f"\n{response_data['message']}")
        return

    results = response_data.get("results", [])

    if not results:
        print("\nNo matching functions found.")
        return

    # Print header
    print("\n" + "=" * 80)
    print("CALLER ANALYSIS RESULTS")
    print("=" * 80)

    # Total statistics
    total_callers = sum(len(r["callers"]) for r in results)
    print(
        f"\nFound {len(results)} matching function(s) with {total_callers} total caller(s)\n"
    )

    # Print each matching function
    for idx, result in enumerate(results, 1):
        function_name = result["function_name"]
        callers = result["callers"]

        # Function header
        print(f"\n[{idx}] Function: {function_name}")
        print(f"    Callers: {len(callers)}")

        if callers:
            print("\n    Called by:")
            for caller_info in callers:
                caller_name = caller_info["caller_name"]
                callsite = caller_info.get("callsite")

                if callsite:
                    # Format callsite (trim whitespace and limit length)
                    callsite_clean = callsite.strip()
                    if len(callsite_clean) > 60:
                        callsite_clean = callsite_clean[:57] + "..."

                    print(f"      • {caller_name}")
                    print(f"        └─ {callsite_clean}")
                else:
                    print(f"      • {caller_name}")
        else:
            print(
                "\n    (No callers found - this function is not called within the analyzed code)"
            )

        # Separator between functions
        if idx < len(results):
            print("\n    " + "-" * 70)

    print("\n" + "=" * 80 + "\n")


async def main(project_path: str, function_name: str) -> None:
    """Main entry point for the example.

    Args:
        project_path: Path to the project to analyze
        function_name: Name of the function to find callers for
    """
    # Validate project path
    if not Path(project_path).exists():
        print(f"Error: Project path does not exist: {project_path}")
        sys.exit(1)

    print(f"Analyzing project: {project_path}")
    print(f"Finding callers of: {function_name}")
    print("\nInitializing runtime...")

    # Create backend configuration
    # This uses Joern backend by default
    config = auto_detect_backend(project_path)
    if not isinstance(config, JoernConfig):
        print("Error: This example currently only supports Joern backend.")
        sys.exit(1)

    config.port = 9000  # Use default Joern port

    # Use AnalysisRuntime with async context manager
    async with AnalysisRuntime(config) as runtime:
        print("Runtime initialized successfully!")

        # Register our custom CallerFinderAgent
        print("Registering CallerFinderAgent...")
        await runtime.register_agent(
            agent_type=CallerFinderAgent,
            agent_name="caller_finder",
            agent_factory=lambda: CallerFinderAgent(),
        )

        # start the runtime
        print("Starting analysis runtime...")
        runtime.start()

        # Send task request to our agent
        print(f"\nSearching for function '{function_name}' and its callers...")

        response = await runtime.send_message(
            request=TaskRequest(
                type="find_callers", payload={"function_name": function_name}
            ),
            target=AgentId("caller_finder", "default"),
        )

        # Check if analysis succeeded
        if not response.success:
            print(f"\nError: {response.error}")
            sys.exit(1)

        # Format and display results
        format_results(response.data)


if __name__ == "__main__":
    # Parse command line arguments
    if len(sys.argv) != 3:
        print("Usage: python find_callers.py <project_path> <function_name>")
        print("\nExample:")
        print("  python find_callers.py ./my_c_project malloc")
        print("  python find_callers.py ./src strcmp")
        sys.exit(1)

    project_path = sys.argv[1]
    function_name = sys.argv[2]

    # Run the async main function
    asyncio.run(main(project_path, function_name))
