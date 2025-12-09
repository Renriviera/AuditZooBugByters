"""Example usage of AuditZoo framework.

This demonstrates how to use AuditZoo to analyze a program.
"""

import asyncio

import auditzoo
from auditzoo.backends.base import JoernConfig
from auditzoo.backends.ingestion import create_ir_view
from auditzoo.core.protocol.envelope import TaskEnvelope


async def main():
    """Example AuditZoo usage."""

    print("=== AuditZoo Example Usage ===\n")

    # Step 1: Create and initialize runtime
    print("1. Creating runtime...")
    runtime = await auditzoo.create_runtime()
    print("   ✓ Runtime created\n")

    # Step 2: Configure backend (Joern in this example)
    print("2. Configuring Joern backend...")
    config = JoernConfig(
        language="c",
        joern_path="/usr/local/bin/joern",  # Adjust to your Joern path
        db_path=None,  # Or specify path to existing CPG
    )
    print(f"   ✓ Backend configured: {config.backend_type}\n")

    # Step 3: Create IR view
    print("3. Creating IR view...")
    try:
        ir_view = await create_ir_view(config)
        print("   ✓ IR view created\n")
    except Exception as e:
        print(f"   ⚠ IR view creation failed (expected if Joern not available): {e}\n")
        print("   Continuing with example...\n")
        ir_view = None

    # Step 4: Register IR view with runtime
    if ir_view:
        print("4. Registering IR view...")
        program_id = "example_program"
        runtime.register_ir_view(program_id, ir_view)
        print(f"   ✓ IR view registered for '{program_id}'\n")

    # Step 5: Start runtime
    print("5. Starting runtime...")
    await runtime.start()
    print("   ✓ Runtime started\n")

    # Step 6: Submit analysis tasks
    print("6. Submitting analysis tasks...")

    # Example: Slicing analysis
    slicing_task = TaskEnvelope(
        task_kind="slicing.request",
        program_id="example_program",
        payload={"function_name": "main", "seed": "x", "direction": "backward"},
    )

    print(f"   - Slicing task: {slicing_task.task_id}")
    # task_id = await runtime.submit_task(slicing_task)
    # print(f"   ✓ Slicing task submitted: {task_id}\n")

    # Example: Access control analysis
    access_control_task = TaskEnvelope(
        task_kind="analysis.access_control",
        program_id="example_program",
        payload={"target_functions": ["authenticate", "authorize"]},
    )

    print(f"   - Access control task: {access_control_task.task_id}")
    # task_id = await runtime.submit_task(access_control_task)
    # print(f"   ✓ Access control task submitted: {task_id}\n")

    print("\n   Note: Task submission is demonstrated but not executed")
    print("   (requires full AutoGen-Core integration)\n")

    # Step 7: Wait for results
    # In a full implementation, we would:
    # - Wait for ResultEnvelopes
    # - Query the fact store for results
    # - Display findings

    print("7. Checking registered agents...")
    capabilities = runtime.plugin_registry.get_all_capabilities()  # type: ignore
    print(f"   Registered agent types: {len(capabilities)}")
    for agent_id, cap in capabilities.items():
        print(f"   - {agent_id}: {cap.description}")
    print()

    # Step 8: Cleanup
    print("8. Shutting down...")
    await runtime.stop()
    await auditzoo.shutdown_runtime()
    print("   ✓ Shutdown complete\n")

    print("=== Example Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
