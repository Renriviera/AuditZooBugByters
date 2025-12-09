"""Task and result envelopes for agent communication.

This module defines the generic wrappers for analysis requests and results.
"""

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class TaskEnvelope:
    """Generic wrapper for analysis task requests.

    Attributes:
        task_id: Unique identifier for this task
        task_kind: Type of task (e.g., "slicing.request", "analysis.buffer_overflow")
        program_id: Target program
        payload: Task-specific data
        requester: ID of the agent that requested this task
        metadata: Additional metadata
    """

    task_kind: str
    program_id: str
    payload: dict[str, Any]
    task_id: str = field(default_factory=lambda: str(uuid4()))
    requester: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_requester(self, requester: str) -> "TaskEnvelope":
        """Create a copy with the requester set."""
        return TaskEnvelope(
            task_id=self.task_id,
            task_kind=self.task_kind,
            program_id=self.program_id,
            payload=self.payload,
            requester=requester,
            metadata=self.metadata,
        )


@dataclass
class ResultEnvelope:
    """Generic wrapper for analysis results.

    Attributes:
        task_id: ID of the task this is a result for
        task_kind: Type of task that was completed
        program_id: Target program
        success: Whether the task completed successfully
        payload: Result-specific data
        error: Error message if success is False
        metadata: Additional metadata
    """

    task_id: str
    task_kind: str
    program_id: str
    success: bool
    payload: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_task(
        cls,
        task: TaskEnvelope,
        success: bool,
        payload: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> "ResultEnvelope":
        """Create a result envelope from a task envelope."""
        return cls(
            task_id=task.task_id,
            task_kind=task.task_kind,
            program_id=task.program_id,
            success=success,
            payload=payload or {},
            error=error,
            metadata=task.metadata,
        )
