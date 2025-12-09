"""Agent capability schemas.

This module defines how analysis agents declare their capabilities:
- Task kinds they can handle
- Fact types they produce and require
- Languages they support
"""

from dataclasses import dataclass, field

from auditzoo.contracts.facts import FactType


@dataclass
class AgentCapability:
    """Describes what an agent type can do.

    Attributes:
        agent_type_id: Unique identifier for this agent type
        task_kinds: Task kinds this agent can handle (e.g., "slicing.request")
        produces: Fact types this agent produces
        requires: Fact types this agent requires
        languages: Programming languages this agent supports (empty = all languages)
        description: Human-readable description
    """

    agent_type_id: str
    task_kinds: set[str] = field(default_factory=set)
    produces: set[FactType] = field(default_factory=set)
    requires: set[FactType] = field(default_factory=set)
    languages: set[str] = field(default_factory=set)
    description: str = ""

    def can_handle_task(self, task_kind: str) -> bool:
        """Check if this agent can handle a specific task kind."""
        return task_kind in self.task_kinds

    def can_produce_fact(self, fact_type: FactType) -> bool:
        """Check if this agent produces a specific fact type."""
        return fact_type in self.produces

    def supports_language(self, language: str) -> bool:
        """Check if this agent supports a specific language.

        Empty languages set means all languages are supported.
        """
        return not self.languages or language in self.languages

    def has_dependencies(self) -> bool:
        """Check if this agent requires any facts."""
        return len(self.requires) > 0
