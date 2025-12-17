from dataclasses import dataclass, field
from typing import Any

from auditzoo.core.ir.facts.base import UnitFact


@dataclass(frozen=True)
class SummaryFact(UnitFact):
    """General-purpose unit fact for summarizing analysis results.

    This is the most common unit fact - use it for any analysis finding
    about a specific CodeUnit.

    Examples:
        # Security vulnerability
        SummaryFact(
            name="vulnerability",
            summary="SQL injection detected",
            details={"severity": "high", "cwe": "CWE-89", "confidence": 0.9}
        )

        # Code metrics
        SummaryFact(
            name="complexity",
            summary="High cyclomatic complexity",
            details={"complexity": 42, "threshold": 10}
        )

        # Taint analysis
        SummaryFact(
            name="taint",
            summary="User input reaches sensitive sink",
            details={"source": "user_input", "sink": "exec_call"}
        )
    """

    name: str  # The type of this summary fact
    summary: str  # Brief description
    details: dict[str, Any] = field(default_factory=dict)  # Detailed data

    def _to_kwargs(self) -> dict[str, Any]:
        """Convert to kwargs dict for serialization."""
        return {
            "name": self.name,
            "summary": self.summary,
            "details": self.details,
        }

    @classmethod
    def _from_kwargs(cls, **kwargs) -> "SummaryFact":
        """Create instance from kwargs dict."""
        return cls(
            name=kwargs.get("name", ""),
            summary=kwargs.get("summary", ""),
            details=kwargs.get("details", {}),
        )
