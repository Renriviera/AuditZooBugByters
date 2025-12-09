"""Message schemas for access control analysis.

Defines the payload structure for access control detection tasks and results.
"""

from dataclasses import dataclass


@dataclass
class AccessControlTaskPayload:
    """Payload for an access control analysis task.

    Attributes:
        target_functions: Optional list of functions to analyze (None = all)
        check_patterns: Optional patterns to identify auth checks
    """

    target_functions: list[str] | None = None
    check_patterns: list[str] | None = None


@dataclass
class AccessControlResultPayload:
    """Payload for access control analysis results.

    Attributes:
        issues_found: Number of issues found
        functions_checked: Number of functions analyzed
    """

    issues_found: int
    functions_checked: int
