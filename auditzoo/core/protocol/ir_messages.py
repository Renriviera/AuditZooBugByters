"""Messages for IR and fact store operations.

This module defines the messages used to interact with IRStoreAgent.
"""

from dataclasses import dataclass, field
from typing import Any

from auditzoo.core.ir.facts import RelationFact, UnitFact


@dataclass
class GetFactsRequest:
    """Request to retrieve facts from the fact store.

    Attributes:
        program_id: Program to get facts for
        fact_types: Optional filter by fact names (None = all types)
        filters: Additional filters (fact-type specific)
    """

    program_id: str
    fact_types: list[str] | None = None
    filters: dict[str, Any] = field(default_factory=dict)


@dataclass
class GetFactsResponse:
    """Response containing facts from the fact store.

    Attributes:
        program_id: Program these facts are for
        facts: List of facts matching the request
        version: Version number of the program state
    """

    program_id: str
    facts: list[UnitFact | RelationFact]
    version: int


@dataclass
class UpdateFactsRequest:
    """Request to update facts in the fact store.

    Attributes:
        program_id: Program to update facts for
        facts: Facts to add or update
        replace: If True, replace existing facts of same name; if False, append
    """

    program_id: str
    facts: list[UnitFact | RelationFact]
    replace: bool = False


@dataclass
class UpdateFactsResponse:
    """Response to a fact update request.

    Attributes:
        program_id: Program that was updated
        success: Whether the update succeeded
        version: New version number after update
        error: Error message if success is False
    """

    program_id: str
    success: bool
    version: int
    error: str | None = None


@dataclass
class GetIRVersionRequest:
    """Request to get the current IR version for a program."""

    program_id: str


@dataclass
class GetIRVersionResponse:
    """Response with IR version information."""

    program_id: str
    version: int


@dataclass
class CheckFactsExistRequest:
    """Request to check if specific fact types exist for a program.

    Attributes:
        program_id: Program to check
        fact_types: Fact names to check for
    """

    program_id: str
    fact_types: list[str]


@dataclass
class CheckFactsExistResponse:
    """Response indicating which fact types exist.

    Attributes:
        program_id: Program that was checked
        existing: Fact names that exist
        missing: Fact names that don't exist
    """

    program_id: str
    existing: list[str]
    missing: list[str]
