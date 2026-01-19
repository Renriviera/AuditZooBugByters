"""Request messages used by all agents.

- Single Request class (sealed; do not subclass).
- type: dot-namespace string, e.g., "ir.get_unit" or "task.analyze".
- payload: dict[str, Any] with request data.
- response_schema: optional JSON Schema for Response.data validation on success.

Conventions (not enforced):
- ir.* for IRStorageAgent
- task.* for analysis tasks
- query.* for quick lookups
"""

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

import jsonschema

from auditzoo.core.protocol.errors import (
    ProtocolInheritanceError,
    ProtocolValidationError,
)
from auditzoo.core.protocol.utils import to_dict_for_validation


@dataclass(frozen=True)
class Request:
    """Universal request message.

    Attributes:
        type: Dot-namespace string (e.g., "ir.get_unit", "task.analyze")
        payload: Request data dict (JSON-serializable recommended)
        request_id: Auto-generated UUID
        response_schema: Optional JSON Schema for Response.data validation
        metadata: Optional metadata (e.g., timestamps, correlation_id)

    Notes:
        - Request is sealed; subclassing raises ProtocolInheritanceError.
        - Validation runs only when response_schema is provided and response is success.
    """

    type: str
    payload: dict[str, Any]
    request_id: str = field(default_factory=lambda: str(uuid4()))
    response_schema: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls) -> None:
        """Prevent subclassing of Request."""
        raise ProtocolInheritanceError(
            "Subclassing Request is not allowed. Use Request directly."
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert request to dictionary for serialization.

        Returns:
            Dictionary representation of the request
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Request":
        """Create request from dictionary.

        Args:
            data: Dictionary containing request fields

        Returns:
            Request instance
        """
        return cls(**data)

    def validate(self, schema: dict[str, Any]) -> bool:
        """Validate request payload against a JSON schema."""
        # Validate with JSON Schema
        try:
            jsonschema.validate(
                instance=to_dict_for_validation(self.payload), schema=schema
            )
            return True
        except jsonschema.ValidationError as e:
            raise ProtocolValidationError(f"JSON Schema validation failed: {e}") from e
