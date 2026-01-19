"""Response messages for agent communication.

This module defines the Response class used by all agents to send responses.
"""

from dataclasses import asdict, dataclass, field
from typing import Any

import jsonschema

from auditzoo.core.protocol.errors import (
    ProtocolInheritanceError,
    ProtocolRuntimeError,
    ProtocolValidationError,
)
from auditzoo.core.protocol.utils import to_dict_for_validation


@dataclass(frozen=True)
class Response:
    """Universal response message.

    Attributes:
        success: Whether the operation succeeded
        data: Response data (any type) if successful
        error: Error message if unsuccessful
        metadata: Optional metadata (may include request_id)

    Notes:
        - Response is sealed; subclassing raises ProtocolInheritanceError.
    """

    success: bool
    data: Any = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls) -> None:
        """Prevent subclassing of Response."""
        raise ProtocolInheritanceError(
            "Subclassing Response is not allowed. Use Response directly."
        )

    @classmethod
    def ok(cls, data: Any, metadata: dict[str, Any] | None = None) -> "Response":
        """Create a successful response."""
        return cls(success=True, data=data, metadata=metadata or {})

    @classmethod
    def fail(cls, error: str, metadata: dict[str, Any] | None = None) -> "Response":
        """Create a failed response."""
        return cls(success=False, error=error, metadata=metadata or {})

    def unwrap(self) -> Any:
        """Get data or raise if the response is a failure."""
        if not self.success:
            raise ProtocolRuntimeError(f"Response failed: {self.error}")
        return self.data

    def unwrap_or(self, default: Any) -> Any:
        """Get data or return default if the response is a failure."""
        return self.data if self.success else default

    def to_dict(self) -> dict[str, Any]:
        """Convert response to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Response":
        """Create response from dictionary."""
        return cls(**data)

    def validate(self, schema: dict[str, Any]) -> bool:
        """Validate response data against a JSON schema."""
        if not self.success:
            # Don't validate error responses
            return True

        if self.data is None:
            return True

        # Validate with JSON Schema
        try:
            jsonschema.validate(
                instance=to_dict_for_validation(self.data), schema=schema
            )
            return True
        except jsonschema.ValidationError as e:
            raise ProtocolValidationError(f"JSON Schema validation failed: {e}") from e
