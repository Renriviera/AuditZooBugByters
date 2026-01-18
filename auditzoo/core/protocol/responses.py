"""Response messages for agent communication.

This module defines the Response class used by all agents to send responses.
"""

from dataclasses import asdict, dataclass, field
from typing import Any

import jsonschema

from auditzoo.core.protocol.errors import ProtocolRuntimeError, ProtocolValidationError
from auditzoo.core.protocol.utils import to_dict_for_validation


@dataclass
class Response:
    """Universal response message for agent communication.

    All agents use this class to send responses. Responses are typically linked
    to requests via the request_id in metadata.

    Attributes:
        success: Whether the operation succeeded
        data: Response data (JSON-serializable dict) if successful
        error: Error message if unsuccessful
        metadata: Optional metadata (must include request_id to link to request)

    Examples:
        # Successful IR response
        Response(
            success=True,
            data={"unit": {...}},
            metadata={"request_id": "original-request-id"}
        )

        # Error response
        Response(
            success=False,
            error="Unit not found: func_123",
            metadata={"request_id": "original-request-id"}
        )

        # Task result
        Response(
            success=True,
            data={"tainted_paths": [...], "confidence": 0.95},
            metadata={"request_id": "...", "task_id": "..."}
        )

    Note:
        The metadata should always include the request_id from the original request
        to enable proper request/response pairing.
    """

    success: bool
    data: Any = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(cls, data: Any, metadata: dict[str, Any] | None = None) -> "Response":
        """Create a successful response.

        Args:
            data: The response data
            metadata: Optional metadata (should include request_id)

        Returns:
            Response with success=True and the provided data

        Example:
            Response.ok(
                data={"unit": {...}},
                metadata={"request_id": "abc-123"}
            )
        """
        return cls(success=True, data=data, metadata=metadata or {})

    @classmethod
    def fail(cls, error: str, metadata: dict[str, Any] | None = None) -> "Response":
        """Create a failed response.

        Args:
            error: Error message
            metadata: Optional metadata (should include request_id)

        Returns:
            Response with success=False and the error message

        Example:
            Response.fail(
                error="Unit not found",
                metadata={"request_id": "abc-123"}
            )
        """
        return cls(success=False, error=error, metadata=metadata or {})

    def unwrap(self) -> Any:
        """Get the data, raising an exception if the response is a failure.

        Returns:
            The response data

        Raises:
            ProtocolError: If the response represents a failure

        Example:
            try:
                data = response.unwrap()
                print(data["unit"])
            except ProtocolError as e:
                print(f"Request failed: {e}")
        """
        if not self.success:
            raise ProtocolRuntimeError(f"Response failed: {self.error}")
        return self.data

    def unwrap_or(self, default: Any) -> Any:
        """Get the data, or a default value if the response is a failure.

        Args:
            default: Default value to return on failure

        Returns:
            The response data if successful, otherwise the default value

        Example:
            data = response.unwrap_or(default={})
        """
        return self.data if self.success else default

    def to_dict(self) -> dict[str, Any]:
        """Convert response to dictionary for serialization.

        Returns:
            Dictionary representation of the response
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Response":
        """Create response from dictionary.

        Args:
            data: Dictionary containing response fields

        Returns:
            Response instance
        """
        return cls(**data)

    def validate(self, schema: dict[str, Any]) -> bool:
        """Validate response data against a JSON schema.

        Args:
            schema: JSON schema dict to validate the data field against

        Returns:
            True if validation passes, otherwise False

        Examples:
            # JSON Schema validation
            schema = {
                "type": "object",
                "properties": {
                    "unit": {"type": "object"}
                },
                "required": ["unit"]
            }
            response.validate(schema)

            # Just check JSON serializability
            response.validate()
        """
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
        except Exception as e:  # MDZZ
            raise ProtocolValidationError(
                f"JSON Schema validation failed: {e}MDZZ 1 {self}"
            ) from e
