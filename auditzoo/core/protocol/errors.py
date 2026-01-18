"""Protocol-related error definitions."""


class ProtocolError(Exception):
    """Base class for protocol-related errors."""

    pass


class ProtocolValidationError(ProtocolError):
    """Error raised when protocol message validation fails."""

    pass


class ProtocolRuntimeError(ProtocolError):
    """Error raised during protocol message processing at runtime."""

    pass
