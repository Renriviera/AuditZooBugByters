"""IR-related error definitions."""


class IRError(Exception):
    """Base class for all IR-related errors."""

    pass


class IRInvalidFactError(IRError):
    """Raised when an invalid fact is encountered."""

    pass


class IRValueError(IRError):
    """Raised when an invalid value is provided in IR operations."""

    pass


class IRRelationKindError(IRError):
    """Raised when an unknown RelationKind is encountered."""

    pass


class IRUnimplementedError(IRError):
    """Raised when a requested IR feature is not implemented."""

    pass


class IRBackendError(IRError):
    """Raised when there is a backend-related error in IR operations."""

    pass


class IRInvalidResponseError(IRError):
    """Raised when a backend response is invalid or cannot be processed."""

    pass


class IRUnitKindError(IRError):
    """Raised when an unknown CodeUnitKind is encountered."""

    pass
