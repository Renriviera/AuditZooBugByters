"""Utility functions for AuditZoo core components."""

import json
from dataclasses import is_dataclass
from typing import Any, cast

from pydantic import TypeAdapter
from typing_extensions import TypedDict


def pydantic_default(o: Any):
    """Pydantic default JSON serializer.

    Args:
        o: The object to serialize.

    Returns:
        A JSON-serializable representation of the object.
    """

    if is_dataclass(o) and not isinstance(o, type):
        return TypeAdapter(type(o)).dump_python(o)

    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def to_json_for_validation(o: Any) -> str:
    """Convert an object to its JSON string representation.
    This is useful for validating objects against JSON schemas.

    Args:
        o: The object to convert.

    Returns:
        JSON string representation of the object.
    """

    return json.dumps(o, default=pydantic_default, sort_keys=True)


def to_dict_for_validation(o) -> dict[str, Any]:
    """Convert an object to its dictionary representation.
    This is useful for validating objects against JSON schemas.

    Args:
        o: The object to convert.

    Returns:
        Dictionary representation of the object.
    """

    return cast(dict[str, Any], json.loads(to_json_for_validation(o)))


def to_schema(ty: type) -> dict[str, Any]:
    """Generate a JSON schema from a Pydantic-compatible type.

    Args:
        ty: The type to generate the schema for.

    Returns:
        JSON schema dictionary.
    """

    return TypeAdapter(ty).json_schema()


def typed_dict(**kwargs) -> type:
    """Generate a TypedDict type from a metadata dictionary.

    Args:
        **kwargs: Keyword arguments where keys are field names and values are field types.

    Returns:
        Generated TypedDict type.
    """

    return TypedDict("_GeneratedTypedDict", kwargs)  # type: ignore
