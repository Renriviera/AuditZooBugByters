"""Utilities for Joern backend."""

import json
import re
from typing import Any

from auditzoo.core.ir.backend_api import BackendResponseError


def _parse_to_json(raw: str, max_unwrap: int = 10) -> Any:
    """Helper to parse a raw string to JSON, handling multiple layers of encoding.

    Args:
        raw: Raw string input.
        max_unwrap: Maximum number of times to unwrap JSON-encoded strings.

    Returns:
        Parsed JSON object.
    """
    # Repeatedly decode JSON until it's not a JSON-encoded string anymore
    s = raw.strip()

    for _ in range(max_unwrap):
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as e:
            # If it looks like it's quoted (single/double), unquote and unescape once
            if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
                inner = s[1:-1]
                # interpret backslash escapes (turn \" into ", etc.)
                s = bytes(inner, "utf-8").decode("unicode_escape")
                continue
            raise BackendResponseError(
                f"Failed to parse Joern JSON response: {raw}"
            ) from e

        if isinstance(obj, str):
            s = obj.strip()
            # also handle triple quotes again if they appear after decoding
            if s.startswith('"""') and s.endswith('"""') and len(s) >= 6:
                s = s[3:-3]
            continue

        return obj

    raise BackendResponseError(
        f"Too many unwrap attempts; input may not be valid JSON: {raw}"
    )


def parse_joern_response(raw: str, response_ty: str = "json", **kwargs) -> Any:
    """Parse a Joern JSON response, handling multiple layers of encoding.

    Args:
        raw: Raw string response from Joern backend.
        response_ty: Expected response type ("json", "str", etc.)
        **kwargs: Additional keyword arguments for parsing.

    Returns:
        Parsed object.

    Raises:
        BackendResponseError: If parsing fails or exceeds max unwrap attempts.
    """

    s = raw.strip()

    updated = True
    while updated:
        # Loop until no more updates
        updated = False

        # If the line includes Scala assignment like: val res2: Type = "...."
        # Match pattern:
        #   i.  (val|var|def) identifier: Type = value
        #   ii. identifier = value
        # We want to extract everything after the = that follows the type declaration
        m = re.match(
            r"^(?:(val|var|def)\s+\w+\s*:\s*[^=]+|(\w+))\s*=\s*(.*)", s, re.DOTALL
        )
        if m:
            s = m.group(3).strip()
            updated = True

        # Drop trailing semicolon if present
        if s.endswith(";"):
            s = s[:-1].strip()
            updated = True

        # Unwrap Scala triple quotes: """..."""
        if s.startswith('"""') and s.endswith('"""') and len(s) >= 6:
            s = s[3:-3]
            updated = True

        # Check Optional wrapping: Some(...), None
        if s.startswith("Some(") and s.endswith(")") and len(s) >= 6:
            s = s[5:-1].strip()
            updated = True
        elif s == "None":
            return None

    match response_ty:
        case "json":
            return _parse_to_json(s)
        case "str":
            while len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
                s = s[1:-1]
            return bytes(s, "utf-8").decode("unicode_escape")
        case "int":
            try:
                # Remove Scala/Java integer suffixes (L for Long) and underscores
                cleaned = s.rstrip("Ll").replace("_", "")
                return int(cleaned)
            except ValueError as e:
                raise BackendResponseError(
                    f"Failed to parse Joern int response: {raw}"
                ) from e
        case "float":
            try:
                return float(s)
            except ValueError as e:
                raise BackendResponseError(
                    f"Failed to parse Joern float response: {raw}"
                ) from e
        case _:
            raise BackendResponseError(
                f"Unsupported response type '{response_ty}' for Joern parsing."
            )
