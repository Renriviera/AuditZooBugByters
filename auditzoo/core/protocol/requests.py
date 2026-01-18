"""Request messages for agent communication.

This module defines the Request class and its specialized subclasses used by all
agents to send requests.

Usage Note
==========

While the specialized request classes (IRRequest, TaskRequest, QueryRequest) provide
automatic prefix handling for convenience, you are also welcome to use the base
`Request` class directly with the full type string (e.g., "ir.get_unit",
"task.taint_analysis", "query.search"). Both approaches are fully supported and
functionally equivalent.

Request Type Definitions
========================

The system supports three categories of requests, each with a specific purpose:

1. **IRRequest** (prefix: "ir.")
   - **Purpose**: Direct operations on the Intermediate Representation (IR) storage
   - **Use cases**: CRUD operations on code units and relations in the code property graph
   - **Handler**: IRStorageAgent
   - **Examples**:
     - `ir.get_unit`: Retrieve a code unit by ID
     - `ir.get_neighbors`: Get related units (callers/callees, contains, etc.)
     - `ir.add_unit`: Add a new code unit to the IR
     - `ir.add_relation`: Create a relationship between code units
     - `ir.query`: Execute a graph query on the IR
   - **Characteristics**: Fast, direct database-like operations

2. **TaskRequest** (prefix: "task.")
   - **Purpose**: Long-running analysis tasks that perform computation or processing
   - **Use cases**: Complex analyses that require multiple steps, computation, or AI reasoning
   - **Handler**: Analysis agents (subclasses of BaseAnalysisAgent)
   - **Examples**:
     - `task.taint_analysis`: Track data flow from sources to sinks
     - `task.vulnerability_scan`: Detect security vulnerabilities in code
     - `task.code_review`: Perform automated code review
     - `task.impact_analysis`: Analyze the impact of code changes
   - **Characteristics**: Compute-intensive, may involve LLM calls, returns analysis results

3. **QueryRequest** (prefix: "query.")
   - **Purpose**: Quick searches and lookups in the IR or codebase
   - **Use cases**: Finding code patterns, filtering units, searching by criteria
   - **Handler**: IRStorageAgent or lightweight query processors
   - **Examples**:
     - `query.search`: Search for code matching a pattern or regex
     - `query.pattern_match`: Find code units matching specific structural patterns
     - `query.filter_by_type`: Get all units of a specific kind (functions, classes, etc.)
     - `query.find_by_name`: Locate code units by name or signature
   - **Characteristics**: Fast lookups, no heavy computation, retrieval-focused

Key Differences
===============

- **IR vs Query**: IR operations are about manipulating the graph structure (CRUD),
  while queries are about searching/filtering existing data
- **Task vs Query**: Tasks involve analysis and computation, while queries are simple lookups
- **Task vs IR**: Tasks perform high-level analysis using IR data, while IR operations
  directly read/write the underlying storage
"""

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

import jsonschema


@dataclass
class Request:
    """Universal request message for agent communication.

    All agents use this class to send requests. The request type uses dot notation
    for namespacing (e.g., "ir.get_unit", "task.analysis").

    Attributes:
        type: Request type using dot notation
            - IR operations: "ir.get_unit", "ir.get_neighbors", "ir.add_fact"
            - Tasks: "task.taint_analysis", "task.vulnerability_scan"
            - Queries: "query.search", "query.pattern_match"
        payload: Request data (JSON-serializable dict)
        request_id: Unique identifier (auto-generated via uuid4)
        metadata: Optional metadata (e.g., timestamps, priority, correlation_id)

    Examples:
        # IR request - get a code unit
        Request(
            type="ir.get_unit",
            payload={"unit_id": "func_123"}
        )

        # IR request - get neighbors (callers/callees)
        Request(
            type="ir.get_neighbors",
            payload={
                "unit_id": "func_123",
                "direction": "in",
                "relation_kind": "calls"
            }
        )

        # Task request
        Request(
            type="task.taint_analysis",
            payload={"source": "user_input", "sink": "sql_query"}
        )

        # Query request
        Request(
            type="query.search",
            payload={"pattern": "malloc.*free", "language": "c"}
        )

    Note:
        The request_id is automatically generated and should not be manually set.
        Responses will reference this request_id in their metadata.
    """

    type: str
    payload: dict[str, Any]
    request_id: str = field(default_factory=lambda: str(uuid4()))
    metadata: dict[str, Any] = field(default_factory=dict)

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
        """Validate request payload against a JSON schema.

        Args:
            schema: JSON schema dict to validate the payload field against

        Returns:
            True if validation passes, otherwise False

        Examples:
            # JSON Schema validation
            schema = {
                "type": "object",
                "properties": {
                    "unit_id": {"type": "string"}
                },
                "required": ["unit_id"]
            }
            request.validate(schema)

            # Just check JSON serializability
            request.validate()
        """
        # Validate with JSON Schema
        try:
            jsonschema.validate(instance=self.payload, schema=schema)
            return True
        except jsonschema.ValidationError as e:
            raise ValueError(f"JSON Schema validation failed: {e}") from e


@dataclass
class IRRequest(Request):
    """IR operation request with automatic 'ir.' prefix.

    Automatically adds 'ir.' prefix to the request type if not already present.

    Examples:
        # Type gets auto-prefixed
        IRRequest(
            type="get_unit",
            payload={"unit_id": "func_123"}
        )  # type becomes "ir.get_unit"

        # Full type also works (won't double-prefix)
        IRRequest(
            type="ir.get_neighbors",
            payload={"unit_id": "func_123", "direction": "in"}
        )  # type stays "ir.get_neighbors"
    """

    def __post_init__(self):
        if not self.type.startswith("ir."):
            self.type = f"ir.{self.type}"


@dataclass
class TaskRequest(Request):
    """Task request with automatic 'task.' prefix.

    Automatically adds 'task.' prefix to the request type if not already present.

    Examples:
        # Type gets auto-prefixed
        TaskRequest(
            type="taint_analysis",
            payload={"source": "user_input", "sink": "sql_query"}
        )  # type becomes "task.taint_analysis"

        # Full type also works
        TaskRequest(
            type="task.vulnerability_scan",
            payload={"target": "auth_module"}
        )  # type stays "task.vulnerability_scan"
    """

    def __post_init__(self):
        if not self.type.startswith("task."):
            self.type = f"task.{self.type}"


@dataclass
class QueryRequest(Request):
    """Query request with automatic 'query.' prefix.

    Automatically adds 'query.' prefix to the request type if not already present.

    Examples:
        # Type gets auto-prefixed
        QueryRequest(
            type="search",
            payload={"pattern": "malloc.*free", "language": "c"}
        )  # type becomes "query.search"

        # Full type also works
        QueryRequest(
            type="query.pattern_match",
            payload={"pattern": ".*"}
        )  # type stays "query.pattern_match"
    """

    def __post_init__(self):
        if not self.type.startswith("query."):
            self.type = f"query.{self.type}"
