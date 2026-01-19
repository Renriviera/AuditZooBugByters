"""Request messages for agent communication.

This module defines the Request class used by all agents to send requests.

Request Design Philosophy
=========================

AuditZoo uses a single, flexible Request class rather than specialized subclasses.
This design choice is intentional:

1. **AutoGen Compatibility**: AutoGen's message routing doesn't handle inheritance
   for @message_handler decorated methods. Using a single Request class ensures
   all messages are properly routed.

2. **Payload Flexibility**: Request payloads are untyped dicts (dict[str, Any]),
   allowing developers to define their own data structures without modifying the
   core protocol. Simply put your dataclasses, TypedDicts, or plain dicts in the
   payload field.

3. **Optional Type Checking**: The response_schema field enables runtime validation
   to help caller-side code understand what response data to expect, without
   requiring static types.

Request Type Conventions
========================

The system uses dot notation for request types to organize requests by category:

1. **IR Operations** (prefix: "ir.")
   - **Purpose**: Direct operations on the Intermediate Representation (IR) storage
   - **Handler**: IRStorageAgent
   - **Examples**: "ir.get_unit", "ir.get_neighbors", "ir.add_fact"
   - **Characteristics**: Fast, direct CRUD operations on the code property graph

2. **Analysis Tasks** (prefix: "task.")
   - **Purpose**: Long-running analysis tasks with computation or processing
   - **Handler**: Custom analysis agents (subclasses of BaseAnalysisAgent)
   - **Examples**: "task.taint_analysis", "task.vulnerability_scan"
   - **Characteristics**: Compute-intensive, may involve LLM calls

3. **Queries** (prefix: "query.")
   - **Purpose**: Quick searches and lookups in the IR or codebase
   - **Handler**: IRStorageAgent or query processors
   - **Examples**: "query.search", "query.pattern_match"
   - **Characteristics**: Fast lookups, no heavy computation

Note: These are conventions, not enforced rules. You can define your own
      request type namespaces (e.g., "custom.my_operation").

Response Schema Pattern
=======================

The optional response_schema field serves a specific purpose:

**Why use response_schema?**
- Helps caller agents understand what data structure to expect in the response
- Enables runtime validation to catch mismatches early
- Acts as documentation for the response format

**Best Practice**: Define response schemas in the CALLEE agent file (the agent
that handles the request), not the caller. This way:
1. Schema lives with the implementation
2. Callers import the schema to validate responses
3. No circular dependencies (as long as agents don't call each other circularly)

**Example**:
```python
# In my_analysis_agent.py (callee)
MY_TASK_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {"type": "array"},
        "confidence": {"type": "number"}
    },
    "required": ["results"]
}

# In caller code
from my_analysis_agent import MY_TASK_RESPONSE_SCHEMA

request = Request(
    type="task.my_analysis",
    payload={"param": "value"},
    response_schema=MY_TASK_RESPONSE_SCHEMA  # Optional validation
)
```
"""

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

import jsonschema

from auditzoo.core.protocol.errors import ProtocolValidationError
from auditzoo.core.protocol.utils import to_dict_for_validation


@dataclass(frozen=True)
class Request:
    """Universal request message for agent communication.

    All agents use this class to send requests. The request type uses dot notation
    for namespacing (e.g., "ir.get_unit", "task.my_analysis").

    Attributes:
        type: Request type using dot notation (e.g., "ir.get_unit", "task.analyze")
        payload: Request data as a dict. You can put any JSON-serializable structure here:
            - Plain dicts: {"param": "value"}
            - Dataclass instances: asdict(my_dataclass)
            - TypedDicts, Pydantic models, etc.
        request_id: Unique identifier (auto-generated via uuid4)
        metadata: Optional metadata (e.g., timestamps, priority, correlation_id)
        response_schema: Optional JSON schema to validate response.data against.
            - Purpose: Helps caller-side code understand expected response structure
            - When to use: Improves type awareness and catches mismatches early
            - Best practice: Define schemas in the callee agent file, import in callers
            - Validation: Only runs if schema provided AND response.success is True

    Examples:
        # Basic IR request with plain dict payload
        Request(
            type="ir.get_unit",
            payload={"unit_id": "func_123"}
        )

        # Task request with custom data structure
        @dataclass
        class TaintAnalysisParams:
            source: str
            sink: str
            max_depth: int = 10

        params = TaintAnalysisParams(source="user_input", sink="sql_query")
        Request(
            type="task.taint_analysis",
            payload=asdict(params)  # Convert dataclass to dict
        )

        # Request with response validation
        CALLERS_SCHEMA = {
            "type": "object",
            "properties": {
                "callers": {"type": "array"},
                "count": {"type": "integer"}
            },
            "required": ["callers"]
        }

        Request(
            type="task.find_callers",
            payload={"function_name": "malloc"},
            response_schema=CALLERS_SCHEMA  # Optional: validates response
        )

    Note:
        - request_id is auto-generated; don't set it manually
        - Responses reference this request_id in their metadata
        - Payload flexibility is intentional; define your own structures
        - AutoGen doesn't support inheritance in @message_handler, so we use
          a single Request class rather than IRRequest/TaskRequest subclasses
    """

    type: str
    payload: dict[str, Any]
    request_id: str = field(default_factory=lambda: str(uuid4()))
    response_schema: dict[str, Any] = field(default_factory=dict)
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
            jsonschema.validate(
                instance=to_dict_for_validation(self.payload), schema=schema
            )
            return True
        except jsonschema.ValidationError as e:
            raise ProtocolValidationError(f"JSON Schema validation failed: {e}") from e
