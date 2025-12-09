"""Message schemas for slicing analysis.

Defines the payload structure for slicing task requests and results.
"""

from dataclasses import dataclass


@dataclass
class SlicingTaskPayload:
    """Payload for a slicing task request.

    Attributes:
        function_name: Name of the function to slice
        seed: Starting point for the slice (variable, line, node)
        direction: "backward" or "forward"
        max_depth: Optional maximum slice depth
    """

    function_name: str
    seed: str
    direction: str = "backward"
    max_depth: int | None = None


@dataclass
class SlicingResultPayload:
    """Payload for a slicing result.

    Attributes:
        nodes: List of node IDs in the slice
        edges: Optional list of edges in the slice
    """

    nodes: list[str]
    edges: list[tuple] | None = None
