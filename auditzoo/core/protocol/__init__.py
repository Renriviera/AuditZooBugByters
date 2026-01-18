"""Protocol definitions for agent communication."""

from .requests import IRRequest, QueryRequest, Request, TaskRequest
from .responses import Response

__all__ = ["Request", "IRRequest", "TaskRequest", "QueryRequest", "Response"]
