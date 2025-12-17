"""Base class for core infrastructure agents.

This module provides a base class for core agents (IRStore, PluginRegistry, etc.)
with common utilities for messaging and logging.
"""

import logging
from typing import Any

from autogen_core import RoutedAgent


class BaseZooAgent(RoutedAgent):
    """Base class for auditzoo infrastructure agents.

    Provides common utilities for sending messages, logging, and error handling.
    Integrates with AutoGen-Core's agent model.
    """

    def __init__(self, agent_id: str):
        super().__init__(agent_id)
        self.agent_id = agent_id
        self.logger = logging.getLogger(f"auditzoo.{agent_id}")

    def log_info(self, message: str, **kwargs):
        """Log an info message."""
        self.logger.info(message, extra=kwargs)

    def log_warning(self, message: str, **kwargs):
        """Log a warning message."""
        self.logger.warning(message, extra=kwargs)

    def log_error(self, message: str, **kwargs):
        """Log an error message."""
        self.logger.error(message, extra=kwargs)

    def log_debug(self, message: str, **kwargs):
        """Log a debug message."""
        self.logger.debug(message, extra=kwargs)

    async def handle_message(self, message: Any) -> Any | None:
        """Handle an incoming message.

        To be implemented by subclasses.
        """
        raise NotImplementedError
