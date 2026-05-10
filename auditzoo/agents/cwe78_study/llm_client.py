"""Thin wrapper around the OpenAI-compatible vLLM endpoint for Qwen."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openai import AsyncOpenAI, BadRequestError

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    base_url: str = "http://localhost:8000/v1"
    model: str = "gpt-5.4-mini"
    temperature: float = 0.1
    api_key: str = "not-needed"
    max_tokens: int = 1024
    seed: int | None = 235711
    # Optional path to an append-only JSONL trace of every chat request +
    # response.  Used for the Phase-A3 deep dive on the UNCERTAIN-collapse
    # root cause; ``None`` disables logging entirely.
    log_io_path: str | None = None


@dataclass
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    call_count: int = 0

    def accumulate(self, prompt_tok: int, completion_tok: int) -> None:
        self.prompt_tokens += prompt_tok
        self.completion_tokens += completion_tok
        self.total_tokens += prompt_tok + completion_tok
        self.call_count += 1

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "call_count": self.call_count,
        }


class LLMClient:
    """Async client for Qwen via vLLM (OpenAI-compatible endpoint)."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig()
        self._client = AsyncOpenAI(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
        )
        self.usage = LLMUsage()
        # Serialise JSONL writes; chat() is async but completions can race
        # across arms/agents sharing the client.
        self._io_lock = threading.Lock()

    async def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Send a chat completion request and return the assistant's reply."""
        request = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature or self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
            "seed": self.config.seed,
        }
        try:
            response = await self._client.chat.completions.create(**request)
        except BadRequestError as exc:
            if "max_tokens" not in str(exc):
                raise
            request["max_completion_tokens"] = request.pop("max_tokens")
            response = await self._client.chat.completions.create(**request)
        choice = response.choices[0]
        text = choice.message.content or ""

        if response.usage:
            self.usage.accumulate(
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
            )

        self._log_io(system_prompt, user_prompt, text, response)
        return text

    def _log_io(
        self,
        system_prompt: str,
        user_prompt: str,
        response_text: str,
        response: Any,
    ) -> None:
        """Append a single JSONL record for one chat round-trip.

        No-op when ``config.log_io_path`` is unset.  We truncate prompts to
        keep the trace from ballooning, but the full response is kept so
        the UNCERTAIN-collapse diagnosis sees exactly what the LLM
        returned.
        """
        path = self.config.log_io_path
        if not path:
            return
        record = {
            "ts": time.time(),
            "model": self.config.model,
            "system_prompt": system_prompt[:2000],
            "user_prompt": user_prompt[:6000],
            "response_text": response_text,
            "usage": (
                {
                    "prompt_tokens": getattr(response.usage, "prompt_tokens", None),
                    "completion_tokens": getattr(
                        response.usage, "completion_tokens", None
                    ),
                }
                if getattr(response, "usage", None)
                else None
            ),
            "finish_reason": getattr(response.choices[0], "finish_reason", None),
        }
        try:
            with self._io_lock:
                with Path(path).open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:  # pragma: no cover - diagnostic path
            logger.warning("Failed to log LLM I/O to %s: %s", path, exc)

    async def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Chat and parse the response as JSON.

        Falls back to extracting JSON from markdown fences if direct parse fails.
        """
        raw = await self.chat(system_prompt, user_prompt, **kwargs)
        return _parse_json(raw)

    def reset_usage(self) -> None:
        self.usage = LLMUsage()


def _parse_json(text: str) -> dict[str, Any]:
    """Best-effort JSON extraction from an LLM response."""
    text = text.strip()
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try stripping markdown fences
    for fence in ("```json", "```"):
        if fence in text:
            start = text.index(fence) + len(fence)
            end = text.index("```", start)
            return json.loads(text[start:end].strip())
    raise ValueError(f"Could not extract JSON from LLM response: {text[:200]}")
