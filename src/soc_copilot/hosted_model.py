"""Client for Splunk Hosted Models (Foundation-Sec, gpt-oss-*).

Wraps the Splunk-hosted inference endpoint with an OpenAI-style chat-completion
interface so the agent loop can stay model-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .config import HostedModelConfig, get_settings


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            d["name"] = self.name
        return d


class HostedModelClient:
    """Thin wrapper over the Splunk Hosted Models REST endpoint."""

    def __init__(self, cfg: HostedModelConfig | None = None, *, timeout: float = 60.0) -> None:
        self._cfg = cfg or get_settings().hosted
        self._client = httpx.Client(
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {self._cfg.token}",
                "Content-Type": "application/json",
            },
            verify=False,
        )

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        """Send a chat-completion request. Returns the parsed JSON response."""
        payload: dict[str, Any] = {
            "model": model or self._cfg.reasoning_model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        resp = self._client.post(self._cfg.url, json=payload)
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HostedModelClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
