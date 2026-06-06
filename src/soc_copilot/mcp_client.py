"""Client for the Splunk MCP Server.

Uses the official `mcp` Python package over streamable-HTTP transport with
bearer-token auth (OAuth is in Controlled Availability per Splunk docs).
"""

from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from .config import MCPConfig, get_settings


@dataclass
class ToolResult:
    name: str
    content: Any
    is_error: bool = False


class MCPClient:
    """Async client over the Splunk MCP Server."""

    def __init__(self, cfg: MCPConfig | None = None) -> None:
        self._cfg = cfg or get_settings().mcp
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "MCPClient":
        self._stack = AsyncExitStack()
        headers = {"Authorization": f"Bearer {self._cfg.token}"} if self._cfg.token else None
        read, write, _ = await self._stack.enter_async_context(
            streamablehttp_client(self._cfg.url, headers=headers)
        )
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    async def list_tools(self) -> list[dict[str, Any]]:
        assert self._session is not None, "MCPClient must be used as async context manager"
        result = await self._session.list_tools()
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description or "",
                    "parameters": t.inputSchema or {"type": "object", "properties": {}},
                },
            }
            for t in result.tools
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        assert self._session is not None, "MCPClient must be used as async context manager"
        result = await self._session.call_tool(name, arguments=arguments)
        content: Any
        if result.content and len(result.content) == 1 and hasattr(result.content[0], "text"):
            content = result.content[0].text
        else:
            content = [getattr(c, "text", str(c)) for c in (result.content or [])]
        return ToolResult(name=name, content=content, is_error=bool(result.isError))
