"""Smoke tests for the agent loop, fully mocked."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soc_copilot.agent import TriageAgent
from soc_copilot.hosted_model import HostedModelClient


SAMPLE = json.loads(
    (Path(__file__).resolve().parents[1] / "examples" / "sample_notable.json").read_text()
)


def _fake_model_response(tool_name: str, args: dict) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": tool_name,
                                "arguments": json.dumps(args),
                            },
                        }
                    ],
                }
            }
        ]
    }


@pytest.mark.asyncio
async def test_agent_terminates_on_final_report() -> None:
    fake_model = MagicMock(spec=HostedModelClient)
    fake_model.chat.side_effect = [
        _fake_model_response(
            "record_evidence",
            {"source": "mcp:search", "summary": "142 failed logons", "payload": {"count": 142}},
        ),
        _fake_model_response(
            "final_report",
            {
                "severity": "high",
                "hypothesis": "Successful brute-force from external IP",
                "rationale": "142 failures followed by a 4624 success from the same src.",
                "recommended_spl": "search index=wineventlog user=j.doe src=203.0.113.47",
                "recommended_actions": ["Disable j.doe", "Block 203.0.113.47 at edge"],
            },
        ),
    ]

    fake_mcp = AsyncMock()
    fake_mcp.list_tools.return_value = []
    fake_mcp.call_tool.return_value = MagicMock(content="ok", is_error=False)
    fake_mcp.__aenter__.return_value = fake_mcp
    fake_mcp.__aexit__.return_value = None

    with patch("soc_copilot.agent.MCPClient", return_value=fake_mcp):
        agent = TriageAgent(model_client=fake_model)
        result = await agent.triage(SAMPLE)

    assert result.finding["severity"] == "high"
    assert "brute-force" in result.finding["hypothesis"].lower()
    assert len(result.evidence) == 1
    assert result.iterations == 2


@pytest.mark.asyncio
async def test_agent_degrades_when_mcp_unreachable() -> None:
    """If the MCP Server (8089) can't be reached, the agent still produces a finding."""
    fake_model = MagicMock(spec=HostedModelClient)
    fake_model.chat.side_effect = [
        _fake_model_response(
            "final_report",
            {
                "severity": "medium",
                "hypothesis": "Likely brute force; MCP enrichment unavailable",
                "rationale": "Reasoned from the notable alone; MCP Server was unreachable.",
            },
        ),
    ]

    def _boom(*_args, **_kwargs):
        raise ConnectionError("8089 unreachable")

    with patch("soc_copilot.agent.MCPClient", side_effect=_boom):
        agent = TriageAgent(model_client=fake_model)
        result = await agent.triage(SAMPLE)

    assert result.finding["severity"] == "medium"
    assert result.iterations == 1
