"""Tool layer exposed to the agent.

The Splunk MCP Server already advertises a rich tool catalog (search, lookup,
list_indexes, etc.) via `MCPClient.list_tools()`. This module adds a thin layer
of fallback / synthetic tools that don't naturally live in MCP — most notably
``write_finding`` which indexes the agent's final report back into Splunk via
the REST API, and ``record_evidence`` which buffers intermediate findings.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import Settings, get_settings


@dataclass
class EvidenceBuffer:
    """In-memory buffer of evidence the agent has gathered this run."""

    items: list[dict[str, Any]] = field(default_factory=list)

    def add(self, source: str, summary: str, payload: Any) -> None:
        self.items.append(
            {"ts": time.time(), "source": source, "summary": summary, "payload": payload}
        )

    def as_dict(self) -> list[dict[str, Any]]:
        return list(self.items)


def write_finding_to_splunk(
    finding: dict[str, Any],
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Index a finding back into Splunk.

    Prefers HEC (port 8088) because it works through a corporate firewall without
    an 8089 management-port IP allowlist. Falls back to the REST receivers/simple
    endpoint (port 8089) when HEC is not configured and direct REST is reachable.
    """
    s = settings or get_settings()

    if s.hec.enabled:
        from .splunk_hec import HECClient

        with HECClient(s.hec) as hec:
            body = hec.send(
                finding,
                index=s.agent.findings_index,
                sourcetype="soc_copilot:finding",
            )
        return {"status": "ok", "transport": "hec", "response": body}

    url = (
        f"{s.splunk.scheme}://{s.splunk.host}:{s.splunk.port}"
        f"/services/receivers/simple?index={s.agent.findings_index}&sourcetype=soc_copilot:finding"
    )
    resp = httpx.post(
        url,
        content=json.dumps(finding),
        auth=(s.splunk.username, s.splunk.password),
        verify=s.splunk.verify_ssl,
        timeout=30.0,
        headers={"Content-Type": "application/json"},
    )
    resp.raise_for_status()
    return {"status": "ok", "transport": "rest", "bytes": len(resp.content)}


def write_feedback_to_splunk(
    feedback: dict[str, Any],
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Index an analyst feedback event (closing the learning loop) into Splunk via HEC.

    The feedback index is consumed by the modular input / scheduled search that
    rebuilds the agent's few-shot memory, so each thumbs-up/down measurably steers
    future triage.
    """
    s = settings or get_settings()
    if not s.hec.enabled:
        raise RuntimeError(
            "HEC is not configured; feedback write requires SPLUNK_HEC_URL/SPLUNK_HEC_TOKEN."
        )
    from .splunk_hec import HECClient

    with HECClient(s.hec) as hec:
        body = hec.send(
            feedback,
            index=s.agent.feedback_index,
            sourcetype="soc_copilot:feedback",
        )
    return {"status": "ok", "transport": "hec", "response": body}


# Local-only tool descriptors merged into the MCP catalog before being sent to the model.
LOCAL_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "record_evidence",
            "description": (
                "Buffer a piece of evidence (search result snippet, lookup hit, IOC) "
                "that should appear in the final report's evidence section. Does not "
                "execute any search by itself."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Origin of the evidence (e.g. 'mcp:search')"},
                    "summary": {"type": "string", "description": "One-sentence summary"},
                    "payload": {"type": "object", "description": "Structured supporting data"},
                },
                "required": ["source", "summary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "score_anomaly",
            "description": (
                "Send a numeric metric series to the Splunk AI Toolkit / Cisco Deep "
                "Time Series Model and return an anomaly score in [0, 1]. Use this to "
                "decide whether a count, volume, or rate is unusual for the host/user."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "series_name": {"type": "string", "description": "Friendly label (e.g. 'failed_logons_per_min')"},
                    "values": {
                        "type": "array",
                        "items": {"type": "number"},
                        "description": "Time-ordered numeric samples",
                    },
                    "context": {"type": "string", "description": "Entity context (user/host) the series belongs to"},
                },
                "required": ["series_name", "values"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "final_report",
            "description": (
                "Emit the agent's final triage report. Calling this ends the agent loop "
                "and the report is written into the configured findings index."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "hypothesis": {"type": "string", "description": "Most likely root cause"},
                    "rationale": {"type": "string", "description": "Why this hypothesis ranks highest"},
                    "recommended_spl": {"type": "string", "description": "Validation/hunt SPL"},
                    "recommended_actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Concrete next steps for the analyst",
                    },
                },
                "required": ["severity", "hypothesis", "rationale"],
            },
        },
    },
]


def score_anomaly_via_aitk(values: list[float], *, settings: Settings | None = None) -> float:
    """Send a series to the Splunk AI Toolkit anomaly endpoint and return a score.

    Falls back to a simple z-score heuristic if the AITK endpoint is unreachable so
    the agent never blocks on infra issues.
    """
    s = settings or get_settings()
    url = (
        f"{s.splunk.scheme}://{s.splunk.host}:{s.splunk.port}"
        f"/services/aitk/anomaly/score"
    )
    try:
        resp = httpx.post(
            url,
            json={"values": values},
            auth=(s.splunk.username, s.splunk.password),
            verify=s.splunk.verify_ssl,
            timeout=15.0,
        )
        resp.raise_for_status()
        return float(resp.json().get("score", 0.0))
    except Exception:
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        var = sum((v - mean) ** 2 for v in values) / len(values)
        std = var ** 0.5 or 1.0
        z = abs(values[-1] - mean) / std
        return min(1.0, z / 4.0)
