"""Core ReAct-style agent loop.

The agent receives a Splunk notable, then iteratively:
  1. Asks the Hosted Model for the next action (tool call or final report).
  2. Resolves the call — MCP tools go to the Splunk MCP Server; the two synthetic
     tools (`record_evidence`, `final_report`) are handled locally.
  3. Feeds the result back into the conversation.

The loop terminates on `final_report` or when ``max_iterations`` is reached.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from . import memory
from .config import Settings, get_settings
from .hosted_model import ChatMessage, HostedModelClient
from .mcp_client import MCPClient
from .tools import LOCAL_TOOLS, EvidenceBuffer, score_anomaly_via_aitk, write_finding_to_splunk

log = logging.getLogger("soc_copilot.agent")


SYSTEM_PROMPT = """You are SOC Co-Pilot, an autonomous Tier-1 SOC analyst embedded in Splunk.

Goal: triage the provided notable event end-to-end. Produce a ranked hypothesis,
supporting evidence, and a concrete next action for the human analyst.

Operating rules:
- Use MCP tools to pull additional context (related events, user activity, host
  process trees, threat intel). Prefer narrow, indexed searches over wildcards.
- Buffer each meaningful finding with `record_evidence` before moving on.
- When you have enough evidence (or after at most a few tool calls), call
  `final_report` with severity, hypothesis, rationale, validation SPL, and
  recommended actions.
- Do NOT speculate beyond the evidence. If the data is inconclusive, say so
  explicitly in the rationale and recommend the SPL that would resolve it.
"""


@dataclass
class AgentResult:
    finding: dict[str, Any]
    evidence: list[dict[str, Any]]
    iterations: int
    transcript: list[dict[str, Any]]


class TriageAgent:
    def __init__(
        self,
        *,
        settings: Settings | None = None,
        model_client: HostedModelClient | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._model = model_client or HostedModelClient(self._settings.hosted)

    async def triage(self, notable: dict[str, Any]) -> AgentResult:
        signature = memory.signature_for(notable)
        few_shot = memory.render_few_shot(signature)

        evidence = EvidenceBuffer()
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=SYSTEM_PROMPT),
        ]
        if few_shot:
            messages.append(ChatMessage(role="system", content=few_shot))
        messages.append(
            ChatMessage(
                role="user",
                content=f"Triage this notable event (JSON):\n{json.dumps(notable, indent=2)}",
            )
        )

        # MCP runs on the Splunk management port (8089), which may be unreachable
        # from a firewalled/non-allowlisted network. Degrade gracefully: if the
        # MCP Server can't be reached, continue with the local tools only and let
        # the model reason over the notable + few-shot memory.
        mcp: MCPClient | None = None
        mcp_tools: list[dict[str, Any]] = []
        try:
            mcp = await MCPClient(self._settings.mcp).__aenter__()
            mcp_tools = await mcp.list_tools()
        except Exception as exc:  # noqa: BLE001 — connectivity is environment-dependent
            log.warning("MCP Server unavailable (%s); running with local tools only", exc)
            mcp = None

        all_tools = mcp_tools + LOCAL_TOOLS
        try:
            for i in range(1, self._settings.agent.max_iterations + 1):
                log.info("agent iteration %d", i)
                response = self._model.chat(messages, tools=all_tools)
                choice = response["choices"][0]["message"]
                messages.append(
                    ChatMessage(role="assistant", content=choice.get("content") or "")
                )

                tool_calls = choice.get("tool_calls") or []
                if not tool_calls:
                    # Model produced free text without a tool call — treat as final.
                    finding = {
                        "severity": "info",
                        "hypothesis": choice.get("content", "(no hypothesis)"),
                        "rationale": "Model returned free-form output without final_report.",
                    }
                    return self._finalize(notable, finding, evidence, i, messages)

                for call in tool_calls:
                    fname = call["function"]["name"]
                    args = json.loads(call["function"].get("arguments") or "{}")

                    if fname == "final_report":
                        return self._finalize(notable, args, evidence, i, messages)

                    if fname == "record_evidence":
                        evidence.add(
                            args.get("source", "agent"),
                            args.get("summary", ""),
                            args.get("payload", {}),
                        )
                        result_content: Any = {"status": "buffered"}
                    elif fname == "score_anomaly":
                        score = score_anomaly_via_aitk(
                            args.get("values", []), settings=self._settings
                        )
                        evidence.add(
                            source="aitk:anomaly",
                            summary=f"Anomaly score for {args.get('series_name', 'series')} = {score:.3f}",
                            payload={"score": score, "context": args.get("context", "")},
                        )
                        result_content = {"score": score}
                    else:
                        if mcp is None:
                            result_content = {
                                "error": (
                                    f"MCP Server unreachable; cannot run '{fname}'. "
                                    "Reason over the notable and available evidence instead, "
                                    "then call final_report."
                                )
                            }
                        else:
                            tr = await mcp.call_tool(fname, args)
                            result_content = tr.content

                    messages.append(
                        ChatMessage(
                            role="tool",
                            name=fname,
                            content=json.dumps(result_content)
                            if not isinstance(result_content, str)
                            else result_content,
                        )
                    )

            # Loop exhausted without final_report — emit a placeholder finding.
            return self._finalize(
                notable,
                {
                    "severity": "info",
                    "hypothesis": "Investigation incomplete",
                    "rationale": f"Reached max_iterations={self._settings.agent.max_iterations}.",
                },
                evidence,
                self._settings.agent.max_iterations,
                messages,
            )
        finally:
            if mcp is not None:
                await mcp.__aexit__(None, None, None)

    def _finalize(
        self,
        notable: dict[str, Any],
        finding_args: dict[str, Any],
        evidence: EvidenceBuffer,
        iterations: int,
        messages: list[ChatMessage],
    ) -> AgentResult:
        finding: dict[str, Any] = {
            "notable_id": notable.get("event_id") or notable.get("id"),
            "rule_name": notable.get("rule_name") or notable.get("search_name"),
            "severity": finding_args.get("severity", "info"),
            "hypothesis": finding_args.get("hypothesis", ""),
            "rationale": finding_args.get("rationale", ""),
            "recommended_spl": finding_args.get("recommended_spl"),
            "recommended_actions": finding_args.get("recommended_actions", []),
            "evidence": evidence.as_dict(),
        }
        return AgentResult(
            finding=finding,
            evidence=evidence.as_dict(),
            iterations=iterations,
            transcript=[m.to_dict() for m in messages],
        )


def persist_finding(finding: dict[str, Any], *, settings: Settings | None = None) -> dict[str, Any]:
    """Public helper so the alert action can persist without touching the agent class."""
    return write_finding_to_splunk(finding, settings=settings)
