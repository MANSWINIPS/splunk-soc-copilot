#!/usr/bin/env python
"""Splunk custom alert action — invokes the SOC Co-Pilot triage agent.

Splunk passes the notable event as a JSON payload on stdin. We deserialize it,
run the agent, and let the agent persist its finding back into Splunk.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

# Allow running outside the installed package (Splunk's alert-action runtime).
try:
    from soc_copilot.agent import TriageAgent, persist_finding
    from soc_copilot.config import get_settings
except ImportError:
    # Fallback: expect SOC_COPILOT_VENV to be set and added to sys.path by the operator.
    sys.stderr.write(
        "ERROR: soc_copilot package not importable. Install with `pip install -e .` "
        "into a venv that Splunk's python can see, or set SOC_COPILOT_VENV.\n"
    )
    sys.exit(2)


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    raw = sys.stdin.read()
    if not raw.strip():
        sys.stderr.write("No payload on stdin\n")
        return 2

    payload = json.loads(raw)
    notable = payload.get("result", payload)

    agent = TriageAgent(settings=get_settings())
    result = asyncio.run(agent.triage(notable))

    try:
        persist_finding(result.finding)
    except Exception as exc:  # alert actions should not crash Splunk's scheduler
        sys.stderr.write(f"persist_finding failed: {exc}\n")
        return 1

    sys.stdout.write(json.dumps({"status": "ok", "iterations": result.iterations}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
