#!/usr/bin/env python
"""Splunk modular input — folds analyst feedback into the agent's few-shot memory.

Runs on the schedule configured in inputs.conf (default: every 5 minutes). Reads
recent events from `index=soc_copilot_feedback`, converts each one to a
FeedbackExample, and persists the updated memory file.
"""

from __future__ import annotations

import json
import sys
import time

try:
    import splunklib.client as splunkclient
    import splunklib.results as splunkresults
except ImportError:
    sys.stderr.write("splunk-sdk not available in Splunk's python environment\n")
    sys.exit(2)

try:
    from soc_copilot import memory
    from soc_copilot.config import get_settings
except ImportError:
    sys.stderr.write("soc_copilot package not importable from Splunk python\n")
    sys.exit(2)


SEARCH = (
    'search (index={idx} OR index=main) sourcetype="soc_copilot:feedback" earliest=-1h '
    '| table _time, notable_signature, hypothesis, rationale, rating'
)


def main() -> int:
    s = get_settings()
    service = splunkclient.connect(
        host=s.splunk.host,
        port=s.splunk.port,
        username=s.splunk.username,
        password=s.splunk.password,
        scheme=s.splunk.scheme,
    )
    job = service.jobs.oneshot(SEARCH.format(idx=s.agent.feedback_index))
    reader = splunkresults.JSONResultsReader(job)

    store = memory.load()
    added = 0
    for item in reader:
        if not isinstance(item, dict):
            continue
        rating = int(item.get("rating", 0))
        if rating == 0:
            continue
        store.add(
            memory.FeedbackExample(
                notable_signature=item.get("notable_signature", "unknown"),
                hypothesis=item.get("hypothesis", ""),
                rationale=item.get("rationale", ""),
                rating=1 if rating > 0 else -1,
                weight=1.0,
            )
        )
        added += 1

    memory.save(store)
    sys.stdout.write(
        json.dumps({"event": "feedback_input", "added": added, "ts": time.time()}) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
