# SOC Co-Pilot — Splunk App

Copy this directory to `$SPLUNK_HOME/etc/apps/soc_copilot/` and restart Splunk.

## Contents

- `default/app.conf` — app metadata
- `default/alert_actions.conf` — registers the **SOC Co-Pilot Triage** custom alert action
- `default/inputs.conf` — schedules `feedback_input.py` every 5 minutes
- `bin/trigger_agent.py` — invoked by the alert action; runs the agent
- `bin/feedback_input.py` — modular input that updates few-shot memory

## Prerequisites

The `soc_copilot` Python package (from the parent repo) must be importable from the
Python interpreter that Splunk uses for its scripts. Two options:

1. **`pip install -e .`** into Splunk's bundled Python:
   ```powershell
   & "C:\Program Files\Splunk\bin\splunk.exe" cmd python -m pip install -e <repo-root>
   ```
2. **Set `SOC_COPILOT_VENV`** to a venv path and modify `trigger_agent.py` /
   `feedback_input.py` to insert that venv's `site-packages` onto `sys.path`.

Option 1 is simpler for the hackathon demo.
