SOC Co-Pilot — Splunk app component
====================================

Closed-loop incident triage agent for Splunk. When a notable event fires, the
agent enriches it via the Splunk MCP Server, reasons with the Foundation-Sec
hosted model, writes a structured finding back to Splunk, and folds analyst
feedback into its few-shot memory.

This app ships:
  - Custom alert action: "SOC Co-Pilot Triage"
  - Modular input:       feedback_input (every 5 minutes)
  - Dashboard:           SOC Co-Pilot Triage Console (default view)

The agent itself is a Python package (`soc_copilot`) installed alongside this
app. See the parent repository README for setup.

Source: https://github.com/YOUR_GH_USER/splunk-soc-copilot
License: MIT
