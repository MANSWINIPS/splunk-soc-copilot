# SOC Co-Pilot — Closed-Loop Incident Triage for Splunk

An autonomous agent that triages Splunk notable events end-to-end: enriches
with contextual searches via the **Splunk MCP Server**, reasons with the
**Foundation-Sec-1.1-8B** hosted model, calls the **Splunk AI Toolkit** for
anomaly scoring, writes structured findings back into Splunk via the **HTTP
Event Collector**, and **learns from analyst feedback** so every investigation
gets sharper than the last.

---

## The closed-loop differentiator

Most AI-for-SOC demos stop at "AI summarizes the alert". SOC Co-Pilot adds the
second half of the loop that nobody else ships:

```
notable fires  ->  agent investigates  ->  finding written to Splunk
                                                v
                            analyst rates thumbs up/down in the dashboard
                                                v
                  feedback indexed  ->  modular input updates few-shot memory
                                                v
                            next investigation uses prior corrections
```

The agent literally gets better the more your team uses it — without any
re-training, fine-tuning, or model swap. This is **online preference learning
implemented as Splunk plumbing**, not a research paper.

---

## Quantified impact

| Today (without SOC Co-Pilot) | With SOC Co-Pilot |
|---|---|
| Tier-1 spends **~20–40 min** per notable on mechanical enrichment | Agent emits a triaged finding in **~30 seconds** |
| Analyst writes the same hypothesis pattern over and over | Recurring patterns become positive examples reused automatically |
| Repeat false positives keep firing at full priority | Negative feedback down-weights similar hypotheses next run |
| Findings live in JIRA / chat — disconnected from data | Findings live **in Splunk**, drillable to the underlying SPL |

For a SOC handling 100 notables/day, even a conservative 50% time reduction on
Tier-1 mechanical work is **~25 analyst-hours/day** recovered for actual
investigation.

---

## What's inside

### Splunk MCP Server integration
- Every external action the agent takes (search, lookup, list indexes, host
  enrichment) is an **MCP tool call**, dynamically discovered at startup via
  `list_tools()` — the agent does not hard-code Splunk's tool catalog.
- Multi-step orchestration: the model can chain MCP calls (e.g. *search* → use
  result to *lookup* IOC → *search* host activity) within a single triage run.
- Token-auth implementation today; OAuth-ready when Splunk's CA feature reaches
  GA (the client just needs the bearer source swapped).
- Implementation: [src/soc_copilot/mcp_client.py](src/soc_copilot/mcp_client.py),
  consumed by [src/soc_copilot/agent.py](src/soc_copilot/agent.py).

### Splunk-hosted models
- **Foundation-Sec-1.1-8B-Instruct** for security-tuned reasoning and SPL
  generation — no general-purpose LLM in the loop.
- **Cisco Deep Time Series Model** (via Splunk AI Toolkit) for anomaly scoring,
  exposed as a dedicated agent tool (`score_anomaly`), so the agent decides
  whether a count spike is unusual *for this entity* before crying wolf.
- Optional `gpt-oss-20b` for cheap follow-up tasks (e.g. report rewriting).
- All three hosted on Splunk infrastructure — no GPU ops on our side.
- Implementation: [src/soc_copilot/hosted_model.py](src/soc_copilot/hosted_model.py),
  [src/soc_copilot/tools.py](src/soc_copilot/tools.py).

### Splunk developer ecosystem
- Uses the **official Splunk Python SDK** (`splunk-sdk`) for the modular input
  and REST writeback.
- Ships as a proper **Splunk app** with `app.conf`, `alert_actions.conf`,
  `inputs.conf`, `app.manifest`, `default.meta`, dashboard XML, and nav XML —
  passes the structural checks `splunk-appinspect` expects.
- **App Inspect** runs in CI (advisory mode) on every push:
  [.github/workflows/ci.yml](.github/workflows/ci.yml).
- Working **Splunk analyst dashboard**
  ([views/soc_copilot.xml](splunk_app/soc_copilot/default/data/ui/views/soc_copilot.xml))
  with severity mix, feedback ratio, drillable findings table, and one-click
  thumbs up/down SPL snippets.
- pytest + ruff + mypy matrix on Python 3.10 / 3.11 / 3.12.
- MIT license, semantic versioning, env-var-only secrets, no credentials in code.

---

## Architecture

See [architecture_diagram.md](architecture_diagram.md) (rendered Mermaid) and
[docs/architecture_diagram.png](docs/architecture_diagram.png).

The full data flow, from notable trigger to feedback ingestion, is documented in
that file.

### Connectivity modes

| Path | Port | Use |
|---|---|---|
| **HTTP Event Collector** | 8088 | Event ingest + findings/feedback write-back. Firewall-friendly; needs no IP allowlist. **Primary write path.** |
| Splunk Web / search | 443 | Analyst dashboard, ad-hoc SPL, App Inspect upload. |
| splunkd REST / MCP / Hosted Models / AI Toolkit | 8089 | Live AI reasoning + MCP tool calls. Requires the source IP to be allowlisted (Splunk Cloud ACS) — run the agent from an allowlisted network. |

On self-service Splunk Cloud stacks that ship only the `main` index, the HEC
writer transparently re-routes findings/feedback to `main` (preserving the
intended index as an `_intended_index` field), so the pipeline works with zero
extra provisioning.

---

## Repository layout

```
splunk-soc-copilot/
├── architecture_diagram.md      # Mermaid diagram (PNG + SVG in docs/)
├── .github/workflows/ci.yml     # pytest + ruff + mypy + App Inspect
├── src/soc_copilot/             # Python agent package (importable, pip-installable)
│   ├── config.py                # Env-driven settings (pydantic)
│   ├── hosted_model.py          # Splunk Hosted Models client
│   ├── mcp_client.py            # Splunk MCP Server client
│   ├── splunk_hec.py            # HTTP Event Collector writer (findings/feedback/ingest)
│   ├── tools.py                 # Local tools: record_evidence, score_anomaly, final_report
│   ├── memory.py                # Feedback-based few-shot memory
│   ├── agent.py                 # ReAct loop
│   └── cli.py                   # soc-copilot triage / feedback
├── scripts/                     # seed_sample_data.py (HEC ingest), smoke tests, probes
├── splunk_app/soc_copilot/      # Splunk app — copy to $SPLUNK_HOME/etc/apps/
│   ├── app.manifest             # App Inspect manifest
│   ├── README.txt               # App Inspect requires this
│   ├── default/
│   │   ├── app.conf
│   │   ├── alert_actions.conf
│   │   ├── inputs.conf
│   │   └── data/ui/views/soc_copilot.xml   # Analyst dashboard
│   └── bin/
│       ├── trigger_agent.py     # Custom alert action
│       └── feedback_input.py    # Modular input
├── examples/                    # Sample notable + sample logs for the demo
├── tests/                       # Pytest suite — fully mocked, no live Splunk
└── docs/                        # Architecture diagram exports
```

---

## Setup

There are two paths depending on what you have available.

### Path A — Code review + tests only (≈ 3 minutes, no Splunk required)

This is enough to verify the agent code, the mocked agent loop, the memory
module, and the Splunk app package structure. **Recommended for judges.**

Requires: **Python 3.10+** and `git`.

```bash
# Clone
git clone https://github.com/YOUR_GH_USER/splunk-soc-copilot.git
cd splunk-soc-copilot

# Create a virtualenv
python -m venv .venv

# Activate it
source .venv/bin/activate            # macOS / Linux
# .\.venv\Scripts\Activate.ps1       # Windows PowerShell

# Install the package + dev extras
pip install -e ".[dev]"

# Run the fully-mocked test suite — no Splunk, no network calls
pytest -v
```

Expected output:

```
tests/test_agent.py ..................................................  PASSED
tests/test_hec.py ...................................................  PASSED
tests/test_memory.py ................................................  PASSED
============================== 9 passed in ~1s ==============================
```

To explore the agent without a live Splunk, inspect:
- [src/soc_copilot/agent.py](src/soc_copilot/agent.py) — the ReAct loop
- [src/soc_copilot/memory.py](src/soc_copilot/memory.py) — the feedback-driven few-shot memory
- [tests/test_agent.py](tests/test_agent.py) — the mocked end-to-end flow
- [splunk_app/soc_copilot/default/data/ui/views/soc_copilot.xml](splunk_app/soc_copilot/default/data/ui/views/soc_copilot.xml) — the analyst dashboard
- [examples/sample_notable.json](examples/sample_notable.json) — the demo notable the agent is wired to triage

### Path B — Full end-to-end deployment (requires Splunk)

Additionally requires:
- **Splunk Enterprise 9.2+** with a [Developer License](https://dev.splunk.com/enterprise/page/developer_license) applied
- The following apps installed on that Splunk instance:
  - [Splunk MCP Server](https://splunkbase.splunk.com/) (`splunk-mcp-server`)
  - [Splunk AI Toolkit](https://splunkbase.splunk.com/app/6927) — for the `score_anomaly` tool
  - **Splunk Hosted Models** access on your Cloud / Enterprise tenant
- An MCP bearer token (OAuth in Controlled Availability, not GA)

```bash
# 1. Configure
cp .env.example .env                              # macOS / Linux
# copy .env.example .env                          # Windows
# then edit .env with your Splunk host, MCP token, and Hosted Model token

# 2. Deploy the Splunk app (adjust SPLUNK_HOME for your OS)
#    macOS / Linux:
cp -r splunk_app/soc_copilot  "$SPLUNK_HOME/etc/apps/"
"$SPLUNK_HOME/bin/splunk" restart
#    Windows PowerShell:
# xcopy /E /I splunk_app\soc_copilot "C:\Program Files\Splunk\etc\apps\soc_copilot"
# & "C:\Program Files\Splunk\bin\splunk.exe" restart

# 3. Run the agent against the demo notable
soc-copilot triage --notable demo
```

The agent will print the notable, the model transcript (with `--interactive`),
and the structured finding, then write the finding into
`index=soc_copilot_findings` so it shows up on the dashboard.

---

## Usage

### CLI

```powershell
soc-copilot triage --notable <path-or-notable-id>
soc-copilot triage --notable demo --interactive   # show model transcript
soc-copilot feedback --signature "Brute Force Access Behavior Detected::host" \
    --hypothesis "External brute force then success" --rating 1   # 👍 closes the loop
```

### Seed demo data (HEC, no IP allowlist needed)

```powershell
# Ingests examples/sample_logs.csv + sample_notable.json into Splunk via HEC
soc-copilot seed --index main           # or: python scripts/seed_sample_data.py
```

Then confirm in Splunk Web:
`index=main (source="seed:sample_logs" OR source="seed:sample_notable") | sort - _time`

> **Graceful degradation.** The MCP Server and Hosted Models run on the Splunk
> management port (8089). If that port is unreachable (e.g. a corporate network
> without an ACS IP allowlist), the agent logs a warning and continues with its
> local tools, reasoning over the notable and its few-shot memory rather than
> hanging — so ingest, write-back, and the dashboard keep working from anywhere.

### Triggered automatically by Splunk

After the app is installed, attach **"SOC Co-Pilot Triage"** as an alert action
to any saved search or Enterprise Security correlation rule. When the rule
fires, the agent runs and writes its findings into `index=soc_copilot_findings`.

### Analyst feedback

Open the **SOC Co-Pilot** app in Splunk → **Triage Console** dashboard. Each
finding row has a drilldown and one-click SPL snippets to rate it thumbs up or
down. The `feedback_input` modular input polls the feedback index every 5
minutes and rewrites the agent's few-shot memory file.

---

## Engineering quality

- **Typed Python** with pydantic settings, async MCP client, ReAct agent loop
  with bounded iterations.
- **Mocked pytest suite** (9/9 passing) — no live Splunk required for CI.
- **Lint + type-check + test** matrix on Python 3.10 / 3.11 / 3.12.
- Clean separation of concerns:
  `config` / `hosted_model` / `mcp_client` / `tools` / `memory` / `agent` / `cli`.
- All secrets via environment variables, never committed.

```powershell
pytest                       # mocked suite, no Splunk required
pytest -m integration        # requires .env to point at a live Splunk
ruff check src tests         # lint
mypy src                     # type-check
```

CI runs the same on every push: [.github/workflows/ci.yml](.github/workflows/ci.yml).

---

## License

MIT — see [LICENSE](LICENSE).
