"""`soc-copilot` command-line entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel

from .agent import TriageAgent, persist_finding
from .config import get_settings

# Ensure Unicode output (checkmarks, emoji) works on consoles that default to a
# legacy code page such as Windows cp1252 — degrade gracefully instead of crashing.
# Must run before the rich Console binds the stream.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

app = typer.Typer(help="SOC Co-Pilot — closed-loop incident triage for Splunk.")
console = Console()


def _load_notable(source: str) -> dict:
    if source == "demo":
        sample = Path(__file__).resolve().parents[2] / "examples" / "sample_notable.json"
        return json.loads(sample.read_text(encoding="utf-8"))
    p = Path(source)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    # Treat as raw JSON on the command line.
    return json.loads(source)


@app.command()
def triage(
    notable: str = typer.Option(..., "--notable", help="Path, raw JSON, or 'demo'."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Skip write-back to Splunk."),
    interactive: bool = typer.Option(False, "--interactive", help="Print the model transcript."),
) -> None:
    """Run the triage agent against a single notable event."""
    settings = get_settings()
    logging.basicConfig(level=settings.agent.log_level, format="%(asctime)s %(levelname)s %(name)s — %(message)s")

    payload = _load_notable(notable)
    console.print(Panel.fit(JSON.from_data(payload), title="Notable", border_style="cyan"))

    agent = TriageAgent(settings=settings)
    result = asyncio.run(agent.triage(payload))

    console.print(Panel.fit(JSON.from_data(result.finding), title="Finding", border_style="green"))
    console.print(f"[dim]Iterations: {result.iterations}[/dim]")

    if interactive:
        console.print(Panel.fit(JSON.from_data(result.transcript), title="Transcript", border_style="magenta"))

    if not dry_run:
        try:
            persist_finding(result.finding, settings=settings)
            console.print("[green]✓ Finding written to Splunk[/green]")
        except Exception as exc:  # surface but do not crash
            console.print(f"[red]✗ Could not write to Splunk: {exc}[/red]")
            sys.exit(2)


@app.command()
def feedback(
    signature: str = typer.Option(..., "--signature", help="Notable signature, e.g. 'Brute Force Access Behavior Detected::host'."),
    hypothesis: str = typer.Option(..., "--hypothesis", help="The finding hypothesis being rated."),
    rationale: str = typer.Option("", "--rationale", help="The finding rationale being rated."),
    rating: int = typer.Option(..., "--rating", help="+1 (useful) or -1 (rejected)."),
    notable_id: str = typer.Option("", "--notable-id", help="Optional notable/event id for traceability."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Skip write-back to Splunk."),
) -> None:
    """Record an analyst 👍/👎 — updates local few-shot memory and indexes feedback into Splunk."""
    from . import memory
    from .tools import write_feedback_to_splunk

    settings = get_settings()
    if rating not in (1, -1):
        console.print("[red]--rating must be +1 or -1[/red]")
        sys.exit(2)

    # 1. Update local few-shot memory so the next run is steered immediately.
    store = memory.load()
    store.add(
        memory.FeedbackExample(
            notable_signature=signature,
            hypothesis=hypothesis,
            rationale=rationale,
            rating=rating,
        )
    )
    memory.save(store)
    console.print("[green]✓ Local few-shot memory updated[/green]")

    # 2. Index the feedback event into Splunk to close the learning loop.
    event = {
        "notable_id": notable_id or None,
        "notable_signature": signature,
        "hypothesis": hypothesis,
        "rationale": rationale,
        "rating": rating,
    }
    if dry_run:
        console.print(Panel.fit(JSON.from_data(event), title="Feedback (dry-run)", border_style="yellow"))
        return
    try:
        resp = write_feedback_to_splunk(event, settings=settings)
        console.print(f"[green]✓ Feedback indexed to Splunk via {resp.get('transport')}[/green]")
    except Exception as exc:  # surface but do not crash
        console.print(f"[red]✗ Could not write feedback to Splunk: {exc}[/red]")
        sys.exit(2)


@app.command()
def seed(
    index: str = typer.Option("main", "--index", help="Target Splunk index (default: main)."),
) -> None:
    """Ingest the demo security logs + notable into Splunk via HEC."""
    import csv
    from datetime import datetime

    from .splunk_hec import HECClient, HECError

    settings = get_settings()
    if not settings.hec.enabled:
        console.print("[red]✗ HEC is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN.[/red]")
        sys.exit(2)

    examples = Path(__file__).resolve().parents[2] / "examples"

    def _ts(value: str) -> float:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

    with (examples / "sample_logs.csv").open(newline="", encoding="utf-8") as fh:
        logs = list(csv.DictReader(fh))
    notable = json.loads((examples / "sample_notable.json").read_text(encoding="utf-8"))

    try:
        with HECClient(settings.hec) as hec:
            for row in logs:
                hec.send(
                    row,
                    index=index,
                    sourcetype="wineventlog:security",
                    source="seed:sample_logs",
                    host=row.get("dest", "win-app-07.corp.example"),
                    timestamp=_ts(row["_time"]),
                )
            hec.send(
                notable,
                index=index,
                sourcetype="notable",
                source="seed:sample_notable",
                host=notable.get("dest", "win-app-07.corp.example"),
                timestamp=_ts(notable["_time"]),
            )
    except HECError as exc:
        console.print(f"[red]✗ HEC ingest failed: {exc}[/red]")
        sys.exit(2)

    console.print(
        f"[green]✓ Seeded {len(logs)} security events + 1 notable into index={index} via HEC[/green]"
    )


@app.command()
def version() -> None:
    """Print the package version."""
    from . import __version__

    console.print(__version__)


if __name__ == "__main__":
    app()
