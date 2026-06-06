"""Seed the demo investigation data into Splunk Cloud via HEC.

Pushes the raw Windows security logs (examples/sample_logs.csv) and the notable
event (examples/sample_notable.json) into Splunk so the SOC Co-Pilot agent has
something real to investigate. HEC (port 8088) works from a corporate network
without an 8089 IP allowlist.

Usage:
    python scripts/seed_sample_data.py
    python scripts/seed_sample_data.py --index main
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as a plain script without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dotenv import load_dotenv  # noqa: E402

from soc_copilot.config import get_settings  # noqa: E402
from soc_copilot.splunk_hec import HECClient, HECError  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LOGS_CSV = ROOT / "examples" / "sample_logs.csv"
NOTABLE_JSON = ROOT / "examples" / "sample_notable.json"


def _parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _load_logs() -> list[dict[str, str]]:
    with LOGS_CSV.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", default="main", help="Target Splunk index (default: main)")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env.local")
    settings = get_settings()

    if not settings.hec.enabled:
        print("HEC is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in .env.local.")
        return 1

    logs = _load_logs()
    notable = json.loads(NOTABLE_JSON.read_text(encoding="utf-8"))

    try:
        with HECClient(settings.hec) as hec:
            # 1. Raw Windows security events (wineventlog:security).
            for row in logs:
                hec.send(
                    row,
                    index=args.index,
                    sourcetype="wineventlog:security",
                    source="seed:sample_logs",
                    host=row.get("dest", "win-app-07.corp.example"),
                    timestamp=_parse_time(row["_time"]),
                )
            print(f"Ingested {len(logs)} raw security events -> index={args.index}")

            # 2. The notable event the agent will triage.
            hec.send(
                notable,
                index=args.index,
                sourcetype="notable",
                source="seed:sample_notable",
                host=notable.get("dest", "win-app-07.corp.example"),
                timestamp=_parse_time(notable["_time"]),
            )
            print(f"Ingested notable {notable['event_id']} -> index={args.index}")
    except HECError as exc:
        print(f"HEC ingest failed: {exc}")
        return 1

    print(
        "\nDone. Verify in Splunk Web (port 443):\n"
        f'  index={args.index} (source="seed:sample_logs" OR source="seed:sample_notable")\n'
        "  | sort - _time"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
