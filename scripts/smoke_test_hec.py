"""Test HEC reachability against both possible Splunk Cloud URLs."""
from __future__ import annotations

import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv(".env.local")

host = os.environ["SPLUNK_HOST"]
token = os.environ["SPLUNK_HEC_TOKEN"]

candidates = [
    f"https://{host}/services/collector",
    f"https://http-inputs-{host}/services/collector",
]

payload = {"event": "soc-copilot smoke test", "sourcetype": "soc:copilot:test"}

for url in candidates:
    print(f"\n--- POST {url}")
    try:
        r = requests.post(
            url,
            headers={"Authorization": f"Splunk {token}"},
            json=payload,
            timeout=15,
        )
        print(f"  status: {r.status_code}")
        print(f"  body:   {r.text[:200]}")
    except requests.RequestException as exc:
        print(f"  ERROR: {exc}")
