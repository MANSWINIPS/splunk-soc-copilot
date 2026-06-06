"""Quick smoke test: confirm we can reach Splunk Cloud with the token."""
from __future__ import annotations

import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv(".env.local")

host = os.environ["SPLUNK_HOST"]
port = os.environ.get("SPLUNK_PORT", "8089")
token = os.environ["SPLUNK_MCP_TOKEN"]
verify = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "true"

url = f"https://{host}:{port}/services/server/info?output_mode=json"
print(f"GET {url}")

try:
    r = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
        timeout=15,
    )
except requests.RequestException as exc:
    print(f"NETWORK ERROR: {exc}")
    sys.exit(1)

print(f"Status: {r.status_code}")
if r.status_code != 200:
    print("Body:", r.text[:500])
    sys.exit(2)

data = r.json()
content = data["entry"][0]["content"]
print(f"Splunk version: {content.get('version')}")
print(f"Server name:    {content.get('serverName')}")
print(f"Server roles:   {content.get('server_roles')}")
print("OK")
