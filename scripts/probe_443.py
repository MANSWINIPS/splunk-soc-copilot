"""Probe which transport reaches splunkd REST from this (corporate) laptop.

Splunk Cloud blocks the management port (8089) by IP allowlist, but the web
tier (443) proxies REST calls to splunkd via /<locale>/splunkd/__raw/...
This script tries several auth/transport combos and reports what works so we
can pick the agent's data path.
"""

from __future__ import annotations

import os
import sys

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings()
load_dotenv(".env.local")

HOST = os.environ["SPLUNK_HOST"]
USER = os.environ["SPLUNK_USERNAME"]
PWD = os.environ["SPLUNK_PASSWORD"]
TOKEN = os.environ.get("SPLUNK_MCP_TOKEN", "")

TIMEOUT = 15


def line(label: str, fn) -> None:
    try:
        code, body = fn()
        print(f"[{label}] status={code} body={body[:160]!r}")
    except Exception as exc:  # noqa: BLE001
        print(f"[{label}] ERROR {type(exc).__name__}: {exc}")


def t_8089_bearer():
    r = requests.get(
        f"https://{HOST}:8089/services/server/info?output_mode=json",
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=TIMEOUT,
        verify=False,
    )
    return r.status_code, r.text


def t_443_raw_bearer():
    r = requests.get(
        f"https://{HOST}/en-US/splunkd/__raw/services/server/info?output_mode=json",
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=TIMEOUT,
        verify=False,
    )
    return r.status_code, r.text


def t_443_raw_basic():
    r = requests.get(
        f"https://{HOST}/en-US/splunkd/__raw/services/server/info?output_mode=json",
        auth=(USER, PWD),
        timeout=TIMEOUT,
        verify=False,
    )
    return r.status_code, r.text


def t_443_login_session():
    s = requests.Session()
    # 1. prime cookies + grab the cval (login form key)
    g = s.get(f"https://{HOST}/en-US/account/login", timeout=TIMEOUT, verify=False)
    cval = ""
    for part in g.text.split("cval"):
        if 'value="' in part[:40]:
            cval = part.split('value="', 1)[1].split('"', 1)[0]
            break
    # 2. post credentials
    p = s.post(
        f"https://{HOST}/en-US/account/login",
        data={"username": USER, "password": PWD, "cval": cval, "set_has_logged_in": "false"},
        timeout=TIMEOUT,
        verify=False,
        allow_redirects=False,
    )
    # 3. pull the CSRF form key cookie for the raw proxy
    form_key = s.cookies.get_dict().get(
        next((k for k in s.cookies.get_dict() if k.startswith("splunkweb_csrf_token")), ""),
        "",
    )
    headers = {"X-Splunk-Form-Key": form_key} if form_key else {}
    r = s.get(
        f"https://{HOST}/en-US/splunkd/__raw/services/server/info?output_mode=json",
        headers=headers,
        timeout=TIMEOUT,
        verify=False,
    )
    return r.status_code, f"login={p.status_code} cookies={list(s.cookies.get_dict())} -> {r.text}"


if __name__ == "__main__":
    print(f"host={HOST} user={USER}")
    line("8089 bearer ", t_8089_bearer)
    line("443 __raw bearer", t_443_raw_bearer)
    line("443 __raw basic ", t_443_raw_basic)
    line("443 login session", t_443_login_session)
    sys.exit(0)
