"""Tests for the HEC client, including the Cloud index-fallback behavior."""

from __future__ import annotations

import json

import httpx
import pytest

from soc_copilot.config import HECConfig
from soc_copilot.splunk_hec import HECClient, HECError


def _client_with_handler(handler) -> HECClient:
    cfg = HECConfig(url="https://example.splunkcloud.com:8088/services/collector", token="tok")
    client = HECClient(cfg)
    # Swap the real transport for a mock one.
    client._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Splunk tok"},
    )
    return client


def test_send_success() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"text": "Success", "code": 0})

    with _client_with_handler(handler) as hec:
        body = hec.send({"a": 1}, index="main", sourcetype="st")

    assert body["code"] == 0
    envelope = json.loads(seen["body"])
    assert envelope["index"] == "main"
    assert envelope["sourcetype"] == "st"
    assert envelope["event"] == {"a": 1}


def test_index_fallback_on_code_7() -> None:
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        envelope = json.loads(request.content.decode())
        calls.append(envelope)
        if envelope.get("index") == "soc_copilot_feedback":
            return httpx.Response(
                400, json={"text": "Incorrect index", "code": 7, "invalid-event-number": 1}
            )
        return httpx.Response(200, json={"text": "Success", "code": 0})

    with _client_with_handler(handler) as hec:
        body = hec.send({"rating": 1}, index="soc_copilot_feedback", sourcetype="st")

    assert body["code"] == 0
    assert body["_routed_to"] == "main"
    assert body["_intended_index"] == "soc_copilot_feedback"
    # First attempt to dedicated index, second routed to main with intended-index tag.
    assert calls[0]["index"] == "soc_copilot_feedback"
    assert calls[1]["index"] == "main"
    assert calls[1]["event"]["_intended_index"] == "soc_copilot_feedback"


def test_non_index_error_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Invalid token")

    with _client_with_handler(handler) as hec:
        with pytest.raises(HECError):
            hec.send({"a": 1}, index="main")


def test_disabled_config_raises() -> None:
    with pytest.raises(HECError):
        HECClient(HECConfig(url="", token=""))
