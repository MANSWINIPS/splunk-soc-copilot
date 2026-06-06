"""HTTP Event Collector (HEC) client.

HEC (port 8088) is the one Splunk write path that works from a corporate
network without an 8089 management-port IP allowlist. The agent uses it to:
  - ingest sample / live security events into an investigation index, and
  - write its findings and analyst feedback back into Splunk (closed loop).

The corporate proxy performs TLS interception, so ``verify_ssl`` is typically
False on this stack (controlled by SPLUNK_VERIFY_SSL).
"""

from __future__ import annotations

import time
from typing import Any, Iterable

import httpx

from .config import HECConfig, get_settings


class HECError(RuntimeError):
    """Raised when the HEC endpoint rejects an event batch."""


class HECClient:
    """Thin client over the Splunk HTTP Event Collector ``/services/collector`` API."""

    # Splunk Cloud self-service stacks ship only the `main` index and a default HEC
    # token scoped to it. When a dedicated index isn't provisioned, HEC returns code 7
    # ("Incorrect index"); we transparently re-route to this index so the demo works
    # out of the box. The intended index is preserved as a `_intended_index` field.
    _FALLBACK_INDEX = "main"

    def __init__(self, cfg: HECConfig | None = None, *, timeout: float = 30.0) -> None:
        self._cfg = cfg or get_settings().hec
        if not self._cfg.enabled:
            raise HECError(
                "HEC is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in .env.local."
            )
        self._client = httpx.Client(
            timeout=timeout,
            headers={"Authorization": f"Splunk {self._cfg.token}"},
            verify=self._cfg.verify_ssl,
        )

    def send(
        self,
        event: Any,
        *,
        index: str | None = None,
        sourcetype: str | None = None,
        source: str = "soc_copilot",
        host: str = "soc-copilot",
        timestamp: float | None = None,
    ) -> dict[str, Any]:
        """Send a single event. ``event`` may be a dict (JSON) or a string (raw)."""
        return self.send_batch(
            [event],
            index=index,
            sourcetype=sourcetype,
            source=source,
            host=host,
            timestamp=timestamp,
        )

    def send_batch(
        self,
        events: Iterable[Any],
        *,
        index: str | None = None,
        sourcetype: str | None = None,
        source: str = "soc_copilot",
        host: str = "soc-copilot",
        timestamp: float | None = None,
    ) -> dict[str, Any]:
        """Send multiple events in one request as newline-delimited HEC envelopes."""
        ts = timestamp if timestamp is not None else time.time()
        materialized = list(events)
        envelopes = [
            _envelope(ev, ts, host, source, index, sourcetype) for ev in materialized
        ]

        resp = self._client.post(self._cfg.url, content="\n".join(envelopes))
        body = _safe_json(resp)

        if resp.status_code == 200 and body.get("code") == 0:
            return body

        # Incorrect index (code 7): retry once routed to the fallback index, tagging
        # each event with the index the caller actually intended. Splunk returns this
        # as HTTP 400, so we inspect the body regardless of status code.
        if body.get("code") == 7 and index and index != self._FALLBACK_INDEX:
            retry = [
                _envelope(
                    _tag_intended_index(ev, index),
                    ts,
                    host,
                    source,
                    self._FALLBACK_INDEX,
                    sourcetype,
                )
                for ev in materialized
            ]
            resp = self._client.post(self._cfg.url, content="\n".join(retry))
            retry_body = _safe_json(resp)
            if resp.status_code == 200 and retry_body.get("code") == 0:
                retry_body["_routed_to"] = self._FALLBACK_INDEX
                retry_body["_intended_index"] = index
                return retry_body
            raise HECError(f"HEC fallback to '{self._FALLBACK_INDEX}' failed: {retry_body or resp.text[:200]}")

        if resp.status_code != 200:
            raise HECError(f"HEC rejected events: HTTP {resp.status_code} {resp.text[:200]}")
        raise HECError(f"HEC error response: {body}")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HECClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _json_line(obj: dict[str, Any]) -> str:
    import json

    return json.dumps(obj, separators=(",", ":"))


def _safe_json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _envelope(
    event: Any,
    ts: float,
    host: str,
    source: str,
    index: str | None,
    sourcetype: str | None,
) -> str:
    envelope: dict[str, Any] = {"time": ts, "host": host, "source": source, "event": event}
    if index:
        envelope["index"] = index
    if sourcetype:
        envelope["sourcetype"] = sourcetype
    return _json_line(envelope)


def _tag_intended_index(event: Any, intended: str) -> Any:
    """Preserve the originally requested index as a field when re-routing to fallback."""
    if isinstance(event, dict):
        return {**event, "_intended_index": intended}
    return {"_intended_index": intended, "message": event}
