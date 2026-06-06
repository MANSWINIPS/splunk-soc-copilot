"""Memory store round-trip tests."""

from __future__ import annotations

from pathlib import Path

import soc_copilot.memory as memory
from soc_copilot.memory import FeedbackExample, MemoryStore


def test_round_trip(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "memory.json"
    monkeypatch.setattr(memory, "_path", lambda: target)

    store = MemoryStore()
    store.add(
        FeedbackExample(
            notable_signature="Brute Force::user",
            hypothesis="Successful credential stuffing",
            rationale="Failures then success from same src",
            rating=1,
            weight=2.0,
        )
    )
    store.add(
        FeedbackExample(
            notable_signature="Brute Force::user",
            hypothesis="Benign user typo",
            rationale="Single user, small count",
            rating=-1,
        )
    )
    memory.save(store)

    loaded = memory.load()
    assert len(loaded.examples) == 2
    good = loaded.best_for("Brute Force::user")
    bad = loaded.worst_for("Brute Force::user")
    assert good[0].rating == 1
    assert bad[0].rating == -1


def test_signature() -> None:
    sig_host = memory.signature_for({"rule_name": "Port Scan", "dest": "host1"})
    sig_user = memory.signature_for({"rule_name": "Brute Force", "user": "alice"})
    sig_none = memory.signature_for({})
    assert sig_host == "Port Scan::host"
    assert sig_user == "Brute Force::user"
    assert sig_none == "unknown_rule::generic"


def test_render_few_shot_empty(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(memory, "_path", lambda: tmp_path / "nope.json")
    assert memory.render_few_shot("X::y") == ""
