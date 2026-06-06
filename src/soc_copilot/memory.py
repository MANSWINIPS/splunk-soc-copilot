"""Few-shot memory built from analyst feedback (👍 / 👎)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import get_settings


@dataclass
class FeedbackExample:
    notable_signature: str  # rule_name + dominant entity type (e.g. "Brute Force Login::user")
    hypothesis: str
    rationale: str
    rating: int  # +1 or -1
    weight: float = 1.0


@dataclass
class MemoryStore:
    examples: list[FeedbackExample] = field(default_factory=list)

    def add(self, ex: FeedbackExample) -> None:
        self.examples.append(ex)

    def best_for(self, signature: str, *, k: int = 3) -> list[FeedbackExample]:
        positive = [e for e in self.examples if e.notable_signature == signature and e.rating > 0]
        positive.sort(key=lambda e: e.weight, reverse=True)
        return positive[:k]

    def worst_for(self, signature: str, *, k: int = 2) -> list[FeedbackExample]:
        negative = [e for e in self.examples if e.notable_signature == signature and e.rating < 0]
        negative.sort(key=lambda e: e.weight, reverse=True)
        return negative[:k]


def _path() -> Path:
    p = get_settings().agent.memory_path
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def load() -> MemoryStore:
    p = _path()
    if not p.exists():
        return MemoryStore()
    raw = json.loads(p.read_text(encoding="utf-8"))
    return MemoryStore(examples=[FeedbackExample(**e) for e in raw.get("examples", [])])


def save(store: MemoryStore) -> None:
    _path().write_text(
        json.dumps({"examples": [asdict(e) for e in store.examples]}, indent=2),
        encoding="utf-8",
    )


def render_few_shot(signature: str) -> str:
    """Render the memory as a system-prompt fragment for the model."""
    store = load()
    good = store.best_for(signature)
    bad = store.worst_for(signature)
    if not good and not bad:
        return ""
    lines: list[str] = ["Prior analyst feedback for similar notables:"]
    for e in good:
        lines.append(f"  + Confirmed useful: {e.hypothesis} — {e.rationale}")
    for e in bad:
        lines.append(f"  - Rejected by analyst: {e.hypothesis} — {e.rationale}")
    return "\n".join(lines)


def signature_for(notable: dict[str, Any]) -> str:
    rule = notable.get("rule_name") or notable.get("search_name") or "unknown_rule"
    entity = "host" if notable.get("dest") else ("user" if notable.get("user") else "generic")
    return f"{rule}::{entity}"
