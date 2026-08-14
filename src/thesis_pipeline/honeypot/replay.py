from __future__ import annotations

import json
from pathlib import Path


def replay_synthetic_events(path: str | Path) -> list[dict[str, object]]:
    """Load authorised synthetic/replayed events only; this module cannot deploy sensors."""
    events = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
        raise ValueError("Honeypot replay fixture must be a JSON array of objects")
    if any(not item.get("synthetic_or_authorised_replay", False) for item in events):
        raise ValueError("Every event must be marked synthetic_or_authorised_replay=true")
    return events
