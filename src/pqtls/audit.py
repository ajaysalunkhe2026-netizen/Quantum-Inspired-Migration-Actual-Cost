"""Append-only, hash-chained audit events for measurement provenance."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def append_audit_event(path: str | Path, event: dict[str, Any]) -> str:
    """Append an event with a SHA-256 link to the previous event; file mode is 0600."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = GENESIS
    if target.exists():
        verified = verify_audit_log(target)
        if not verified["valid"]:
            raise ValueError("Audit log integrity check failed; refusing to append")
        previous = str(verified["last_hash"])
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_hash": previous,
        "event": event,
    }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    line = _canonical({**payload, "event_hash": digest}) + b"\n"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    return digest


def verify_audit_log(path: str | Path) -> dict[str, Any]:
    """Verify event hashes and chain continuity without modifying the file."""
    previous = GENESIS
    count = 0
    target = Path(path)
    if not target.exists():
        return {"valid": True, "events": 0, "last_hash": GENESIS}
    with target.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                row = json.loads(line)
                supplied = row.pop("event_hash")
            except (json.JSONDecodeError, KeyError) as exc:
                return {"valid": False, "line": line_number, "reason": str(exc)}
            if row.get("previous_hash") != previous:
                return {"valid": False, "line": line_number, "reason": "chain mismatch"}
            calculated = hashlib.sha256(_canonical(row)).hexdigest()
            if supplied != calculated:
                return {"valid": False, "line": line_number, "reason": "hash mismatch"}
            previous = supplied
            count += 1
    return {"valid": True, "events": count, "last_hash": previous}
