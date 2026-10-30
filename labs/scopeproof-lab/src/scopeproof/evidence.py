"""Append-only-in-session, integrity-checkable evidence chain for synthetic events.

SHA-256 linking is tamper-evident only with a separately retained final digest.
It is not an identity signature, legal authorization, or trusted timestamp.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
_KEYS = frozenset({"sequence", "timestamp", "kind", "details", "previous_hash", "event_hash"})


def canonical_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidenceWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.counter = 0
        self.previous_hash = GENESIS
        self._stream = path.open("x", encoding="utf-8", newline="\n")

    def record(self, kind: str, details: dict[str, Any],
               when: datetime | None = None) -> str:
        if not isinstance(kind, str) or not kind or not isinstance(details, dict):
            raise ValueError("invalid evidence event")
        stamp = when or datetime.now(timezone.utc)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("an event timestamp must contain a timezone")
        event = {
            "sequence": self.counter + 1,
            "timestamp": stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "kind": kind, "details": details,
            "previous_hash": self.previous_hash,
        }
        digest = sha256_hex(canonical_bytes(event))
        event["event_hash"] = digest
        self._stream.write(canonical_bytes(event).decode("utf-8") + "\n")
        self._stream.flush()
        self.counter += 1
        self.previous_hash = digest
        return digest

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> EvidenceWriter:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def verify_chain(path: Path) -> tuple[int, str]:
    count = 0
    previous = GENESIS
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValueError(f"invalid JSON evidence line {count + 1}") from exc
            if not isinstance(row, dict) or set(row) != _KEYS:
                raise ValueError(f"invalid evidence structure at line {count + 1}")
            if type(row["sequence"]) is not int or row["sequence"] != count + 1:
                raise ValueError(f"invalid event sequence at line {count + 1}")
            if row["previous_hash"] != previous:
                raise ValueError(f"broken evidence link at line {count + 1}")
            declared = row.pop("event_hash")
            expected = sha256_hex(canonical_bytes(row))
            if declared != expected:
                raise ValueError(f"evidence hash mismatch at line {count + 1}")
            previous = expected
            count += 1
    if not count:
        raise ValueError("empty evidence chain")
    return count, previous
