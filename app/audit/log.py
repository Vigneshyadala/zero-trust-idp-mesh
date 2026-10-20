"""Audit log of authentication and policy events.

Feeds the admin dashboard. Events are kept in a bounded in-memory buffer
and, when IDP_AUDIT_FILE is set, also appended to a JSON-lines file.
Never put tokens, authorization codes or secrets in an event.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class AuditEvent:
    event: str    # e.g. token_issued, token_denied, token_revoked
    outcome: str  # "success" | "blocked" | "error"
    subject: str | None = None
    client_id: str | None = None
    ip: str | None = None
    detail: dict = field(default_factory=dict)
    ts: int = field(default_factory=lambda: int(time.time()))


class AuditLog:
    def __init__(self, max_events: int = 1000, path: str | None = None) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._path = path

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(event)) + "\n")

    def recent(self, limit: int = 100, outcome: str | None = None) -> list[AuditEvent]:
        with self._lock:
            items = list(self._events)
        if outcome:
            items = [e for e in items if e.outcome == outcome]
        return list(reversed(items))[:limit]

    def counts(self) -> dict[str, int]:
        with self._lock:
            tally = Counter((e.event, e.outcome) for e in self._events)
        return {f"{name}:{outcome}": n for (name, outcome), n in tally.items()}


_audit = AuditLog(path=os.getenv("IDP_AUDIT_FILE"))


def get_audit() -> AuditLog:
    return _audit


def set_audit(log: AuditLog) -> None:
    global _audit
    _audit = log