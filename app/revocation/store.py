"""Token revocation store.

Tokens carry a unique `jti`. Revoking a token records its jti until the
token would have expired anyway. The store sits behind a small interface
so the in-memory version (tests, single process) can be swapped for a
Redis Bloom filter shared across the mesh.
"""
from __future__ import annotations

import threading
import time
from typing import Protocol


class RevocationStore(Protocol):
    def revoke(self, jti: str, expires_at: int) -> None: ...

    def is_revoked(self, jti: str) -> bool: ...


class InMemoryRevocationStore:
    def __init__(self) -> None:
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()

    def revoke(self, jti: str, expires_at: int) -> None:
        with self._lock:
            self._entries[jti] = expires_at

    def is_revoked(self, jti: str) -> bool:
        now = int(time.time())
        with self._lock:
            # Drop entries for tokens that have expired on their own.
            expired = [k for k, exp in self._entries.items() if exp <= now]
            for k in expired:
                del self._entries[k]
            return jti in self._entries


_store: RevocationStore = InMemoryRevocationStore()


def get_store() -> RevocationStore:
    return _store


def set_store(store: RevocationStore) -> None:
    global _store
    _store = store
