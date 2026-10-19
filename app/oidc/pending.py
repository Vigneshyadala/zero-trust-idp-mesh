import secrets
import time
from dataclasses import dataclass

from app.core.config import settings


@dataclass
class PendingAuthorization:
    client_id: str
    redirect_uri: str
    scope: str
    state: str | None
    nonce: str | None
    code_challenge: str
    expires_at: float


# In-memory (single process). Moves to Redis in Week 3.
_pending: dict[str, PendingAuthorization] = {}


def _purge_expired() -> None:
    now = time.time()
    for key in [k for k, v in _pending.items() if v.expires_at < now]:
        del _pending[key]


def create_pending(**fields) -> str:
    _purge_expired()
    request_id = secrets.token_urlsafe(24)
    _pending[request_id] = PendingAuthorization(
        expires_at=time.time() + settings.pending_lifetime, **fields
    )
    return request_id


def get_pending(request_id: str) -> PendingAuthorization | None:
    entry = _pending.get(request_id)
    if entry is None or entry.expires_at < time.time():
        _pending.pop(request_id, None)
        return None
    return entry


def consume_pending(request_id: str) -> PendingAuthorization | None:
    entry = get_pending(request_id)
    _pending.pop(request_id, None)
    return entry
