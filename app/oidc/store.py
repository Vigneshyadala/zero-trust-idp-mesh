import secrets
import time
from dataclasses import dataclass

from app.core.config import settings


@dataclass
class AuthCode:
    client_id: str
    redirect_uri: str
    subject: str
    scope: str
    nonce: str | None
    code_challenge: str
    expires_at: float
    # True only when the authenticator verified the user (PIN or biometric).
    # Defaults to False, so a code created without proof counts as unverified.
    user_verified: bool = False


# In-memory store: fine for one process. Moves to Redis in Week 3.
_codes: dict[str, AuthCode] = {}


def _purge_expired() -> None:
    now = time.time()
    for key in [k for k, v in _codes.items() if v.expires_at < now]:
        del _codes[key]


def create_code(**fields) -> str:
    _purge_expired()
    code = secrets.token_urlsafe(32)
    _codes[code] = AuthCode(expires_at=time.time() + settings.code_lifetime, **fields)
    return code


def consume_code(code: str) -> AuthCode | None:
    # Single use: the code is removed even if later checks fail.
    entry = _codes.pop(code, None)
    if entry is None or entry.expires_at < time.time():
        return None
    return entry
