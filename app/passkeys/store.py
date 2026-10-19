import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from app.core.config import settings


@dataclass
class Credential:
    credential_id: str  # base64url
    did: str
    public_key: str  # base64url COSE public key
    sign_count: int
    created_at: int


class CredentialStore:
    """WebAuthn credentials persisted to a JSON file (public data only)."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._items: dict[str, Credential] = {}
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._items = {k: Credential(**v) for k, v in raw.items()}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({k: asdict(v) for k, v in self._items.items()}, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

    def add(self, credential: Credential) -> None:
        with self._lock:
            self._items[credential.credential_id] = credential
            self._save()

    def get(self, credential_id: str) -> Credential | None:
        return self._items.get(credential_id)

    def for_did(self, did: str) -> list[Credential]:
        return [c for c in self._items.values() if c.did == did]

    def update_sign_count(self, credential_id: str, sign_count: int) -> None:
        with self._lock:
            self._items[credential_id].sign_count = sign_count
            self._save()


credentials = CredentialStore(os.getenv("IDP_CREDENTIALS_PATH", "data/credentials.json"))


@dataclass
class Ceremony:
    kind: str
    challenge: bytes
    did: str
    request_id: str | None
    expires_at: float


# Short-lived, single-use WebAuthn ceremonies (in memory).
_ceremonies: dict[str, Ceremony] = {}


def create_ceremony(kind: str, challenge: bytes, did: str, request_id: str | None = None) -> str:
    now = time.time()
    for key in [k for k, v in _ceremonies.items() if v.expires_at < now]:
        del _ceremonies[key]
    ceremony_id = secrets.token_urlsafe(24)
    _ceremonies[ceremony_id] = Ceremony(
        kind, challenge, did, request_id, now + settings.ceremony_lifetime
    )
    return ceremony_id


def consume_ceremony(ceremony_id: str, kind: str) -> Ceremony | None:
    # Always removed, even when verification later fails: one attempt per challenge.
    ceremony = _ceremonies.pop(ceremony_id, None)
    if ceremony is None or ceremony.kind != kind or ceremony.expires_at < time.time():
        return None
    return ceremony
