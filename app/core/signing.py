from app.revocation.store import get_store
import base64
import hashlib
import os
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from app.core.config import settings

KEY_PATH = Path(os.getenv("IDP_SIGNING_KEY_PATH", "keys/idp_signing.pem"))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _load_or_create_key() -> Ed25519PrivateKey:
    if KEY_PATH.exists():
        return load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return key


_private_key = _load_or_create_key()
_public_raw = _private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
KEY_ID = _b64url(hashlib.sha256(_public_raw).digest()[:12])


def jwks() -> dict:
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url(_public_raw),
                "use": "sig",
                "alg": "EdDSA",
                "kid": KEY_ID,
            }
        ]
    }


def issue_token(subject: str, audience: str, lifetime: int = 3600, extra: dict | None = None) -> str:
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + lifetime,
        "jti": str(uuid.uuid4()),
    }
    if extra:
        claims.update(extra)
    return jwt.encode(claims, _private_key, algorithm="EdDSA", headers={"kid": KEY_ID})


def verify_token(token: str, audience: str) -> dict:
    # The algorithm list is pinned on purpose: it blocks "alg: none" and
    # algorithm-confusion attacks.
    claims = jwt.decode(
        token,
        _private_key.public_key(),
        algorithms=["EdDSA"],
        audience=audience,
        issuer=settings.issuer,
    )
    jti = claims.get("jti")
    if jti and get_store().is_revoked(jti):
        raise jwt.InvalidTokenError("token has been revoked")
    return claims
