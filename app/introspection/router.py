"""RFC 7662-style token introspection for resource servers.

Resource servers that cannot call verify_token themselves ask the IdP whether
an access token is still active, which makes revocation visible to them.
Protected by a shared key in the X-Introspection-Key header. Disabled unless
IDP_INTROSPECTION_KEY is set. Only access tokens can be introspected.
"""
import hmac
import os

import jwt
from fastapi import APIRouter, Form, Header, HTTPException
from fastapi.responses import JSONResponse

from app.core import signing

router = APIRouter()
NO_STORE = {"Cache-Control": "no-store"}
SHARED_CLAIMS = ("sub", "scope", "client_id", "exp", "iat", "iss")


def _authorize(key: str | None) -> None:
    expected = os.getenv("IDP_INTROSPECTION_KEY")
    if not expected:
        raise HTTPException(503, "introspection disabled: IDP_INTROSPECTION_KEY is not set")
    if not key or not hmac.compare_digest(key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(401, "invalid introspection key")


@router.post("/introspect")
def introspect(
    token: str | None = Form(None),
    x_introspection_key: str | None = Header(None),
):
    _authorize(x_introspection_key)
    inactive = JSONResponse({"active": False}, headers=NO_STORE)
    if not token:
        return inactive
    try:
        claims = signing.verify_token(token, signing.settings.issuer)
    except jwt.InvalidTokenError:
        return inactive
    body = {"active": True, "token_type": "Bearer"}
    for name in SHARED_CLAIMS:
        if name in claims:
            body[name] = claims[name]
    return JSONResponse(body, headers=NO_STORE)