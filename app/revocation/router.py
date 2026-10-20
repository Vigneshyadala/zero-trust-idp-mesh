"""RFC 7009-style token revocation endpoint."""
import jwt
from fastapi import APIRouter, Form
from fastapi.responses import Response

from app.core import signing
from app.revocation.store import get_store

router = APIRouter()


@router.post("/revoke")
def revoke(token: str | None = Form(None)):
    if token:
        try:
            claims = signing.verify_token(token, signing.settings.issuer)
        except jwt.InvalidTokenError:
            claims = None
        if claims and claims.get("jti"):
            get_store().revoke(claims["jti"], int(claims["exp"]))
    # Always 200 so the endpoint is not an oracle for token validity.
    return Response(status_code=200, headers={"Cache-Control": "no-store"})
