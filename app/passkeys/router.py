import base64
import binascii
import hashlib
import json
import time
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import settings
from app.did.keys import public_key_from_did, verify
from app.oidc.pending import consume_pending, get_pending
from app.oidc.store import create_code
from app.passkeys import store

router = APIRouter(tags=["passkeys"])

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
STATIC_FILES = {
    "passkeys.js": "text/javascript",
    "passkeys.css": "text/css",
}
PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _uv() -> UserVerificationRequirement:
    return (
        UserVerificationRequirement.REQUIRED
        if settings.require_user_verification
        else UserVerificationRequirement.PREFERRED
    )


def _b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not valid base64url") from exc


def register_proof_message(did: str, challenge: bytes) -> bytes:
    # Binds the DID key to this specific, single-use registration challenge.
    return f"webauthn-register:{did}:{bytes_to_base64url(challenge)}".encode()


def _validate_did(did: str) -> bytes:
    try:
        return public_key_from_did(did)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class DidRequest(BaseModel):
    did: str


class RegisterVerifyRequest(BaseModel):
    ceremony_id: str
    credential: dict
    did_proof: str  # base64url ed25519 signature by the DID key


class LoginOptionsRequest(BaseModel):
    did: str
    request_id: str


class LoginVerifyRequest(BaseModel):
    ceremony_id: str
    credential: dict


# ---------------------------------------------------------------- registration


@router.post("/webauthn/register/options")
def register_options(request: DidRequest):
    _validate_did(request.did)
    existing = store.credentials.for_did(request.did)
    options = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_name=request.did,
        user_display_name="DID " + request.did[-8:],
        user_id=hashlib.sha256(request.did.encode()).digest(),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=_uv(),
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
            for c in existing
        ],
    )
    ceremony_id = store.create_ceremony("register", options.challenge, request.did)
    return {"ceremony_id": ceremony_id, "options": json.loads(options_to_json(options))}


@router.post("/webauthn/register/verify", status_code=201)
def register_verify(request: RegisterVerifyRequest):
    ceremony = store.consume_ceremony(request.ceremony_id, "register")
    if ceremony is None:
        raise HTTPException(status_code=400, detail="registration challenge is invalid or expired")

    # 1. Proof that the caller controls the DID's private key.
    public_key = _validate_did(ceremony.did)
    try:
        proof = _b64url_decode(request.did_proof)
    except ValueError:
        raise HTTPException(status_code=401, detail="did_proof is not valid base64url")
    if not verify(public_key, proof, register_proof_message(ceremony.did, ceremony.challenge)):
        raise HTTPException(status_code=401, detail="did_proof does not prove control of this DID")

    # 2. The WebAuthn attestation itself.
    try:
        verified = verify_registration_response(
            credential=request.credential,
            expected_challenge=ceremony.challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.rp_origin,
            require_user_verification=settings.require_user_verification,
        )
    except (InvalidRegistrationResponse, InvalidJSONStructure, ValueError):
        raise HTTPException(status_code=400, detail="passkey registration could not be verified")

    credential_id = bytes_to_base64url(verified.credential_id)
    if store.credentials.get(credential_id) is not None:
        raise HTTPException(status_code=409, detail="this passkey is already registered")

    store.credentials.add(
        store.Credential(
            credential_id=credential_id,
            did=ceremony.did,
            public_key=bytes_to_base64url(verified.credential_public_key),
            sign_count=verified.sign_count,
            created_at=int(time.time()),
        )
    )
    return {"registered": True, "did": ceremony.did, "credential_id": credential_id}


# ----------------------------------------------------------------------- login


@router.post("/webauthn/login/options")
def login_options(request: LoginOptionsRequest):
    _validate_did(request.did)
    if get_pending(request.request_id) is None:
        raise HTTPException(status_code=400, detail="authorization request is invalid or expired")
    creds = store.credentials.for_did(request.did)
    if not creds:
        raise HTTPException(status_code=404, detail="no passkey is registered for this DID")

    options = generate_authentication_options(
        rp_id=settings.rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in creds
        ],
        user_verification=_uv(),
    )
    ceremony_id = store.create_ceremony("login", options.challenge, request.did, request.request_id)
    return {"ceremony_id": ceremony_id, "options": json.loads(options_to_json(options))}


@router.post("/webauthn/login/verify")
def login_verify(request: LoginVerifyRequest):
    ceremony = store.consume_ceremony(request.ceremony_id, "login")
    if ceremony is None:
        raise HTTPException(status_code=400, detail="login challenge is invalid or expired")

    credential_id = request.credential.get("id")
    stored = store.credentials.get(credential_id) if isinstance(credential_id, str) else None
    if stored is None or stored.did != ceremony.did:
        raise HTTPException(status_code=401, detail="passkey is not registered for this DID")

    pending = get_pending(ceremony.request_id)
    if pending is None:
        raise HTTPException(status_code=400, detail="authorization request is invalid or expired")

    try:
        verified = verify_authentication_response(
            credential=request.credential,
            expected_challenge=ceremony.challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.rp_origin,
            credential_public_key=base64url_to_bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=settings.require_user_verification,
        )
    except (InvalidAuthenticationResponse, InvalidJSONStructure, ValueError):
        raise HTTPException(status_code=401, detail="passkey authentication failed")

    store.credentials.update_sign_count(stored.credential_id, verified.new_sign_count)
    consume_pending(ceremony.request_id)

    code = create_code(
        client_id=pending.client_id,
        redirect_uri=pending.redirect_uri,
        subject=ceremony.did,
        scope=pending.scope,
        nonce=pending.nonce,
        code_challenge=pending.code_challenge,
        user_verified=bool(getattr(verified, "user_verified", False)),
    )
    query = {"code": code}
    if pending.state is not None:
        query["state"] = pending.state
    sep = "&" if "?" in pending.redirect_uri else "?"
    return {"redirect_to": f"{pending.redirect_uri}{sep}{urlencode(query)}"}


# ------------------------------------------------------------- browser UI/pages


@router.get("/login", include_in_schema=False)
@router.get("/demo", include_in_schema=False)
def login_page():
    return FileResponse(WEB_DIR / "login.html", media_type="text/html", headers=PAGE_HEADERS)


@router.get("/static/{name}", include_in_schema=False)
def static_file(name: str):
    media_type = STATIC_FILES.get(name)
    if media_type is None:
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(WEB_DIR / name, media_type=media_type, headers=PAGE_HEADERS)
