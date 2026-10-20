from app.audit.log import AuditEvent, get_audit
from fastapi import Request
from app.policy.runtime import evaluate_request
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

from app.core import signing
from app.core.config import settings
from app.did.keys import public_key_from_did
from app.oidc.clients import get_client
from app.oidc.pending import create_pending
from app.oidc.pkce import is_valid_challenge, verify_s256
from app.oidc.store import consume_code, create_code

router = APIRouter(tags=["oidc"])

SUPPORTED_SCOPES = {"openid", "profile"}
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@router.get("/.well-known/openid-configuration")
def discovery():
    issuer = settings.issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": sorted(SUPPORTED_SCOPES),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nonce"],
    }


@router.get("/jwks.json")
def jwks():
    return signing.jwks()


def _redirect(redirect_uri: str, params: dict) -> RedirectResponse:
    query = urlencode({k: v for k, v in params.items() if v is not None})
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{query}", status_code=302, headers=NO_STORE)


@router.get("/authorize")
def authorize(
    response_type: str | None = None,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    scope: str = "",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    login_hint: str | None = None,
):
    # Until client_id and redirect_uri are verified we must NOT redirect,
    # otherwise the endpoint becomes an open redirector.
    client = get_client(client_id)
    if client is None:
        raise HTTPException(status_code=400, detail="unknown client_id")
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri is not registered for this client")

    def fail(error: str, description: str) -> RedirectResponse:
        return _redirect(redirect_uri, {"error": error, "error_description": description, "state": state})

    if response_type != "code":
        return fail("unsupported_response_type", "only response_type=code is supported")

    scopes = scope.split()
    if "openid" not in scopes:
        return fail("invalid_scope", "the openid scope is required")

    if code_challenge_method != "S256" or not code_challenge or not is_valid_challenge(code_challenge):
        return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")

    if not settings.dev_login:
        # Real authentication: park the request and send the user to the passkey login page.
        request_id = create_pending(
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scope=" ".join(s for s in scopes if s in SUPPORTED_SCOPES),
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
        )
        return RedirectResponse(
            f"{settings.issuer}/login?request_id={request_id}",
            status_code=302,
            headers=NO_STORE,
        )

    try:
        public_key_from_did(login_hint or "")
    except ValueError:
        return fail("login_required", "login_hint must be a valid did:key")

    code = create_code(
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        subject=login_hint,
        scope=" ".join(s for s in scopes if s in SUPPORTED_SCOPES),
        nonce=nonce,
        code_challenge=code_challenge,
    )
    return _redirect(redirect_uri, {"code": code, "state": state})


def _token_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers=NO_STORE,
    )


@router.post("/token")
def token(
    request: Request,
    grant_type: str | None = Form(None),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str | None = Form(None),
    code_verifier: str | None = Form(None),
):
    if grant_type != "authorization_code":
        return _token_error("unsupported_grant_type", "only authorization_code is supported")
    if not (code and redirect_uri and client_id and code_verifier):
        return _token_error("invalid_request", "missing required parameter")
    if get_client(client_id) is None:
        return _token_error("invalid_client", "unknown client", status=401)

    entry = consume_code(code)
    if (
        entry is None
        or entry.client_id != client_id
        or entry.redirect_uri != redirect_uri
        or not verify_s256(code_verifier, entry.code_challenge)
    ):
        get_audit().record(
            AuditEvent(
                event="token_denied",
                outcome="error",
                client_id=client_id,
                ip=request.client.host if request.client else None,
                detail={"reason": "invalid_grant"},
            )
        )
        return _token_error("invalid_grant", "authorization code is invalid, expired or already used")

    decision = evaluate_request(request)
    if not decision.allowed:
        get_audit().record(
            AuditEvent(
                event="token_denied",
                outcome="blocked",
                subject=entry.subject,
                client_id=client_id,
                ip=request.client.host if request.client else None,
                detail={"score": decision.score, "reasons": list(decision.reasons)},
            )
        )
        return _token_error(
            "access_denied", "request blocked by zero-trust policy", status=403
        )

    access_token = signing.issue_token(
        entry.subject,
        audience=settings.issuer,
        lifetime=settings.access_token_lifetime,
        extra={"scope": entry.scope, "client_id": client_id},
    )
    id_extra = {"nonce": entry.nonce} if entry.nonce else None
    id_token = signing.issue_token(
        entry.subject,
        audience=client_id,
        lifetime=settings.access_token_lifetime,
        extra=id_extra,
    )
    get_audit().record(
        AuditEvent(
            event="token_issued",
            outcome="success",
            subject=entry.subject,
            client_id=client_id,
            ip=request.client.host if request.client else None,
        )
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": settings.access_token_lifetime,
            "scope": entry.scope,
        },
        headers=NO_STORE,
    )
