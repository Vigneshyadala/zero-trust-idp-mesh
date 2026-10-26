import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.core import signing
from app.core.config import settings
from app.did.keys import did_from_public_key, generate_keypair, public_key_bytes
from app.main import app
from app.oidc.pkce import challenge_from_verifier

client = TestClient(app)
REDIRECT = "http://127.0.0.1:8080/callback"
DID = did_from_public_key(public_key_bytes(generate_keypair()))


@pytest.fixture(autouse=True)
def dev_login(monkeypatch):
    monkeypatch.setattr(settings, "dev_login", True)


def _authorize(verifier, drop=(), **overrides):
    params = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": REDIRECT,
        "scope": "openid profile",
        "state": "xyz",
        "nonce": "n-0S6_WzA2Mj",
        "code_challenge": challenge_from_verifier(verifier),
        "code_challenge_method": "S256",
        "login_hint": DID,
    }
    params.update(overrides)
    for key in drop:
        params.pop(key, None)
    return client.get("/authorize", params=params, follow_redirects=False)


def _query(response):
    return {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}


def _exchange(code, verifier, **overrides):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": "demo-client",
        "code_verifier": verifier,
    }
    data.update(overrides)
    return client.post("/token", data=data)


def _new_code():
    verifier = secrets.token_urlsafe(32)
    response = _authorize(verifier)
    return verifier, _query(response)["code"]


def test_rfc7636_test_vector():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert challenge_from_verifier(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_full_authorization_code_flow():
    verifier = secrets.token_urlsafe(32)
    response = _authorize(verifier)
    assert response.status_code == 302
    query = _query(response)
    assert query["state"] == "xyz"

    tokens = _exchange(query["code"], verifier)
    assert tokens.status_code == 200
    body = tokens.json()
    assert body["token_type"] == "Bearer"
    assert tokens.headers["cache-control"] == "no-store"

    id_claims = signing.verify_token(body["id_token"], audience="demo-client")
    assert id_claims["sub"] == DID
    assert id_claims["nonce"] == "n-0S6_WzA2Mj"
    access_claims = signing.verify_token(body["access_token"], audience=settings.issuer)
    assert access_claims["sub"] == DID
    assert "openid" in access_claims["scope"]


def test_wrong_code_verifier_rejected():
    _, code = _new_code()
    response = _exchange(code, secrets.token_urlsafe(32))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_authorization_code_is_single_use():
    verifier, code = _new_code()
    assert _exchange(code, verifier).status_code == 200
    second = _exchange(code, verifier)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_token_redirect_uri_mismatch_rejected():
    verifier, code = _new_code()
    response = _exchange(code, verifier, redirect_uri="http://localhost:8080/callback")
    assert response.json()["error"] == "invalid_grant"


def test_unregistered_redirect_uri_is_not_redirected():
    response = _authorize(secrets.token_urlsafe(32), redirect_uri="https://evil.example/cb")
    assert response.status_code == 400
    assert "location" not in response.headers


def test_unknown_client_is_not_redirected():
    response = _authorize(secrets.token_urlsafe(32), client_id="nobody")
    assert response.status_code == 400
    assert "location" not in response.headers


def test_missing_pkce_rejected_and_state_echoed():
    response = _authorize(secrets.token_urlsafe(32), drop=("code_challenge", "code_challenge_method"))
    query = _query(response)
    assert query["error"] == "invalid_request"
    assert query["state"] == "xyz"


def test_plain_challenge_method_rejected():
    response = _authorize(secrets.token_urlsafe(32), code_challenge_method="plain")
    assert _query(response)["error"] == "invalid_request"


def test_openid_scope_required():
    response = _authorize(secrets.token_urlsafe(32), scope="profile")
    assert _query(response)["error"] == "invalid_scope"


def test_without_dev_login_user_is_sent_to_passkey_login(monkeypatch):
    monkeypatch.setattr(settings, "dev_login", False)
    response = _authorize(secrets.token_urlsafe(32))
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.path == "/login"
    assert "request_id" in parse_qs(location.query)


def test_unsupported_grant_type_rejected():
    response = client.post("/token", data={"grant_type": "password"})
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_token_denied_by_zero_trust_policy(monkeypatch):
    verifier, code = _new_code()
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "10")
    response = _exchange(code, verifier)
    assert response.status_code == 403
    assert response.json()["error"] == "access_denied"
    assert "access_token" not in response.json()


def test_denied_attempt_burns_the_authorization_code(monkeypatch):
    verifier, code = _new_code()
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "10")
    assert _exchange(code, verifier).status_code == 403
    monkeypatch.delenv("IDP_DENY_THRESHOLD")
    retry = _exchange(code, verifier)
    assert retry.status_code == 400
    assert retry.json()["error"] == "invalid_grant"


def test_token_denied_by_zero_trust_policy(monkeypatch):
    verifier, code = _new_code()
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "10")
    response = _exchange(code, verifier)
    assert response.status_code == 403
    assert response.json()["error"] == "access_denied"
    assert "access_token" not in response.json()


def test_denied_attempt_burns_the_authorization_code(monkeypatch):
    verifier, code = _new_code()
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "10")
    assert _exchange(code, verifier).status_code == 403
    monkeypatch.delenv("IDP_DENY_THRESHOLD")
    retry = _exchange(code, verifier)
    assert retry.status_code == 400
    assert retry.json()["error"] == "invalid_grant"


def test_successful_exchange_is_audited():
    from app.audit.log import get_audit

    verifier, code = _new_code()
    assert _exchange(code, verifier).status_code == 200
    event = get_audit().recent()[0]
    assert event.event == "token_issued" and event.outcome == "success"
    assert event.client_id == "demo-client" and event.subject
    assert "access_token" not in str(event)


def test_policy_block_is_audited(monkeypatch):
    from app.audit.log import get_audit

    verifier, code = _new_code()
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "10")
    assert _exchange(code, verifier).status_code == 403
    event = get_audit().recent()[0]
    assert event.event == "token_denied" and event.outcome == "blocked"
    assert event.detail["reasons"] == ["invalid_ip", "no_user_verification"]


def test_bad_code_is_audited():
    from app.audit.log import get_audit

    verifier, _ = _new_code()
    assert _exchange("bogus", verifier).status_code == 400
    event = get_audit().recent()[0]
    assert event.event == "token_denied" and event.outcome == "error"
    assert event.detail == {"reason": "invalid_grant"}


def test_revocation_is_audited():
    from app.audit.log import get_audit
    from app.core import signing

    token = signing.issue_token("did:key:zTest", signing.settings.issuer)
    client.post("/revoke", data={"token": token})
    event = get_audit().recent()[0]
    assert event.event == "token_revoked" and event.subject == "did:key:zTest"
