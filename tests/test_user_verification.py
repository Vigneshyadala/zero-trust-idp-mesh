import secrets

from app.audit.log import get_audit
from app.oidc.store import consume_code, create_code
from tests.test_oauth import REDIRECT, _exchange, challenge_from_verifier


def _code(user_verified=None):
    verifier = secrets.token_urlsafe(32)
    fields = dict(
        client_id="demo-client",
        redirect_uri=REDIRECT,
        subject="did:key:zTest",
        scope="openid",
        nonce=None,
        code_challenge=challenge_from_verifier(verifier),
    )
    if user_verified is not None:
        fields["user_verified"] = user_verified
    return verifier, create_code(**fields)


def test_code_is_unverified_by_default():
    _, code = _code()
    assert consume_code(code).user_verified is False


def test_code_keeps_the_verified_flag():
    _, code = _code(user_verified=True)
    assert consume_code(code).user_verified is True


def test_verified_code_is_issued_a_token_at_a_strict_threshold(monkeypatch):
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "60")
    verifier, code = _code(user_verified=True)
    assert _exchange(code, verifier).status_code == 200


def test_unverified_code_is_blocked_at_the_same_threshold(monkeypatch):
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "60")
    verifier, code = _code()
    response = _exchange(code, verifier)
    assert response.status_code == 403
    assert response.json()["error"] == "access_denied"
    event = get_audit().recent()[0]
    assert event.event == "token_denied" and event.outcome == "blocked"
    assert event.detail["reasons"] == ["invalid_ip", "no_user_verification"]
    assert event.detail["score"] == 90


def test_issued_event_records_the_verification_flag():
    for flag in (True, False):
        verifier, code = _code(user_verified=flag)
        assert _exchange(code, verifier).status_code == 200
        assert get_audit().recent()[0].detail == {"user_verified": flag}