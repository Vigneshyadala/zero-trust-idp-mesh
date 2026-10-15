import jwt
import pytest

from app.core import signing


def test_issue_and_verify_roundtrip():
    token = signing.issue_token("did:key:z6MkExample", audience="demo-client")
    claims = signing.verify_token(token, audience="demo-client")
    assert claims["sub"] == "did:key:z6MkExample"
    assert claims["iss"]


def test_wrong_audience_rejected():
    token = signing.issue_token("user", audience="client-a")
    with pytest.raises(jwt.InvalidTokenError):
        signing.verify_token(token, audience="client-b")


def test_expired_token_rejected():
    token = signing.issue_token("user", audience="demo-client", lifetime=-10)
    with pytest.raises(jwt.InvalidTokenError):
        signing.verify_token(token, audience="demo-client")


def test_tampered_signature_rejected():
    token = signing.issue_token("user", audience="demo-client")
    header, payload, _ = token.split(".")
    forged = ".".join([header, payload, signing._b64url(b"x" * 64)])
    with pytest.raises(jwt.InvalidTokenError):
        signing.verify_token(forged, audience="demo-client")
