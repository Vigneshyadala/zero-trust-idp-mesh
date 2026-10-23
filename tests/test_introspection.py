from fastapi.testclient import TestClient

from app.core import signing
from app.main import app

client = TestClient(app)
GOOD = {"X-Introspection-Key": "k3y"}


def _enable(monkeypatch):
    monkeypatch.setenv("IDP_INTROSPECTION_KEY", "k3y")


def _token(**kw):
    return signing.issue_token(
        "did:key:zTest",
        signing.settings.issuer,
        extra={"scope": "openid", "client_id": "demo-client"},
        **kw,
    )


def _introspect(token, headers=GOOD):
    return client.post("/introspect", data={"token": token}, headers=headers)


def test_disabled_without_configured_key(monkeypatch):
    monkeypatch.delenv("IDP_INTROSPECTION_KEY", raising=False)
    assert _introspect(_token()).status_code == 503


def test_wrong_key_is_rejected(monkeypatch):
    _enable(monkeypatch)
    assert _introspect(_token(), {"X-Introspection-Key": "nope"}).status_code == 401


def test_missing_key_is_rejected(monkeypatch):
    _enable(monkeypatch)
    assert _introspect(_token(), {}).status_code == 401


def test_active_token_is_described(monkeypatch):
    _enable(monkeypatch)
    r = _introspect(_token())
    body = r.json()
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert body["active"] is True
    assert body["sub"] == "did:key:zTest"
    assert body["scope"] == "openid"
    assert body["client_id"] == "demo-client"
    assert body["token_type"] == "Bearer"
    assert "jti" not in body


def test_revoked_token_is_inactive(monkeypatch):
    _enable(monkeypatch)
    token = _token()
    assert _introspect(token).json()["active"] is True
    assert client.post("/revoke", data={"token": token}).status_code == 200
    assert _introspect(token).json() == {"active": False}


def test_garbage_token_is_inactive(monkeypatch):
    _enable(monkeypatch)
    assert _introspect("not-a-jwt").json() == {"active": False}


def test_expired_token_is_inactive(monkeypatch):
    _enable(monkeypatch)
    assert _introspect(_token(lifetime=-10)).json() == {"active": False}


def test_missing_token_parameter_is_inactive(monkeypatch):
    _enable(monkeypatch)
    r = client.post("/introspect", data={}, headers=GOOD)
    assert r.status_code == 200 and r.json() == {"active": False}