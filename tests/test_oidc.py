from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_discovery_document_has_required_fields():
    response = client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    body = response.json()
    for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        assert field in body
    assert "code" in body["response_types_supported"]


def test_jwks_endpoint_returns_key_set():
    response = client.get("/jwks.json")
    assert response.status_code == 200
    assert response.json() == {"keys": []}
