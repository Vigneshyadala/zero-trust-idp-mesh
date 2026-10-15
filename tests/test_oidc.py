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


def test_jwks_endpoint_returns_ed25519_key():
    response = client.get("/jwks.json")
    assert response.status_code == 200
    key = response.json()["keys"][0]
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert key["alg"] == "EdDSA"
    assert key["kid"]
