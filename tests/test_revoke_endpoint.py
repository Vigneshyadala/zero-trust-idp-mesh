import jwt
import pytest
from fastapi.testclient import TestClient

from app.core import signing
from app.main import app

client = TestClient(app)


def _access_token():
    return signing.issue_token("did:key:zTest", signing.settings.issuer)


def test_revoke_makes_token_invalid():
    token = _access_token()
    assert signing.verify_token(token, signing.settings.issuer)
    response = client.post("/revoke", data={"token": token})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    with pytest.raises(jwt.InvalidTokenError):
        signing.verify_token(token, signing.settings.issuer)


def test_revoke_garbage_token_still_returns_200():
    assert client.post("/revoke", data={"token": "not-a-jwt"}).status_code == 200


def test_revoke_without_token_returns_200():
    assert client.post("/revoke", data={}).status_code == 200


def test_revoking_one_token_leaves_others_valid():
    first, second = _access_token(), _access_token()
    client.post("/revoke", data={"token": first})
    assert signing.verify_token(second, signing.settings.issuer)
