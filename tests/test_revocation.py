import time

import jwt
import pytest

from app.core import signing
from app.revocation.store import InMemoryRevocationStore, get_store

AUD = "test-audience"


def _jti(token):
    return jwt.decode(token, options={"verify_signature": False})["jti"]


def test_revoked_jti_is_reported_revoked():
    store = InMemoryRevocationStore()
    store.revoke("abc", int(time.time()) + 60)
    assert store.is_revoked("abc")


def test_unknown_jti_is_not_revoked():
    assert not InMemoryRevocationStore().is_revoked("never-seen")


def test_entry_is_dropped_after_token_expiry():
    store = InMemoryRevocationStore()
    store.revoke("old", int(time.time()) - 1)
    assert not store.is_revoked("old")


def test_verify_token_rejects_revoked_token():
    token = signing.issue_token("did:key:zTest", AUD)
    assert signing.verify_token(token, AUD)["sub"] == "did:key:zTest"
    get_store().revoke(_jti(token), int(time.time()) + 3600)
    with pytest.raises(jwt.InvalidTokenError):
        signing.verify_token(token, AUD)


def test_revoking_one_token_does_not_affect_another():
    first = signing.issue_token("did:key:zTest", AUD)
    second = signing.issue_token("did:key:zTest", AUD)
    get_store().revoke(_jti(first), int(time.time()) + 3600)
    assert signing.verify_token(second, AUD)["sub"] == "did:key:zTest"
