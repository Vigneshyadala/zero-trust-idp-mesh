"""Runs against a real Redis Stack. Skipped unless IDP_REDIS_URL is set."""
import os
import time
import uuid

import pytest

from app.revocation.redis_store import RedisBloomRevocationStore

URL = os.getenv("IDP_REDIS_URL")
pytestmark = pytest.mark.skipif(not URL, reason="IDP_REDIS_URL not set")


def test_real_bloom_filter_round_trip():
    store = RedisBloomRevocationStore.from_url(URL, prefix=f"test:{uuid.uuid4().hex}")
    jti = uuid.uuid4().hex
    assert not store.is_revoked(jti)
    store.revoke(jti, int(time.time()) + 120)
    assert store.is_revoked(jti)
    assert not store.is_revoked(uuid.uuid4().hex)
