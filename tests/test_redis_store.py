import time

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError

from app.revocation.redis_store import BUCKET_SECONDS, RedisBloomRevocationStore


class FakeBloom:
    def __init__(self, server):
        self.server = server

    def reserve(self, key, error_rate, capacity):
        if key in self.server.filters:
            raise ResponseError("item exists")
        self.server.filters[key] = set()

    def add(self, key, item):
        self.server.filters[key].add(item)
        return 1

    def exists(self, key, item):
        return 1 if item in self.server.filters.get(key, ()) else 0


class FakeRedis:
    def __init__(self):
        self.filters = {}
        self.ttls = {}

    def bf(self):
        return FakeBloom(self)

    def expire(self, key, seconds):
        self.ttls[key] = seconds


class DownRedis:
    def bf(self):
        raise RedisConnectionError("redis is down")


def exp_in(seconds):
    return int(time.time()) + seconds


def test_revoked_jti_is_detected():
    store = RedisBloomRevocationStore(FakeRedis())
    store.revoke("abc", exp_in(600))
    assert store.is_revoked("abc")


def test_unknown_jti_is_not_revoked():
    store = RedisBloomRevocationStore(FakeRedis())
    store.revoke("abc", exp_in(600))
    assert not store.is_revoked("other")


def test_filter_key_gets_a_ttl_just_past_its_hour():
    client = FakeRedis()
    store = RedisBloomRevocationStore(client)
    store.revoke("abc", exp_in(600))
    (ttl,) = client.ttls.values()
    # token lifetime (600s) can push expiry into the next hourly bucket
    assert 0 < ttl <= BUCKET_SECONDS + 600 + 60


def test_second_revoke_in_same_hour_reuses_the_filter():
    client = FakeRedis()
    store = RedisBloomRevocationStore(client)
    store.revoke("one", exp_in(600))
    store.revoke("two", exp_in(600))
    assert store.is_revoked("one") and store.is_revoked("two")


def test_redis_outage_fails_closed():
    store = RedisBloomRevocationStore(DownRedis())
    assert store.is_revoked("anything")
