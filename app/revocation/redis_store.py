"""Redis Bloom filter revocation store, shared across the mesh.

Bloom filters cannot delete entries, so revoked jtis go into one filter per
hour, keyed by the hour in which the token expires. Each key gets a TTL just
past the end of its hour, so Redis discards old filters on its own.

Trade-offs (document in the final report):
  * A Bloom filter has no false negatives (a revoked token is never missed)
    but a small false-positive rate (default 0.1%): a valid token may very
    rarely be rejected and the user simply signs in again.
  * If Redis is unreachable the store fails closed: tokens are treated as
    revoked, so an outage blocks logins instead of letting revoked tokens in.

Requires the RedisBloom module (included in the redis/redis-stack image).
"""
from __future__ import annotations

import logging
import math
import time

import redis
from redis.exceptions import RedisError, ResponseError

log = logging.getLogger("idp.revocation")

BUCKET_SECONDS = 3600


class RedisBloomRevocationStore:
    def __init__(
        self,
        client,
        prefix: str = "idp:revoked",
        error_rate: float = 0.001,
        capacity: int = 100_000,
        max_token_lifetime: int = 3600,
    ) -> None:
        self._client = client
        self._prefix = prefix
        self._error_rate = error_rate
        self._capacity = capacity
        self._extra_buckets = math.ceil(max_token_lifetime / BUCKET_SECONDS)

    @classmethod
    def from_url(cls, url: str, **kwargs):
        return cls(redis.Redis.from_url(url), **kwargs)

    def _key(self, bucket: int) -> str:
        return f"{self._prefix}:{bucket}"

    def revoke(self, jti: str, expires_at: int) -> None:
        bucket = int(expires_at) // BUCKET_SECONDS
        key = self._key(bucket)
        bloom = self._client.bf()
        try:
            bloom.reserve(key, self._error_rate, self._capacity)
        except ResponseError as exc:
            if "exists" not in str(exc).lower():
                raise
        bloom.add(key, jti)
        bucket_end = (bucket + 1) * BUCKET_SECONDS
        self._client.expire(key, max(bucket_end - int(time.time()), 0) + 60)

    def is_revoked(self, jti: str) -> bool:
        first = int(time.time()) // BUCKET_SECONDS
        try:
            bloom = self._client.bf()
            for bucket in range(first, first + self._extra_buckets + 1):
                if bloom.exists(self._key(bucket), jti):
                    return True
            return False
        except RedisError:
            log.exception("revocation store unavailable; failing closed")
            return True
