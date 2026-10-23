from fastapi.testclient import TestClient

from app.audit.log import get_audit
from app.main import app
from app.ratelimit.limiter import RateLimiter, limiter_from_env, set_limiter

client = TestClient(app)
BAD = {
    "grant_type": "authorization_code",
    "code": "bogus",
    "redirect_uri": "http://localhost:8080/callback",
    "client_id": "demo-client",
    "code_verifier": "abc",
}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


# ------------------------------------------------------------ unit tests


def test_allows_up_to_the_limit():
    limiter = RateLimiter(2, 60, clock=Clock())
    assert limiter.check("a") == (True, 0)
    assert limiter.check("a") == (True, 0)


def test_blocks_over_the_limit_with_retry_after():
    clock = Clock()
    limiter = RateLimiter(2, 60, clock=clock)
    limiter.check("a")
    limiter.check("a")
    assert limiter.check("a") == (False, 60)
    clock.now = 10
    assert limiter.check("a") == (False, 50)


def test_window_slides():
    clock = Clock()
    limiter = RateLimiter(1, 10, clock=clock)
    assert limiter.check("a")[0]
    clock.now = 10
    assert limiter.check("a")[0]


def test_keys_are_independent():
    limiter = RateLimiter(1, 60, clock=Clock())
    assert limiter.check("a")[0]
    assert limiter.check("b")[0]
    assert not limiter.check("a")[0]


def test_blocked_attempts_do_not_extend_the_lockout():
    clock = Clock()
    limiter = RateLimiter(1, 10, clock=clock)
    assert limiter.check("a")[0]
    clock.now = 5
    assert not limiter.check("a")[0]
    clock.now = 10
    assert limiter.check("a")[0]


def test_limit_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("IDP_RATE_LIMIT", "2/60")
    limiter = limiter_from_env()
    assert limiter.check("a")[0] and limiter.check("a")[0]
    assert not limiter.check("a")[0]


def test_limit_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("IDP_RATE_LIMIT", "off")
    assert limiter_from_env() is None


# ------------------------------------------------------ through the app


def test_requests_over_the_limit_get_429():
    set_limiter(RateLimiter(3, 60))
    for _ in range(3):
        assert client.post("/token", data=BAD).status_code == 400
    blocked = client.post("/token", data=BAD)
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.json()["error"] == "rate_limited"


def test_limit_is_per_endpoint():
    set_limiter(RateLimiter(2, 60))
    client.post("/token", data=BAD)
    client.post("/token", data=BAD)
    assert client.post("/token", data=BAD).status_code == 429
    assert client.post("/revoke", data={}).status_code == 200


def test_unprotected_paths_are_not_limited():
    set_limiter(RateLimiter(1, 60))
    for _ in range(5):
        assert client.get("/health").status_code == 200


def test_blocked_request_is_audited():
    set_limiter(RateLimiter(1, 60))
    client.post("/token", data=BAD)
    client.post("/token", data=BAD)
    event = get_audit().recent()[0]
    assert event.event == "rate_limited" and event.outcome == "blocked"
    assert event.detail == {"path": "/token"}


def test_limiting_can_be_disabled():
    set_limiter(None)
    for _ in range(40):
        assert client.post("/token", data=BAD).status_code == 400


def test_admin_key_guessing_is_limited(monkeypatch):
    monkeypatch.setenv("IDP_ADMIN_KEY", "s3cret")
    set_limiter(RateLimiter(3, 60))
    wrong = {"X-Admin-Key": "nope"}
    for _ in range(3):
        assert client.get("/admin/api/events", headers=wrong).status_code == 401
    assert client.get("/admin/api/events", headers=wrong).status_code == 429