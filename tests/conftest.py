import pytest


@pytest.fixture(autouse=True)
def _policy_all_hours(monkeypatch):
    monkeypatch.setenv("IDP_ALLOWED_HOURS", "0-24")


@pytest.fixture(autouse=True)
def _fresh_revocation_store():
    from app.revocation.store import InMemoryRevocationStore, set_store

    set_store(InMemoryRevocationStore())


@pytest.fixture(autouse=True)
def _fresh_audit_log():
    from app.audit.log import AuditLog, set_audit

    set_audit(AuditLog())


@pytest.fixture(autouse=True)
def _rate_limit_generous():
    from app.ratelimit.limiter import RateLimiter, set_limiter

    set_limiter(RateLimiter(10_000, 60))
