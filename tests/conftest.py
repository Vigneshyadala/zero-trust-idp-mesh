import pytest


@pytest.fixture(autouse=True)
def _policy_all_hours(monkeypatch):
    monkeypatch.setenv("IDP_ALLOWED_HOURS", "0-24")


@pytest.fixture(autouse=True)
def _fresh_revocation_store():
    from app.revocation.store import InMemoryRevocationStore, set_store

    set_store(InMemoryRevocationStore())
