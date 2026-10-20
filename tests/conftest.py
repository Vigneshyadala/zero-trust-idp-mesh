import pytest


@pytest.fixture(autouse=True)
def _policy_all_hours(monkeypatch):
    monkeypatch.setenv("IDP_ALLOWED_HOURS", "0-24")
