from datetime import datetime
from types import SimpleNamespace

from app.policy.runtime import evaluate_request


def req(host):
    return SimpleNamespace(client=SimpleNamespace(host=host))


NOON = datetime(2026, 10, 20, 12, 0)


def test_normal_request_allowed():
    assert evaluate_request(req("203.0.113.10"), NOON).allowed


def test_blocked_network_from_env_is_denied(monkeypatch):
    monkeypatch.setenv("IDP_BLOCKED_NETWORKS", "203.0.113.0/24")
    d = evaluate_request(req("203.0.113.10"), NOON)
    assert not d.allowed and "blocked_ip" in d.reasons


def test_threshold_from_env_can_deny(monkeypatch):
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "10")
    d = evaluate_request(req("not-an-ip"), NOON)
    assert not d.allowed


def test_allowed_hours_from_env(monkeypatch):
    monkeypatch.setenv("IDP_ALLOWED_HOURS", "9-17")
    monkeypatch.setenv("IDP_DENY_THRESHOLD", "20")
    night = datetime(2026, 10, 20, 3, 0)
    assert not evaluate_request(req("203.0.113.10"), night).allowed
    assert evaluate_request(req("203.0.113.10"), NOON).allowed
