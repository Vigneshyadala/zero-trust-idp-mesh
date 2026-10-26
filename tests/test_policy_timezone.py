from datetime import datetime, timezone
from types import SimpleNamespace

from app.policy.runtime import evaluate_request, policy_now

UTC_EVENING = datetime(2026, 10, 26, 20, 0, tzinfo=timezone.utc)


def req(host="203.0.113.10"):
    return SimpleNamespace(client=SimpleNamespace(host=host))


def test_configured_zone_converts_the_hour(monkeypatch):
    monkeypatch.setenv("IDP_TIMEZONE", "Asia/Kolkata")
    local = policy_now(UTC_EVENING)
    assert (local.hour, local.minute) == (1, 30)


def test_second_zone_without_daylight_saving(monkeypatch):
    monkeypatch.setenv("IDP_TIMEZONE", "Asia/Tokyo")
    assert policy_now(UTC_EVENING).hour == 5


def test_utc_zone(monkeypatch):
    monkeypatch.setenv("IDP_TIMEZONE", "UTC")
    assert policy_now(UTC_EVENING).hour == 20


def test_unset_uses_server_local_time(monkeypatch):
    monkeypatch.delenv("IDP_TIMEZONE", raising=False)
    assert policy_now(UTC_EVENING).hour == UTC_EVENING.astimezone().hour


def test_unknown_zone_falls_back_to_utc(monkeypatch):
    monkeypatch.setenv("IDP_TIMEZONE", "Mars/Olympus")
    assert policy_now(UTC_EVENING).hour == 20


def test_same_instant_is_in_hours_in_one_zone_and_off_hours_in_another(monkeypatch):
    monkeypatch.setenv("IDP_ALLOWED_HOURS", "6-22")
    monkeypatch.setenv("IDP_TIMEZONE", "UTC")
    assert evaluate_request(req(), policy_now(UTC_EVENING)).reasons == ()
    monkeypatch.setenv("IDP_TIMEZONE", "Asia/Kolkata")
    decision = evaluate_request(req(), policy_now(UTC_EVENING))
    assert decision.reasons == ("off_hours",)