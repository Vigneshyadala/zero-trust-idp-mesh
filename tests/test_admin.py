from fastapi.testclient import TestClient

from app.audit.log import AuditEvent, get_audit
from app.main import app

client = TestClient(app)
GOOD = {"X-Admin-Key": "s3cret"}


def _enable(monkeypatch):
    monkeypatch.setenv("IDP_ADMIN_KEY", "s3cret")


def test_disabled_when_no_key_configured(monkeypatch):
    monkeypatch.delenv("IDP_ADMIN_KEY", raising=False)
    assert client.get("/admin/api/events", headers=GOOD).status_code == 503


def test_wrong_key_is_rejected(monkeypatch):
    _enable(monkeypatch)
    r = client.get("/admin/api/events", headers={"X-Admin-Key": "nope"})
    assert r.status_code == 401


def test_missing_key_is_rejected(monkeypatch):
    _enable(monkeypatch)
    assert client.get("/admin/api/summary").status_code == 401


def test_events_are_returned_newest_first(monkeypatch):
    _enable(monkeypatch)
    get_audit().record(AuditEvent(event="token_issued", outcome="success", subject="a"))
    get_audit().record(AuditEvent(event="token_issued", outcome="success", subject="b"))
    r = client.get("/admin/api/events", headers=GOOD)
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert [e["subject"] for e in r.json()["events"]] == ["b", "a"]


def test_outcome_filter(monkeypatch):
    _enable(monkeypatch)
    get_audit().record(AuditEvent(event="token_issued", outcome="success"))
    get_audit().record(AuditEvent(event="token_denied", outcome="blocked"))
    r = client.get("/admin/api/events?outcome=blocked", headers=GOOD)
    assert [e["event"] for e in r.json()["events"]] == ["token_denied"]


def test_invalid_outcome_filter_is_rejected(monkeypatch):
    _enable(monkeypatch)
    r = client.get("/admin/api/events?outcome=bogus", headers=GOOD)
    assert r.status_code == 422


def test_summary_counts(monkeypatch):
    _enable(monkeypatch)
    get_audit().record(AuditEvent(event="token_issued", outcome="success"))
    get_audit().record(AuditEvent(event="token_issued", outcome="success"))
    get_audit().record(AuditEvent(event="token_denied", outcome="blocked"))
    body = client.get("/admin/api/summary", headers=GOOD).json()
    assert body["total"] == 3
    assert body["counts"] == {"token_issued:success": 2, "token_denied:blocked": 1}


def test_page_is_served_without_data():
    r = client.get("/admin")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Admin key" in r.text