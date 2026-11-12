import csv
import io

from fastapi.testclient import TestClient

from app.audit.log import AuditEvent, get_audit
from app.main import app

client = TestClient(app)
GOOD = {"X-Admin-Key": "s3cret"}
COLUMNS = ["time_utc", "event", "outcome", "subject", "client_id", "ip", "detail"]


def _enable(monkeypatch):
    monkeypatch.setenv("IDP_ADMIN_KEY", "s3cret")


def _rows(response):
    return list(csv.reader(io.StringIO(response.text)))


def test_csv_requires_the_admin_key(monkeypatch):
    _enable(monkeypatch)
    assert client.get("/admin/api/events.csv").status_code == 401
    assert client.get("/admin/api/events.csv", headers={"X-Admin-Key": "wrong"}).status_code == 401


def test_csv_is_disabled_when_no_key_is_configured(monkeypatch):
    monkeypatch.delenv("IDP_ADMIN_KEY", raising=False)
    assert client.get("/admin/api/events.csv", headers=GOOD).status_code == 503


def test_csv_has_header_rows_and_download_headers(monkeypatch):
    _enable(monkeypatch)
    get_audit().record(AuditEvent(event="token_issued", outcome="success", subject="did:key:abc", ts=0))
    r = client.get("/admin/api/events.csv", headers=GOOD)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "audit-events.csv" in r.headers["content-disposition"]
    assert "no-store" in r.headers["cache-control"]
    rows = _rows(r)
    assert rows[0] == COLUMNS
    assert rows[1][0] == "1970-01-01T00:00:00+00:00"
    assert rows[1][1:4] == ["token_issued", "success", "did:key:abc"]


def test_csv_honours_the_outcome_filter(monkeypatch):
    _enable(monkeypatch)
    get_audit().record(AuditEvent(event="token_issued", outcome="success"))
    get_audit().record(AuditEvent(event="token_denied", outcome="blocked"))
    rows = _rows(client.get("/admin/api/events.csv?outcome=blocked", headers=GOOD))
    assert [row[1] for row in rows[1:]] == ["token_denied"]
    assert client.get("/admin/api/events.csv?outcome=bogus", headers=GOOD).status_code == 422


def test_csv_neutralises_spreadsheet_formulas(monkeypatch):
    _enable(monkeypatch)
    get_audit().record(AuditEvent(event="token_denied", outcome="error", subject="=HYPERLINK(\"http://x\")"))
    get_audit().record(AuditEvent(event="token_denied", outcome="error", subject="@SUM(1)"))
    cells = [row[3] for row in _rows(client.get("/admin/api/events.csv", headers=GOOD))[1:]]
    assert all(cell.startswith("'") for cell in cells)


def test_csv_limit_is_bounded(monkeypatch):
    _enable(monkeypatch)
    assert client.get("/admin/api/events.csv?limit=501", headers=GOOD).status_code == 422
    assert client.get("/admin/api/events.csv?limit=0", headers=GOOD).status_code == 422
