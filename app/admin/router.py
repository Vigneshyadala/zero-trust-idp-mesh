"""Read-only admin API and dashboard page for security officers.

Protected by a shared key in the X-Admin-Key header, compared in constant
time. If IDP_ADMIN_KEY is not set the admin interface is disabled.
"""
import csv
import hmac
import io
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response

from app.audit.log import get_audit
from app.passkeys.router import PAGE_HEADERS

router = APIRouter(prefix="/admin")
PAGE = Path(__file__).resolve().parent.parent / "web" / "admin.html"
NO_STORE = {"Cache-Control": "no-store"}
CSV_COLUMNS = ["time_utc", "event", "outcome", "subject", "client_id", "ip", "detail"]


def _csv_safe(value) -> str:
    """Stop spreadsheets from running a cell as a formula (CSV injection)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def require_admin(x_admin_key: str | None = Header(None)) -> None:
    expected = os.getenv("IDP_ADMIN_KEY")
    if not expected:
        raise HTTPException(503, "admin interface disabled: IDP_ADMIN_KEY is not set")
    if not x_admin_key or not hmac.compare_digest(
        x_admin_key.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(401, "invalid admin key")


@router.get("")
def page():
    return FileResponse(PAGE, media_type="text/html", headers={**PAGE_HEADERS, **NO_STORE})


@router.get("/api/events", dependencies=[Depends(require_admin)])
def events(
    limit: int = Query(100, ge=1, le=500),
    outcome: str | None = Query(None, pattern="^(success|blocked|error)$"),
):
    items = get_audit().recent(limit=limit, outcome=outcome)
    return JSONResponse({"events": [asdict(e) for e in items]}, headers=NO_STORE)


@router.get("/api/events.csv", dependencies=[Depends(require_admin)])
def events_csv(
    limit: int = Query(500, ge=1, le=500),
    outcome: str | None = Query(None, pattern="^(success|blocked|error)$"),
):
    items = get_audit().recent(limit=limit, outcome=outcome)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for e in items:
        when = datetime.fromtimestamp(e.ts, timezone.utc).isoformat()
        writer.writerow([
            when, _csv_safe(e.event), _csv_safe(e.outcome), _csv_safe(e.subject),
            _csv_safe(e.client_id), _csv_safe(e.ip), _csv_safe(json.dumps(e.detail, sort_keys=True)),
        ])
    headers = {**NO_STORE, "Content-Disposition": 'attachment; filename="audit-events.csv"'}
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8", headers=headers)


@router.get("/api/summary", dependencies=[Depends(require_admin)])
def summary():
    counts = get_audit().counts()
    return JSONResponse(
        {"total": sum(counts.values()), "counts": counts}, headers=NO_STORE
    )