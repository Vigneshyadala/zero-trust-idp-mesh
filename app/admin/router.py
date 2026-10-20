"""Read-only admin API and dashboard page for security officers.

Protected by a shared key in the X-Admin-Key header, compared in constant
time. If IDP_ADMIN_KEY is not set the admin interface is disabled.
"""
import hmac
import os
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from app.audit.log import get_audit

router = APIRouter(prefix="/admin")
PAGE = Path(__file__).resolve().parent.parent / "web" / "admin.html"
NO_STORE = {"Cache-Control": "no-store"}


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
    return FileResponse(PAGE, media_type="text/html", headers=NO_STORE)


@router.get("/api/events", dependencies=[Depends(require_admin)])
def events(
    limit: int = Query(100, ge=1, le=500),
    outcome: str | None = Query(None, pattern="^(success|blocked|error)$"),
):
    items = get_audit().recent(limit=limit, outcome=outcome)
    return JSONResponse({"events": [asdict(e) for e in items]}, headers=NO_STORE)


@router.get("/api/summary", dependencies=[Depends(require_admin)])
def summary():
    counts = get_audit().counts()
    return JSONResponse(
        {"total": sum(counts.values()), "counts": counts}, headers=NO_STORE
    )