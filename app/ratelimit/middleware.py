"""Applies the rate limiter to the sensitive endpoints."""
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.audit.log import AuditEvent, get_audit
from app.ratelimit.limiter import get_limiter

PROTECTED = ("/token", "/revoke", "/introspect", "/admin/api")


def _bucket(path: str) -> str | None:
    for prefix in PROTECTED:
        if path == prefix or path.startswith(prefix + "/"):
            return prefix
    return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        bucket = _bucket(request.url.path)
        limiter = get_limiter()
        if bucket and limiter:
            host = request.client.host if request.client else "unknown"
            allowed, retry_after = limiter.check(f"{host}|{bucket}")
            if not allowed:
                get_audit().record(
                    AuditEvent(
                        event="rate_limited",
                        outcome="blocked",
                        ip=host,
                        detail={"path": bucket},
                    )
                )
                return JSONResponse(
                    {"error": "rate_limited", "error_description": "too many requests"},
                    status_code=429,
                    headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
                )
        return await call_next(request)