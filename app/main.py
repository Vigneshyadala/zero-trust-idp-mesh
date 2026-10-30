from fastapi import FastAPI
from app.ratelimit.middleware import RateLimitMiddleware

from app.did.router import router as did_router
from app.ledger.router import router as ledger_router
from app.oidc.router import router as oidc_router
from app.passkeys.router import router as passkeys_router
from app.admin.router import router as admin_router
from app.introspection.router import router as introspection_router
from app.revocation.router import router as revocation_router
from app.home.router import router as home_router

app = FastAPI(title="Zero-Trust IdP Mesh")
app.add_middleware(RateLimitMiddleware)
app.include_router(oidc_router)
app.include_router(did_router)
app.include_router(ledger_router)
app.include_router(passkeys_router)
app.include_router(revocation_router)
app.include_router(admin_router)
app.include_router(introspection_router)
app.include_router(home_router)


@app.get("/health")
def health():
    return {"status": "ok"}
