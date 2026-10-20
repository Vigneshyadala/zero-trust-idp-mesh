from fastapi import FastAPI

from app.did.router import router as did_router
from app.ledger.router import router as ledger_router
from app.oidc.router import router as oidc_router
from app.passkeys.router import router as passkeys_router
from app.revocation.router import router as revocation_router

app = FastAPI(title="Zero-Trust IdP Mesh")
app.include_router(oidc_router)
app.include_router(did_router)
app.include_router(ledger_router)
app.include_router(passkeys_router)
app.include_router(revocation_router)


@app.get("/health")
def health():
    return {"status": "ok"}
