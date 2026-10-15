from fastapi import FastAPI

from app.did.router import router as did_router
from app.oidc.router import router as oidc_router

app = FastAPI(title="Zero-Trust IdP Mesh")
app.include_router(oidc_router)
app.include_router(did_router)


@app.get("/health")
def health():
    return {"status": "ok"}
