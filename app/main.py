from fastapi import FastAPI

app = FastAPI(title="Zero-Trust IdP Mesh")


@app.get("/health")
def health():
    return {"status": "ok"}
