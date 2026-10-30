from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.passkeys.router import PAGE_HEADERS, WEB_DIR

router = APIRouter()
ASSETS = {"site.css": "text/css"}


@router.get("/", include_in_schema=False)
def home():
    return FileResponse(WEB_DIR / "index.html", media_type="text/html", headers=PAGE_HEADERS)


@router.get("/assets/{name}", include_in_schema=False)
def asset(name: str):
    media_type = ASSETS.get(name)
    if media_type is None:
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(WEB_DIR / name, media_type=media_type, headers=PAGE_HEADERS)