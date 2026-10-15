from fastapi import APIRouter, HTTPException

from app.did.document import build_did_document

router = APIRouter(tags=["did"])


@router.get("/did/{did}")
def resolve_did(did: str):
    try:
        return build_did_document(did)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
