from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.did.document import build_did_document
from app.did.keys import public_key_from_did, verify
from app.ledger import service
from app.ledger.chain import AlreadyAnchored

router = APIRouter(prefix="/ledger", tags=["ledger"])


class AnchorRequest(BaseModel):
    did: str
    signature: str  # base64url ed25519 signature over the anchor message


@router.post("/anchor", status_code=201)
def anchor(request: AnchorRequest):
    try:
        public_key = public_key_from_did(request.did)
        document = build_did_document(request.did)
        signature = service.b64url_decode(request.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    doc_hash = service.document_hash(document)
    message = service.anchor_message(request.did, doc_hash)
    if not verify(public_key, signature, message):
        raise HTTPException(status_code=401, detail="signature does not prove control of this DID")

    try:
        return service.ledger.anchor(request.did, doc_hash)
    except AlreadyAnchored:
        raise HTTPException(status_code=409, detail="DID is already anchored")


@router.get("/did/{did}")
def anchored_status(did: str):
    try:
        document = build_did_document(did)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    current_hash = service.document_hash(document)
    block = service.ledger.find(did)
    if block is None:
        return {"did": did, "anchored": False}
    anchored_hash = block["entry"]["did_document_hash"]
    return {
        "did": did,
        "anchored": True,
        "block_index": block["index"],
        "block_hash": block["hash"],
        "anchored_document_hash": anchored_hash,
        "current_document_hash": current_hash,
        "matches": anchored_hash == current_hash,
    }


@router.get("/chain")
def chain():
    return {
        "length": len(service.ledger.blocks),
        "valid": service.ledger.validate(),
        "blocks": service.ledger.blocks,
    }
