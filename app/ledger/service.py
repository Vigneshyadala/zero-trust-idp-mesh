import base64
import binascii
import os

from app.ledger.chain import Ledger, canonical, sha256_hex

ledger = Ledger(os.getenv("IDP_LEDGER_PATH", "data/ledger.json"))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature is not valid base64url") from exc


def document_hash(document: dict) -> str:
    return sha256_hex(canonical(document))


def anchor_message(did: str, doc_hash: str) -> bytes:
    # Domain-separated so a signature made for anchoring can't be reused elsewhere.
    return f"anchor:{did}:{doc_hash}".encode()
