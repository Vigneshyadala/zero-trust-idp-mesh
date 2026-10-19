import pytest
from fastapi.testclient import TestClient

from app.did.document import build_did_document
from app.did.keys import did_from_public_key, generate_keypair, public_key_bytes, sign
from app.ledger import service
from app.ledger.chain import Ledger
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_ledger(monkeypatch, tmp_path):
    monkeypatch.setattr(service, "ledger", Ledger(tmp_path / "ledger.json"))


def _identity():
    key = generate_keypair()
    return key, did_from_public_key(public_key_bytes(key))


def _signed_request(key, did):
    doc_hash = service.document_hash(build_did_document(did))
    signature = service.b64url_encode(sign(key, service.anchor_message(did, doc_hash)))
    return {"did": did, "signature": signature}


def test_new_ledger_has_valid_genesis_block():
    response = client.get("/ledger/chain")
    body = response.json()
    assert body["length"] == 1
    assert body["valid"] is True
    assert body["blocks"][0]["entry"] == {"type": "genesis"}


def test_anchor_and_verify_did():
    key, did = _identity()
    response = client.post("/ledger/anchor", json=_signed_request(key, did))
    assert response.status_code == 201
    assert response.json()["entry"]["did"] == did

    status = client.get(f"/ledger/did/{did}").json()
    assert status["anchored"] is True
    assert status["matches"] is True
    assert status["block_index"] == 1
    assert client.get("/ledger/chain").json()["valid"] is True


def test_signature_from_other_key_rejected():
    _, did = _identity()
    other_key, _ = _identity()
    response = client.post("/ledger/anchor", json=_signed_request(other_key, did))
    assert response.status_code == 401
    assert client.get(f"/ledger/did/{did}").json()["anchored"] is False


def test_duplicate_anchor_rejected():
    key, did = _identity()
    request = _signed_request(key, did)
    assert client.post("/ledger/anchor", json=request).status_code == 201
    assert client.post("/ledger/anchor", json=request).status_code == 409


def test_unanchored_did_reports_false():
    _, did = _identity()
    assert client.get(f"/ledger/did/{did}").json() == {"did": did, "anchored": False}


def test_invalid_did_and_signature_rejected():
    assert client.get("/ledger/did/not-a-did").status_code == 400
    key, did = _identity()
    response = client.post("/ledger/anchor", json={"did": did, "signature": "!!!"})
    assert response.status_code in (400, 401)


def test_tampering_breaks_the_chain():
    key, did = _identity()
    client.post("/ledger/anchor", json=_signed_request(key, did))
    ledger = service.ledger
    assert ledger.validate() is True
    ledger.blocks[1]["entry"]["did_document_hash"] = "f" * 64
    assert ledger.validate() is False


def test_ledger_persists_to_disk(tmp_path):
    path = tmp_path / "persist.json"
    first = Ledger(path)
    first.anchor("did:key:z6MkExample", "a" * 64)
    reloaded = Ledger(path)
    assert len(reloaded.blocks) == 2
    assert reloaded.validate() is True
