import pytest
from fastapi.testclient import TestClient

from app.did.document import build_did_document
from app.did.keys import (
    b58decode,
    b58encode,
    did_from_public_key,
    generate_keypair,
    public_key_bytes,
    public_key_from_did,
    sign,
    verify,
)
from app.main import app

client = TestClient(app)


def test_base58_roundtrip():
    data = b"\x00\x00hello world"
    assert b58decode(b58encode(data)) == data


def test_did_roundtrip():
    pub = public_key_bytes(generate_keypair())
    did = did_from_public_key(pub)
    assert did.startswith("did:key:z6Mk")
    assert public_key_from_did(did) == pub


def test_did_document_structure():
    did = did_from_public_key(public_key_bytes(generate_keypair()))
    doc = build_did_document(did)
    assert doc["id"] == did
    assert doc["verificationMethod"][0]["controller"] == did


def test_sign_and_verify():
    key = generate_keypair()
    pub = public_key_bytes(key)
    sig = sign(key, b"message")
    assert verify(pub, sig, b"message")
    assert not verify(pub, sig, b"tampered")


def test_invalid_did_rejected():
    with pytest.raises(ValueError):
        public_key_from_did("did:web:example.com")


def test_resolver_endpoint():
    did = did_from_public_key(public_key_bytes(generate_keypair()))
    response = client.get(f"/did/{did}")
    assert response.status_code == 200
    assert response.json()["id"] == did
    assert client.get("/did/not-a-did").status_code == 400
