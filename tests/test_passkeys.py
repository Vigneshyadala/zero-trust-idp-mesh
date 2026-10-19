import base64
import hashlib
import json
import os
import secrets
from urllib.parse import parse_qs, urlsplit

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.core import signing
from app.core.config import settings
from app.did.keys import did_from_public_key, generate_keypair, public_key_bytes, sign
from app.main import app
from app.oidc.pkce import challenge_from_verifier
from app.passkeys import store
from app.passkeys.router import register_proof_message

client = TestClient(app)
REDIRECT = "http://localhost:8080/callback"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class VirtualAuthenticator:
    """A software passkey: builds the same structures a browser would return."""

    def __init__(self, user_verified=True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0
        self.flags = 0x01 | (0x04 if user_verified else 0)

    def _cose_key(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )

    @staticmethod
    def _rp_hash() -> bytes:
        return hashlib.sha256(settings.rp_id.encode()).digest()

    def create(self, options: dict, origin: str | None = None) -> dict:
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": options["challenge"],
                "origin": origin or settings.rp_origin,
                "crossOrigin": False,
            }
        ).encode()
        attested = (
            bytes(16)
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + self._cose_key()
        )
        auth_data = self._rp_hash() + bytes([self.flags | 0x40]) + (0).to_bytes(4, "big") + attested
        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client_data),
                "attestationObject": b64(attestation_object),
            },
            "clientExtensionResults": {},
        }

    def get(self, options: dict, origin: str | None = None, challenge: str | None = None) -> dict:
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge or options["challenge"],
                "origin": origin or settings.rp_origin,
                "crossOrigin": False,
            }
        ).encode()
        self.sign_count += 1
        auth_data = self._rp_hash() + bytes([self.flags]) + self.sign_count.to_bytes(4, "big")
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client_data),
                "authenticatorData": b64(auth_data),
                "signature": b64(signature),
            },
            "clientExtensionResults": {},
        }


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "credentials", store.CredentialStore(tmp_path / "credentials.json"))
    monkeypatch.setattr(settings, "dev_login", False)


def make_identity():
    key = generate_keypair()
    return key, did_from_public_key(public_key_bytes(key))


def register(did, did_key, authenticator, proof_key=None):
    options = client.post("/webauthn/register/options", json={"did": did}).json()
    challenge = unb64(options["options"]["challenge"])
    proof = b64(sign(proof_key or did_key, register_proof_message(did, challenge)))
    return client.post(
        "/webauthn/register/verify",
        json={
            "ceremony_id": options["ceremony_id"],
            "credential": authenticator.create(options["options"]),
            "did_proof": proof,
        },
    )


def start_authorization(verifier=None):
    verifier = verifier or secrets.token_urlsafe(32)
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "state": "st-1",
            "nonce": "nn-1",
            "code_challenge": challenge_from_verifier(verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    request_id = parse_qs(urlsplit(response.headers["location"]).query)["request_id"][0]
    return verifier, request_id


def login_options(did, request_id):
    return client.post("/webauthn/login/options", json={"did": did, "request_id": request_id})


def login_verify(options, credential):
    return client.post(
        "/webauthn/login/verify",
        json={"ceremony_id": options["ceremony_id"], "credential": credential},
    )


def test_register_passkey_for_did():
    did_key, did = make_identity()
    response = register(did, did_key, VirtualAuthenticator())
    assert response.status_code == 201
    assert response.json()["did"] == did
    assert len(store.credentials.for_did(did)) == 1


def test_registration_rejected_without_did_control():
    _, did = make_identity()
    attacker_key, _ = make_identity()
    response = register(did, None, VirtualAuthenticator(), proof_key=attacker_key)
    assert response.status_code == 401
    assert store.credentials.for_did(did) == []


def test_registration_rejected_for_wrong_origin():
    did_key, did = make_identity()
    options = client.post("/webauthn/register/options", json={"did": did}).json()
    challenge = unb64(options["options"]["challenge"])
    response = client.post(
        "/webauthn/register/verify",
        json={
            "ceremony_id": options["ceremony_id"],
            "credential": VirtualAuthenticator().create(
                options["options"], origin="https://evil.example"
            ),
            "did_proof": b64(sign(did_key, register_proof_message(did, challenge))),
        },
    )
    assert response.status_code == 400
    assert store.credentials.for_did(did) == []


def test_registration_requires_user_verification():
    did_key, did = make_identity()
    response = register(did, did_key, VirtualAuthenticator(user_verified=False))
    assert response.status_code == 400


def test_registration_challenge_is_single_use():
    did_key, did = make_identity()
    options = client.post("/webauthn/register/options", json={"did": did}).json()
    challenge = unb64(options["options"]["challenge"])
    body = {
        "ceremony_id": options["ceremony_id"],
        "credential": VirtualAuthenticator().create(options["options"]),
        "did_proof": b64(sign(did_key, register_proof_message(did, challenge))),
    }
    assert client.post("/webauthn/register/verify", json=body).status_code == 201
    assert client.post("/webauthn/register/verify", json=body).status_code == 400


def test_full_login_issues_working_tokens():
    did_key, did = make_identity()
    authenticator = VirtualAuthenticator()
    assert register(did, did_key, authenticator).status_code == 201

    verifier, request_id = start_authorization()
    options = login_options(did, request_id).json()
    result = login_verify(options, authenticator.get(options["options"]))
    assert result.status_code == 200

    redirect = urlsplit(result.json()["redirect_to"])
    assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == REDIRECT
    query = parse_qs(redirect.query)
    assert query["state"] == ["st-1"]

    tokens = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": REDIRECT,
            "client_id": "demo-client",
            "code_verifier": verifier,
        },
    )
    assert tokens.status_code == 200
    claims = signing.verify_token(tokens.json()["id_token"], audience="demo-client")
    assert claims["sub"] == did
    assert claims["nonce"] == "nn-1"
    assert store.credentials.for_did(did)[0].sign_count == 1


def test_login_with_unregistered_passkey_rejected():
    did_key, did = make_identity()
    assert register(did, did_key, VirtualAuthenticator()).status_code == 201
    _, request_id = start_authorization()
    options = login_options(did, request_id).json()
    result = login_verify(options, VirtualAuthenticator().get(options["options"]))
    assert result.status_code == 401


def test_login_rejected_for_other_dids_passkey():
    key_a, did_a = make_identity()
    key_b, did_b = make_identity()
    auth_a, auth_b = VirtualAuthenticator(), VirtualAuthenticator()
    register(did_a, key_a, auth_a)
    register(did_b, key_b, auth_b)
    _, request_id = start_authorization()
    options = login_options(did_a, request_id).json()
    result = login_verify(options, auth_b.get(options["options"]))
    assert result.status_code == 401


def test_login_with_wrong_challenge_rejected():
    did_key, did = make_identity()
    authenticator = VirtualAuthenticator()
    register(did, did_key, authenticator)
    _, request_id = start_authorization()
    options = login_options(did, request_id).json()
    forged = authenticator.get(options["options"], challenge=b64(os.urandom(32)))
    assert login_verify(options, forged).status_code == 401


def test_replayed_assertion_rejected():
    did_key, did = make_identity()
    authenticator = VirtualAuthenticator()
    register(did, did_key, authenticator)
    _, request_id = start_authorization()
    options = login_options(did, request_id).json()
    assertion = authenticator.get(options["options"])
    assert login_verify(options, assertion).status_code == 200
    assert login_verify(options, assertion).status_code == 400  # ceremony already used


def test_stale_sign_count_rejected():
    did_key, did = make_identity()
    authenticator = VirtualAuthenticator()
    register(did, did_key, authenticator)
    for _ in range(2):
        _, request_id = start_authorization()
        options = login_options(did, request_id).json()
        assert login_verify(options, authenticator.get(options["options"])).status_code == 200
    # a cloned authenticator whose counter has fallen behind
    authenticator.sign_count = 0
    _, request_id = start_authorization()
    options = login_options(did, request_id).json()
    assert login_verify(options, authenticator.get(options["options"])).status_code == 401


def test_login_options_need_a_registered_passkey_and_valid_request():
    _, did = make_identity()
    _, request_id = start_authorization()
    assert login_options(did, request_id).status_code == 404
    assert login_options(did, "does-not-exist").status_code == 400


def test_login_page_and_static_files_served_with_csp():
    page = client.get("/login")
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert client.get("/static/passkeys.js").status_code == 200
    assert client.get("/static/../../etc/passwd").status_code in (404, 422)
    assert client.get("/static/secret.txt").status_code == 404
