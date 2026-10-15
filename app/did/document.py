from app.did.keys import public_key_from_did


def build_did_document(did: str) -> dict:
    public_key_from_did(did)  # validates the DID, raises ValueError if bad
    fingerprint = did.split(":")[-1]
    key_id = f"{did}#{fingerprint}"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": fingerprint,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }
