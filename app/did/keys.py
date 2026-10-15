from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"
_DID_PREFIX = "did:key:z"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _ALPHABET[rem] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _ALPHABET.index(ch)  # ValueError on invalid characters
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    leading_ones = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_ones + body


def generate_keypair() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def did_from_public_key(public_key: bytes) -> str:
    return _DID_PREFIX + b58encode(_ED25519_MULTICODEC + public_key)


def public_key_from_did(did: str) -> bytes:
    if not did.startswith(_DID_PREFIX):
        raise ValueError("Only did:key identifiers are supported")
    try:
        raw = b58decode(did[len(_DID_PREFIX):])
    except ValueError as exc:
        raise ValueError("DID contains invalid characters") from exc
    if not raw.startswith(_ED25519_MULTICODEC) or len(raw) != 34:
        raise ValueError("DID does not contain an ed25519 public key")
    return raw[2:]


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False
