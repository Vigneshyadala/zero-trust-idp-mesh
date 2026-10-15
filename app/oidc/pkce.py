import base64
import hashlib
import hmac
import re

_VERIFIER_RE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")
_CHALLENGE_RE = re.compile(r"[A-Za-z0-9\-_]{43}")


def challenge_from_verifier(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def is_valid_challenge(challenge: str) -> bool:
    return bool(_CHALLENGE_RE.fullmatch(challenge))


def verify_s256(verifier: str, challenge: str) -> bool:
    if not _VERIFIER_RE.fullmatch(verifier):
        return False
    return hmac.compare_digest(challenge_from_verifier(verifier), challenge)
