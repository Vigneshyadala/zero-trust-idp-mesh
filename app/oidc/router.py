from fastapi import APIRouter

from app.core.config import settings

router = APIRouter(tags=["oidc"])


@router.get("/.well-known/openid-configuration")
def discovery():
    issuer = settings.issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile"],
        "code_challenge_methods_supported": ["S256"],
    }


@router.get("/jwks.json")
def jwks():
    # Placeholder: public signing keys are added once key management exists.
    return {"keys": []}
