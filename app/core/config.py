import os
from dataclasses import dataclass


@dataclass
class Settings:
    # WebAuthn requires a real hostname (not an IP), so the default is localhost.
    issuer: str = os.getenv("IDP_ISSUER", "http://localhost:8000")
    # DEV ONLY: lets /authorize accept a DID via login_hint without proof of
    # ownership. Off by default; passkey login is the real authentication.
    dev_login: bool = os.getenv("IDP_DEV_LOGIN", "0") == "1"
    code_lifetime: int = 60
    access_token_lifetime: int = 3600

    # WebAuthn relying party. rp_id must equal the host of the page's origin.
    rp_id: str = os.getenv("IDP_RP_ID", "localhost")
    rp_name: str = os.getenv("IDP_RP_NAME", "Zero-Trust IdP Mesh")
    rp_origin: str = os.getenv("IDP_RP_ORIGIN", "http://localhost:8000")
    require_user_verification: bool = os.getenv("IDP_REQUIRE_UV", "1") == "1"
    ceremony_lifetime: int = 300
    pending_lifetime: int = 600


settings = Settings()
