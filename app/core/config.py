import os
from dataclasses import dataclass


@dataclass
class Settings:
    issuer: str = os.getenv("IDP_ISSUER", "http://127.0.0.1:8000")
    # DEV ONLY: lets /authorize accept a DID via login_hint without proof of
    # ownership. Replaced by WebAuthn / DID challenge-response in Week 2.
    dev_login: bool = os.getenv("IDP_DEV_LOGIN", "0") == "1"
    code_lifetime: int = 60
    access_token_lifetime: int = 3600


settings = Settings()
