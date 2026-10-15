import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    issuer: str = os.getenv("IDP_ISSUER", "http://127.0.0.1:8000")


settings = Settings()
