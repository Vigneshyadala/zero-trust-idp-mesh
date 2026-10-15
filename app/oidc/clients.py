from dataclasses import dataclass


@dataclass(frozen=True)
class Client:
    client_id: str
    redirect_uris: tuple[str, ...]


# Public clients only (PKCE instead of a client secret).
CLIENTS = {
    "demo-client": Client(
        client_id="demo-client",
        redirect_uris=(
            "http://127.0.0.1:8080/callback",
            "http://localhost:8080/callback",
        ),
    ),
}


def get_client(client_id: str | None) -> Client | None:
    return CLIENTS.get(client_id) if client_id else None
