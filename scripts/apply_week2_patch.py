from pathlib import Path


def patch(path, old, new, count_label):
    file = Path(path)
    text = file.read_text(encoding="utf-8")  # universal newlines: CRLF is normalised
    if new in text:
        print(f"already patched {path}: {count_label}")
        return
    if text.count(old) != 1:
        raise SystemExit(f"{path}: could not find the expected {count_label} exactly once - not patched")
    file.write_text(text.replace(old, new), encoding="utf-8")
    print(f"patched {path}: {count_label}")


patch(
    "app/oidc/router.py",
    "from app.oidc.pkce import is_valid_challenge, verify_s256\n",
    "from app.oidc.pending import create_pending\n"
    "from app.oidc.pkce import is_valid_challenge, verify_s256\n",
    "import",
)

patch(
    "app/oidc/router.py",
    '''    if not settings.dev_login:
        return fail("temporarily_unavailable", "user authentication (WebAuthn) is not enabled yet")
''',
    '''    if not settings.dev_login:
        # Real authentication: park the request and send the user to the passkey login page.
        request_id = create_pending(
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scope=" ".join(s for s in scopes if s in SUPPORTED_SCOPES),
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
        )
        return RedirectResponse(
            f"{settings.issuer}/login?request_id={request_id}",
            status_code=302,
            headers=NO_STORE,
        )
''',
    "dev-login branch in /authorize",
)

patch(
    "tests/test_oauth.py",
    '''def test_login_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "dev_login", False)
    response = _authorize(secrets.token_urlsafe(32))
    assert _query(response)["error"] == "temporarily_unavailable"
''',
    '''def test_without_dev_login_user_is_sent_to_passkey_login(monkeypatch):
    monkeypatch.setattr(settings, "dev_login", False)
    response = _authorize(secrets.token_urlsafe(32))
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.path == "/login"
    assert "request_id" in parse_qs(location.query)
''',
    "login-disabled test",
)
