# Zero-Trust Identity Provider Mesh

Decentralized, zero-trust identity provider built with Python and FastAPI
(Zaalima Development - Enterprise Project 3).

Replaces username/password tables with Decentralized Identifiers (DIDs),
WebAuthn (FIDO2) and cryptographic identity anchoring.

## Status

| Week | Scope | State |
|------|-------|-------|
| 1 | OIDC / OAuth 2.0 server, ed25519 DIDs, repo rules | Complete |
| 2 | WebAuthn passkeys, simulated ledger anchoring | Complete |
| 3 | Zero-trust policy engine, token revocation, admin dashboard | Planned |
| 4 | Penetration tests, Docker + Traefik deployment, final report | Planned |

## Implemented

### Week 1

- OIDC discovery: `/.well-known/openid-configuration`
- JWKS: `/jwks.json` (Ed25519 / EdDSA signing key)
- DID resolver: `/did/{did}` (did:key, ed25519)
- Authorization code flow with mandatory PKCE (S256): `/authorize`, `/token`
- JWT access and ID tokens signed with EdDSA, algorithm pinned on verification
- Single-use, 60-second authorization codes
- Exact redirect_uri matching, no open redirects

### Week 2

- WebAuthn (FIDO2) passkey registration and login, bound to a DID
- Browser login page at `/login`, reached from `/authorize` via a
  pending-request ID
- DID is generated in the browser; its private key never leaves it
- Passkey credentials stored server-side in `data/` (git-ignored)
- Simulated ledger anchoring of DIDs
- End-to-end flow verified manually: `/authorize` -> passkey sign-in ->
  callback code -> `/token` -> EdDSA-signed access and ID tokens
- 45 automated tests passing

## Security notes

- Private signing key lives in `keys/` and is git-ignored. Never commit it.
- Passkey credential data lives in `data/` and is git-ignored. Never commit it.
- `IDP_DEV_LOGIN=1` enables a development-only login that trusts the
  `login_hint` DID without proof. It is off by default and must never be
  enabled in a deployed environment. Passkey login replaces it.
- Authorization codes are stored in memory (single process) until Redis is
  added in Week 3.
- All commits are signed (SSH signing).

## Run locally

    python -m venv .venv
    source .venv/Scripts/activate      # Git Bash on Windows
    pip install -r requirements.txt
    uvicorn app.main:app --reload

Run the tests:

    python -m pytest -v

Interactive API docs: http://127.0.0.1:8000/docs

## Try the passkey login

1. Start the server (see above).
2. Open this URL in Chrome:

        http://localhost:8000/authorize?response_type=code&client_id=demo-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=openid&state=abc&nonce=n1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256

3. Create an identity, register a passkey, then sign in with the passkey.
4. The browser is redirected to `localhost:8080/callback?code=...`. Nothing
   listens on port 8080, so the page will not load. That is expected: copy the
   code from the address bar and exchange it at `/token` within 60 seconds.

## Project layout

    app/core/       settings and JWT signing
    app/did/        ed25519 keys, did:key resolver, DID documents
    app/oidc/       OIDC / OAuth 2.0 endpoints, PKCE, client registry,
                    pending authorization requests
    app/passkeys/   WebAuthn registration and login, credential store
    app/web/        login page (HTML, CSS, JavaScript)
    scripts/        helper scripts
    tests/          pytest suite

## Branching

Feature branches (`feat/...`, `docs/...`) merged into `main` with `--no-ff`.