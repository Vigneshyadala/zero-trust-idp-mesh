# Zero-Trust Identity Provider Mesh

Decentralized, zero-trust identity provider built with Python and FastAPI
(Zaalima Development - Enterprise Project 3).

Replaces username/password tables with Decentralized Identifiers (DIDs),
WebAuthn (FIDO2) and cryptographic identity anchoring.

## Status

| Week | Scope | State |
|------|-------|-------|
| 1 | OIDC / OAuth 2.0 server, ed25519 DIDs, repo rules | Complete |
| 2 | WebAuthn, simulated ledger anchoring | Planned |
| 3 | Zero-trust policy engine, token revocation, admin dashboard | Planned |
| 4 | Penetration tests, Docker + Traefik deployment, final report | Planned |

## Implemented (Week 1)

- OIDC discovery: `/.well-known/openid-configuration`
- JWKS: `/jwks.json` (Ed25519 / EdDSA signing key)
- DID resolver: `/did/{did}` (did:key, ed25519)
- Authorization code flow with mandatory PKCE (S256): `/authorize`, `/token`
- JWT access and ID tokens signed with EdDSA, algorithm pinned on verification
- Single-use, 60-second authorization codes
- Exact redirect_uri matching, no open redirects

## Security notes

- Private signing key lives in `keys/` and is git-ignored. Never commit it.
- `IDP_DEV_LOGIN=1` enables a development-only login that trusts the
  `login_hint` DID without proof. It is off by default and must never be
  enabled in a deployed environment. WebAuthn replaces it in Week 2.
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

## Project layout

    app/core/    settings and JWT signing
    app/did/     ed25519 keys, did:key resolver, DID documents
    app/oidc/    OIDC / OAuth 2.0 endpoints, PKCE, client registry
    tests/       pytest suite

## Branching

Feature branches (`feat/...`, `docs/...`) merged into `main` with `--no-ff`.
