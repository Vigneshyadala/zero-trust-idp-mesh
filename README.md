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
| 3 | Zero-trust policy engine, token revocation, admin dashboard | Complete |
| 4 | Penetration tests, Docker + Traefik deployment, final report | In progress |

Week 4 so far: penetration test suite, Docker image, compose stack and local
HTTPS are done. Remaining: production TLS configuration and the final report.

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

### Week 3

- Zero-trust policy engine (`app/policy/`): risk score from IP blocklist,
  device and user-verification signals and time of day. A score at or above
  the threshold blocks token issuance with `access_denied` (HTTP 403) and the
  authorization code is burned.
- Token revocation (`app/revocation/`): every token carries a `jti`;
  `POST /revoke` (RFC 7009 style, always returns 200) records it, and
  `verify_token` rejects revoked tokens. Two stores behind one interface:
  in-memory (default) and a Redis Bloom filter (one filter per hour, filters
  expire on their own). The Redis store fails closed if Redis is unreachable.
- Audit log (`app/audit/`): token issued, token denied (policy or bad grant)
  and token revoked events. Bounded in-memory buffer with an optional
  JSON-lines file. Tokens and codes are never logged.
- Admin dashboard at `/admin`: read-only view of audit events and counts,
  protected by an `X-Admin-Key` header. Disabled unless `IDP_ADMIN_KEY` is set.

### Week 4 (so far)

- Penetration test suite (`tests/test_pentest.py`, results in
  `docs/pentest-results.txt`): replay of codes and revoked tokens, expired
  tokens, `alg: none`, HS256 algorithm confusion, attacker-signed and tampered
  tokens, wrong audience and issuer, missing or downgraded PKCE, redirect
  abuse, stolen codes with wrong verifier, unknown clients.
- Docker image: non-root user, health check, no secrets baked in.
- Compose stack: app, Redis and Traefik. Only Traefik is published to the host.
- Local HTTPS through Traefik with a self-signed development certificate and
  an HTTP to HTTPS redirect.
- 110 automated tests passing (1 skipped: the live-Redis test, which runs only
  when `IDP_REDIS_URL` is set).

## Security notes

- Private signing key lives in `keys/` and is git-ignored. Never commit it.
- Passkey credentials live in `data/` and are git-ignored. Never commit them.
- `.env` and `deploy/traefik/certs/` are git-ignored. Never commit them.
- `IDP_DEV_LOGIN=1` enables a development-only login that trusts the
  `login_hint` DID without proof. It is off by default and must never be
  enabled in a deployed environment. Passkey login replaces it.
- Authorization codes are stored in memory (single process).
- The policy engine's device and user-verification signals are placeholders
  that are currently assumed true; only IP and time-of-day are active.
- Behind a proxy, the app trusts forwarded client addresses from any source
  (`--forwarded-allow-ips=*`). This is acceptable only because the app is
  reachable solely through Traefik on a private network.
- Redis has no password and is reachable only from the internal Docker network.
- All commits are signed (SSH signing).

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `IDP_ISSUER` | Token issuer URL | `http://localhost:8000` |
| `IDP_RP_ID` | WebAuthn relying party ID | `localhost` |
| `IDP_RP_ORIGIN` | WebAuthn origin | `http://localhost:8000` |
| `IDP_REQUIRE_UV` | Require WebAuthn user verification | `1` |
| `IDP_DEV_LOGIN` | Development-only login (never in production) | `0` |
| `IDP_REDIS_URL` | Use the Redis Bloom revocation store | unset (in-memory) |
| `IDP_BLOCKED_NETWORKS` | Comma-separated CIDRs the policy engine blocks | none |
| `IDP_ALLOWED_HOURS` | Allowed hours, `start-end` (local time) | `6-22` |
| `IDP_DENY_THRESHOLD` | Risk score that blocks issuance | `70` |
| `IDP_ADMIN_KEY` | Admin dashboard key (dashboard off if unset) | unset |
| `IDP_AUDIT_FILE` | Also write audit events to this JSON-lines file | unset |

## Run locally

    python -m venv .venv
    source .venv/Scripts/activate      # Git Bash on Windows
    pip install -r requirements.txt
    uvicorn app.main:app --reload

Run the tests:

    python -m pytest -v

Interactive API docs: http://127.0.0.1:8000/docs

## Run with Docker (app, Redis, Traefik, local HTTPS)

    python scripts/gen_dev_cert.py
    echo "IDP_ADMIN_KEY=choose-a-long-random-value" > .env
    docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build

The service is then at https://localhost:8443 (self-signed certificate, so the
browser shows a warning) and http://localhost:8000 redirects to it. Stop with:

    docker compose -f docker-compose.yml -f docker-compose.local.yml down

## Try the passkey login

1. Start the server.
2. Open this URL in Chrome (use `https://localhost:8443` instead of
   `http://localhost:8000` when running under Docker):

        http://localhost:8000/authorize?response_type=code&client_id=demo-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=openid&state=abc&nonce=n1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256

3. Create an identity, register a passkey, then sign in with the passkey.
4. The browser is redirected to `localhost:8080/callback?code=...`. Nothing
   listens on port 8080, so the page will not load. That is expected: copy the
   code from the address bar and exchange it at `/token` within 60 seconds.

## Project layout

    app/core/        settings and JWT signing
    app/did/         ed25519 keys, did:key resolver, DID documents
    app/ledger/      simulated ledger anchoring of DID documents
    app/oidc/        OIDC / OAuth 2.0 endpoints, PKCE, client registry
    app/passkeys/    WebAuthn registration and login, credential store
    app/policy/      zero-trust risk scoring and enforcement
    app/revocation/  token revocation (in-memory and Redis Bloom filter)
    app/audit/       audit log of authentication events
    app/admin/       admin API and dashboard page
    app/web/         HTML, CSS and JavaScript pages
    deploy/traefik/  reverse proxy routing and TLS configuration
    scripts/         helper scripts (development certificate generator)
    tests/           pytest suite, including the penetration tests
    docs/            test evidence and reports

## Branching

Feature branches (`feat/...`, `docs/...`, `fix/...`) merged into `main` with
`--no-ff`.