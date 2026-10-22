# 3. Security Audit

## 3.1 Scope and method

The audit covers the identity provider service: the OIDC and OAuth endpoints,
token signing and verification, the zero-trust policy engine, revocation, the
audit log, the admin dashboard, and the container and proxy configuration.

Method: an automated penetration suite (`tests/test_pentest.py`) in which each
test plays the attacker; a passing test means the attack failed. The suite runs
in-process against the real application. Output is saved in
`docs/pentest-results.txt` and can be reproduced with:

    python -m pytest tests/test_pentest.py -v

Result at the time of writing: 18 attack tests, all resisted. The full suite
has 110 passing tests and 1 skipped (the live-Redis test, which runs only when
`IDP_REDIS_URL` is set).

## 3.2 Threat results

| # | Class | Attack | Result |
|---|-------|--------|--------|
| 1 | Replay | Reuse an authorization code after a successful exchange | Refused (`invalid_grant`) |
| 2 | Replay | Use an access token after it was revoked | Refused |
| 3 | Replay | Use an expired token | Refused |
| 4 | Forgery | Unsigned token (`alg: none`) | Refused |
| 5 | Forgery | HS256 token signed with the public key (algorithm confusion) | Refused |
| 6 | Forgery | Token signed with an attacker's Ed25519 key | Refused |
| 7 | Forgery | Valid token with its payload edited (`sub`, `exp`) | Refused |
| 8 | Forgery | Token issued for a different audience | Refused |
| 9 | Forgery | Token claiming a different issuer | Refused |
| 10 | Flow abuse | Authorization request without PKCE | No code issued |
| 11 | Flow abuse | PKCE downgrade to the `plain` method | No code issued |
| 12 | Flow abuse | Unregistered `redirect_uri` | No redirect, no code |
| 13 | Interception | Stolen code redeemed with a wrong verifier | Refused, no token |
| 14 | Interception | Failed guess, then the real owner retries | Code is already burned; both refused |
| 15 | Interception | Code redeemed without a verifier | Refused |
| 16 | Interception | Code redeemed against a different `redirect_uri` | Refused |
| 17 | Flow abuse | Token request from an unknown client | Refused (HTTP 401) |
| 18 | Leakage | Token response caching | `Cache-Control: no-store` present |

## 3.3 Man-in-the-middle

The in-process suite cannot test the network. Transport protection was checked
separately against the Docker stack: HTTPS is served by Traefik, plain HTTP
answers with a redirect to HTTPS, and responses carry `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. The
development certificate is self-signed. The production configuration (Let's
Encrypt, automatic renewal, HSTS) is written and validated but has not been run
against a live domain.

At the application layer, PKCE with S256 and exact `redirect_uri` matching
mean that an intercepted authorization code is useless without the client's
code verifier.

## 3.4 Findings and limitations

Severity is the author's assessment for a production deployment.

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| F1 | Revocation is enforced inside the IdP's token verification only. A resource server that validates tokens with the published key alone will not see revocations. There is no introspection endpoint. | Medium | Open. Add an introspection endpoint |
| F2 | `/revoke` verifies tokens with the issuer as audience, so only access tokens can be revoked; ID tokens are ignored | Low | Open. ID tokens are for the client only |
| F3 | The policy engine's device-known and user-verified signals are placeholders assumed true. Only IP and time of day are active | Medium | Open. Store these facts with the code at login |
| F4 | No rate limiting or lockout on `/token`, `/revoke` or the admin key check | Medium | Open. Add a rate limit at Traefik or in the app |
| F5 | Admin access uses one shared key in a header, compared in constant time. No per-user identity, no expiry | Medium | Open. Bind admin access to a DID and passkey |
| F6 | Audit log is an in-memory buffer of 1000 events; the optional file is not tamper-evident | Medium | Open. Hash-chain the file or ship it off-host |
| F7 | Authorization codes live in process memory, so the service is single-instance | Low | Accepted for this scope. Move to Redis to scale out |
| F8 | The app trusts forwarded client addresses from any source (`--forwarded-allow-ips=*`) | Low | Mitigated: the app is reachable only through Traefik on a private network |
| F9 | Redis has no password or TLS and relies on network isolation | Low | Mitigated by isolation. Add auth for production |
| F10 | The ledger is a simulation: `validate()` detects an edited block but not a complete consistent rewrite of the file | Medium | Accepted. See section 2.6 |
| F11 | Time-of-day policy uses server local time; the container clock is UTC | Low | Open. Make the time zone configurable |
| F12 | Redis Bloom filter has a 0.1% false-positive rate: a valid token may be rejected and the user signs in again | Low | Accepted and documented |
| F13 | WebAuthn ceremony attacks (for example, a replayed assertion) are not part of the penetration suite | Low | Open. Add tests |
| F14 | Production TLS and HSTS are untested against a live domain | Low | Open. Verify when a domain is available |

## 3.5 Controls verified

- Algorithm pinned to EdDSA; `alg: none` and HS256 confusion rejected.
- PKCE (S256) mandatory; `plain` and missing challenges rejected.
- Authorization codes are single use, expire in 60 seconds, and a failed
  exchange also consumes the code.
- Exact `redirect_uri` matching, with no open redirect.
- Revocation fails closed when Redis is unreachable.
- Policy decision runs before any token is issued; a denied request burns the
  code.
- Secrets are kept out of Git and out of the image: signing key, passkey data,
  `.env`, and certificate keys.
- Container runs as a non-root user and only the proxy publishes ports.
- The admin dashboard is disabled unless `IDP_ADMIN_KEY` is set, and it renders
  event data with `textContent`, so log content cannot inject script.

## 3.6 Recommended next steps

1. Add an introspection endpoint so resource servers can honour revocation (F1).
2. Add rate limiting and temporary lockout (F4).
3. Carry the real device and user-verification facts into the policy engine (F3).
4. Replace the shared admin key with DID and passkey authentication (F5).
5. Make the audit log tamper-evident and durable (F6).
6. Add a password to Redis (F9) and run the production TLS configuration
   against a real domain (F14).