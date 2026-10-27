# 3. Security Audit

## 3.1 Scope and method

The audit covers the identity provider service: the OIDC and OAuth endpoints,
token signing and verification, the zero-trust policy engine, revocation, the
audit log, the admin dashboard, and the container and proxy configuration.

Method: an automated penetration suite (`tests/test_pentest.py`) in which each
test plays the attacker; a passing test means the attack failed. The suite runs
in-process against the real application. Output is saved in
`docs/pentest-results.txt` and can be reproduced with:

    python -m pytest tests/test_pentest.py tests/test_pentest_endpoints.py tests/test_pentest_webauthn.py -v

Result at the time of writing: 36 attack tests, all resisted. The full suite
has 160 passing tests and 1 skipped (the live-Redis test, which runs only when
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
| 19 | Introspection | Call `/introspect` without the key or with a wrong key | Refused (HTTP 401), no token data returned |
| 20 | Introspection | Unsigned `alg: none` token | Reported inactive |
| 21 | Introspection | HS256 token signed with the public key | Reported inactive |
| 22 | Introspection | Token signed with an attacker's key | Reported inactive |
| 23 | Introspection | Valid token with an edited payload | Reported inactive |
| 24 | Introspection | Token claiming a different issuer | Reported inactive |
| 25 | Introspection | An ID token presented as an access token | Reported inactive |
| 26 | Introspection | Probe why a token is inactive (revoked, expired, garbage, empty) | Identical `{"active": false}` answers |
| 27 | Rate limiting | Guess the introspection key | HTTP 429 after the limit, including for the right key until the window passes |
| 28 | Rate limiting | Brute-force authorization codes at `/token` | HTTP 400 up to the limit, then 429; blocked attempts audited |
| 29 | Rate limiting | Exceed the limit while holding a real code | Refused with 429; the code is not consumed |
| 30 | WebAuthn | Login assertion signed by a different key under a real credential ID | Refused (HTTP 401), no code issued |
| 31 | WebAuthn | Assertion of ceremony type `webauthn.create` presented at login | Refused (HTTP 401) |
| 32 | WebAuthn | Passkey login without user verification while it is required | Refused (HTTP 401) |
| 33 | WebAuthn | Registration challenge used at the login endpoint | Refused (HTTP 400) |
| 34 | WebAuthn | Login challenge used at the registration endpoint | Refused (HTTP 400), nothing registered |
| 35 | WebAuthn | Two logins opened from one authorization request | Only one completes; the other is refused (HTTP 400) |
| 36 | Policy | Passkey login without user verification under a strict policy | Blocked at `/token` (HTTP 403) and audited; with user verification the token is issued |

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
| F1 | Revocation is enforced inside the IdP's token verification only. A resource server that validates tokens with the published key alone will not see revocations. There is no introspection endpoint. | Medium | Mitigated: key-protected `POST /introspect` shows revocation to resource servers (access tokens only) |
| F2 | `/revoke` verifies tokens with the issuer as audience, so only access tokens can be revoked; ID tokens are ignored | Low | Open. ID tokens are for the client only |
| F3 | The device-known signal in the policy engine is a placeholder assumed true. The user-verified signal is real: it comes from the passkey login and is stored with the authorization code (a dev-login code counts as unverified). It changes decisions only when `IDP_REQUIRE_UV=0`, because the default already refuses logins without user verification | Medium | Partly mitigated. Track known devices |
| F4 | Rate limiting covers `/token`, `/revoke`, `/introspect` and the admin API (per client address, sliding window, HTTP 429 with `Retry-After`, audited). State is in memory, so limits are per process and reset on restart | Low | Mitigated. Move the counters to Redis to share limits across instances |
| F5 | Admin access uses one shared key in a header, compared in constant time. No per-user identity, no expiry | Medium | Open. Bind admin access to a DID and passkey |
| F6 | Audit log is an in-memory buffer of 1000 events; the optional file is not tamper-evident | Medium | Open. Hash-chain the file or ship it off-host |
| F7 | Authorization codes live in process memory, so the service is single-instance | Low | Accepted for this scope. Move to Redis to scale out |
| F8 | The app trusts forwarded client addresses from any source (`--forwarded-allow-ips=*`) | Low | Mitigated: the app is reachable only through Traefik on a private network |
| F9 | Redis has no password or TLS and relies on network isolation | Low | Mitigated by isolation. Add auth for production |
| F10 | The ledger is a simulation: `validate()` detects an edited block but not a complete consistent rewrite of the file | Medium | Accepted. See section 2.6 |
| F11 | Time-of-day policy time zone | Low | Mitigated: `IDP_TIMEZONE` sets the zone (UTC in the Docker stack); allowed hours are evaluated in that zone |
| F12 | Redis Bloom filter has a 0.1% false-positive rate: a valid token may be rejected and the user signs in again | Low | Accepted and documented |
| F13 | WebAuthn ceremony attacks | Low | Mitigated. Replay, stale sign counter, wrong challenge, wrong origin, another DID's passkey and a missing DID proof are tested in `tests/test_passkeys.py`; forged signature, ceremony-type confusion, ceremony reuse across registration and login, authorization-request reuse and the user-verification policy are tested in `tests/test_pentest_webauthn.py` |
| F14 | Production TLS and HSTS are untested against a live domain | Low | Open. Verify when a domain is available |
| F15 | Rate limits are keyed by client address, so someone sharing a resource server's address could exhaust its introspection allowance (a lockout, not a bypass) | Low | Open. Key introspection limits by authenticated caller, or exempt trusted internal addresses |

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

1. Roll out introspection to resource servers, each with its own key (F1).
2. Move rate-limit counters to Redis so limits hold across instances (F4).
3. Track known devices and feed that fact into the policy engine (F3).
4. Replace the shared admin key with DID and passkey authentication (F5).
5. Make the audit log tamper-evident and durable (F6).
6. Add a password to Redis (F9) and run the production TLS configuration
   against a real domain (F14).