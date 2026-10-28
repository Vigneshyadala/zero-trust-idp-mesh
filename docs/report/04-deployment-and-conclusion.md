# 4. Deployment, Operations and Conclusion

## 4.1 Container image

The `Dockerfile` builds from `python:3.12-slim`, installs the pinned
requirements, copies only the `app/` package and runs as an unprivileged user
(uid 10001). The signing key and passkey data are never baked into the image:
`.dockerignore` excludes `keys/`, `data/`, `.env`, tests and documents, and both
directories are mounted as volumes at runtime. A health check calls `/health`
every 15 seconds.

## 4.2 Compose stack

| Service | Image | Published ports | Role |
|---------|-------|-----------------|------|
| `app` | built from `Dockerfile` | none | The IdP, reached only through Traefik |
| `redis` | `redis/redis-stack-server` | none | Revocation state (Bloom filters) |
| `traefik` | `traefik:v3.1` | 8000, 8443 (local) or 80, 443 (production) | TLS termination, redirect, security headers |

All three share a private network. `app` starts only after Redis reports
healthy. Traefik reads its routes from files, so it needs no access to the
Docker socket. Named volumes hold the signing key (`idp-keys`), passkeys, ledger
and audit file (`idp-data`) and Redis data (`redis-data`).

Configuration is by environment variables (listed in the README). Secrets such as `IDP_ADMIN_KEY` and `REDIS_PASSWORD` live in `.env`, which is git-ignored.

## 4.3 Local run with HTTPS

```
python scripts/gen_dev_cert.py
echo "IDP_ADMIN_KEY=choose-a-long-random-value" > .env
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

The service answers at `https://localhost:8443`; `http://localhost:8000`
redirects to it. The development certificate is self-signed, so browsers warn
about it. The local override sets the issuer and WebAuthn origin to the HTTPS
address, because a passkey is bound to its origin.

Verified results of this setup:

| Check | Result |
|-------|--------|
| `https://localhost:8443/health` | 200 with security headers |
| `http://localhost:8000/health` | 302 redirect to the HTTPS address |
| Discovery document | issuer is `https://localhost:8443` |
| Redis | healthy; app started after it |

## 4.4 Production configuration (written, not run)

`docker-compose.prod.yml` and `deploy/traefik/prod-routes.yml` add:

- a `Host()` rule for the real domain
- Let's Encrypt certificates (TLS-ALPN challenge), stored in the `letsencrypt`
  volume and renewed automatically by Traefik
- redirection of all HTTP to HTTPS at the entry point
- an HSTS header (one year)

Steps to deploy, on a server with a public domain whose DNS points to it and
ports 80 and 443 open:

1. Put `IDP_ADMIN_KEY`, `REDIS_PASSWORD`, `IDP_DOMAIN` and `ACME_EMAIL` in `.env`.
2. Replace `idp.example.com` in `deploy/traefik/prod-routes.yml` with the domain.
3. Test first against the Let's Encrypt staging server by adding
   `--certificatesresolvers.letsencrypt.acme.caserver=https://acme-staging-v02.api.letsencrypt.org/directory`
   to the Traefik command, then remove it.
4. Start the stack:

```
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

**Status:** this configuration validates (`docker compose config`), and it
refuses to start if `IDP_DOMAIN` or `ACME_EMAIL` is missing, but it has not been
run against a live domain because none was available during the project.

## 4.5 Backup and recovery

Two volumes hold state that cannot be recreated:

- `idp-keys`: the signing key. Losing it invalidates every issued token and
  changes the published key ID.
- `idp-data`: passkey credentials, the ledger and the audit file. Losing it
  means users must register again, and DID anchors are lost.

Back up a volume to a file (check the exact volume name first with
`docker volume ls`; Compose prefixes it with the project name):

```
docker volume ls
MSYS_NO_PATHCONV=1 docker run --rm -v zero-trust-idp-mesh_idp-keys:/data -v "$PWD":/backup alpine tar czf /backup/keys-backup.tgz -C /data .
```

Restore with the reverse (`tar xzf ... -C /data`) into an empty volume. Store
backups off the host and never commit them to Git; the signing key is a secret.
Redis holds only revocation entries that expire on their own, so it does not need
backing up.

## 4.6 Operations notes

- **Key rotation.** The service publishes a single signing key, so replacing it
  invalidates all issued tokens at once. Supporting two keys in the JWKS during
  a rotation is future work.
- **Passkeys and origin.** Changing the host or scheme changes the WebAuthn
  origin, so existing passkeys stop working.
- **Time zone.** The policy engine evaluates allowed hours in the zone set by
  `IDP_TIMEZONE` (an IANA name such as `Asia/Kolkata`). The Docker stack defaults
  to UTC; without the setting the server's local time is used.
- **Audit.** The in-memory audit buffer is lost on restart unless
  `IDP_AUDIT_FILE` is set (the compose file sets it to `/srv/data/audit.log`).
- **Common local problem.** If `docker` commands fail with "failed to connect to
  the docker API", Docker Desktop is not running.
- **Port clash.** The local stack uses host ports 8000 and 8443; stop any
  development server on 8000 first.

## 4.7 Testing summary

| Suite | Tests |
|-------|-------|
| Week 1 and 2 (OIDC, DID, ledger, passkeys, signing) | 45 |
| Policy engine, runtime and `/token` enforcement | 15 |
| Revocation, Redis store, `/revoke` | 15 (one live-Redis test skipped) |
| Audit log and its wiring | 10 |
| Admin dashboard | 8 |
| Penetration tests | 36 |
| Rate limiting | 13 |
| Token introspection | 8 |
| Policy time zone | 6 |
| User verification | 5 |
| **Total** | **161 collected: 160 passed, 1 skipped** |

The skipped test exercises a live Redis and runs when `IDP_REDIS_URL` is set. The
Redis store is otherwise covered by tests against a fake client.

## 4.8 Conclusion

The project replaces a password table with DIDs and WebAuthn passkeys, issues
standards-based OIDC tokens signed with EdDSA, and puts a zero-trust policy check
in front of every issuance. Tokens can be revoked individually through a Redis
Bloom filter that fails closed, events are recorded in an audit log with a
key-protected dashboard, and the whole system runs as a hardened container stack
behind Traefik with TLS.

Against the project plan, every deliverable is implemented and tested, with these
exceptions stated openly: the ledger is a simulation, one policy signal (known device) is a placeholder, and the production TLS configuration has not been run against a
live domain. The security audit (section 3) lists these and the other findings
with recommended fixes. The most valuable next steps are known-device tracking in the policy engine, shared rate-limit counters in Redis, and DID-based admin authentication.
## 4.9 Live Redis verification

The Redis Bloom filter store was exercised against a real Redis Stack
container (`redis/redis-stack-server`) on 22 October 2026 using
`IDP_REDIS_URL=redis://localhost:6379/0 python -m pytest tests/test_redis_store_integration.py`.
The test passed: a revoked identifier was reported revoked, and an unseen
identifier was not.
