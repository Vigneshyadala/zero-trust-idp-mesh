# 2. Cryptographic Workflows

## 2.1 Decentralized identifiers (DIDs)

A user's identity is a `did:key` identifier built from an Ed25519 public key
(the multibase `z6Mk...` form). The key pair is generated in the user's
browser and the private key never leaves it. The server resolves a DID to a
DID document (`GET /did/{did}`) without storing any account record. Because a
`did:key` document is derived from the key itself, resolution needs no lookup
and cannot be altered by the server.

## 2.2 Passkey registration and sign-in (WebAuthn)

[CHECK before submitting: describe the registration and login ceremonies as
implemented in `app/passkeys/router.py`: the challenge, what the credential is
bound to (the DID), the relying-party ID and origin checks, signature counter
handling, and the user-verification requirement (`IDP_REQUIRE_UV`).]

## 2.3 Authorization code and PKCE

- The client sends a PKCE challenge (`code_challenge`, method `S256`).
  Requests without a challenge, or with method `plain`, are refused.
- After a successful sign-in the server issues a random authorization code,
  valid for 60 seconds and bound to the client, the exact `redirect_uri`, the
  user's DID and the challenge.
- At `/token` the code is **consumed first**, then checked: client, redirect
  URI and `SHA-256(code_verifier)` against the stored challenge. A failed
  attempt therefore also destroys the code, so a stolen code cannot be
  retried with guessed verifiers.

## 2.4 Token signing and verification

| Item | Value |
|------|-------|
| Algorithm | EdDSA (Ed25519) |
| Header | `alg: EdDSA`, `kid` = first 12 bytes of SHA-256(public key), base64url |
| Claims | `iss`, `sub` (the user's DID), `aud`, `iat`, `exp`, `jti`, plus `scope` and `client_id` |
| Access token | audience is the issuer; lifetime 3600 s |
| ID token | audience is the client; carries the `nonce` when one was sent |
| Key storage | `keys/` volume, git-ignored, never inside the container image |
| Public key | published at `/jwks.json` |

Verification pins the algorithm list to `["EdDSA"]` and checks signature,
issuer, audience and expiry. Pinning rejects `alg: none` tokens and
algorithm-confusion attempts (for example an HS256 token "signed" with the
public key). It then checks the token's `jti` against the revocation store.

## 2.5 Revocation

Every token carries a unique `jti`. `POST /revoke` accepts a token, verifies
its signature first (so only a holder of a genuine token can revoke it), and
records its `jti` until the token's own expiry. The endpoint always answers
HTTP 200, so it cannot be used to test whether a token is valid.

Two stores implement one interface:

- **In-memory**: default, used in tests and single-process runs.
- **Redis Bloom filter**: one filter per hour, keyed by the hour in which the
  token expires, each with a TTL just past that hour so Redis removes old
  filters itself. A Bloom filter never misses a revoked `jti` (no false
  negatives); its false-positive rate is configured at 0.1%, meaning a valid
  token may very rarely be rejected and the user signs in again. If Redis is
  unreachable the store fails closed and reports tokens as revoked.

## 2.6 Ledger anchoring

```mermaid
sequenceDiagram
    participant U as User browser
    participant I as IdP
    participant L as Ledger
    U->>I: POST ledger anchor with DID and signature
    I->>I: build DID document and hash it
    I->>I: verify signature over "anchor:DID:hash"
    I->>L: append block if DID not yet anchored
    L-->>I: block index and hash
    I-->>U: 201 Created
```

1. The server builds the DID document, serializes it as canonical JSON
   (sorted keys, no whitespace) and takes its SHA-256 hash.
2. The signed message is `anchor:{did}:{document_hash}`. The fixed prefix is
   domain separation, so a signature made for anchoring cannot be replayed in
   another context. The signature must verify under the DID's own key, which
   proves control of the DID.
3. The ledger appends a block: `index`, `timestamp`, `entry`
   (`did_anchor`, DID, document hash) and `previous_hash`. The block's `hash`
   is SHA-256 over the canonical JSON of those four fields. The first block
   uses a previous hash of 64 zeros.
4. A DID can be anchored once; a second attempt returns HTTP 409.
5. `GET /ledger/did/{did}` compares the anchored document hash with a freshly
   computed one and returns `matches`. `GET /ledger/chain` recomputes every
   block hash and link and reports whether the chain is valid.
6. Writes use a temporary file and an atomic replace, so a crash cannot leave
   a half-written ledger.

**Limits (state these in the audit):** the ledger is a simulation. A single
process owns the JSON file, so `validate()` detects an edited block but cannot
detect someone who rewrites the whole chain consistently. There is no
consensus, replication, or external timestamping, and a `did:key` document has
no additional data to bind beyond the key itself. A production design would
anchor to an external chain or an IPFS-based store, or at minimum publish the
latest block hash to a place the operator cannot silently change.