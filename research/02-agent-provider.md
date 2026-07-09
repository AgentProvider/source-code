# The Agent Provider Role — Deep Dive & Design Decisions

> Sources: `draft-hardt-oauth-aauth-protocol` (normative agent-token requirements),
> `draft-hardt-aauth-bootstrap-01` (informational enrollment/refresh patterns),
> `draft-hardt-aauth-events-00` (AP as event inbox),
> `draft-hardt-httpbis-signature-key-05` (key schemes used in the ceremonies).

## 1. What an AP is

The AP is the trust anchor for a fleet of agents. It:

- **issues agent tokens** (`aa-agent+jwt`) binding each agent instance's signing key
  (`cnf.jwk`) to a stable identifier (`sub = aauth:local@domain` where `domain` is the
  AP's domain);
- **publishes metadata + JWKS** so any party can verify those tokens without contacting
  the AP;
- is a **policy enforcement point**: every token refresh is a chance to re-check device
  posture, attestation freshness, and account status, and to *refuse* — that refusal is
  the AP's revocation mechanism (tokens are ≤24h, typically 1h);
- optionally is the agent's **event inbox** (AAuth Events): resources deliver
  `aa-event+jwt` tokens to the AP's `event_endpoint`; the AP routes them to agents that
  cannot receive inbound HTTP.

The AP deliberately sees very little: enrollment and refresh requests, and (if events are
enabled) event deliveries. It does not see the agent's traffic to PSes, resources, or ASes.

## 2. Key model (bootstrap draft, two-key pattern)

Per platform, the recommended pattern is **two keys per agent install**:

- **Durable key** — the enrollment anchor. Lives as long as the install (IndexedDB
  non-extractable WebCrypto key, Secure Enclave/StrongBox key, TPM key…). It signs
  *only* refresh requests to the AP. Its RFC 7638 thumbprint (`durable_jkt`) is the AP's
  lookup key for the enrollment.
- **Ephemeral key** — generated fresh per agent-token issuance. Its public half goes in
  `agent_token.cnf.jwk`; it signs every HTTP request the agent makes for that token's
  lifetime, then is discarded at the next refresh.

Why: an ephemeral-key leak is bounded to one token lifetime; the durable key's attack
surface is only the AP refresh path. Receivers can't tell the patterns apart (they only
check `cnf.jwk` vs the HTTP signature), so a **single-key pattern** (durable key used for
everything) is equally valid where simplicity wins.

### Ceremonies on the wire (Signature-Key schemes)

- **Two-key refresh** — `Signature-Key: sig=jkt-jwt;jwt="..."`:
  the durable key signs a "naming JWT" (`typ: jkt-s256+jwt`, header `jwk` = durable public
  key, `iss = urn:jkt:sha-256:<thumbprint(header jwk)>`, `iat`/`exp`, `jti` for replay
  protection, `cnf.jwk` = the *new ephemeral public key*), and the **ephemeral** key signs
  the HTTP request itself (RFC 9421). The AP: verifies the naming JWT against its own
  header `jwk`; recomputes and string-compares `iss`; looks up the enrollment by the
  durable key's thumbprint; verifies the HTTP signature against `cnf.jwk`; applies policy;
  issues a fresh agent token with `cnf.jwk` = ephemeral key.
- **Single-key refresh** — `Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="..."`:
  the durable key signs the HTTP request directly; AP looks up the enrollment by the
  key's thumbprint and re-issues with the same `cnf.jwk`.
- **Self-hosted agents** are their own AP: one key, published in their own JWKS at their
  own domain; they self-issue agent tokens. (Our server also serves this deployment shape:
  run it on your own domain for a fleet of one.)

## 3. Identifier strategy

`sub = aauth:{local}@{ap-domain}`. Requirements: `local` ∈ `[a-z0-9._+-]`, non-empty,
≤255, stable for the lifetime of the install (across ephemeral rotations), `+` reserved
for sub-agents. The bootstrap draft allows any opaque scheme; deriving from the durable
key thumbprint or random assignment at enrollment are the canonical options.

**Our choice**: random 16-char lowercase base32 (Crockford alphabet folded to lowercase,
no ambiguous letters) assigned at enrollment, stored with the enrollment record. Rationale
vs thumbprint-derivation: survives a future "re-key this enrollment" admin operation, and
leaks nothing about the key. Per-install identity: a new durable key = a new agent; the
PS handles cross-device grouping.

Sub-agents: `local = {parent_local}+{discriminator}`, `discriminator` non-empty,
`[a-z0-9._-]` (no nested `+`).

## 4. Normative obligations checklist (what the code must enforce)

From the protocol spec:

- [ ] Agent token `typ: aa-agent+jwt`, header `kid`, `alg` never `none`; EdDSA recommended.
- [ ] Claims: `iss` (our issuer URL, valid server identifier), `dwk: "aauth-agent.json"`,
      `sub` (valid agent identifier, stable), `jti` (unique), `cnf.jwk`, `iat`, `exp`.
- [ ] Lifetime ≤ 24h (enforce at config load *and* issuance).
- [ ] `ps` claim: only a valid server identifier (https, host-only, lowercase…).
- [ ] Sub-agent rule: **never issue a sub-agent token whose `parent_agent` is itself a
      sub-agent** (single-level depth), and sub-agent `local` = parent local + `+` + disc.
- [ ] Metadata: `issuer` MUST equal the URL the document is served from (verifiers reject
      otherwise); `jwks_uri` REQUIRED; all URLs https.
- [ ] JWKS: serve with cache headers; support multiple keys (rotation) with distinct `kid`s.
- [ ] Verify HTTP Message Signatures on ceremony endpoints per the AAuth profile:
      covered components MUST include `@method`, `@authority`, `@path`, `signature-key`;
      `created` within the validity window (default 60s); respond `401` +
      `Signature-Error` on failure (`invalid_signature`, `invalid_input` +
      `required_input`, `unsupported_algorithm` + `supported_algorithms`, `invalid_key`,
      `unknown_key`, `invalid_jwt`, `expired_jwt`, `invalid_request`).
- [ ] Errors: RFC 9457 `application/problem+json` with `error` member.
- [ ] Events (if enabled): everything in `06-events.md` §AP validation — including
      "MUST NOT return 202 before the event is durably recorded".

From the events spec (AP-specific):

- [ ] Publish `event_endpoint` in metadata.
- [ ] Issue subscribe tokens (`aa-subscribe+jwt`) with `iss`, `dwk: aauth-agent.json`,
      `sub` (agent id), `aud` (resource URL), `cnf.jwk` (agent's *current* key), `eid`
      (opaque, unique at the AP), `iat`/`exp`, optional `max_uses`.
- [ ] Validate event deliveries: `typ aa-event+jwt`; JWT signature via resource JWKS
      (`{iss}/.well-known/aauth-resource.json`); HTTP signature by the *same* key
      (the "dwk-without-cnf" extension of the jwt scheme); subscription lookup by `eid`
      (404 unknown); `iss` == subscription's authorized resource (403); `exp` future;
      `aud` == subscribed agent; `max_uses` accounting (atomic increment, 429 when
      exceeded, `remaining_uses` in the 202 body when max_uses set).

## 5. Non-normative surface we must design ourselves

The bootstrap draft explicitly leaves enrollment/refresh endpoints AP-internal. Our design
(documented in `docs/api.md`, rationale here):

### 5.1 Enrollment — `POST /enroll`

Body: `{"enrollment_token"?, "enrollment_assertion"?, "ps"?, "platform"?, "label"?}`,
signed with `sig=hwk` using the **durable key** (proof of possession at enrollment).

- Methods (config `enrollment.methods`, composable; evaluated assertion → token →
  allowlist → open, no fall-through on a presented-but-invalid credential):
  - `token` (default) — admin mints one-time enrollment tokens; the
    "signed-in account / invitation" stand-in appropriate for self-hosting.
  - `federated` — trusted-issuer assertions: Kubernetes/cloud/CI OIDC tokens,
    operator-minted `cnf`-bound JWTs (static/remote JWKS), or corporate-CA
    `x5c` chains with SAN policy + CRLs. Secret-free workload identity; claim
    policy + `embed_claims` stamped into issued tokens. See
    `docs/federated-enrollment.md` / `docs/federated-enrollment-design.md`.
  - `allowlist` — orchestrator pre-registers the durable-key thumbprint via the
    admin API; consumed on first use.
  - `open` — any key may enroll (local dev, trusted networks).
- Effect: assigns `local`, stores `{local, durable_jkt, ps?, platform?, label?,
  method, issuer?, subject?, embed_claims?, created_at, status: active}`.
- Response: `201 {"agent": "aauth:local@domain"}`; idempotent re-enroll of the
  same key returns the existing identity before any credential is consumed.
- Attestation (WebAuthn / App Attest / Play Integrity verdicts) is optional per
  the bootstrap draft; X.509-rooted hardware attestation rides the `x5c` issuer
  type, and Apple/Google verdict verification can front the token-mint step.

### 5.2 Token issuance / refresh — `POST /agent-token`

- Two-key: `Signature-Key: sig=jkt-jwt` as in §2. `jti` of the naming JWT is
  replay-checked (storage, TTL = naming JWT lifetime).
- Single-key: `Signature-Key: sig=hwk`; thumbprint must match an enrollment.
- Body (all optional): `{"ps": ...}` — override/confirm the PS to bind into the token
  (must equal enrollment's `ps` unless config `allow_ps_override`).
- Policy hook: enrollment `status` must be `active`.
- Response: `200 {"agent_token": "...", "expires_in": N, "agent": "aauth:..."}`.

### 5.3 Sub-agent tokens — `POST /subagent-token`

Signed with the **parent's current agent token** (`sig=jwt` scheme; the parent's ephemeral
key signs the request). Body: `{"discriminator": "search1", "cnf_jwk": {...}}` — the
sub-agent generates its own key pair and hands the public key to the parent out of band.

- Enforce: parent token valid + not itself a sub-agent (no `parent_agent`); discriminator
  syntax; issued token: `sub = aauth:{parent_local}+{disc}@{domain}`,
  `parent_agent = parent sub`, `ps` = parent's `ps`, `cnf.jwk` = provided key,
  `exp = min(policy_exp, parent_token.exp)` (a sub-agent should not outlive the consent
  context of its parent's token).

### 5.4 Events plumbing (agent side)

- `POST /subscribe` (signed with agent token): body `{"resource": "https://...",
  "max_uses": N?, "ttl": secs?}` → AP mints `eid`, stores subscription
  `{eid, agent, resource, max_uses, uses:0, created}`, returns
  `{"subscribe_token": "...", "eid": "..."}`.
- `GET /inbox` (signed with agent token): poll pending events (workload pattern);
  `?wait=N` or `Prefer: wait=N` long-polls (capped 50 s). SSE/push streams are
  valid AP→agent options (events draft) but not implemented here.
- `POST /events` — the public `event_endpoint` (resource-facing), per §4.
- `DELETE /subscriptions/{eid}` (signed with agent token) — cancel.

### 5.5 Admin — under `/admin/*`, bearer token from config (constant-time compare)

- `POST /admin/enrollment-tokens` → one-time enrollment token (optionally `ps` pinned,
  labels).
- `GET /admin/agents`, `GET /admin/agents/{local}`, `POST /admin/agents/{local}/revoke`
  (sets `status: revoked` → next refresh fails → agent ages out within ≤ token lifetime),
  `POST /admin/agents/{local}/reinstate`.

## 6. Scale & multi-instance requirements

- **Verification is stateless for the world**: everything a verifier needs is the JWT +
  our JWKS. Horizontal scale of *verification load* lands on the well-known endpoints —
  they must be cheap (pre-serialized bytes, cache headers).
- **Shared state** across instances is small and low-write:
  - enrollments (read on every refresh, write on enroll/revoke)
  - enrollment tokens (single-use consume — needs atomicity)
  - naming-JWT `jti` replay cache (TTL entries — needs atomicity)
  - event subscriptions + use counters (atomic increment) + inbox queues
- **Signing keys** must be identical on all instances (same key file / secret mount);
  rotation = add new key with new `kid`, switch `active`, keep the old public key
  published until the last token signed with it expires (≤ max token lifetime).
- Storage abstraction with three backends: `memory` (dev/tests), `file` (single host,
  crash-safe JSON journal), `redis` (multi-instance; minimal RESP2 client — no extra
  dependency). All mutating ops that need atomicity map to Redis primitives
  (`SET NX`, `GETDEL`, `INCR`, `LPUSH/BRPOP`).
- Clocks: `iat`/`exp`/`created` windows assume NTP-synced hosts (spec: 60s default window).

## 7. Security notes specific to the AP

- **AP signing key compromise = fleet identity compromise.** Keep the key file 0600,
  support passing via env/secret manager, document rotation. (Same rigor the spec demands
  of PS keys.)
- **Enrollment tokens** are the anti-fraud gate for self-hosted mode: single-use, expiring,
  unguessable (192-bit random), constant-time compared, consumed atomically.
- **Naming-JWT replay**: enforce `jti` single-use within the JWT's validity; require
  `exp - iat` ≤ 5 minutes for naming JWTs.
- **`created` window** on HTTP signatures: default 60s, configurable.
- **Egress admission** for resource JWKS fetches on `/events` (SSRF defense): https only,
  no cross-host redirects, block private/loopback/link-local ranges by default, response
  size cap, timeout, per-issuer once-per-minute floor, 24h cache ceiling.
- **Body limits** on all endpoints; strict JSON parsing; problem+json errors that don't
  leak internals.
- The AP does not need a replay cache for general request signatures (it's not required),
  but the `jti` check on naming JWTs and single-use enrollment tokens cover the
  state-changing paths.

## 8. What we intentionally do NOT implement

- Person Server / Access Server / Resource roles (separate servers; see
  `04-connecting-agents.md` and `05-connecting-resources-mcp.md` for how they interact
  with us).
- Platform attestation verification (App Attest / Play Integrity / WebAuthn) — hooks only.
- Payment (`402`), missions, consent UI — PS/AS territory.
- AP-to-agent push (APNs/FCM) and SSE/WebSocket streaming — we provide the poll +
  long-poll inbox primitive; streaming/push transports are deployment-specific and
  not shipped.
