# apd HTTP API

All endpoints except the well-known documents and `/healthz` require an
[AAuth HTTP Message Signature](../research/03-http-signatures.md) covering at
least `@method`, `@authority`, `@path`, `signature-key`, with `created` inside
the configured window (default 60 s). Errors are RFC 9457 `application/problem+json`
with a machine-readable `error` member; signature failures also carry a
`Signature-Error` response header (and, for `unsupported_algorithm`, an
`Accept-Signature-Alg: Ed25519` header naming the algorithms apd accepts).

Bodies are JSON. Request-body size is capped by `max_body_bytes` (default 64 KiB).

## Public (unsigned)

### `GET /.well-known/aauth-agent.json`
Agent Provider metadata. `issuer`, `jwks_uri`, `accept_signature_algs`, optional
display fields, and `event_endpoint` when events are enabled.
`Cache-Control: public, max-age=300`.

`accept_signature_algs` (AAuth `-11`) is the **exact** set of fully-specified JWS
algorithms this verifier accepts — neither a subset nor a superset — advertised
before first contact rather than after a failure. It is the out-of-band twin of the
`Accept-Signature-Alg` response header, and apd publishes `["Ed25519"]`.

### `GET /.well-known/jwks.json`
The AP's public signing keys (Ed25519 JWKs, `kid`-tagged, active key first). Each
key carries the fully-specified `alg: "Ed25519"` required by sig-key §3.3.

### `GET /healthz`
`{"status":"ok","mode":"demo","issuer":...,"uptime_secs":N}`.
`mode` is `"demo"` while AAuth remains an Internet-Draft (see the README
status notice); the server also announces this at startup on the CLI and as a
`demo_mode_notice` structured log event.

## Agent ceremony endpoints

### `POST /enroll`
Establish an agent identity, keyed by the **durable key** thumbprint.
Sign with `Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="…";alg="Ed25519"`
(the durable key). Per sig-key §3.3 the `hwk` scheme now carries a required,
fully-specified `alg="Ed25519"`; an `hwk` missing `alg` is rejected `invalid_key`.

Body: `{ "enrollment_token"?: string, "enrollment_assertion"?: string,
"ps"?: url, "platform"?: string, "label"?: string }`

Authorization is by any enabled method (`enrollment.methods`), evaluated as:
presented **assertion** → presented **token** → **allow-list** → **open**; a
presented-but-invalid credential is a hard `403` (no fall-through).

- `enrollment_token` — a single-use admin-minted token (consumed atomically),
  **or** a reusable static token predefined in config
  (`enrollment.static_tokens` / `APD_STATIC_ENROLL_TOKEN`) — a dev/staging
  convenience; compared constant-time and audited as `token_kind: "static"`.
- `enrollment_assertion` — a JWS/JWT from a configured trusted issuer
  (Kubernetes/CI OIDC token, operator-minted cnf-bound JWT, an `x5c`
  certificate-chain JWS, or a **SPIFFE SVID** — a JWT-SVID under a trusted
  `trust_domain`, or an X.509-SVID via `x5c`). See
  [`federated-enrollment.md`](federated-enrollment.md) for the format, issuer
  types, and recipes. Single-use `jti` enforcement applies to non-key-bound
  assertions by default.
- `ps` binds a Person Server into future agent tokens (validated server
  identifier); a federated issuer's `ps` pin is authoritative.
- Re-enrolling the same durable key is idempotent and returns the existing
  identity (checked before any credential is consumed).

Responses: `201 {"agent":"aauth:local@domain","status":"enrolled"}` (or
`200 {..,"status":"existing"}`). Errors: `403 enrollment_required` /
`invalid_enrollment_token` / `invalid_assertion` / `method_disabled` /
`ps_mismatch`, `400 invalid_request`, `401` signature errors.

### `POST /agent-token`
Issue or refresh an agent token.

- **Two-key**: `Signature-Key: sig=jkt-jwt;jwt="<naming JWT>"` — the durable key
  signs a `jkt-s256+jwt` naming JWT delegating to a fresh ephemeral key (whose
  `cnf.jwk` the HTTP request is signed with). The naming JWT's `jti` is
  replay-guarded and its lifetime bounded by `naming_jwt_max_lifetime_secs`.
- **Single-key**: `Signature-Key: sig=hwk;...` — the durable key signs directly.

Body (optional): `{ "ps"?: url }` — overrides the enrollment's `ps` when
`allow_ps_override` is true.

Response: `200 {"agent_token":..,"token_type":"aa-agent+jwt","expires_in":N,"agent":..}`.
Errors: `403 not_enrolled` / `enrollment_revoked` / `ps_mismatch`, `401 invalid_jwt`
(includes naming-JWT replay), signature errors.

The issued `aa-agent+jwt` carries the usual claims (`iss`, `sub`, `dwk`,
`cnf.jwk`, `iat`, `exp`, `jti`, optional `ps`) plus an **`assurance`** claim
(`none`/`low`/`medium`/`high`) derived from how the agent enrolled, and any
issuer `embed_claims`. Receivers may gate on `assurance`; see
[configuration.md](configuration.md#assurance-tiers).

### `POST /subagent-token`
A parent mints a sub-agent identity. Sign with the **parent's agent token**
(`Signature-Key: sig=jwt;jwt="<agent token>"`).

Body: `{ "discriminator": string, "cnf_jwk": JWK }` — the sub-agent generates its
own key pair and the parent forwards the public JWK.

Enforced: parent must be top-level (single-level depth); discriminator is
non-empty lowercase LDH/`._`, no `+`; issued token has
`sub = aauth:{parent_local}+{disc}@domain`, `parent_agent = parent`,
`exp = min(policy, parent.exp)`.

Response: `200 {"agent_token":..,"agent":..,"parent_agent":..,"expires_in":N}`.
Errors: `403 nested_subagent`, `400 invalid_request`/`invalid_key`.

## Events endpoints (when `events.enabled`)

### `POST /subscribe`
Agent asks the AP to authorize a resource to deliver events. Sign with the agent token.

Body: `{ "resource": url, "max_uses"?: int, "ttl"?: secs }`.

Response: `200 {"subscribe_token":..,"token_type":"aa-subscribe+jwt","eid":..,"expires_in":N}`.
The agent presents the subscribe token to the resource's subscription endpoint;
keep your own `eid → context` map.

### `DELETE /subscriptions/{eid}`
Cancel a subscription (signed with the owning agent token). `204`, or `404`/`403`.

### `POST /events`  (resource-facing)
A resource delivers an event. Present the **event token** (`aa-event+jwt`) via
`Signature-Key: sig=jwt;jwt="..."`; the resource's own JWKS key (discovered from
`{iss}/.well-known/aauth-resource.json`, egress-admitted) verifies **both** the
JWT and the HTTP signature (the `dwk`-without-`cnf` pattern). Optional JSON body
is the event payload.

Validated in order: `typ`, event-token claims (incl. `exp` in the future),
resource JWKS signature, HTTP signature, subscription lookup by `eid`, `iss` ==
authorized resource, `aud` == subscribed agent, then `max_uses` (atomic
increment). The event is **durably recorded before** `202`.

Response: `202 {"remaining_uses":N}` (present only when `max_uses` was set; `0`
⇒ subscription exhausted and cleaned up), else `202 {}`. Errors: `404
unknown_subscription`, `403 resource_mismatch`/`agent_mismatch`,
`429 max_uses_exceeded`, `401` signature errors.

### `GET /inbox`
Agent drains pending events (signed with the agent token). Honors
`Prefer: wait=N` for long-polling (capped at 50 s). Events whose `exp` has passed
are dropped. Response: `200 {"events":[{"event_token":..,"payload":..,"eid":..,"iss":..}]}`.

## Admin API (when `admin_token` set)

Bearer-gated, and it accepts either credential:

- **A shared token** — `Authorization: Bearer <admin_token>`, constant-time compared.
- **An identity-provider token** — `Authorization: Bearer <jwt>` from the IdP named
  in `admin_oidc`. Verified against the IdP's JWKS (discovery, egress-admitted),
  with `iss`, `aud`, `exp` and a required claim gate. Enterprise SSO for
  operators: see [configuration.md](configuration.md#admin-api-authentication).

The credential's shape selects the path, so operators need not declare which they
hold. Every state-changing action records an `actor` — `oidc:alice@acme.example`
or `static-token` — so an audit can answer who revoked an agent.

These endpoints are **not** AAuth-signed — front them with your own network
controls. Disabled entirely if neither credential is configured.

- `POST /admin/enrollment-tokens` — `{ "ps"?: url, "label"?: string, "ttl"?: secs }`
  → `201 {"enrollment_token":..,"expires_in":N}` (single-use).
- `POST /admin/allowed-keys` — `{ "jkt": thumbprint, "ps"?: url, "label"?: string,
  "ttl"?: secs }` → `201`. Pre-registers a durable-key thumbprint for the
  `allowlist` enrollment method (consumed on first enrollment).
- `GET /admin/allowed-keys` → `{ "allowed_keys":[...], "count":N }`.
- `DELETE /admin/allowed-keys/{jkt}` → `204` (withdraw a pre-registration).
- `GET /admin/agents` → `{ "agents":[...], "count":N }`.
- `GET /admin/agents/{local}` → the agent record (includes enrollment `method`,
  federated `issuer`/`subject`, and `embed_claims`).
- `POST /admin/agents/{local}/revoke` — future token issuance refused, **and
  the agent's Person Server is notified** about tokens already issued. Returns
  `{"local":..,"status":"revoked","ps_notification":{...}}`.

  Per the spec's Token Revocation rules, the AP calls the PS's
  `revocation_endpoint` once per outstanding token with `{"iss","jti"}` — the
  pair recipients key revocation state by. apd tracks each issued `jti` under a
  TTL equal to the token's remaining life, so the index self-prunes.

  The call signs as the AP itself using the `jwks_uri` Signature-Key scheme
  (`id` = your issuer, `dwk` = `aauth-agent.json`, `kid` = the active key), which
  is how the PS confirms the caller is the `iss` of the token being revoked.

  **Local revocation is authoritative and always succeeds.** The notification is
  best effort; `ps_notification.status` is one of `sent`, `disabled`, `no_ps`,
  `no_endpoint`, or `failed`, and is also written to the audit log. A PS that
  cannot be reached never fails the operation — that access is then bounded by
  the token lifetime, exactly as the spec describes. Disable with
  `revocation.notify_ps: false`.
- `POST /admin/agents/{local}/reinstate`.

## Audit events

Every enrollment decision and issuance is emitted as one JSON line to stderr
(and `audit_log_file` when configured): `enroll`, `enroll_denied`,
`agent_token_issued`, `subagent_token_issued`, `agent_revoked`,
`agent_reinstated`, `enrollment_token_minted`, `allowed_key_added`,
`allowed_key_removed`. The `enroll` event includes the derived `assurance` tier.

## Observability (OpenTelemetry)

When `telemetry.enabled` (or `APD_TELEMETRY_ENABLED=1`), apd exports **metrics
and traces** over OTLP/HTTP to an OpenTelemetry Collector — there is no scrape
endpoint on apd itself; it pushes to `{telemetry.endpoint}/v1/{metrics,traces}`.
Off by default. Metrics (scope `apd`): `apd.enroll.total`
(`method`/`assurance`/`result`), `apd.agent_token.total`,
`apd.subagent_token.total`, `apd.verify_fail.total` (by route),
`apd.requests.total` (route + status class), `apd.request.duration` histogram.
Traces: one SERVER span per request (method, route template, status). See
[configuration.md](configuration.md#observability).

## Conformance client

[`tools/aauthcheck`](https://github.com/AgentProvider/source-code/tree/main/tools/aauthcheck)
is a standalone client built on `aauth-core`. It enrols a throwaway agent at a
live Agent Provider and then exercises a target server the way a real agent
would — signed RFC 9421 requests, real tokens, no mocks.

```sh
cd tools/aauthcheck
cargo run                                     # AP checks + third-party interop
cargo run -- --target https://ps.example      # also grade a Person Server
```

It verifies the agent-token `alg` is the fully-specified `Ed25519`, that an
independent resource accepts our tokens, and — for a Person Server — metadata,
JWKS algorithms, unsigned rejection, signed acceptance, and every person-token
claim including the ≤1 h lifetime. Non-zero exit on failure, so it works in CI.

## CLI

```
apd serve [--config apd.json]
apd keygen [--keys apd-keys.json] [--rotate] [--prune-days N]
apd enroll-token --config apd.json [--ps https://ps.example] [--ttl 3600]
apd example-config [--federated] > apd.json
apd version
```

`enroll-token` writes directly to the configured persistent store (file/redis);
for the memory backend, use `POST /admin/enrollment-tokens` on the running server.
`example-config --federated` prints a starting point with trusted issuers for
federated enrollment.
