# apd HTTP API

All endpoints except the well-known documents and `/healthz` require an
[AAuth HTTP Message Signature](../research/03-http-signatures.md) covering at
least `@method`, `@authority`, `@path`, `signature-key`, with `created` inside
the configured window (default 60 s). Errors are RFC 9457 `application/problem+json`
with a machine-readable `error` member; signature failures also carry a
`Signature-Error` response header.

Bodies are JSON. Request-body size is capped by `max_body_bytes` (default 64 KiB).

## Public (unsigned)

### `GET /.well-known/aauth-agent.json`
Agent Provider metadata. `issuer`, `jwks_uri`, optional display fields, and
`event_endpoint` when events are enabled. `Cache-Control: public, max-age=300`.

### `GET /.well-known/jwks.json`
The AP's public signing keys (Ed25519 JWKs, `kid`-tagged, active key first).

### `GET /healthz`
`{"status":"ok","issuer":...,"uptime_secs":N}`.

## Agent ceremony endpoints

### `POST /enroll`
Establish an agent identity, keyed by the **durable key** thumbprint.
Sign with `Signature-Key: sig=hwk;...` (the durable key).

Body: `{ "enrollment_token"?: string, "ps"?: url, "platform"?: string, "label"?: string }`

- `enrollment_token` is **required** in `token` enrollment mode, forbidden-if-absent
  otherwise; single-use, consumed atomically.
- `ps` binds a Person Server into future agent tokens (validated server identifier).
- Re-enrolling the same durable key is idempotent and returns the existing identity.

Responses: `201 {"agent":"aauth:local@domain","status":"enrolled"}` (or
`200 {..,"status":"existing"}`). Errors: `403 enrollment_required` /
`invalid_enrollment_token`, `400 invalid_request`, `401` signature errors.

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

Validated in order: `typ`, resource JWKS signature, HTTP signature, subscription
lookup by `eid`, `iss` == authorized resource, `exp` future, `max_uses`
(atomic), `aud` == subscribed agent. The event is **durably recorded before**
`202`.

Response: `202 {"remaining_uses":N}` (present only when `max_uses` was set; `0`
⇒ subscription exhausted and cleaned up), else `202 {}`. Errors: `404
unknown_subscription`, `403 resource_mismatch`/`agent_mismatch`,
`429 max_uses_exceeded`, `401` signature errors.

### `GET /inbox`
Agent drains pending events (signed with the agent token). Honors
`Prefer: wait=N` for long-polling (capped at 50 s). Events whose `exp` has passed
are dropped. Response: `200 {"events":[{"event_token":..,"payload":..,"eid":..,"iss":..}]}`.

## Admin API (when `admin_token` set)

Bearer-gated: `Authorization: Bearer <admin_token>` (constant-time compared;
these endpoints are **not** AAuth-signed — front them with your own network/mTLS
controls). Disabled entirely if no admin token is configured.

- `POST /admin/enrollment-tokens` — `{ "ps"?: url, "label"?: string, "ttl"?: secs }`
  → `201 {"enrollment_token":..,"expires_in":N}` (single-use).
- `GET /admin/agents` → `{ "agents":[...], "count":N }`.
- `GET /admin/agents/{local}` → the agent record.
- `POST /admin/agents/{local}/revoke` — future token issuance refused
  (existing tokens age out within ≤ their lifetime).
- `POST /admin/agents/{local}/reinstate`.

## CLI

```
apd serve [--config apd.json]
apd keygen [--keys apd-keys.json] [--rotate] [--prune-days N]
apd enroll-token --config apd.json [--ps https://ps.example] [--ttl 3600]
apd example-config > apd.json
apd version
```

`enroll-token` writes directly to the configured persistent store (file/redis);
for the memory backend, use `POST /admin/enrollment-tokens` on the running server.
