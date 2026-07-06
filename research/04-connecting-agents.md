# Connecting an Agent to the Agent Provider — Engineering Guide

> How to build an agent that uses this AP for identity, then operates across the AAuth
> ecosystem. Wire formats are normative (protocol spec); the enrollment/refresh ceremony
> is this AP's design (bootstrap-draft-compatible).

## 0. TL;DR lifecycle

```
generate durable key ──► POST /enroll (hwk, enrollment token) ──► aauth:local@domain
        │
        ▼  every ~55 min (before exp)
generate ephemeral key ──► POST /agent-token (jkt-jwt) ──► agent_token (aa-agent+jwt)
        │
        ▼
sign every request with the ephemeral key; present agent_token via Signature-Key: sig=jwt
        │
        ├─► resource says 401 requirement=agent-token  → you're done, retry signed
        ├─► resource says 202 requirement=interaction  → send user to url?code=..., poll Location
        ├─► resource returns AAuth-Access header       → replay via Authorization: AAuth …, cover "authorization"
        └─► resource says 401 requirement=auth-token   → send resource-token to your PS, get auth_token,
                                                          present auth_token via Signature-Key instead
```

## 1. Keys

Generate Ed25519 keys. Recommended: two-key pattern —

- **durable key**: created once at install, stored as securely as the platform allows
  (file mode 0600 minimum; Secure Enclave/TPM/non-extractable WebCrypto where available).
  Signs only `/enroll` (once) and `/agent-token` (per refresh).
- **ephemeral key**: fresh per token; lives in memory; signs everything else.

Single-key mode is fine for simple workloads: use the durable key for everything and
refresh with `sig=hwk`.

## 2. Enroll (once per install)

Operator mints an enrollment token: `apd admin` API or CLI (see `docs/api.md`). Then:

```http
POST /enroll HTTP/1.1
Host: ap.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...durable key signature...:
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<durable pub>"

{"enrollment_token": "<one-time token>", "ps": "https://ps.example", "platform": "workload"}
```

→ `201 {"agent": "aauth:k7q3p9n2@ap.example"}`. Store nothing except your durable key —
the AP finds you by its thumbprint. (In `open` enrollment mode, omit `enrollment_token`.)

## 3. Get / refresh an agent token

1. Generate ephemeral Ed25519 key pair.
2. Build the **naming JWT**, signed by the durable key:
   - header: `{"typ":"jkt-s256+jwt","alg":"EdDSA","jwk":{<durable public JWK>}}`
   - payload: `{"iss":"urn:jkt:sha-256:<RFC7638 thumbprint of durable JWK>",
     "iat":now,"exp":now+300,"jti":"<random>","cnf":{"jwk":{<ephemeral public JWK>}}}`
3. Sign the HTTP request with the **ephemeral** key:

```http
POST /agent-token HTTP/1.1
Host: ap.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=...
Signature: sig=:...ephemeral key signature...:
Signature-Key: sig=jkt-jwt;jwt="<naming JWT>"

{}
```

→ `200 {"agent_token":"eyJ...","expires_in":3600,"agent":"aauth:k7q3p9n2@ap.example"}`

Refresh proactively (e.g. at 90% of lifetime). Every auth token you hold dies with the
key it's bound to, so refresh agent token → re-obtain auth tokens (there are no refresh
tokens in AAuth; re-run the resource-token → PS flow, which is one request when consent
is remembered).

`jti` in the naming JWT is single-use — never reuse a naming JWT.

## 4. Signing requests (everywhere)

Per the AAuth profile (see `research/03-http-signatures.md`): cover at least
`@method`, `@authority`, `@path`, `signature-key`; add `authorization` when sending
`Authorization: AAuth …`; add `aauth-mission` when sending `AAuth-Mission`; add whatever
a resource's metadata lists in `additional_signature_components` (commonly
`content-digest` — then also send an RFC 9530 `Content-Digest` header). Set `created` to
now (NTP-synced; default server window is ±60 s). Present exactly one credential via
`Signature-Key: sig=jwt;jwt="<agent_token or auth_token>"` — agents MUST use the `jwt`
scheme toward resources/PS/AS (never bare `hwk`).

Present the **agent token** until you hold an **auth token** for that resource, then
present the auth token (its `cnf.jwk` is the same ephemeral key, so your signing code
doesn't change).

## 5. Talking to resources — the single loop

Fetch `{resource}/.well-known/aauth-resource.json` (optional but lets you plan):
`access_mode` ∈ `agent-token` | `aauth-access-token` | `auth-token`; the runtime
`AAuth-Requirement` header is always authoritative. Then loop:
make request → read `AAuth-Requirement` → satisfy → retry.

- `401 requirement=agent-token` → sign with your agent token.
- `202 requirement=interaction; url=".."; code=".."` + `Location` → get the user to
  `{url}?code={code}` (browser, QR, or relay via your PS's `interaction_endpoint`); poll
  `Location` (GET, signed, respect `Retry-After`; `status:"interacting"` = stop prompting;
  403 denied/abandoned; 408 expired; 410 gone; 429 add 5 s).
- response with `AAuth-Access: <token68>` → store; send back as
  `Authorization: AAuth <token68>` with `authorization` covered. Any response may rotate
  it — always adopt the newest.
- `401 requirement=auth-token; resource-token="eyJ..."` → three/four-party flow, next
  section.
- `402` → payment protocol (x402/MPP) + poll `Location` — only if you declared the
  `payment` capability.

Declare what you can handle: `AAuth-Capabilities: interaction, clarification, payment`
on requests to resources (omit what you can't do — absence means "none").

## 6. Using a Person Server (three/four-party)

Prerequisite: your agent token carries `ps` (set at enrollment or in the `/agent-token`
body). Verify the resource token before forwarding it: `iss` == the resource you called,
`agent` == your identifier, `agent_jkt` == thumbprint of *your* signing key, `exp` future.

```http
POST {ps.token_endpoint} HTTP/1.1
Content-Type: application/json
Prefer: wait=45
Signature-Key: sig=jwt;jwt="<agent_token>"
... signature headers ...

{"resource_token":"eyJ...","justification":"Find available meeting times",
 "platform":"workload","capabilities":["interaction","clarification"]}
```

Responses: `200 {auth_token, expires_in}` — verify `iss` == resource token `aud`,
`aud` == the resource, `cnf.jwk` == your key, `agent` == you; or `202` deferred
(interaction/clarification) — same polling loop; during clarification, respond by POSTing
`{"action":"clarification_response"|"updated_request",...}` or DELETE to cancel.
Resource tokens live ≤5 min — if consent took longer, fetch a fresh resource token and
resubmit (the PS remembers consent, so it resolves immediately).

Missions, permission/audit/interaction endpoints are PS features; see the protocol spec
§Missions. From the AP's perspective they don't exist.

## 7. Sub-agents

Parent (a top-level agent) mints identities for its workers via this AP:

1. Sub-agent generates its own ephemeral key pair, gives the public JWK to the parent.
2. Parent: `POST /subagent-token` signed with the parent's agent token
   (`Signature-Key: sig=jwt`), body
   `{"discriminator":"search1","cnf_jwk":{...}}`.
3. AP returns an agent token with `sub = aauth:{parent_local}+search1@ap.example`,
   `parent_agent = <parent id>`, `exp` capped to the parent token's `exp`.

Rules the ecosystem enforces (and this AP enforces at issuance): one level deep only;
sub-agents never call a PS directly — the parent requests auth tokens for them
(`subagent_token` parameter at the PS token endpoint); the sub-agent obtains its own
resource tokens (they get bound to *its* key via `agent_jkt`).

## 8. Receiving events (AAuth Events)

1. `POST /subscribe` (signed with agent token): `{"resource":"https://resource.example",
   "max_uses":1?}` → `{"subscribe_token":"...","eid":"evt_..."}`.
   Keep your own `eid → context` map.
2. Register at the resource: signed POST to its subscription endpoint (public channel) or
   to a **subscription ticket URL** the resource gave you in an authenticated response
   (protected channel), presenting `Signature-Key: sig=jwt;jwt="<subscribe_token>"`
   (the subscribe token *replaces* the agent token on that request; its `cnf.jwk` is your
   current key, so sign as usual).
3. Later, the resource POSTs an `aa-event+jwt` to this AP's `/events`. Collect it
   by polling `GET /inbox?wait=30` (signed; `?wait=N` or `Prefer: wait=N`
   long-polls up to 50 s) → `{"events":[{"event_token":"...","payload":{...}}]}`,
   acked on delivery.
4. Verify each event token yourself before acting: `typ aa-event+jwt`, signature via the
   resource's JWKS, `aud` == your agent id, `exp` future (it's the response deadline),
   dedupe on `(iss, eid)`.

Subscribe-token `exp` is the *registration* window (default 24 h), not the subscription
lifetime — that's negotiated with the resource.

## 9. Failure-handling cheat sheet

| you see | do |
|---|---|
| `401` + `Signature-Error: error=expired_jwt` | refresh agent token, retry |
| `401` + `invalid_signature` | check clock skew (±60 s), covered components, key |
| `401` + `invalid_input; required_input=(…)` | re-sign covering the listed components |
| `403` problem `{"error":"denied"}` on a pending URL | user said no — stop |
| `408` on pending URL | expired — start the flow over |
| `410` on pending URL | terminal already delivered — never retry this URL |
| `429` | add 5 s to your poll interval (and/or sign your requests) |
| auth token rejected after key rotation | expected — re-run resource-token → PS flow |
| AP refuses refresh (`403 enrollment_revoked`) | your enrollment was revoked; contact operator |
