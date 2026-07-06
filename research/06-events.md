# AAuth Events — The AP as the Agent's Inbox

> Source: `draft-hardt-aauth-events-00`. This is the one AAuth extension where the AP has
> a live protocol role beyond token issuance. Summary + the parts our implementation must
> get exactly right.

## 1. Problem & shape

Agents can't receive webhooks (no public URL, intermittent execution). AAuth Events makes
the **AP the agent's permanent event inbox** — the Web-Push pattern, but the "push
service" already has a cryptographic trust relationship with the agent.

Four phases:

1. **Subscribe-token acquisition** (AP-internal, non-normative): agent asks its AP;
   AP mints an `eid`, stores a subscription record, returns an `aa-subscribe+jwt`.
2. **Subscription registration** (normative): agent presents the subscribe token as the
   `Signature-Key` JWT on a signed POST to the resource's subscription endpoint (or a
   pre-authorized ticket URL for protected channels).
3. **Delivery, resource → AP** (normative): on event fire, resource POSTs to the AP's
   `event_endpoint` presenting an `aa-event+jwt` via `Signature-Key`, body = payload.
4. **Delivery, AP → agent** (AP-internal, non-normative): poll / long-poll / SSE / push.

## 2. Subscribe token (`typ: aa-subscribe+jwt`) — we issue these

Signed by the **AP's** key (same JWKS as agent tokens). Claims:

| claim | value |
|---|---|
| `iss` | AP URL (resource uses it to find our metadata → `event_endpoint`) |
| `dwk` | `aauth-agent.json` |
| `sub` | agent identifier |
| `aud` | **the resource** authorized to deliver events for this `eid` |
| `cnf.jwk` | agent's *current* signing key (verifies the registration HTTP sig) |
| `eid` | opaque AP-generated correlation id, unique at the AP |
| `iat`/`exp` | registration validity window (NOT subscription lifetime) — default 24 h |
| `max_uses` | optional; AP-enforced cap on accepted event tokens for this `eid`; absent = unlimited |

Notes: the subscribe token *replaces* the agent token on the registration request —
structurally analogous (AP-signed + `cnf.jwk`), distinguished by `typ`. Resources SHOULD
reject duplicate registrations per `eid`.

## 3. Event token (`typ: aa-event+jwt`) — we verify these

Signed by the **resource**. Claims: `iss` (resource), `dwk: aauth-resource.json`,
`aud` (**agent identifier**, not the AP), `eid`, `iat`, `exp` (= the agent's response
deadline; event-specific). No `cnf` — transport envelope only; event data rides in the
POST body (AsyncAPI-schema'd).

**Signature-Key extension**: when a `jwt`-scheme JWT has `dwk` but no `cnf`, the HTTP
signing key is the JWT's own signing key — resolved from `{iss}/.well-known/{dwk}` by
header `kid`. One key verifies both the JWT and the HTTP signature.

## 4. AP validation of a delivery (`POST /events`)

The spec lists these checks (draft-events §Event Delivery). `apd` runs them in a
fail-cheap order that is a safe reordering — no check depends on another's side
effects, and the "durably record before 202" MUST is preserved. The two
deliberate deviations from the spec's numbering are noted inline.

1. Extract JWT from `Signature-Key`; `typ == aa-event+jwt`.
2. Validate event-token claims, including **`exp` in the future** (spec step 6,
   done early here — it's a property of the token, cheap to reject on).
3. Resource JWKS via `{iss}/.well-known/aauth-resource.json` (egress admission! resource
   URLs are attacker-influencable); verify JWT signature by `kid` (refresh once on a
   cache-hit key that fails, for silent re-keying).
4. Verify HTTP signature with the same key (dwk-without-cnf).
5. Look up subscription by `eid` → else `404`.
6. `iss` == the subscription's authorized resource (the subscribe token's `aud`) → else `403`.
7. `aud` == the subscription's agent identifier → else `403`. **Run before the
   `max_uses` increment** (reverse of the spec's step 7/8) so a wrong-agent event
   never mutates the counter.
8. `max_uses`: **atomic** use-count increment; exceeded → `429`.

Then: **durably record the event before returning `202`** (this is a MUST — a `202` is a
delivery promise). Response body: `{"remaining_uses": N}` when `max_uses` was set
(`0` ⇒ subscription exhausted; we mark it complete after delivery), empty/`{}` otherwise.
Other errors: `400` malformed, `401` HTTP-sig failure.

## 5. AP → agent delivery (our design; spec leaves it open)

- **Poll / long-poll** (what `apd` ships): `GET /inbox` signed with the agent token,
  optionally `?wait=N` or `Prefer: wait=N` to long-poll (capped at 50 s). Returns and
  acks pending `{event_token, payload}` pairs for that agent. Durable until fetched.
- **SSE / push** (not implemented; the events draft lists them as valid
  platform-dependent options): a persistent SSE/WebSocket stream, or mobile push
  (APNs/FCM), could deliver from the same inbox. Operators can bridge these from
  the poll inbox today.

Agent-side verification (their job, we document it): `typ`, resource JWKS signature,
`aud` == self, `exp` future, dedupe on `(iss, eid)`, map `eid` → local context.

## 6. Security highlights

- `aud` scoping prevents a compromised resource from injecting into another resource's
  channel — enforce check #5 strictly.
- Replay: AP enforces `max_uses` + `exp`; agent dedupes `(iss, eid)`.
- Ticket URLs (protected subscriptions) are the *resource's* concern: short-lived,
  single-use, bound to the subscribing agent's `sub`.
- The AP sees every event envelope + payload → document retention (we keep events only
  until acked + a configurable TTL).
- Don't cache the AP `event_endpoint` at the resource beyond normal HTTP caching of the
  well-known doc; the AP may move it. (We serve cacheable metadata with a modest max-age.)
