# Connecting Resources & MCP Servers to the AAuth Ecosystem — Engineering Guide

> How a resource (any HTTP API, including an MCP server) works with agents whose identity
> comes from this Agent Provider. The resource never calls the AP for verification — it
> fetches our published JWKS. Sources: protocol spec (resource sections),
> `draft-hardt-aauth-r3` (vocabularies / MCP), `draft-hardt-aauth-events` (event delivery).

## 1. Adoption ladder (each step is complete on its own)

1. **Recognize signatures (identity-based access)** — replaces API keys. Verify the HTTP
   Message Signature + agent token; apply your own ACLs keyed on the agent identifier.
2. **Resource-managed auth (two-party)** — keep your existing OAuth/consent, wrap your
   existing token in the `AAuth-Access` header bound to the agent's signature.
3. **PS-asserted (three-party)** — issue resource tokens with `aud` = the agent's PS;
   accept identity claims (`sub`, `email`, `tenant`, `groups`, `roles`) from the PS-issued
   auth token; apply your own policy.
4. **Federated (four-party)** — deploy/choose an Access Server; resource tokens get
   `aud` = AS; the AS enforces your policy.

## 2. Step 1: verifying an agent (the 80% case)

On a signed request with `Signature-Key: sig=jwt;jwt="<agent token>"`:

1. Parse `Signature-Input`/`Signature`/`Signature-Key` (labels must correlate).
2. Require covered components ⊇ `{@method, @authority, @path, signature-key}`; `created`
   within your window (default 60 s; advertise `signature_window` in metadata otherwise).
3. Verify the agent token JWT:
   - header `typ == aa-agent+jwt`, `alg != none`;
   - `dwk == "aauth-agent.json"`; fetch `{iss}/.well-known/aauth-agent.json` (**verify the
     document's `issuer` equals `iss`**), then its `jwks_uri`, find header `kid`, verify.
     Cache the JWKS (≥1 min floor, ≤24 h ceiling, refresh once on unknown kid). Apply
     egress admission (https only, no cross-host redirects, no private IPs, size/timeout
     caps).
   - `exp` future, `iat` not future; `iss` a valid server identifier.
4. Verify the HTTP signature with `cnf.jwk` from the token.
5. Your principal is `sub` (e.g. `aauth:k7q3p9n2@ap.example`) — stable across key
   rotations. Key it into your ACLs / rate limits / audit exactly like an API-key id.
   `(iss)` tells you which AP vouches for it; trust APs accordingly.
6. `ps` claim (if present) is where you'd send a resource token for three-party mode.
   `parent_agent` (if present) marks a sub-agent; attribute to the parent chain in audit.

Failure responses: `401` + `Signature-Error` (see `research/03-http-signatures.md`).
Challenge unauthenticated requests with
`401` + `AAuth-Requirement: requirement=agent-token` (that tells AAuth agents an *agent
token* specifically is required) — optionally alongside your legacy `WWW-Authenticate`.
Policy denial after successful verification is a plain `403` (no Signature-Error).

Replay hardening for state-changing endpoints (optional per spec): dedupe on
`(key thumbprint, created, @method, @authority, @path)` within the window; and/or require
`content-digest` in covered components via `additional_signature_components` metadata.

## 3. Publish resource metadata

`GET /.well-known/aauth-resource.json`:

```json
{
  "issuer": "https://resource.example",
  "jwks_uri": "https://resource.example/.well-known/jwks.json",
  "access_mode": "agent-token",
  "name": "Example Data Service",
  "scope_descriptions": {"data.read": "Read access…", "data.write": "…"},
  "signature_window": 60,
  "additional_signature_components": ["content-digest"],
  "authorization_endpoint": "https://resource.example/authorize",
  "r3_vocabularies": {
    "urn:aauth:vocabulary:mcp": "https://resource.example/mcp",
    "urn:aauth:vocabulary:asyncapi": "https://resource.example/asyncapi.json"
  }
}
```

- `issuer` MUST equal the origin the document is served from.
- `jwks_uri` is REQUIRED only once you issue resource tokens / make signed calls / emit
  event tokens. Pure verify-only resources may omit it.
- `access_mode` (`agent-token` | `aauth-access-token` | `auth-token`) is advisory;
  runtime `AAuth-Requirement` always wins and can differ per endpoint.

## 4. Two-party: wrapping your existing auth (`AAuth-Access`)

- When you need your own consent/login: reply
  `202 Accepted` + `Location: <pending url>` + `Retry-After` + `Cache-Control: no-store` +
  `AAuth-Requirement: requirement=interaction; url="https://you/interact"; code="A1B2-C3D4"`,
  body `{"status":"pending"}`. Interaction codes: Crockford base32, ≥40 bits, single-use,
  rate-limited; support `?code=...&callback=...` and redirect to `callback` with
  `?error=access_denied|user_abandoned|server_error|temporarily_unavailable|interaction_expired`
  on failure.
- On success return `200` with `AAuth-Access: <token68>` — an *opaque wrapper* of your
  internal token (never usable as a bare bearer token). The agent sends it back as
  `Authorization: AAuth <token68>` and MUST cover `authorization` in its signature —
  reject if not covered. Rotate at will by returning a fresh `AAuth-Access` on any
  response.
- Pending URLs: unguessable, same-origin, verify the agent's signature on every poll,
  `410` after terminal.

## 5. Three/four-party: issuing resource tokens

When an endpoint needs user authorization, mint an `aa-resource+jwt` (you need signing
keys + `jwks_uri` for this):

```json
{
  "iss": "https://resource.example", "dwk": "aauth-resource.json",
  "aud": "<agent's ps claim, or your AS>", "jti": "…",
  "agent": "<agent identifier from its token>",
  "agent_jkt": "<RFC7638 thumbprint of the agent's current signing key>",
  "iat": …, "exp": "≤ 5 minutes",
  "scope": "data.read data.write",
  "mission": {"approver": "…", "s256": "…"}   // echo AAuth-Mission if present
}
```

Deliver it either from your `authorization_endpoint` (`{"resource_token": "…"}`) or as a
challenge: `401` + `AAuth-Requirement: requirement=auth-token; resource-token="eyJ…"`.
You may step-up at any time, even against a valid auth token.

Then verify incoming **auth tokens** (`typ aa-auth+jwt`): JWT trust
(`dwk` ∈ {`aauth-access.json`, `aauth-person.json`}, issuer JWKS, `exp`/`iat`) **plus**
request-context binding: `aud` == you, `agent` matches, `cnf.jwk` == the HTTP signing key
(reject structurally-incomplete `cnf`), `act` chain sane, at least one of `sub`/`scope`,
scope ⊆ what you asked for. In three-party mode you are trusting the *agent's chosen PS*
for identity claims only — namespace users by `(iss, sub)` (+ `tenant`), and keep policy
decisions yours.

## 6. MCP servers specifically

MCP's OAuth-based authorization gives each agent a different `client_id` per server,
bearer tokens, and no portable identity. Fronting an MCP server with AAuth fixes exactly
that; the drafts define the integration points:

- **Transport**: MCP over Streamable HTTP is just HTTP — apply §2 verification as
  middleware in front of the MCP endpoint. The agent identity (`sub`) becomes the MCP
  session's principal; per-agent rate limits and tool ACLs key off it.
- **Discovery**: advertise the MCP endpoint as an R3 vocabulary in your resource
  metadata: `"r3_vocabularies": {"urn:aauth:vocabulary:mcp": "<mcp server url>"}`.
  Agents that know only your hostname fetch `aauth-resource.json`, see the MCP vocabulary
  + `access_mode`, and connect.
- **Scopes ↔ tools**: for coarse control, define scopes like `tools.read`/`tools.exec`
  in `scope_descriptions`. For per-tool grants, R3's MCP vocabulary expresses operations
  as MCP tool names so auth tokens can carry exactly which tools are granted
  (R3 is an exploratory draft — treat as directional).
- **Elicitation / human-in-the-loop**: map to `202` + `requirement=interaction` rather
  than blocking the MCP call.
- **Mode choice**: identity-based works today (verify agent token, allowlist agents);
  two-party wraps an existing OAuth-protected MCP server via `AAuth-Access`; three-party
  gets you real user identity at the MCP server without running your own IdP.

## 7. Emitting events to agents (via this AP)

If your API has async outcomes (waitlists, order status, long jobs):

1. Accept subscription registrations: signed request whose `Signature-Key` JWT is an
   **`aa-subscribe+jwt`** issued by the agent's AP. Verify: `typ`, AP JWKS via
   `{iss}/.well-known/aauth-agent.json`, `exp`, **`aud` == your URL**, `cnf.jwk` == HTTP
   signing key, `eid` non-empty. Store `{eid, iss(=AP), sub(=agent), event_types…}`;
   dedupe registrations by `eid`. For protected channels, hand out single-use
   **subscription ticket URLs** from an authenticated call and verify `sub` matches.
2. When the event fires, mint an **`aa-event+jwt`**: `{iss: you, dwk: "aauth-resource.json",
   aud: <agent identifier>, eid, iat, exp: <response deadline>}`, and POST it to the AP's
   `event_endpoint` (resolve fresh from `{ap}/.well-known/aauth-agent.json`), presenting
   the event token itself as `Signature-Key: sig=jwt` and signing the HTTP request with
   the *same* resource key (`dwk`-without-`cnf` pattern). Body = your AsyncAPI-described
   payload (keep sensitive detail out; agents fetch specifics via authed API calls).
3. Handle AP responses: `202` (+ `remaining_uses` when the subscription had `max_uses` —
   `0` ⇒ clean up), `404` unknown/expired eid ⇒ drop subscription, `403` you're not the
   authorized resource, `429` uses exceeded.
4. Describe channels with AsyncAPI and advertise `urn:aauth:vocabulary:asyncapi`.

## 8. Trusting this AP

Whether to honor tokens from a given AP is your policy. Signals: the AP's metadata
(name/description/logos, ToS), your history with agents from that `iss`, AP-added claims
(attestation etc. — only as trustworthy as the AP). Self-hosted APs (fleet of one) are
first-class: same verification path, trust decision is per-`iss`.
