# Guide: giving an AI agent AAuth identity & auth

This is a practical, implement-this-in-order guide for making an AI agent
authenticate with AAuth — get a cryptographic identity from an Agent Provider
(this `apd`), sign every request, and obtain authorization at resources. It is
the "what do I actually build" companion to the deeper
[`research/04-connecting-agents.md`](../research/04-connecting-agents.md).

> **Mental model.** AAuth replaces API keys. Instead of copying a shared secret,
> your agent holds a private signing key that never leaves it, and proves its
> identity by *signing each HTTP request*. An Agent Provider vouches for the
> public key. Resources verify the signature against the AP's published keys —
> nobody has to pre-register you.

## 0. What you need before you start

| You need | Why |
|---|---|
| An **Agent Provider** to enroll with | issues your `aa-agent+jwt` identity. Run `apd`, use a hosted AP, or self-host (be your own AP). |
| Ability to **generate Ed25519 keys** | your identity is a keypair. |
| Ability to **make HTTP requests and set arbitrary headers** | you must attach `Signature-*` headers. |
| An **Ed25519 signer** (raw sign over bytes) | to produce the HTTP Message Signature and the JWTs you build. |
| SHA-256 + base64url | for JWK thumbprints and JWT encoding. |
| (For three/four-party auth) a **Person Server** you're configured to use | to obtain user-scoped auth tokens. Optional; not needed for identity-based access. |

You do **not** need: a public URL/inbound HTTP, pre-registration at each
resource, an OAuth client_id, or any shared secret.

## 1. The one primitive you must implement first: signing a request

Everything below is "sign a request and send it." Implement this once.

Per the AAuth profile (RFC 9421 + Signature-Key), every request carries three
headers and covers **at least** `@method`, `@authority`, `@path`,
`signature-key`:

```http
POST /agent-token HTTP/1.1
Host: ap.example
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:<base64 ed25519 signature>:
Signature-Key: sig=jwt;jwt="<your agent token>"
```

To build the `Signature` value you sign the **signature base**, one line per
covered component then the params line, joined with `\n` (no trailing newline):

```
"@method": POST
"@authority": ap.example
"@path": /agent-token
"signature-key": sig=jwt;jwt="<your agent token>"
"@signature-params": ("@method" "@authority" "@path" "signature-key");created=1730217600
```

Rules that will bite you if you get them wrong:

- `@authority` is the lowercased `Host` (host[:port], default ports elided).
- `@path` is the path **without** the query string.
- The `"signature-key"` line value is the full `Signature-Key` header value
  (`sig=...`). Build the header string first, then sign over it.
- `@signature-params` reproduces your `Signature-Input` inner list **exactly**
  (same order, same params). Emit it once and reuse the same bytes.
- `created` = now, Unix seconds. Servers reject outside ±60 s by default — **sync
  your clock (NTP)**.
- The signing algorithm is Ed25519; there is no `alg` guessing — the key type
  decides it.

> This repo's `aauth-core` implements exactly this (`sig::sign_request`); the
> integration tests in `crates/apd/src/tests.rs` are a working reference agent.

**Checklist — signing:** ☐ Ed25519 raw sign ☐ build signature base ☐ cover the
four required components ☐ set `created` to now ☐ present the credential via
`Signature-Key: sig=jwt;jwt="..."`.

## 2. Generate keys

Recommended **two-key** pattern:

- **Durable key** — created once per install, stored as securely as your
  platform allows (mode `0600` file at minimum; OS keystore/TPM/Secure Enclave
  where available). It signs *only* enrollment and refresh. Losing it = new
  identity.
- **Ephemeral key** — generated fresh each time you refresh your agent token;
  lives in memory; signs every other request. Its public half is what the agent
  token binds (`cnf.jwk`).

Simpler **single-key** pattern is allowed: use the durable key for everything and
refresh with the `hwk` scheme. Start here if you just want it working; adopt the
two-key split later — receivers can't tell the difference.

## 3. Enroll (once per install)

Get an operator-minted enrollment token (in `token` mode) — from your AP's admin
(`apd`: `POST /admin/enrollment-tokens` or `apd enroll-token`). In `open` mode,
skip it.

Sign `POST {AP}/enroll` with your **durable key** using the `hwk` scheme:

```http
POST /enroll HTTP/1.1
Host: ap.example
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=...
Signature: sig=:...:
Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="<durable pub>"

{"enrollment_token":"<one-time>","ps":"https://ps.example","platform":"workload"}
```

→ `201 {"agent":"aauth:k7q3p9n2@ap.example"}`. That `aauth:local@domain` string
is your stable identity. Store only your durable key — the AP finds you by its
thumbprint. Set `ps` if you'll use a Person Server for user-scoped auth.

**Checklist — enroll:** ☐ obtain enrollment token (token mode) ☐ sign with
durable key / `hwk` ☐ record your agent id ☐ include `ps` if you need
three/four-party auth.

## 4. Get an agent token (and refresh it before it expires)

Agent tokens are short-lived (≤24h; commonly 1h). Refresh proactively (~90% of
lifetime). No refresh tokens exist — you just repeat this.

**Two-key** — generate a fresh ephemeral key, build a naming JWT signed by the
**durable** key that delegates to the ephemeral key, and sign the request with
the **ephemeral** key:

Naming JWT (header `typ:"jkt-s256+jwt"`, `alg:"EdDSA"`, `jwk:<durable pub>`;
payload `iss:"urn:jkt:sha-256:<thumbprint(durable)>"`, `iat`, `exp≤iat+300`,
`jti:<random>`, `cnf.jwk:<ephemeral pub>`):

```http
POST /agent-token HTTP/1.1
Host: ap.example
Signature-Key: sig=jkt-jwt;jwt="<naming JWT>"
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=...
Signature: sig=:<ephemeral-key signature>:

{}
```

→ `200 {"agent_token":"eyJ...","expires_in":3600,"agent":"aauth:...@..."}`

**Single-key** — sign `POST /agent-token` directly with your durable key using
`Signature-Key: sig=hwk;...`.

Never reuse a naming JWT (`jti` is single-use). When you rotate the ephemeral key
or the agent token expires, any auth tokens you held for resources die with it —
re-run the resource flow (§6), which is one request when consent is remembered.

**Checklist — token:** ☐ fresh ephemeral key per refresh ☐ naming JWT signed by
durable, HTTP signed by ephemeral ☐ refresh before `exp` ☐ unique `jti`.

## 5. Call a resource — the single loop

Optionally fetch `{resource}/.well-known/aauth-resource.json` to read
`access_mode` and plan ahead. Then run one loop for every request: **send →
read `AAuth-Requirement` → satisfy it → retry.** Present your credential via
`Signature-Key: sig=jwt;jwt="<agent_token>"` until you hold an auth token, then
present the auth token instead (same signing code — its `cnf.jwk` is your key).

Also declare what you can handle: `AAuth-Capabilities: interaction, clarification,
payment` (omit what you can't do — absence means "none").

What you might get back and what to do:

| Response | Meaning | Your action |
|---|---|---|
| `200` | done | use the result |
| `401` `AAuth-Requirement: requirement=agent-token` | identity-only access | sign with your agent token and retry |
| `202` `requirement=interaction; url; code` + `Location` | a human must act | get the user to `{url}?code={code}` (browser / QR / relay via your PS), then poll `Location` (signed GET, respect `Retry-After`) |
| response with `AAuth-Access: <token>` | opaque resource token (two-party) | store it; send back as `Authorization: AAuth <token>` **and cover `authorization` in your signature**; adopt any newer value the resource returns |
| `401` `requirement=auth-token; resource-token="eyJ..."` | user-scoped auth needed (three/four-party) | go to §6 |
| `402` | payment | run x402/MPP + poll `Location` — only if you declared `payment` |
| `403` (problem json) | policy denial after valid auth | stop; surface it |

Polling terminal codes: `200` success, `403 denied/abandoned`, `408 expired`
(start over), `410 gone` (never retry that URL), `429` (add 5 s to interval).
`status:"interacting"` in a `202` body = the user arrived; stop prompting.

**Checklist — resource loop:** ☐ implement the requirement switch ☐ handle `202`
polling ☐ bind `AAuth-Access` by covering `authorization` ☐ send
`AAuth-Capabilities`.

## 6. Get a user-scoped auth token from a Person Server (three/four-party)

Prerequisite: your agent token has a `ps` claim (set at enrollment). When a
resource challenges with `requirement=auth-token`, it hands you a
**resource token**. Verify it, then send it to your PS's `token_endpoint`:

1. Verify the resource token: `iss` == the resource you called, `agent` == you,
   `agent_jkt` == thumbprint of your current signing key, `exp` in the future.
2. Discover your PS (`{ps}/.well-known/aauth-person.json` → `token_endpoint`).
3. POST it, signed with your agent token:

```http
POST /token HTTP/1.1
Host: ps.example
Content-Type: application/json
Prefer: wait=45
Signature-Key: sig=jwt;jwt="<agent_token>"
... signature headers ...

{"resource_token":"eyJ...","justification":"Find available meeting times",
 "capabilities":["interaction","clarification"]}
```

4. Handle the response like any deferred flow: `200 {auth_token, expires_in}`, or
   `202` (interaction/clarification — same polling loop; answer clarifications by
   POSTing `{"action":"clarification_response"|"updated_request",...}` to the
   pending URL, or DELETE to cancel).
5. Verify the returned auth token: `iss` == resource-token `aud`, `aud` == the
   resource, `cnf.jwk` == your key, `agent` == you.
6. Present it to the resource via `Signature-Key: sig=jwt;jwt="<auth_token>"`.

Resource tokens live ≤5 min. If consent took longer and it expired, fetch a fresh
resource token and resubmit — the PS remembers consent, so it resolves fast.

Whether the PS asserts identity itself (three-party) or federates with the
resource's Access Server (four-party) is invisible to you — same flow either way.

**Checklist — PS flow:** ☐ verify resource token before forwarding ☐ discover PS
metadata ☐ sign the token request with your agent token ☐ handle `202`
polling/clarification ☐ verify the auth token ☐ present auth token on later calls.

## 7. Optional: sub-agents (worker/tool agents under a parent)

If your agent spawns workers, each gets its own identity without re-consent:

1. The sub-agent generates its **own** Ed25519 keypair and hands the public JWK
   to the parent.
2. The parent calls `POST {AP}/subagent-token` signed with the **parent's agent
   token**, body `{"discriminator":"search1","cnf_jwk":{...}}`.
3. AP returns an agent token with `sub = aauth:{parent}+search1@domain` and
   `parent_agent`.

Rules: one level deep only; a sub-agent never calls a PS directly — the parent
requests auth tokens on its behalf (`subagent_token` param at the PS). The
sub-agent obtains its **own** resource tokens (bound to its key) and signs its
own resource requests.

## 8. Optional: receive async events (AAuth Events)

Agents can't receive webhooks, so the AP is your inbox:

1. `POST {AP}/subscribe` (signed with agent token) `{"resource":"https://...",
   "max_uses":1}` → `{"subscribe_token":"...","eid":"..."}`. Keep your own
   `eid → context` map.
2. Register at the resource: signed POST to its subscription endpoint (or a
   ticket URL it gave you), presenting `Signature-Key: sig=jwt;jwt="<subscribe_token>"`
   (the subscribe token replaces the agent token here; its `cnf.jwk` is your key).
3. Collect events: `GET {AP}/inbox?wait=30` (signed; `?wait=N` or `Prefer: wait=N`
   long-polls up to 50 s) → `{"events":[...]}`.
4. Verify each event token yourself: `typ:aa-event+jwt`, signature via the
   resource's JWKS, `aud` == your agent id, `exp` in the future, dedupe on
   `(iss, eid)`.

## 9. Failure cheat sheet

| You see | Do |
|---|---|
| `401` `Signature-Error: error=expired_jwt` | refresh your agent token, retry |
| `401` `invalid_signature` | check clock skew, covered components, key match |
| `401` `invalid_input; required_input=(…)` | re-sign covering the listed components (e.g. `content-digest`) |
| `403` `{"error":"denied"}` on a pending URL | user declined — stop |
| `408` on a pending URL | expired — start the flow over |
| `410` on a pending URL | terminal already delivered — never retry it |
| `429` | add 5 s to your poll interval |
| auth token rejected after you rotated keys | expected — re-run the resource→PS flow |
| AP refuses refresh (`403 enrollment_revoked`) | your enrollment was revoked; contact the operator |

## 10. Minimal viable agent (the shortest path)

If you only want to replace an API key with cryptographic identity and nothing
else:

1. Generate one Ed25519 key.
2. Enroll (single-key `hwk`), get an agent token.
3. Sign requests, present `Signature-Key: sig=jwt;jwt="<agent_token>"`.
4. Handle `401 requirement=agent-token` by retrying signed.

That's **identity-based access** — no PS, no missions, no user consent. Add the
PS flow (§6) only when a resource needs a real user identity behind the agent.
