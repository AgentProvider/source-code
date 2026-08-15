# Implementing a Person Server — a complete build specification

> **Source:** `draft-hardt-oauth-aauth-protocol-11` (14 August 2026),
> https://github.com/dickhardt/AAuth. Normative statements below carry the
> spec's MUST/SHOULD meaning and are traceable to it. Passages marked
> **[design]** are implementation guidance, not protocol requirements.
>
> **Audience:** an engineer building a Person Server from nothing.
> **Companion notes:** [01 — protocol overview](01-aauth-protocol-overview.md),
> [03 — HTTP signatures](03-http-signatures.md).
> This repository implements the *Agent Provider*, a different role; see
> [02](02-agent-provider.md) for that.

---

## 1. What you are building

A **Person Server (PS)** represents a person to the rest of AAuth. Where an
Agent Provider vouches for a piece of software ("this is agent X"), the PS
vouches for the human behind it ("agent X acts for this person, and here is what
they allow").

Concretely, a PS does five things:

1. **Binds agents to a person** — one agent, exactly one person, forever.
2. **Issues person tokens** — "this agent acts for this person at this resource".
3. **Issues auth tokens** — "this person authorizes this specific access".
4. **Runs consent** — reaches the human when a decision is needed.
5. **Keeps the record** — retention, audit, revocation, and (optionally) missions.

The PS is the most demanding role in AAuth. It is the only one that holds a
relationship with a human, and the only one that must still be correct when an
agent is actively lying to it.

### 1.1 What the PS is not

- It is **not** an identity provider. It MAY delegate authentication to one
  (enterprise IdP over OIDC, passkeys, whatever the person chose).
- It is **not** the resource's policy engine. A resource applies its own policy
  to the claims the PS asserts. In four-party deployments an Access Server does
  that job.
- It does **not** issue agent identity. That is the Agent Provider.

### 1.2 The trust posture that makes it work

No party pre-registers with any other. A resource that has never heard of your
PS can verify your tokens by fetching `{iss}/.well-known/aauth-person.json` and
your JWKS over HTTPS. That is the whole trust bootstrap. It means **your metadata
document and your JWKS are load-bearing security surfaces** — treat their
availability and integrity as you would a signing key.

---

## 2. Conformance summary

An implementation is a conforming PS if it:

| # | Requirement | Section |
|---|---|---|
| 1 | Publishes `/.well-known/aauth-person.json` whose `issuer` equals its own URL | §4 |
| 2 | Publishes a JWKS where every key carries a fully-specified `alg` | §5 |
| 3 | Maintains one-agent-to-one-person binding | §6 |
| 4 | Issues directed (pairwise) `sub` values, unique within the issuer | §7 |
| 5 | Publishes and serves `person_token_endpoint` | §8 |
| 6 | Publishes and serves `auth_token_endpoint` | §9 |
| 7 | Verifies agent tokens and HTTP signatures on every request | §11 |
| 8 | Verifies resource tokens, including `presented_jti` resolution | §11.2 |
| 9 | Retains a record of every person token it issues | §13 |
| 10 | Returns the defined error codes with RFC 9457 problem details | §16 |

Everything else — missions, interaction relay, permissions, audit — is OPTIONAL
and advertised by the presence of its metadata field.

---

## 3. Architecture at a glance

```
                    ┌──────────────────────────────────────┐
   Agent ──────────▶│  PS                                  │
   (agent token)    │                                      │
                    │  person_token_endpoint   REQUIRED    │──▶ person token
                    │  auth_token_endpoint     REQUIRED    │──▶ auth token
                    │  interaction_endpoint    optional    │
                    │  mission_endpoint        optional    │
                    │  revocation_endpoint     optional    │◀── AP revokes here
                    │  permission_endpoint     optional    │
                    │  audit_endpoint          optional    │
                    │                                      │
                    │  ┌────────────────────────────────┐  │
                    │  │ state you MUST keep            │  │
                    │  │  • agent → person bindings     │  │
                    │  │  • directed sub per (person,   │  │
                    │  │    resource)                   │  │
                    │  │  • issued person-token records │  │
                    │  │  • consent decisions           │  │
                    │  │  • pending requests            │  │
                    │  └────────────────────────────────┘  │
                    │                                      │
                    │  ── reaches the human ───────────────│──▶ push / web / app
                    └──────────────────────────────────────┘
                                    │
                                    └──▶ AS (four-party only)
```

---

## 4. Metadata document

Serve at `/.well-known/aauth-person.json`, `Content-Type: application/json`,
cacheable.

```json
{
  "issuer": "https://ps.example",
  "jwks_uri": "https://ps.example/.well-known/jwks.json",
  "person_token_endpoint": "https://ps.example/person",
  "auth_token_endpoint": "https://ps.example/token",
  "interaction_endpoint": "https://ps.example/interaction",
  "mission_endpoint": "https://ps.example/mission",
  "revocation_endpoint": "https://ps.example/revoke",
  "accept_signature_algs": ["Ed25519"],
  "name": "Example Person Server",
  "description": "Manage which agents act for you and review what they do.",
  "scopes_supported": ["openid", "profile", "email", "tenant", "groups"],
  "claims_supported": ["sub", "email", "name", "tenant"]
}
```

| Field | Requirement | Notes |
|---|---|---|
| `issuer` | REQUIRED | MUST equal the URL the document was fetched from. Goes in `iss` of every token you issue. |
| `jwks_uri` | REQUIRED | Your public keys. |
| `auth_token_endpoint` | REQUIRED | **Renamed from `token_endpoint` in -11.** |
| `person_token_endpoint` | REQUIRED | Every PS MUST publish and serve this. |
| `mission_endpoint` | OPTIONAL | Present ⇒ you support missions. A mission's URL is `{mission_endpoint}/{mission_s256}`. |
| `permission_endpoint` | OPTIONAL | Permission for actions with no remote resource. |
| `audit_endpoint` | OPTIONAL | Agents log completed actions. |
| `interaction_endpoint` | OPTIONAL | Agents relay interaction to the user through you. |
| `mission_control_endpoint` | OPTIONAL | Non-agent principals. **Deliberately unspecified** — see §10.4. |
| `revocation_endpoint` | OPTIONAL | Where an **Agent Provider** revokes an agent token, and where you accept revocations. |
| `accept_signature_algs` | OPTIONAL | Exact set your verifier accepts — neither subset nor superset. |
| `scopes_supported`, `claims_supported` | RECOMMENDED | What you can assert. |
| `name`, `description`, `logo_uri`, `logo_dark_uri`, `documentation_uri`, `tos_uri`, `policy_uri` | OPTIONAL | Display. **`description` is Markdown — you MUST sanitize before rendering.** |

> **Trap.** `issuer` must match the fetch URL *exactly*: `https`, host only, no
> port, no path, no trailing slash, lowercase. Verifiers reject a mismatch, and
> the failure looks like "my tokens are inexplicably rejected".

---

## 5. Keys and algorithms

- **`Ed25519` is REQUIRED.** `ES256` SHOULD be supported. Use the
  fully-specified JOSE identifier `Ed25519` — the polymorphic `EdDSA` **MUST NOT**
  be used (RFC 9864).
- Every key at your `jwks_uri` **MUST** carry a fully-specified `alg`. So must
  every `cnf` JWK you emit.
- `none` and symmetric algorithms MUST NOT be used.
- A verifier MUST select the key matching `kid` without requiring the other JWKS
  members to be usable — so one unusable key must not break your key set.
- **Do not send the `alg` signature parameter** in `Signature-Input`, and ignore
  it if a caller sends one.

**[design]** Support key rotation from day one: publish the new key, sign with
it, keep old public keys until every token signed with them has expired (≤1 h),
then prune.

---

## 6. The core invariant: agent–person binding

> The PS MUST ensure that each agent is associated with **exactly one person**.

This is the trust invariant the whole role rests on. Get it wrong and consent
granted by one person becomes exercisable by another.

Rules:

- Recognise a returning agent by the tuple **`(agent_token.iss, agent_token.sub)`**.
  Not `sub` alone — `sub` is unique only within its Agent Provider.
- On first sight of a new tuple for a person, treat it as **new-agent enrollment**
  and say so clearly at the consent screen. Show the Agent Provider's `name` and
  `logo_uri` (fetched from its metadata) beside the agent-supplied `platform` and
  `device` values.
- Once bound, the PS **MUST NOT** let a different person claim that agent.
- To move an agent to another person, **revoke the old binding first**, then
  establish a new one.

**[design]** Store the binding keyed by `(iss, sub)` with the person id, the
creation time, and the enrollment context. Make "revoke binding" a first-class
operation — it is the fastest kill switch you have, because it stops all future
auth tokens immediately.

**Display trust.** `platform` and `device` are **agent-attested** — the agent
says them, nothing verifies them. Show them so a person can tell entries apart
in a dashboard. Never make a security decision on them.

---

## 7. Directed identifiers (`sub`)

The `sub` you issue identifies the person to one resource.

- `sub` **MUST** be unique within your issuer. `(iss, sub)` is the identifier.
- You **SHOULD** derive a **pairwise pseudonymous** value per `aud`, so two
  resources see different values for the same person and cannot correlate.
- `tenant` is organizational context and is **never** part of the identifier.
- The **same** `sub` MUST appear in the person token, in the resource token
  derived from it, and in every auth token for that resource. It **MUST NOT**
  vary with the agent or its key.

That last rule matters: the person is the subject, not the agent. Two agents
acting for the same person at the same resource present the same `sub`.

**[design]** `sub = base64url(HMAC-SHA256(pairwise_secret, person_id || aud))`
is sufficient and stateless. Keep `pairwise_secret` with your signing keys — its
loss re-identifies every user at every resource.

---

## 8. `person_token_endpoint` — REQUIRED

The newest endpoint (added in `-11`) and the one most agents will hit first.

**Request.** A signed `POST`. The agent presents its **agent token** via
`Signature-Key` with `scheme=jwt`. Because the request carries a body, the agent
MUST also sign `content-digest` and `content-type`.

```http
POST /person HTTP/1.1
Host: ps.example
Content-Type: application/json
Content-Digest: sha-256=:...:
Signature-Input: sig=("@method" "@authority" "@path"
    "content-type" "content-digest" "signature-key");created=1730217600
Signature: sig=:...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{ "resource": "https://resource.example",
  "mission_s256": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" }
```

| Parameter | Requirement | Your obligation |
|---|---|---|
| `resource` | REQUIRED | Validate against Server Identifier rules. Becomes `aud`. |
| `mission_s256` | OPTIONAL | Verify the mission **exists, is active, and belongs to this agent**. Reject otherwise. Copy into the token. |
| `subagent_token` | OPTIONAL | The signing agent MUST be named by its `parent_agent`. The issued `cnf` is the **sub-agent's** key. |
| `upstream_token` | OPTIONAL | Call chaining. Issue for the person the upstream token was issued for, from its `sub`, **which you MUST have issued**. |

Without `upstream_token`, issue for the person bound to the requesting agent. If
you cannot determine the person, **reject**.

**Response** `200`:

```json
{ "person_token": "eyJhbGc...", "expires_in": 3600 }
```

You MAY require interaction first and return `202` with
`requirement=interaction` (§12).

**The consent question is not what you might assume.** Because a resource MAY
serve requests on identity alone, holding a person token is effectively access.
So ask *"may this agent act at this resource as you?"* — not *"may it learn your
name?"* Before issuing for a resource the person has not used, you SHOULD fetch
the resource's metadata and show its `name`, `description`, and `access_mode`,
so the person answers the question the resource will actually apply.

**Rate-limit distinct `resource` values per agent.** Each one obliges you to
derive and retain a directed `sub`.

### 8.1 Person token structure

```json
{ "typ": "aa-person+jwt", "alg": "Ed25519", "kid": "ps-key-1" }
```

| Claim | Requirement | Value |
|---|---|---|
| `iss` | REQUIRED | Your PS URL |
| `dwk` | REQUIRED | `aauth-person.json` |
| `aud` | REQUIRED | The resource URL |
| `sub` | REQUIRED | Directed identifier — same value you use in auth tokens |
| `cnf` | REQUIRED | `{ "jwk": <agent's public key> }` |
| `jti` | REQUIRED | Unique; you will be asked about it later |
| `iat`, `exp` | REQUIRED | See lifetime below |
| `mission_s256` | OPTIONAL | When operating under a mission |
| `tenant` | OPTIONAL | Organizational context |

**Lifetime.** MUST NOT exceed **1 hour**, MUST NOT outlive the agent token
presented when it was requested, and MUST NOT outlive the mission's `expires_at`
when `mission_s256` is present. Take the minimum of all three.

**Assurance floor — state this in your docs.** A person token asserts
*recognition and agency*, and guarantees continuity of `(iss, sub)`. A resource
MUST NOT read it as evidence of identity proofing, legal identity, or any
assurance level.

---

## 9. `auth_token_endpoint` — REQUIRED

Where agents bring a **resource token** and get an **auth token**. Renamed from
`token_endpoint` in `-11`.

**Modes:**

| Mode | Trigger | What you do |
|---|---|---|
| PS authorization (three-party) | `resource_token.aud` = your URL | Assert identity + consent; issue the auth token |
| AS-federated (four-party) | `resource_token.aud` = an AS URL | **You** call the AS, satisfy its requirements, verify its auth token, hand it to the agent |
| Call chaining | `resource_token` + `upstream_token` | A resource acting as an agent downstream |

**Request parameters:**

| Parameter | Requirement | Notes |
|---|---|---|
| `resource_token` | REQUIRED | The resource token |
| `upstream_token` | OPTIONAL | Call chaining |
| `subagent_token` | OPTIONAL | Parent-mediated; signer MUST be its `parent_agent` |
| `justification` | OPTIONAL | Markdown. **Sanitize.** SHOULD show at consent. MAY log. |
| `login_hint`, `prompt`, `domain_hint`, `tenant` | OPTIONAL | OIDC-style hints; `prompt` ∈ `none`/`login`/`consent`/`select_account` |
| `platform`, `device` | OPTIONAL | Agent-attested display only |
| `capabilities` | OPTIONAL | What the agent can handle (e.g. can it drive an interaction?). Within a mission, falls back to values captured at approval. |

**Concurrency.** An agent MAY have several requests pending at once — a mission
touching several resources does exactly this. Each gets its own pending URL and
lifecycle. You MUST handle them independently, and you own the human experience:
batch the prompts or serialise them, but do not deadlock.

### 9.1 Auth token structure

| Claim | Requirement | Notes |
|---|---|---|
| `iss` | REQUIRED | You (or the AS) |
| `dwk` | REQUIRED | `aauth-person.json` (or `aauth-access.json`) |
| `aud` | REQUIRED | The resource URL |
| `sub` | **REQUIRED** | Directed identifier — **now mandatory in -11** |
| `ps` | REQUIRED | The PS of the authorization |
| `cnf` | REQUIRED | The agent's key |
| `jti`, `iat`, `exp` | REQUIRED | `exp` ≤ 1 h, and never outliving the agent token |
| `scope` | as applicable | Space-separated |
| `mission_s256`, `tenant`, OIDC claims | OPTIONAL | |

**Removed in -11:** the auth token carries **no agent identifier**, and **`act`
and the delegation chain are gone**. Do not emit them.

**Do not copy a directed `sub` from an upstream token.** You MAY emit one only
from your own authenticated federation step.

---

## 10. Optional endpoints

### 10.1 `interaction_endpoint`
Where agents relay an interaction to the user through you — the agent cannot show
a UI, so you do. Pairs with `requirement=interaction` (§12).

### 10.2 `mission_endpoint`
The **owning agent's** surface. Three operations, one shape:

- `POST {mission_endpoint}` — propose a mission.
- `POST {mission_endpoint}/{mission_s256}` with `action: update` — record a change
  in the work. Appended to the log and digested. It does **not** change the blob,
  `mission_s256`, or any token. A mission's meaning is the approved blob **plus**
  its accepted updates; an audit MUST read both.
- `POST {mission_endpoint}/{mission_s256}` with `action: completion` — lifecycle
  transition. Moved off the interaction endpoint in `-11`.

Mission blob: identified by `mission_s256` = base64url(SHA-256(exact approved
bytes)). Carries `approved_resources`, MAY carry `expires_at`. **No token
carrying `mission_s256` may outlive `expires_at`, and every decision path MUST
compare the current time to it.** `capabilities` lives in the approval response,
not the blob — it must not perturb the digest. The blob's member list is a
floor: you MAY add members, and a blob with an extra member is a *different*
mission because it has a different digest.

Termination reasons — `completed`, `revoked`, `expired`, `superseded`,
`administrative` — are an open set recorded outside the immutable blob, surfaced
as an OPTIONAL `termination_reason` on `mission_terminated`.

> **Security requirement, easy to miss.** A PS **MUST answer identically —
> status, body, headers, and timing —** whether a mission does not exist or the
> agent does not own it. Otherwise your endpoint is an existence oracle for
> anyone who has seen a `mission_s256` in an auth token. Use a constant-time
> path, not an early return.

### 10.3 `permission_endpoint` / `audit_endpoint`
Permission for actions with no remote resource; a log of completed actions.
Both OPTIONAL.

### 10.4 `mission_control_endpoint`
For principals AAuth does not define — the person, an administrator, a
management service. Authentication model and operations are **deliberately left
to a companion specification**. If you build it, you are designing, not
implementing.

---

## 11. Verification you must perform

### 11.1 Every request
1. Verify the HTTP Message Signature (RFC 9421, AAuth profile): covered
   components MUST include `@method`, `@authority`, `@path`, `signature-key`;
   `created` within your window (60 s default).
2. Requests with a body MUST also cover `content-digest` and `content-type`.
3. Verify the **agent token** from `Signature-Key`: `typ` is `aa-agent+jwt`;
   `dwk` is `aauth-agent.json`; fetch `{iss}/.well-known/aauth-agent.json`,
   confirm its `issuer` equals `iss`, follow `jwks_uri`, match `kid`, verify the
   signature; check `exp`/`iat`; confirm `cnf.jwk` signed the HTTP request.
4. Apply **egress admission** to those fetches: HTTPS only, no redirects, no
   private/loopback addresses, size and time caps, pin the resolved IP. The URLs
   come from an attacker-supplied token.

### 11.2 Resource tokens — including the step people miss

1. `typ` is `aa-resource+jwt`.
2. `dwk` is `aauth-resource.json`; discover JWKS; verify signature by `kid`.
3. `exp` in the future, `iat` not in the future.
4. `aud` matches **your** identifier.
5. `agent_jkt` matches the thumbprint of the key that signed the HTTP request —
   or, for a parent-mediated sub-agent request, the `subagent_token`'s `cnf.jwk`,
   because the *parent* signs.
6. **Resolve `presented_jti` against your retained person-token records.**
   No record ⇒ reject with `unknown_person_token`. A record ⇒ verify `ps`, `sub`,
   `mission_s256`, and `tenant` **match exactly**; reject on any mismatch or
   omission. A mismatch against an existing record is evidence of tampering —
   mission stripping — and SHOULD be **surfaced to operators**, not merely
   rejected.
7. If `mission_s256` is present, verify the mission is active and the current
   time precedes `expires_at`.

Step 6 is why the retention obligation exists. Comparing claims alone cannot
detect mission stripping, because concurrent missions mean several person tokens
exist per agent and resource.

---

## 12. Deferred responses and polling

When you need the human, do not block. Return `202 Accepted` with:

```http
AAuth-Requirement: requirement=interaction; url="https://ps.example/i/abc"; code="8412"
Location: https://ps.example/pending/xyz
```

- `requirement` values you emit: `interaction`, `approval`, `clarification`,
  `claims` (AS→PS).
- The agent polls the `Location`. Honour `Prefer: wait=N` for long-polling.
- The interaction **code is a correlation identifier, not a credential** — the
  code alone MUST NOT authorize the decision.
- Terminal polling errors include `denied` (403).

`AAuth-Requirement` and `WWW-Authenticate` are independent; both MAY appear.

---

## 13. Retention — a hard obligation

> Issuing a person token creates a retention obligation.

For **every** person token you issue, retain: `jti`, `ps`, `sub`,
`mission_s256`, `tenant`, `exp`.

Retain it **beyond `exp` by at least the longest resource token lifetime you
accept**. Resource tokens live ≤5 minutes, so `exp + 5 min` is the floor;
**[design]** use `exp + 1 hour` for clock skew and operational slack.

Forget too early and you reject legitimate resource tokens with
`unknown_person_token`. Never forget and you accumulate unboundedly — put a TTL
on the record, do not rely on a cleanup job.

---

## 14. Revocation, in both directions

**Inbound — an Agent Provider revokes an agent token at your `revocation_endpoint`.**

```http
POST /revoke        { "iss": "https://ap.example", "jti": "..." }
```

- Both members REQUIRED. **Key your revocation state by `(iss, jti)`** — a `jti`
  is unique only within its issuer.
- Verify the caller by HTTP Message Signature. Accept revocation **only** from
  the issuer of the token being revoked, or from a trusted PS. An AP signs as
  itself using the `jwks_uri` scheme.
- `200` if revoked or already invalid; `404` if you do not recognise the pair.
- On success you **MUST** deny subsequent requests presenting that agent token,
  and **SHOULD** revoke the auth tokens you issued for that agent by calling each
  resource's own `revocation_endpoint`.

**Outbound — you revoke what you issued.** Call the resource's
`revocation_endpoint` with the auth token's `(iss, jti)`. When you revoke a
mission, mark it revoked, deny subsequent token requests naming its digest, and
SHOULD revoke outstanding auth tokens issued under it.

**Understand the limit.** Verification is offline — a resource caches your JWKS
and checks signatures locally. Nothing in that path reports a revocation. A
holder no revocation request reaches is bounded by token lifetime alone.
Revocation shortens exposure; it does not eliminate it. **Short lifetimes are
the real control.**

---

## 15. Security requirements

- **You are a high-value target.** You see every authorization in a mission.
  Apply access control, audit logging, and monitoring accordingly. Compromise
  affects every agent and mission you manage.
- **Mitigate the centralisation.** The person chooses their PS and can migrate.
  You MAY delegate authentication to an IdP they chose, and policy evaluation to
  services they chose. Externally you present one interface regardless.
- Sanitize every Markdown field (`description`, `justification`) before render.
- Constant-time comparison for secrets and for the mission existence check.
- Egress admission on every metadata/JWKS fetch (§11.1).
- Rate-limit person-token issuance per agent by distinct `resource`.

---

## 16. Error codes

RFC 9457 `application/problem+json` with a required `error` member.

| Error | Status | Meaning |
|---|---|---|
| `invalid_request` | 400 | Malformed JSON, missing fields, bad `resource`/`mission_s256` |
| `invalid_agent_token` | 400 | Agent token malformed or signature failed |
| `expired_agent_token` | 400 | Agent token expired |
| `invalid_resource_token` | 400 | Resource token malformed or signature failed |
| `expired_resource_token` | 400 | Resource token expired |
| `unknown_person_token` | 400 | `presented_jti` not among your retained records |
| `user_unreachable` | 403 | **Terminal** — no channel to the user *and* the agent declared no `interaction` capability |
| `denied` | 403 | User or approver explicitly denied (polling) |
| `mission_terminated` | 403 | With OPTIONAL `termination_reason` |
| `server_error` | 500 | Internal |

Signature failures are `401` with `Signature-Error`. A `403` **MUST NOT** carry
`Signature-Error` or either `Accept-Signature-*` header.

---

## 17. Suggested build order **[design]**

Nothing below is normative; it is the order that keeps you shippable.

| Phase | Build | You can now |
|---|---|---|
| **1** | Metadata, JWKS, key rotation, signature + agent-token verification | Be discovered and authenticate callers |
| **2** | Agent–person binding, directed `sub`, a minimal consent UI | Recognise people and agents |
| **3** | `person_token_endpoint` + retention | Serve identity-only resources — the common case |
| **4** | `auth_token_endpoint` (three-party), deferred `202` + polling | Serve consent-gated resources |
| **5** | `revocation_endpoint`, outbound revocation | Terminate access in real time |
| **6** | Missions | Governance |
| **7** | AS federation (four-party), call chaining | Enterprise deployments |

Phase 3 delivers most of the value. A resource that only needs to know *who the
person is* is satisfied by a person token, with no resource token and no auth
token — which is precisely why `-11` introduced it.

## 18. Interoperability testing

- **Agent side:** [`agentd`](https://agentd.dev) implements the AAuth client and
  can drive your endpoints.
- **Agent Provider:** the public sandbox at `https://sandbox.agentprovider.dev`
  issues real agent tokens with open enrollment — you need one to test with.
- **Resource side:** [`mcpg`](https://mcpg.dev) verifies agent identity as a
  gateway; `whoami.aauth.dev` is a public test resource.

Test these failure paths explicitly: an expired agent token; a resource token
whose `presented_jti` you never issued; a `mission_s256` for a mission owned by
a different agent (check the **timing** of both answers); a revoked agent token
presented after revocation.

---

## 19. Open items

- `mission_control_endpoint` — authentication and operations are left to a
  companion specification (`draft-mcguinness-mission-aauth-management` is the
  starting point for the mission endpoint's error model).
- `justification` — the spec carries a **TODO** on recommended sections.
- AAuth is an Internet-Draft. Pin the revision you build against and re-read the
  Document History before upgrading.
