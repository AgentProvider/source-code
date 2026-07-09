# apd — a self-hostable AAuth Agent Provider

> ⚠️ **Under active development.** AAuth is a set of evolving IETF Internet-Drafts,
> not a finalized standard. `apd` tracks a specific revision of that spec family
> (see [Status](#status--license)) and will change — sometimes in
> backwards-incompatible ways — as the drafts mature. Treat it as a
> spec-tracking reference implementation: great for building against AAuth today
> and for interop experiments, but pin a commit and review the changelog before
> relying on it in production. Feedback and issues welcome.

`apd` is a fast, dependency-light **Agent Provider (AP)** for the
[AAuth protocol](https://github.com/dickhardt/AAuth) — the role that gives every
agent a cryptographic identity. It issues **agent tokens** (`aa-agent+jwt`) that
bind an agent instance's Ed25519 signing key to a stable identifier
`aauth:local@domain`, publishes the metadata and JWKS any party needs to verify
those tokens, and (optionally) acts as the agent's **event inbox** for
[AAuth Events](https://github.com/dickhardt/AAuth).

Written in Rust, built to be **self-hosted by a single engineer** or run as a
**horizontally-scaled multi-instance fleet**. Verification is fully stateless —
every relying party checks a token against the published JWKS without ever
calling `apd`.

```
   Agent ──enroll(durable key)──▶  apd  ──issues──▶  agent_token (aa-agent+jwt)
     │                             │                       │
     │◀──── refresh (jkt-jwt) ─────┘                       │ presented via
     │                                                     ▼ Signature-Key: sig=jwt
     └── signs every HTTP request (RFC 9421) ──▶ Resources / Person Servers / Access Servers
                                                  (verify against apd's published JWKS)
```

## Why this exists

AAuth replaces API keys and per-server OAuth registration with **self-sovereign,
proof-of-possession agent identity**. The AP is the small but load-bearing piece
that mints and rotates those identities. The protocol keeps the AP's normative
surface deliberately tiny (token issuance + JWKS + metadata), so `apd` can be
simple, fast, and easy to operate. Everything else in AAuth — consent, missions,
resource policy — lives in other roles (Person Server, Access Server, Resource),
which `apd` never needs to talk to.

### Integration guides — "what do I actually build?"

Hands-on, implement-in-order guides for the two sides that establish auth:

- [`docs/guide-ai-agent-auth.md`](docs/guide-ai-agent-auth.md) — **make an AI agent authenticate with AAuth**: keys, enroll, get/refresh a token, sign requests, the resource loop, the Person Server flow, sub-agents, events, and a minimal-viable path.
- [`docs/guide-mcp-server-auth.md`](docs/guide-mcp-server-auth.md) — **add AAuth auth to an MCP server or any HTTP API**: the adoption ladder (identity → resource-managed → PS-asserted → federated), the verification core, MCP-specific wiring, resource tokens, and trusting Agent Providers.
- [`docs/enrollment.md`](docs/enrollment.md) — **set up enrollment for your users**: what enrollment is, how the spec frames it, apd's hooks, and the patterns for connecting users (invitation, self-service behind your login, IdP group restriction, attested-device, self-hosted).

### Research notes — the spec, distilled

See [`research/`](research/) for a full, detail-level reading of the spec family:

- [`research/01-aauth-protocol-overview.md`](research/01-aauth-protocol-overview.md) — the whole protocol, distilled
- [`research/02-agent-provider.md`](research/02-agent-provider.md) — the AP role in depth + every design decision here
- [`research/03-http-signatures.md`](research/03-http-signatures.md) — RFC 9421 + Signature-Key schemes as implemented
- [`research/04-connecting-agents.md`](research/04-connecting-agents.md) — how to build an agent against this AP
- [`research/05-connecting-resources-mcp.md`](research/05-connecting-resources-mcp.md) — how resources & MCP servers plug in
- [`research/06-events.md`](research/06-events.md) — the AP-as-inbox event flow

## What it implements

| Area | Detail |
|---|---|
| **Agent tokens** | `aa-agent+jwt`, Ed25519, `cnf.jwk` bound, `≤24h` (config, default 1h), optional `ps` claim |
| **Enrollment** | durable-key first-contact; `token` mode (admin-minted single-use tokens) or `open` mode |
| **Refresh** | two-key (`jkt-jwt` naming JWT, replay-guarded) and single-key (`hwk`) ceremonies |
| **Sub-agents** | parent-mediated issuance, `parent_agent` claim, single-level-depth enforced, `exp` capped to parent |
| **Metadata + JWKS** | `/.well-known/aauth-agent.json`, `/.well-known/jwks.json`, cacheable, key rotation with `kid` |
| **HTTP signatures** | full RFC 9421 verify per the AAuth profile; `Signature-Error` responses; egress-admitted JWKS discovery |
| **AAuth Events** | subscribe tokens, resource-facing `/events` delivery endpoint, agent `/inbox` (poll + long-poll) |
| **Admin API** | mint enrollment tokens, list/inspect/revoke/reinstate agents (bearer-gated, constant-time) |
| **Storage** | `memory`, `file` (crash-safe snapshot), `redis` (multi-instance; hand-rolled RESP2, no client dep) |

## Dependencies

Kept intentionally small (see `Cargo.toml`): `ed25519-dalek`, `sha2`,
`getrandom`, `serde`/`serde_json`, `tokio`, `hyper`/`hyper-util`,
`rustls`/`webpki-roots` for outbound TLS. No web framework, no JWT library, no
Redis client, no base64/structured-field crates — the protocol primitives are
implemented from the RFCs in [`crates/aauth-core`](crates/aauth-core) and unit-tested
against published test vectors (RFC 8037 keys/signatures, RFC 7638 thumbprints).

## Quick start (local, no TLS)

```sh
# build
cargo build --release
BIN=./target/release/apd

# generate the AP signing key
$BIN keygen --keys apd-keys.json

# minimal dev config (http + loopback; NEVER use insecure_dev_mode in prod)
cat > apd.json <<'JSON'
{
  "issuer": "http://localhost:8420",
  "listen": "127.0.0.1:8420",
  "keys_file": "apd-keys.json",
  "storage": { "backend": "memory" },
  "enrollment": { "mode": "open" },
  "admin_token": "dev-admin",
  "insecure_dev_mode": true,
  "events": { "enabled": true }
}
JSON

$BIN serve --config apd.json
```

Then:

```sh
curl -s http://localhost:8420/.well-known/aauth-agent.json | jq
curl -s http://localhost:8420/.well-known/jwks.json | jq
curl -s http://localhost:8420/healthz
```

Driving the signed endpoints (`/enroll`, `/agent-token`, …) requires an AAuth
agent that signs HTTP Message Signatures — see
[`research/04-connecting-agents.md`](research/04-connecting-agents.md) for the exact
ceremony, and the in-repo integration tests
(`crates/apd/src/tests.rs`) for a working reference agent implementation.

## Production deployment

See [`docs/deployment.md`](docs/deployment.md) for TLS termination, the
single-instance and multi-instance (Redis) topologies, key rotation, and
container/systemd examples. The full HTTP surface is in
[`docs/api.md`](docs/api.md); every configuration field is in
[`docs/configuration.md`](docs/configuration.md).

## Layout

```
crates/
  aauth-core/   # protocol primitives (no I/O): b64, JWK/JWKS, JWT, identifiers,
                # RFC 8941 structured fields, RFC 9421 signatures, Signature-Key schemes, tokens
  apd/          # the daemon: config, keys, storage, egress-admitted HTTP client,
                # JWKS cache, handlers (enroll/token/subagent/events/admin), router, CLI
research/       # engineering notes distilled from the AAuth spec family
docs/           # api / configuration / deployment reference
```

## Testing

```sh
cargo test                                  # unit + in-process end-to-end (incl. a live mock resource)
APD_TEST_REDIS=127.0.0.1:6379 cargo test    # additionally exercise the Redis backend
cargo clippy --workspace --all-targets      # zero warnings
```

## Status & license

Implements `draft-hardt-oauth-aauth-protocol-09` and companion drafts
(`bootstrap-01`, `events-00`, `httpbis-signature-key-05`) as of 2026-06. AAuth is
an evolving IETF Internet-Draft; treat this as a spec-tracking reference
implementation. Dual-licensed MIT OR Apache-2.0.
