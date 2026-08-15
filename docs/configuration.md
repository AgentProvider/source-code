# apd configuration

Configuration is a JSON file (`--config`, default `apd.json`) with environment
overrides. `apd example-config` prints a starting point. Unknown fields are
rejected, so typos fail loudly at startup.

## Fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `issuer` | string | — (required) | The AP's server identifier. Must be `https://host` (lowercase, no port/path/trailing slash) unless `insecure_dev_mode`. This exact URL must serve the well-known documents. Goes into every token's `iss`, and its host is the `domain` of issued agent identifiers. |
| `listen` | string | `127.0.0.1:8420` | TCP bind address. |
| `keys_file` | string | `apd-keys.json` | AP Ed25519 signing keys (see `apd keygen`). **Secret**; share across instances. |
| `storage` | object | memory | See below. |
| `agent_token_ttl_secs` | int | `3600` | Agent-token lifetime. Must be `1..=86400` (spec ceiling 24h). |
| `subscribe_token_ttl_secs` | int | `86400` | Subscribe-token registration window. |
| `signature_window_secs` | int | `60` | Allowed skew for the HTTP-signature `created` timestamp. |
| `naming_jwt_max_lifetime_secs` | int | `300` | Max accepted `exp-iat` on two-key refresh naming JWTs; also the replay-guard TTL. |
| `enrollment.methods` | string[] | `["token"]` | Enabled enrollment gates, any of `token`, `federated`, `allowlist`, `open`. Evaluated per request as assertion → token → allowlist → open; a presented-but-invalid credential never falls through. (Legacy `enrollment.mode` string still accepted.) |
| `enrollment.trusted_issuers` | object[] | `[]` | Trusted assertion issuers for the `federated` method — OIDC discovery, direct/inline/file JWKS, or `x5c` CA bundles, with audience/claim/SAN/cnf policy and `embed_claims`. Full field reference and per-environment recipes: [`federated-enrollment.md`](federated-enrollment.md). |
| `enrollment.static_tokens` | object[] | `[]` | Predefined **static enrollment tokens** for the `token` method — `{ "token": "...", "ps"?: url, "label"?: string }`. **Reusable** (unlike minted tokens) and live as long as the config: a dev/staging convenience so agents can enroll with a known token (docker-compose, CI, local runs) without a runtime mint step. ≥16 chars enforced; compared constant-time; presence announced with a startup warning + `static_enrollment_tokens_active` audit event; enrollments audit as `token_kind: "static"`. Prefer minted or federated enrollment in production. |
| `enrollment.default_ps` | url | — | `ps` bound into tokens when neither the enrollment nor the request sets one. |
| `admin_token` | string | — | Enables the `/admin` API. Prefer the `APD_ADMIN_TOKEN` env var. |
| `allow_ps_override` | bool | `true` | Allow a token request to override the enrollment's bound `ps`. |
| `metadata.*` | strings | — | `name`, `description`, `logo_uri`, `logo_dark_uri`, `documentation_uri`, `tos_uri`, `policy_uri` — surfaced in `aauth-agent.json`. |
| `events.enabled` | bool | `true` | Enable subscribe tokens, `/events`, `/inbox`, and the `event_endpoint` in metadata. |
| `events.inbox_ttl_secs` | int | `604800` | How long undelivered inbox events / subscription records are retained. |
| `events.max_pending_per_agent` | int | `1000` | Inbox cap per agent (oldest dropped). |
| `events.max_payload_bytes` | int | `65536` | Max event payload accepted at `/events`. |
| `max_body_bytes` | int | `65536` | Global request-body cap. |
| `jwks_cross_origin_hosts` | string[] | `[]` | Hosts explicitly admitted as **cross-origin JWKS hosts** when verifying foreign (event) tokens — i.e. a resource whose metadata points `jwks_uri` at a different host than its `issuer` (e.g. a CDN). Empty means same-origin JWKS only, per the Signature-Key draft's requirement that cross-origin JWKS URLs need explicit deployment admission. List bare hostnames, e.g. `["jwks.cdn.example"]`. |
| `audit_log_file` | string | — | Append structured JSON audit events (enrollments, denials, issuance, revocation, allowed-key changes) to this file, in addition to stderr. |
| `telemetry.enabled` | bool | `false` | Enable OpenTelemetry export. Also `APD_TELEMETRY_ENABLED=1`. See [Observability](#observability). |
| `telemetry.endpoint` | url | `http://localhost:4318` | OTLP/HTTP base endpoint of an OTEL Collector; signals go to `{endpoint}/v1/traces` and `/v1/metrics`. Env `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `telemetry.service_name` | string | `apd` | `service.name` resource attribute. Env `OTEL_SERVICE_NAME`. |
| `telemetry.metric_interval_secs` | int | `30` | Metric export interval. |
| `insecure_dev_mode` | bool | `false` | **Dev only.** Allows `http://` issuer + ports, and outbound fetches over http / to private/loopback addresses. Never enable in production. |

## Storage

```json
"storage": { "backend": "memory" }
"storage": { "backend": "file", "path": "/var/lib/apd/state.json" }
"storage": { "backend": "redis", "redis_addr": "127.0.0.1:6379", "key_prefix": "apd:" }
```

- **memory** — per-process; nothing persists. Dev, tests, or a stateless
  single instance where losing enrollments on restart is acceptable.
- **file** — memory plus a crash-safe JSON snapshot (atomic tmp+rename) on every
  mutation. Single host only.
- **redis** — required for multi-instance. All atomic operations map to Redis
  primitives (`SET NX`, `GETDEL`, `INCR`, `RPUSH`/`LTRIM`, `MULTI`/`EXEC`). Uses
  a minimal built-in RESP2 client over plain TCP — run Redis on localhost, a
  trusted network, or behind a TLS tunnel (`stunnel`/service mesh). Requires
  Redis ≥ 6.2 (`GETDEL`).

## Environment overrides

Applied after the file loads: `APD_ISSUER`, `APD_LISTEN`, `APD_KEYS_FILE`,
`APD_ADMIN_TOKEN`, `APD_REDIS_ADDR` (setting the last switches the backend to
redis), and `APD_STATIC_ENROLL_TOKEN` (appends one static enrollment token,
labeled `env` — keeps dev tokens out of committed config files). Useful for
containers and secret injection — keep `admin_token`, Redis addresses, and
static tokens out of the committed config.

## Validation

At startup `apd` rejects: a non-conforming `issuer`, `agent_token_ttl_secs`
outside `1..=86400`, a storage backend missing its required path/address, an
unknown `enrollment.mode`, and a malformed `enrollment.default_ps`. Fix the
reported field and restart.

## Assurance tiers

Every issued agent token carries an `assurance` claim so Person Servers and
resources can apply policy proportional to how the agent enrolled. The tier is
derived from the enrollment method:

| Enrollment | `assurance` |
|---|---|
| `open` | `none` |
| static enrollment token | `low` |
| admin-minted token / `allowlist` | `medium` |
| `federated` OIDC / JWKS | `medium` |
| `federated` `x5c` / `spiffe` | `high` |

Override per federated issuer with `"assurance": "<tier>"` (lowercase
`[a-z0-9_]`, ≤32 chars). Sub-agents inherit their parent's tier. The claim is
protected — a trusted issuer's `embed_claims` cannot forge it.

## Admin API authentication

The admin API accepts either a shared bearer token or a token from your identity
provider. Configure both during a migration; configure only `admin_oidc` once
everyone has moved.

| Field | Default | Meaning |
|---|---|---|
| `admin_token` | *(none)* | Shared bearer token. Prefer `APD_ADMIN_TOKEN`. |
| `admin_oidc.issuer` | *(required)* | Your IdP's issuer URL. The token's `iss` must equal it exactly, and it is checked before any key is fetched. |
| `admin_oidc.audience` | *(required)* | Required `aud`. Without it, a token your IdP minted for any other application would administer this provider. |
| `admin_oidc.required_claims` | *(required, non-empty)* | Claim path → matcher. This is the authorization gate. |
| `admin_oidc.principal_claim` | `sub` | Which claim names the operator in the audit log. `email` reads better in a review. |
| `admin_oidc.jwks_uri` | *(discovery)* | Explicit JWKS URL, skipping discovery. |

```json
"admin_oidc": {
  "issuer": "https://acme.okta.com",
  "audience": "apd-admin",
  "required_claims": { "groups": "apd-admins" },
  "principal_claim": "email"
}
```

Operators then call the API with a token from the IdP:

```sh
curl -X POST https://ap.example.com/admin/agents/<local>/revoke \
  -H "Authorization: Bearer $(your-idp-cli token)"
```

**Why this exists.** A shared token proves only that the caller holds the secret.
Every action looks identical afterwards, it cannot be withdrawn from one person,
and offboarding means rotating it for everyone at once. With `admin_oidc` each
action carries the operator's name:

```json
{"event":"agent_revoked","actor":"oidc:alice@acme.example","local":"k7q3p9n2"}
{"event":"agent_revoked","actor":"static-token","local":"m4x8b1c5"}
```

The shared-token case is labelled `static-token` rather than `admin`, so a
reviewer can see at a glance which actions carried no operator identity.

**`required_claims` may not be empty.** Authenticating against the company IdP
proves employment, not entitlement — an empty gate would make every account with
a login an administrator. apd refuses to start rather than accept that. Matchers
use the same syntax as trusted issuers: exact, an array of allowed values, or a
trailing `*` prefix. A multi-valued claim such as `groups` matches when any of
its values does.

## Revocation

| Field | Default | Meaning |
|---|---|---|
| `revocation.notify_ps` | `true` | On `POST /admin/agents/{local}/revoke`, also call the agent's Person Server `revocation_endpoint`. |
| `revocation.max_tracked_tokens` | `64` | Safety cap on outstanding token identifiers tracked per agent. |

Revocation in AAuth names a **token**, not an agent: recipients key revocation
state by `(iss, jti)`. apd therefore records each issued `jti` with a TTL equal
to the token's remaining life — the index self-prunes, and there is no reaper.
On revoke it sends one signed `POST {revocation_endpoint}` per outstanding
token, signing as the AP itself with the `jwks_uri` scheme so the PS can confirm
the caller is the token's `iss`.

**Local revocation is authoritative.** Refusing to re-issue always takes effect,
whatever the PS does. The notification is best effort and its outcome
(`sent` / `disabled` / `no_ps` / `no_endpoint` / `failed`) appears in the admin
response and the audit log. Where no revocation reaches a holder, access is
bounded by the token lifetime — which is the argument for keeping
`agent_token_ttl_secs` short.

Set `notify_ps: false` to keep revocation purely local; apd then skips the `jti`
index entirely.

## Observability

Set `telemetry.enabled` (or `APD_TELEMETRY_ENABLED=1`) to export **metrics and
traces** over OTLP/HTTP (protobuf) to an OpenTelemetry Collector. Disabled by
default with zero overhead (instruments are no-ops). Standard `OTEL_*` env vars
(`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`) are honored.

Metrics (scope `apd`): `apd.enroll.total` (dimensioned by `method`,
`assurance`, `result`), `apd.agent_token.total`, `apd.subagent_token.total`,
`apd.verify_fail.total` (by route), `apd.requests.total` (route + status class),
and the `apd.request.duration` histogram (seconds, by route). Traces: one
SERVER span per request tagged with method, route template, and status code.
Route templates keep per-agent paths from exploding cardinality.

```json
"telemetry": { "enabled": true, "endpoint": "http://otel-collector:4318", "service_name": "apd" }
```
