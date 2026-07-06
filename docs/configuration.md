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
| `enrollment.mode` | string | `token` | `token` (admin-minted single-use tokens) or `open` (any key may enroll). |
| `enrollment.default_ps` | url | — | `ps` bound into tokens when neither the enrollment nor the request sets one. |
| `admin_token` | string | — | Enables the `/admin` API. Prefer the `APD_ADMIN_TOKEN` env var. |
| `allow_ps_override` | bool | `true` | Allow a token request to override the enrollment's bound `ps`. |
| `metadata.*` | strings | — | `name`, `description`, `logo_uri`, `logo_dark_uri`, `documentation_uri`, `tos_uri`, `policy_uri` — surfaced in `aauth-agent.json`. |
| `events.enabled` | bool | `true` | Enable subscribe tokens, `/events`, `/inbox`, and the `event_endpoint` in metadata. |
| `events.inbox_ttl_secs` | int | `604800` | How long undelivered inbox events / subscription records are retained. |
| `events.max_pending_per_agent` | int | `1000` | Inbox cap per agent (oldest dropped). |
| `events.max_payload_bytes` | int | `65536` | Max event payload accepted at `/events`. |
| `max_body_bytes` | int | `65536` | Global request-body cap. |
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
redis). Useful for containers and secret injection — keep `admin_token` and
Redis addresses out of the committed config.

## Validation

At startup `apd` rejects: a non-conforming `issuer`, `agent_token_ttl_secs`
outside `1..=86400`, a storage backend missing its required path/address, an
unknown `enrollment.mode`, and a malformed `enrollment.default_ps`. Fix the
reported field and restart.
