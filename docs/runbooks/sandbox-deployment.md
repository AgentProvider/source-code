# Runbook — Sandbox Agent Provider deployment

**Audience:** DevOps / SRE.
**Service:** `apd` (AAuth Agent Provider), public developer sandbox.
**Version:** `apd` 0.2.0.
**Status:** Ready to deploy. Read section 3 first. It lists the work to do before you deploy.

---

## 1. What this service is

The sandbox is a **public, hosted AAuth Agent Provider**. Developers use it to build and test agents, MCP servers, and client applications.

No hosted Agent Provider exists in the AAuth ecosystem today. A developer must run one locally. This sandbox removes that step.

**In scope**
- Issue agent tokens to any developer.
- Serve the AAuth discovery documents.
- Accept open enrollment. No sign-up.

**Not in scope**
- Production identity. The tokens are for testing only.
- Any promise of data retention. The data is ephemeral.
- User accounts, billing, or a UI. These come later.

### Roles

| Component | Role | Who runs it |
|---|---|---|
| `apd` | Agent Provider | Us. This runbook. |
| A developer agent | Agent | The developer. |
| An MCP server | Resource | The developer. |
| `whoami.aauth.dev` | Resource | A third party. We use it to test. |

---

## 2. Naming and DNS

### 2.1 The subdomain decision

Use this host:

```
sandbox.agentprovider.dev
```

The `issuer` value is then `https://sandbox.agentprovider.dev`.

**Reserve this host for later. Do not use it now:**

```
ap.agentprovider.dev      # a future stable or production Agent Provider
```

Keep the sandbox and any future production instance on separate hosts. A shared host would mix test identities with real identities.

### 2.2 Why the host cannot change later

> **WARNING — the issuer is permanent.**
>
> The `issuer` goes into the `iss` claim of every token. The agent identifier also derives from it. An agent becomes `aauth:k7q3p9n2@sandbox.agentprovider.dev`.
>
> A change of host does three things:
> - It breaks every token that we already issued.
> - It changes every agent identifier.
> - It breaks every developer integration.
>
> Agree the host before the first deployment.

### 2.3 AAuth rules for the host

The `issuer` must satisfy the AAuth server identifier rules. `apd` rejects the configuration if it does not.

- Use `https`. Not `http`.
- Use the scheme and host only.
- Use no port, no path, no query, and no trailing slash.
- Use lower case.

### 2.4 DNS records

The apex `agentprovider.dev` serves the marketing site from GitHub Pages. Do **not** change the apex records.

Add one new record for the sandbox:

| Name | Type | Value | Notes |
|---|---|---|---|
| `sandbox` | `A` / `AAAA` or `CNAME` | The ingress load balancer | Points at the cluster, not at GitHub Pages. |

Confirm that the record does not collide with the Pages configuration.

### 2.5 TLS

The certificate must cover `sandbox.agentprovider.dev`.

- Use cert-manager with Let's Encrypt, or a cloud load balancer certificate.
- Set the Kubernetes secret name to `apd-sandbox-tls`.
- Enable automatic renewal. Alert on a certificate that expires in less than 21 days.

---

## 3. Code preparations — do this before you deploy

Read this section before you plan the work.

### 3.1 Blocking issue: agent records never expire

`apd` writes each agent record with no expiry time. See `crates/apd/src/handlers/agent.rs`. The `put` call passes `None` as the TTL.

Open enrollment plus a public network plus no expiry gives unbounded growth. The storage will fill.

**Choose one of these two options.**

**Option A — memory storage. Zero code. Use this for the first release.**
- Set `storage.backend: memory`.
- All state lives in the pod memory.
- A restart clears all agents.
- Restart the pod once every 24 hours with a `CronJob`.
- Accept the effect: a redeployment removes every sandbox agent.
- Publish this behaviour in the developer documentation.

**Option B — a record TTL. A small code change. Do this later.**
- Add a configuration field, for example `enrollment.agent_ttl_secs`.
- Pass `Some(Duration)` to the two `put` calls in the enrol handler. The calls write `agent_key` and `jkt_key`.
- The refresh path also writes the record. That write then extends the lifetime. The result is a sliding window.
- Effort: about half a day, and tests.

**Decision for the first release: use Option A.** It needs no code, and it removes the risk.

### 3.2 Other findings

| Item | Status | Action |
|---|---|---|
| Rate limiting | Not in `apd`. This is by design. | Apply it at the ingress. See section 6.4. |
| Per-IP agent quota | Not available. | Accept the risk. The ingress rate limit reduces it. |
| `env: sandbox` claim in tokens | Not possible in open mode. `embed_claims` needs a federated issuer. | Do not build it. The `iss` value already identifies the sandbox. |
| Admin API | Available. It uses a bearer token, and not an AAuth signature. | Never expose it to the internet. See section 6.5. |
| Events endpoints | Available. They add outbound fetches. | Disable them in the first release. |

### 3.3 Documentation to publish with the deployment

Write a developer quickstart page before you announce the service. The page must state:

- the issuer URL;
- that the data is ephemeral, and that agents disappear;
- that the tokens have no production value;
- the token lifetime;
- the rate limits.

---

## 4. Prerequisites

Confirm each item before you start.

- A Kubernetes cluster, version 1.23 or later.
- `kubectl` with access to the cluster.
- `helm`, version 3.8 or later. OCI support is required.
- An ingress controller. This runbook assumes ingress-nginx.
- cert-manager, or another certificate source.
- Permission to change the `agentprovider.dev` DNS zone.
- An OpenTelemetry Collector endpoint. This is optional.

---

## 5. Sizing

`apd` is a single static binary. It uses few resources.

| Setting | Value |
|---|---|
| CPU request | 50m |
| CPU limit | 500m |
| Memory request | 64Mi |
| Memory limit | 256Mi |
| Replicas | 1 |
| Storage | None. Memory backend. |

Keep one replica. More than one replica needs Redis and shared state. The sandbox does not need that yet.

The image is about 11 MB. It is distroless. It runs as user 65532. It needs no writable root file system.

---

## 6. Configuration

### 6.1 The values file

Use `deploy/sandbox/values-sandbox.yaml` from this repository. It holds the full configuration.

### 6.2 Setting reference

| Setting | Value | Reason |
|---|---|---|
| `issuer` | `https://sandbox.agentprovider.dev` | Permanent. See section 2.2. |
| `config.agentTokenTtlSecs` | `300` | Five minutes. Developers then test the refresh path in a normal session. |
| `config.signatureWindowSecs` | `60` | The default. It needs correct clocks. |
| `config.enrollment.methods` | `["open"]` | No credential. This is the point of a sandbox. |
| `config.events.enabled` | `false` | Reduces the attack surface in the first release. |
| `config.insecureDevMode` | `false` | **Never `true`.** This is a public HTTPS service. |
| `storage.backend` | `memory` | Ephemeral by design. See section 3.1. |
| `admin.enabled` | `true` | Needed for operations. Keep it internal. |

### 6.3 Ingress rules

> **CRITICAL — the proxy must not change the request.**
>
> The AAuth signature covers `@method`, `@authority`, and `@path`. A proxy that rewrites the host or the path breaks every request.

Configure the ingress as follows.

- Preserve the `Host` header. Do not rewrite it.
- Preserve the path. Do not add or remove a prefix.
- Never strip these headers: `Signature`, `Signature-Input`, `Signature-Key`.
- Never strip these response headers: `Signature-Error`, `Accept-Signature-Alg`.
- Set the read timeout to 75 seconds or more. The `/inbox` endpoint holds a connection for up to 50 seconds.
- Set the maximum body size to 64 KB.

#### If you do not run ingress-nginx

The list above is the contract. `values-sandbox.yaml` expresses it in
`nginx.ingress.kubernetes.io/*` annotations, and **those annotations are silently
ignored by every other controller** — they are not rejected, so the deployment
comes up looking correct with none of the settings applied.

The reference sandbox itself runs APISIX in front of envoy Gateway, not
ingress-nginx, so this is the common case rather than the exception. Equivalents:

| Requirement | ingress-nginx | Gateway API / envoy |
|---|---|---|
| Preserve `Host` | `upstream-vhost` | default; do not add a `URLRewrite` filter |
| Read timeout ≥ 75 s | `proxy-read-timeout: "75"` | `HTTPRoute.spec.rules[].timeouts.request` |
| Body size 64 KB | `proxy-body-size: "64k"` | `BackendTrafficPolicy` |
| Block `/admin/*` | `configuration-snippet` | a route with no backend, matched first |

**Read timeout is the one that fails late.** Envoy Gateway defaults an HTTPRoute
to a **15-second** request timeout, well under the 50 seconds `/inbox` holds a
connection. Everything else works; long-polling returns `504` once the agent
starts waiting, which looks like an apd bug and is not one. Set it before
enabling events, not after the first report.

Verify the contract holds rather than trusting the configuration:

```sh
# Host and path arrive unchanged — a signed request is the real test.
cd tools/aauthcheck && cargo run --release -- --ap https://sandbox.example.com

# Long-poll survives the proxy (only meaningful once events are enabled).
time curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Prefer: wait=50' https://sandbox.example.com/inbox
# 401 after ~0 s = reached apd (unsigned, as expected).
# 504 after ~15 s = the proxy timeout is too low.
```

### 6.4 Rate limits

`apd` has no rate limiter. Apply the limits at the ingress.

| Path | Limit | Reason |
|---|---|---|
| `/enroll` | 5 requests per minute per IP | Enrolment creates state. |
| `/agent-token` | 30 requests per minute per IP | Token refresh is frequent. |
| All paths | 20 concurrent connections per IP | Protects the long-poll endpoint. |

### 6.5 Endpoints that must not reach the internet

Block these paths at the ingress. They use a bearer token, and not an AAuth signature.

```
/admin/*
```

Reach the admin API through `kubectl port-forward` only.

> **Check this before you deploy.**
>
> The values file blocks `/admin` with an nginx `configuration-snippet`
> annotation. Recent ingress-nginx versions disable snippets by default. The
> setting is `allow-snippet-annotations`.
>
> Run Test 5 in section 8. If the block does not work, use one of these
> alternatives:
> - Enable `allow-snippet-annotations` in the controller.
> - Add a second Ingress for the `/admin` path that routes to no backend.
> - Set `admin.enabled: false`, and enable it only during an operation.

---

## 7. Deployment procedure

### Step 1 — Create the namespace

```sh
kubectl create namespace apd-sandbox
```

### Step 2 — Create the signing keys

The signing keys are the most important secret. Every token depends on them.

```sh
docker run --rm -v "$PWD:/data" ghcr.io/agentprovider/apd:0.2.0 \
  keygen --keys /data/apd-keys.json

kubectl -n apd-sandbox create secret generic apd-sandbox-keys \
  --from-file=apd-keys.json
```

**Outcome:** A secret named `apd-sandbox-keys` exists.

**Now do this:**
1. Copy `apd-keys.json` to the team secret store.
2. Delete the local file.
3. Never commit the file.

### Step 3 — Create the admin token

```sh
kubectl -n apd-sandbox create secret generic apd-sandbox-admin \
  --from-literal=admin-token="$(openssl rand -hex 32)"
```

**Outcome:** A secret named `apd-sandbox-admin` exists.

### Step 4 — Confirm the DNS record

```sh
dig +short sandbox.agentprovider.dev
```

**Outcome:** The command returns the ingress address. Do not continue without this.

### Step 5 — Install the chart

```sh
helm install apd-sandbox oci://ghcr.io/agentprovider/charts/apd \
  --version 0.2.0 \
  --namespace apd-sandbox \
  --values deploy/sandbox/values-sandbox.yaml
```

**Outcome:** The pod reaches the `Running` state.

### Step 6 — Confirm the certificate

```sh
kubectl -n apd-sandbox get certificate
```

**Outcome:** The certificate shows `READY=True`. Wait for it before you test.

### Step 7 — Add the restart schedule

Option A needs a daily restart. Create a `CronJob` that runs this command:

```sh
kubectl -n apd-sandbox rollout restart deployment/apd-sandbox
```

Run it at 03:00 UTC.

**Outcome:** Sandbox data never lives longer than 24 hours.

---

## 8. Verification

Run every test. Record the result.

### Test 1 — Health

```sh
curl -s https://sandbox.agentprovider.dev/healthz
```

**Expected:** `{"status":"ok","mode":"demo","issuer":"https://sandbox.agentprovider.dev",...}`

### Test 2 — Discovery document

```sh
curl -s https://sandbox.agentprovider.dev/.well-known/aauth-agent.json
```

**Expected:** The `issuer` field equals `https://sandbox.agentprovider.dev` exactly. A mismatch breaks every verifier. Stop and fix it.

### Test 3 — Public keys

```sh
curl -s https://sandbox.agentprovider.dev/.well-known/jwks.json
```

**Expected:** One key. The fields are `"kty":"OKP"`, `"crv":"Ed25519"`, and `"alg":"Ed25519"`.

The `alg` value must be `Ed25519`. It must not be `EdDSA`. Version 0.2.0 made this change.

### Test 4 — An unsigned request fails

```sh
curl -s -i -X POST https://sandbox.agentprovider.dev/enroll
```

**Expected:** `401`. The response carries a `Signature-Error` header.

### Test 5 — The admin API is not public

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://sandbox.agentprovider.dev/admin/agents
```

**Expected:** `403` or `404` from the ingress. A `401` from `apd` means the block failed. Fix the ingress.

### Test 6 — The host and path survive the proxy

Complete a full enrolment with a signed request. A pass proves that the proxy preserves `@authority` and `@path`.

**Expected:** `201` and an agent identifier.

### Test 7 — Interoperability

Point a test agent at `https://whoami.aauth.dev`. Use the sandbox for the agent token.

**Expected:** `whoami.aauth.dev` fetches our discovery document and our JWKS. It then returns the agent identity.

A pass proves that a third-party implementation accepts our tokens.

---

## 9. Monitoring

### 9.1 Enable telemetry

Set the Collector endpoint in the values file. `apd` pushes OTLP over HTTP. It has no scrape endpoint.

### 9.2 Metrics

| Metric | Meaning |
|---|---|
| `apd.enroll.total` | Enrolments. Labels: `method`, `assurance`, `result`. |
| `apd.agent_token.total` | Agent tokens issued. |
| `apd.subagent_token.total` | Sub-agent tokens issued. |
| `apd.verify_fail.total` | Signature or assertion failures. |
| `apd.requests.total` | Requests. Labels: route, status class. |
| `apd.request.duration` | Request duration histogram. |

### 9.3 Alerts

| Alert | Condition | Severity |
|---|---|---|
| Service down | `/healthz` fails for 2 minutes | Page |
| Certificate expiry | Less than 21 days remain | Ticket |
| Verification failures | `apd.verify_fail.total` rises sharply | Ticket |
| Enrolment flood | `apd.enroll.total` exceeds the normal rate | Ticket |
| Memory growth | Pod memory above 200Mi | Ticket. See section 3.1. |
| Restart loop | More than 3 restarts in 10 minutes | Page |

### 9.4 Logs

`apd` writes structured JSON audit lines to stderr. The events include `enroll`, `enroll_denied`, `agent_token_issued`, and `agent_revoked`.

Collect stderr. Keep it for 30 days.

---

## 10. Operational procedures

### 10.1 Rotate the signing keys

Rotation is safe and online. Old public keys stay in the JWKS until the old tokens expire.

```sh
# 1. Get the current keys from the secret store.
# 2. Add a new active key.
docker run --rm -v "$PWD:/data" ghcr.io/agentprovider/apd:0.2.0 \
  keygen --keys /data/apd-keys.json --rotate

# 3. Replace the secret.
kubectl -n apd-sandbox create secret generic apd-sandbox-keys \
  --from-file=apd-keys.json --dry-run=client -o yaml | kubectl apply -f -

# 4. Restart.
kubectl -n apd-sandbox rollout restart deployment/apd-sandbox

# 5. Wait for the longest token lifetime. This is 5 minutes.
# 6. Remove the old keys.
docker run --rm -v "$PWD:/data" ghcr.io/agentprovider/apd:0.2.0 \
  keygen --keys /data/apd-keys.json --prune-days 1
```

Repeat steps 3 and 4 after the prune.

### 10.2 Block one agent

```sh
kubectl -n apd-sandbox port-forward svc/apd-sandbox 8420:8420

curl -X POST http://localhost:8420/admin/agents/<local>/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The Agent Provider then refuses new tokens. The current token expires within 5 minutes.

### 10.3 Clear all sandbox data

```sh
kubectl -n apd-sandbox rollout restart deployment/apd-sandbox
```

The memory backend loses all state on restart.

### 10.4 Roll back a release

```sh
helm -n apd-sandbox rollback apd-sandbox
```

Do not change the `issuer` during a rollback.

---

## 11. Incident guide

| Symptom | Probable cause | Action |
|---|---|---|
| Every signature fails | The proxy rewrites the host or the path. | Check the ingress. See section 6.3. |
| Every signature fails after a change | Clock drift on the node. | Check NTP. The window is 60 seconds. |
| Verifiers reject our tokens | The `issuer` does not match the serving host. | Compare Test 2 with the URL. |
| Third parties fail, and we pass | The client still sends `alg: EdDSA`. | Version 0.2.0 requires `Ed25519`. This is correct behaviour. |
| Memory grows and does not fall | Agent records accumulate. | Restart. Then plan Option B in section 3.1. |
| `/inbox` requests time out | The proxy read timeout is too short. | Set 75 seconds or more. |

---

## 12. Security checklist

Confirm every line before you announce the service.

- [ ] `insecure_dev_mode` is `false`.
- [ ] The `issuer` uses `https` and matches the serving host exactly.
- [ ] TLS is valid, and renewal is automatic.
- [ ] `/admin/*` is blocked at the ingress.
- [ ] The admin token comes from a secret. It is not in the values file.
- [ ] The signing keys are in the team secret store, and not in Git.
- [ ] Rate limits are active on `/enroll` and `/agent-token`.
- [ ] The maximum body size is 64 KB.
- [ ] No developer can add an issuer URL. That would create an SSRF risk.
- [ ] NTP runs on every node.
- [ ] The developer documentation states that the data is ephemeral.

---

## 13. Ownership

| Item | Owner |
|---|---|
| Service and infrastructure | DevOps |
| `apd` code and releases | Engineering |
| Signing keys | DevOps. Copy in the team secret store. |
| Developer documentation | Engineering |

---

## 14. Later work

Do these after the first release is stable.

1. Add the agent TTL. See Option B in section 3.1.
2. Add GitHub sign-in. It gives persistent agents and a per-user quota.
3. Add a request inspector. It shows the signature base string, and it speeds up developer debugging.
4. Add a "test my server" tool for MCP server authors.
5. Publish a static test fixture pack.
6. Enable events when a developer needs them.
