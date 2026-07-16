# apd — Backlog

Forward-looking work for the AAuth Agent Provider (`apd`). Items are things that
**should or could** become part of an agent provider but are not implemented
today. Each entry records *what*, *why*, *where it would land*, the *spec anchor*,
and a rough *effort*. Nothing here is a known bug — see the issue tracker for those.

Anchors use `draft-hardt-aauth-bootstrap-01` (informational AP-implementer
guidance) and the wider AAuth family (`draft-hardt-oauth-aauth-protocol`,
`draft-hardt-httpbis-signature-key`).

> **Already shipped, deliberately not in this list:** federated enrollment
> (OIDC / operator-JWT / X.509-CA / SPIFFE allowlist), static enrollment tokens,
> `hwk` single-key + `jkt-jwt` two-key refresh with naming-JWT `jti` replay guard,
> `ps` targeting, sub-agent tokens, AAuth Events (subscribe / deliver / inbox),
> AP signing-key rotation with JWKS overlap + prune (`apd keygen --rotate
> --prune-days`), admin revoke / reinstate / list, multi-instance storage
> (memory / file / redis), SSRF egress admission, and per-install random identity.

---

## A. Spec-anchored (from the bootstrap draft)

### A1. Platform attestation methods (WebAuthn / App Attest / Play Integrity)
- **What:** An optional enrollment method that verifies a platform attestation
  object at `/enroll` and gates it on a **server-nominated, single-use,
  short-lived nonce** (≤5 min). Covers Apple App Attest, Google Play Integrity,
  and WebAuthn registration. Needs (a) a nonce-issuance endpoint (e.g.
  `POST /enroll/challenge` → `{nonce, exp}`), (b) verification of the attestation
  against the platform trust root, (c) nonce single-use consumption in the store.
- **Why:** Lets an AP prove the durable key is hardware-bound (Secure Enclave /
  StrongBox) and that the caller is the AP's genuine app — the anti-fraud gate
  for consumer and regulated deployments.
- **Where:** new `crates/apd/src/enrollment/attest_*.rs` method modules behind the
  existing enrollment dispatch; nonce store reuses the `put_if_absent` replay
  primitive already used for naming-JWT `jti` (`handlers/agent.rs`).
- **Spec:** bootstrap §5, §8.3 (re-attest cadence), §10.4 (nonce replay).
- **Effort:** L. App Attest / Play Integrity trust-root verification is the bulk;
  the AP-side nonce plumbing is small and already has a working analog.
- **Note:** apd's federated enrollment (`jti`-replay-protected assertions) is the
  current server-side analog; this item is about the *client-attestation* trust
  roots we don't yet parse.

### A2. Periodic re-attestation on refresh
- **What:** Optional policy to require a fresh App Attest assertion / Play
  Integrity verdict every _N_ days at refresh, by embedding a server nonce in the
  refresh challenge. Depends on A1.
- **Why:** Bounds trust in a long-lived enrollment without re-attesting on every
  refresh (which the draft explicitly says is unnecessary).
- **Where:** refresh path in `handlers/agent.rs::agent_token` — there is already a
  `// Refresh is the AP's policy re-evaluation point` marker comment where this
  gate belongs.
- **Spec:** bootstrap §8.3.
- **Effort:** S (once A1 exists).

### A3. Desktop enrollment / key-handling method
- **What:** First-class support for native desktop durable keys — macOS Keychain
  (Secure Enclave), Windows TPM via CNG, Linux Secret Service / TPM2 — following
  the mobile two-key pattern (hardware durable key, in-memory ephemeral key).
  Mostly a **client** concern, but the AP side benefits from a documented profile
  and any platform-specific attestation the OS exposes.
- **Why:** Desktop is marked TBD in the draft; agent runtimes (Claude Desktop,
  IDE agents) are a primary deployment target.
- **Where:** documentation profile + optional attestation module (ties to A1).
- **Spec:** bootstrap §4.4 (TBD).
- **Effort:** M (mostly docs + optional TPM attestation verification).

### A4. Workload / headless identity enrollment (SPIFFE SVID, WIMSE, cloud IMDS)
- **What:** Verify a workload identity credential at enrollment rather than a
  user gesture: SPIFFE/SPIRE **SVID** (X.509 or JWT-SVID) signature + trust-domain
  check, WIMSE workload identity, or cloud IMDS attestation (AWS/GCP/Azure
  instance identity documents). Today apd has a SPIFFE **allowlist** (static list
  of trusted IDs) but does not verify a presented SVID against a SPIRE trust
  bundle.
- **Why:** Headless agents in k8s / CI / cloud have no user to attest; the trust
  anchor is platform attestation. This is the "enterprise, no human in the loop"
  path.
- **Where:** new enrollment method module; JWT-SVID reuses the existing
  `enrollment/assertion.rs` verification; X.509-SVID reuses `enrollment/x509.rs`
  chain logic with SPIFFE SAN policy.
- **Spec:** bootstrap §4.5 (TBD); complements existing X.509-CA enrollment.
- **Effort:** M — X.509/JWT-SVID reuses existing verifiers; IMDS roots are new.

### A5. Assurance-tier claims surfaced to receivers
- **What:** A structured, AP-defined claim (e.g. `assurance` / `amr`-style) in the
  agent token that tells receivers *how* the agent was enrolled (software key vs.
  hardware-attested vs. self-hosted) so a PS can apply proportional policy at its
  consent screen. Today `embed_claims` can carry arbitrary claims per enrollment,
  but there is no first-class, method-derived assurance level.
- **Why:** The draft's multi-tenant guidance: free tier gets weak tokens, paid /
  enterprise tier gets attested tokens, and the difference is surfaced to
  receivers. Also underpins "receivers apply policy proportional to trust in AP."
- **Where:** derive from the enrollment method in `issue.rs`; add config to map
  method → assurance value.
- **Spec:** bootstrap §5.4, §10.1.
- **Effort:** S.

### A6. Durable-key rotation & anomaly detection
- **What:** (a) Detect anomalous refresh patterns (velocity, geo/asn shifts if
  available, sudden ephemeral-key churn) and flag/suspend an enrollment; (b) a
  documented, self-service **durable-key rotation** path. Under per-install
  identity a new durable key is a *new* agent (new `sub`) — this item is about
  making that transition observable and letting a user revoke a compromised
  durable enrollment quickly (admin revoke exists; a user-facing path does not).
- **Why:** Durable-key compromise lets an attacker mint refreshes until revoked;
  the draft asks APs to detect anomalies and give users a revoke path.
- **Where:** refresh accounting already lives on `AgentRecord`
  (`last_issued_at`, `tokens_issued`); add rate/pattern checks + a status.
- **Spec:** bootstrap §10.3.
- **Effort:** M.

### A7. Optional account-linked identity mode
- **What:** An opt-in mode where the AP keeps an `(ap_user, durable_jkt)` mapping,
  enabling (i) multi-device grouping under one account, (ii) durable-key rotation
  that **preserves** the agent `sub`, and (iii) cross-device continuity. The
  default stays per-install (no user-account system, no correlation) as the draft
  recommends.
- **Why:** Enterprises and consumer products with real accounts want device
  grouping and "same agent across my devices"; the draft notes this correlation
  belongs at the PS by default but an AP may offer it.
- **Where:** new optional storage record + config flag; identity minting in
  `handlers/agent.rs` would consult the mapping before allocating a fresh local.
- **Spec:** bootstrap §6.1, §11.1 (privacy trade-off must be documented).
- **Effort:** M — mostly storage + a privacy-sensitive config surface.

---

## B. Operational & enterprise maturity (beyond the draft)

### B1. Metrics & observability
- **What:** A `/metrics` Prometheus endpoint (enroll / token / refresh counts,
  latencies, replay rejects, JWKS-cache hit rate) and structured, exportable
  audit events. Audit records already exist internally; this exposes them.
- **Why:** Multi-instance production deployments need SLOs and abuse visibility.
- **Where:** `router.rs` + a lightweight counter registry; audit export in
  `audit.rs`.
- **Effort:** M. Keep dependency-free (hand-rolled text exposition format) to
  match the project's minimal-deps posture.

### B2. Rate limiting & abuse protection
- **What:** Per-key / per-IP throttles on `/enroll` and `/agent-token`, and a
  configurable cap on active enrollments per durable key / per account.
- **Why:** Enrollment and refresh are unauthenticated-until-verified; a flood is
  cheap to send and expensive to verify (signature checks, JWKS fetches).
- **Where:** middleware in `router.rs` / `reqctx.rs`; counters in the store so it
  works across instances.
- **Spec:** operational; supports bootstrap §10.3 anomaly posture.
- **Effort:** M.

### B3. Data-retention policy & documentation
- **What:** Configurable retention for enrollment / refresh audit events and a
  documented data-retention statement. The AP only sees enroll + refresh traffic
  (not downstream PS/resource calls), so its retention surface is small and worth
  stating explicitly.
- **Why:** The draft asks APs to document retention for these events; enterprises
  require it for procurement.
- **Where:** `config.rs` (retention TTLs) + a `PRIVACY.md` / docs page.
- **Spec:** bootstrap §11.2.
- **Effort:** S.

### B4. Multi-tenant isolation
- **What:** Per-tenant signing keys, config, and storage namespacing behind one
  deployment, with a tenant selector (host-based or path-based).
- **Why:** SaaS operators want one apd fleet serving many customer domains
  without cross-tenant key or data leakage; pairs with A5 tiering.
- **Where:** `config.rs`, `keys.rs`, `storage.rs` key prefixes, `router.rs`
  tenant resolution.
- **Effort:** L — touches key management and every storage key.

### B5. Sub-agent depth policy
- **What:** Revisit the current single-level sub-agent restriction — decide
  whether bounded multi-level delegation (with per-level exp capping and an
  explicit depth claim) is warranted, or keep single-level as the deliberate
  ceiling. Today `parent_agent` must not itself be a sub-agent.
- **Why:** Agent orchestration graphs (planner → workers → tools) may want >1
  level; needs a threat-model decision before loosening.
- **Where:** `tokens.rs::validate_agent_token`, `issue.rs`, `handlers/agent.rs`.
- **Spec:** protocol draft (sub-agent naming); no bootstrap anchor.
- **Effort:** S–M (design decision first).

---

## Prioritization sketch

1. **B1 / B2** (metrics, rate limiting) — unblock safe production operation.
2. **A4** (workload / SVID enrollment) — highest-leverage new *capability* for the
   headless/enterprise target audience; reuses existing verifiers.
3. **A5** (assurance tiers) — small, makes existing enrollment methods legible to
   receivers.
4. **A1 / A2** (platform attestation + re-attest) — larger, consumer-mobile focus.
5. **A6 / A7 / B3 / B4 / A3 / B5** — as demand and threat model dictate.
