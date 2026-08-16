# Implementation status

What apd does, what it deliberately does not, and — the section that matters —
what is implemented but has never been exercised by a real counterparty.

apd tracks `draft-hardt-oauth-aauth-protocol-11`,
`draft-hardt-httpbis-signature-key-08`, `draft-hardt-aauth-bootstrap-01` and
`draft-hardt-aauth-events-00`. The Budgets draft puts the Agent Provider out of
scope in its own text, so it is not tracked.

[Person Server](https://personserver.dev) publishes the equivalent list for the
PS role. Read both: the two are counterparties, and a gap on either side is a
gap in the flow.

---

## 1 · Required by the specs, not done or partial

Nothing known. The Agent Provider's obligations under protocol-11 —
metadata, JWKS, agent tokens, sub-agent tokens, signature verification, token
revocation to the Person Server — are implemented, and the -11 additions
(fully-specified `Ed25519`, `accept_signature_algs`, the new error responses and
verification steps) landed in v0.3.0.

The `account` request parameter added in -10 is **resource-side** by §6.1: it
travels from the agent to the resource's authorization endpoint, and an Agent
Provider has no part in it. Its absence here is correct, not a gap.

If you find something in the drafts that an AP must do and apd does not, that is
a bug — please open an issue.

## 2 · Deliberately excluded

- **SSE / WebSocket / push (APNs, FCM) event delivery to agents.** The events
  draft permits them; apd ships the poll and long-poll inbox primitive instead.
  Streaming and push transports are deployment-specific, and the primitive is
  what a workload behind a firewall can actually use.
- **Platform attestation** (App Attest, Play Integrity, WebAuthn) — enrollment
  hooks exist, no verification is performed. Real attestation needs vendor
  relationships and per-platform key material that a self-hostable daemon cannot
  assume.
- **Rate limiting and abuse throttling** — delegated to the ingress or gateway in
  front of apd rather than built into the daemon, which is where deployments
  already have the primitives.
- **Payment (`402`), missions, consent UI** — Person Server and Access Server
  territory. An AP that rendered consent would be claiming an authority it does
  not have.
- **HSM / KMS key custody** — signing keys are a `0600` file on disk.

## 3 · Implemented, never verified against a real counterparty

This is the section to read before trusting a green test suite. Everything here
is covered by tests and none of it has met a live counterparty, because for most
of it no live counterparty exists yet.

- **Everything a resource initiates.** A resource that *accepts* an agent token
  is verified (below), but no live resource has ever called *into* apd, so the
  resource-facing half of events is still self-tested.
- **Events, end to end.** `/subscribe`, `/events`, `/inbox` and
  `DELETE /subscriptions/{eid}` are tested in-process. **No real resource has
  ever delivered an event to apd.** The whole feature has only ever seen traffic
  it generated itself.
- **Sub-agent tokens.** Issued and tested, but no real resource has ever accepted
  one. Issuance is verified; acceptance is not.
- **Federated enrollment beyond mocks.** The `oidc` method is tested against a
  mock issuer; `x5c` and `spiffe` against synthetic certificates and SVIDs. No
  real Kubernetes projected service-account token, no real SPIFFE workload API,
  no real corporate CA has ever enrolled an agent here.
- **Admin SSO with a real identity provider.** Okta-shaped fixtures pin the
  document shapes — a pathful custom-AS issuer, RS256 over a real RSA key, an
  Okta-shaped JWKS — but **no live tenant has ever authenticated against apd**.
  `docs/identity-providers.md` ships a first-tenant checklist that nobody has
  run. psd's SSO stands in exactly the same place.
- **Storage at scale.** The file backend is tested functionally. No load test,
  no long-running deployment, no measured behaviour under concurrent writes.

### Verified live, for contrast

- Metadata, JWKS, enrollment (`open`, `token`, `allowlist`) and agent-token
  issuance, against the deployed sandbox using `tools/aauthcheck` as a real
  signing client.
- **AP→PS token revocation**, end to end with no mocks, against a real psd —
  twice, including once against the released `psd:0.1.0` container rather than a
  development build.
- **An independent third-party resource accepting an apd agent token.**
  `whoami.aauth.dev` — the AAuth Who Am I service, `access_mode: agent-token` —
  accepts a token issued by the live sandbox and echoes back the identity it
  sees:

  ```json
  {"iss":"https://sandbox.agentprovider.dev",
   "sub":"aauth:5ypvy2pea5w29qbx@sandbox.agentprovider.dev"}
  ```

  Run it yourself: `cd tools/aauthcheck && cargo run --release --
  --ap https://sandbox.agentprovider.dev`. This is the strongest evidence here,
  because the counterparty was written by neither of us and agrees anyway.

  It does **not** exercise auth tokens or resource tokens: `access_mode` is
  `agent-token`, so no Person Server or Access Server takes part. A resource
  that challenges for an auth token is still missing, and that is what psd's
  `/token` path needs.
- Cross-implementation conformance against psd: 27/27.
- The sandbox deployment itself, and every runnable example in the docs.

---

## What this means

apd is complete for the Agent Provider role as the drafts define it. But
"complete" and "known to work" are different claims, and the honest summary is:

> **Agent tokens are verified end to end, including at a resource neither of us
> wrote.** What remains unverified is everything a resource *initiates* —
> inbound events, and sub-agent tokens being accepted — because no live resource
> has yet called into apd.

The cheapest way to shorten section 3 further is a resource that challenges for
an auth token and delivers an event back. `whoami.aauth.dev` does neither: it is
`access_mode: agent-token`, which is exactly why it could verify the agent-token
path so cleanly and cannot touch the rest.
