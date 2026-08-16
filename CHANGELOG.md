# Changelog

Notable changes to `apd`. Versions follow [semantic versioning](https://semver.org).

Security fixes are called out explicitly, because deciding whether to upgrade is
the reason most people read this file.

## [0.5.0] — unreleased

### Security

- **Verify that `@authority` is our own before acting on a signed request.** A
  signature made for one host was otherwise replayable against another: the
  component binds a signature to its target, but only if the verifier checks the
  value names itself. The check runs before parsing, verification or any key
  fetch, so a mismatched request costs nothing and reveals nothing
  (`400 invalid_request`, no `Signature-Error`).
- **Refuse RFC 2606 / 6761 reserved TLDs before DNS.** `.local`, `.internal`,
  `.test` and friends resolve differently depending on where a daemon happens to
  run, so admitting them makes egress policy a function of the network rather
  than of configuration.

### Added

- **Enterprise SSO for the admin API.** Admin endpoints accept a token from your
  identity provider alongside — or instead of — the shared bearer token. The
  credential's shape selects the path, so operators need not declare which they
  hold. Every state-changing action now records an `actor`
  (`oidc:alice@acme.example`, or `static-token`), so an audit can finally answer
  who revoked an agent. `required_claims` is mandatory and refused when empty:
  authenticating against the company IdP proves employment, not entitlement.
  See [docs/identity-providers.md](docs/identity-providers.md) for Okta, Entra,
  Google, Keycloak and Auth0.
- `docs/STATUS.md` — what is implemented, what is deliberately absent, and what
  has never been exercised by a real counterparty.
- `tools/aauthcheck` — a conformance client that enrols a real agent and signs
  real requests, including an interop step against `whoami.aauth.dev`.

### Fixed

- **`admin_oidc.issuer` accepts an issuer with a path.** It was validated as an
  AAuth server identifier, which requires a bare origin — so an Okta custom
  authorization server, an Entra tenant and a Keycloak realm were all refused at
  startup, leaving only issuer forms that cannot mint a usable token. Admin SSO
  could not have worked with Okta at all.
- **A multi-valued claim matches when any of its values does.** `{"groups":
  "admins"}` against an array-valued claim previously could never match: it
  failed closed, but silently, so the configuration looked correct and denied
  everyone.
- **An unreachable issuer is no longer reported as `unknown_key`.** A network or
  DNS failure fetching a JWKS was indistinguishable from a genuinely unknown
  key, which sends an operator hunting for a key problem that does not exist.
- **Claim-gate failures say which problem occurred** — a claim the identity
  provider never sent, or a value that is not permitted. The two have different
  fixes in different systems.
- Two bugs found by live cross-implementation testing against `psd`: egress
  admission now tries every admitted address (a dual-stack host whose first
  address refuses is no longer fatal), and revocation signs its body correctly.
- Docker builds key their cargo cache mounts per architecture instead of
  serializing on a shared lock, so multi-arch builds stay parallel.
- The release workflow is idempotent, and `:latest` moves only for a final
  release.

## [0.4.0] — 2026-08-14

- **AP→PS token revocation.** Revoking an agent notifies its Person Server about
  tokens already issued, discovered from the PS's metadata and signed with the
  `jwks_uri` scheme. Local revocation stays authoritative and happens first; the
  notification is best-effort and its outcome is reported and audited.

## [0.3.0] — 2026-08-14

- Track AAuth `-11`: the person token (`aa-person+jwt`), the
  `accept_signature_algs` common metadata field, and correct handling of the
  RFC 9421 signature `alg` parameter, which a verifier must ignore.

## [0.2.0] — 2026-08-13

- **AAuth `-10` and Signature-Key `-08` compliance.** Fully-specified `Ed25519`
  throughout, replacing polymorphic `EdDSA`; the `hwk` scheme now requires
  `alg`; new error responses and verification steps.

## [0.1.0] — 2026-08-12

- First release. Agent Provider with five enrollment methods (open, token,
  allowlist, federated, SPIFFE), agent and sub-agent token issuance, AAuth
  Events, assurance tiers, an admin API, and OpenTelemetry metrics and traces.
