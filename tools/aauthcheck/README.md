# aauthcheck

An AAuth conformance client. It enrols a throwaway agent at a live **Agent
Provider**, then exercises a target server exactly as a real agent would —
signed RFC 9421 requests, real tokens, no mocks.

Built on [`aauth-core`](../../crates/aauth-core), so it doubles as a worked
example of the crate used as a *client*.

## Use

```sh
# Agent Provider checks + third-party interop only
cargo run

# Also grade a Person Server under test
cargo run -- --target https://ps.example

# Point at a different Agent Provider
cargo run -- --ap https://ap.example --target https://ps.example
```

Exit status is non-zero if any check fails, so it works in CI.

## What it checks

**Agent Provider** (default `https://sandbox.agentprovider.dev`)

- enrolment succeeds and returns an agent identifier
- an agent token is issued
- the token header `alg` is the fully-specified `Ed25519`, not the polymorphic
  `EdDSA` — the `-10` change, and the most common interop failure
- `dwk` is `aauth-agent.json`

**Interop** — an independent resource (`whoami.aauth.dev`) accepts that agent
token and echoes the identity back. This is the check our own test suite can
never make: it proves a *third-party verifier* accepts what we issue.

**Person Server** (`--target`)

- metadata `issuer` equals the URL it was fetched from
- `person_token_endpoint` **and** `auth_token_endpoint` are present
  (the latter renamed from `token_endpoint` in `-11`)
- every JWKS key carries a fully-specified `alg`; none is `EdDSA`
- an unsigned request to the person-token endpoint is refused with `401`
- a **signed** request carrying a real agent token is accepted
- the issued person token: `typ` is `aa-person+jwt`, `alg` is `Ed25519`,
  `dwk` is `aauth-person.json`, `aud` echoes the requested resource, the
  required claims are present, `cnf.jwk` is present, and the lifetime is
  **≤ 1 hour**
- or, on a deferred `202`, that `AAuth-Requirement` is present

## Notes

- Every run enrols a **new** agent at the sandbox. The sandbox is ephemeral and
  wiped daily, so this leaves no lasting state.
- It is a client, not a server: it makes real outbound HTTPS requests and needs
  network access.
- Tracks `draft-hardt-oauth-aauth-protocol-11`.
