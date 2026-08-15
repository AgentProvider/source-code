# aauth-core

Protocol primitives for [AAuth](https://github.com/dickhardt/AAuth) —
`draft-hardt-oauth-aauth-protocol` and `draft-hardt-httpbis-signature-key`.

No I/O, no async runtime, no framework. You resolve keys; this crate does the
cryptography and the wire formats.

```toml
[dependencies]
aauth-core = "0.4"
```

---

## Is this "the official AAuth crate"?

**No — and it is worth being precise about that.**

- There is **no official or IETF-blessed** AAuth crate. AAuth is a set of
  Internet-Drafts, not a released standard, and the drafts bless no
  implementation.
- This crate is the protocol layer extracted from
  [`apd`](https://agentprovider.dev), a self-hostable Agent Provider. It is
  MIT/Apache-2.0 and deliberately **role-agnostic**: nothing in it assumes you
  are an Agent Provider.
- It is offered as a **shared foundation**, not claimed as a standard. Use it,
  fork it, or ignore it.

**Why a shared crate is worth having.** These primitives are subtle and easy to
get subtly wrong: the RFC 9421 signature base is whitespace- and
ordering-sensitive; RFC 7638 thumbprints must serialise exactly; `Signature-Key`
schemes each have their own verification order. Every AAuth party needs the same
code, and a bug in it is a security bug for all of them.

There is already evidence of the cost of not sharing: when AAuth `-10` replaced
the polymorphic `EdDSA` identifier with the fully-specified `Ed25519`, every
implementation that had rolled its own JOSE layer had to find and fix it
independently. A shared crate makes that one release.

**What depending on it means.** See [Versioning](#versioning-and-draft-tracking)
— the drafts still change, and this crate follows them.

---

## What is in it

| Module | Covers |
|---|---|
| `b64` | Unpadded base64url, strict |
| `jwk` | Ed25519 JWKs, JWKS documents, RFC 7638 thumbprints |
| `jwt` | Compact JWS sign and verify — `Ed25519` only, `none` rejected |
| `ident` | Agent identifiers (`aauth:local@domain`) and server identifiers |
| `sfv` | RFC 8941 Structured Fields, the subset AAuth uses |
| `sig` | RFC 9421 signature base, request signing, verification, error codes |
| `sigkey` | `Signature-Key` schemes: `hwk`, `jwt`, `jkt-jwt`, `jwks_uri` |
| `tokens` | Claim types and validation: agent, subscribe, event tokens; `typ` constants for person, resource, and auth tokens |

## Who it is for

Every AAuth role needs most of this:

| You are building | You need |
|---|---|
| **An agent** | `jwk`, `sig::sign_request`, `sigkey::serialize_*` |
| **A resource / gateway** | `sig::parse_request_signature` + `verify_parsed`, `tokens::validate_agent_token` |
| **An Agent Provider** | all of the above, plus `jwt::sign` to mint tokens |
| **A Person Server** | the same verification path, plus `jwt::sign` for person and auth tokens |

---

## Signing a request (agent side)

```rust
use aauth_core::{jwk, sig, sigkey, now_unix};

let key = jwk::generate_signing_key();
let public = jwk::Jwk::from_verifying_key(&key.verifying_key());

// Which Signature-Key scheme you use depends on the ceremony:
//   hwk       — an inline public key (enrollment, single-key refresh)
//   jwt       — present an agent token (calling a resource)
//   jkt-jwt   — a naming JWT delegating to an ephemeral key (two-key refresh)
//   jwks_uri  — sign as a server, discovered via your own metadata
let scheme = sigkey::serialize_hwk(&public);

let no_headers = |_: &str| None;
let signed = sig::sign_request(
    "POST", "ap.example", "/enroll", "",
    &[],            // extra covered components
    &no_headers,    // header lookup, for those components
    &scheme,
    &key,
    now_unix(),
)?;

// signed.signature_input / signed.signature / signed.signature_key
// go on the request as the three headers of the same name.
# Ok::<(), aauth_core::sig::SigError>(())
```

Note `Jwk::from_verifying_key` stamps `alg: "Ed25519"` for you. Since `-10` a JWK
without a fully-specified `alg` is rejected by conforming verifiers, and the
polymorphic `EdDSA` is forbidden.

## Verifying a request (server side)

Two steps, because key resolution is yours: the scheme may require fetching a
JWKS, and only you know your egress policy.

```rust
use aauth_core::sig::{self, RequestParts, VerifyPolicy};
use aauth_core::sigkey::SigKeyScheme;

let parts = RequestParts {
    method: "POST", authority: "ps.example", path: "/person", query: "",
    header: &|name| lookup_header(name),      // your header accessor
};
let policy = VerifyPolicy {
    now: aauth_core::now_unix(),
    window_secs: 60,
    extra_required: vec!["content-digest".into(), "content-type".into()],
};

let parsed = sig::parse_request_signature(&parts, &policy)?;  // structure, window, components

let key = match &parsed.scheme {
    SigKeyScheme::Hwk(jwk) => jwk.clone(),                 // inline key
    SigKeyScheme::Jwt(token) => resolve_cnf_jwk(token)?,   // you fetch the issuer JWKS
    other => return Err(unsupported(other)),
};

sig::verify_parsed(&parsed, &key)?;                        // the cryptography
```

`parse_request_signature` enforces the AAuth profile: `@method`, `@authority`,
`@path`, and `signature-key` must be covered, and `created` must be inside your
window. Errors carry a `SigErrorCode` that maps directly to the `Signature-Error`
response header.

## Minting and validating tokens

```rust
use aauth_core::{jwt, tokens};

let payload = serde_json::json!({
    "iss": "https://ps.example",
    "dwk": "aauth-person.json",
    "aud": "https://resource.example",
    "sub": directed_sub,
    "cnf": { "jwk": agent_public_key.public_only() },
    "jti": aauth_core::rand_token(128),
    "iat": now, "exp": now + 3600,
});
let token = jwt::sign(tokens::TYP_PERSON, Some("ps-key-1"), None, &payload, &signing_key);

// Verifying an agent token you were handed:
let claims = tokens::verify_agent_token_with_key(&agent_token, &issuer_jwk, now, false)?;
```

`typ` constants are provided for every AAuth token type — `TYP_AGENT`,
`TYP_PERSON`, `TYP_RESOURCE`, `TYP_AUTH`, `TYP_SUBSCRIBE`, `TYP_EVENT` — so a
verifier can recognise a type it does not itself issue.

---

## What this crate deliberately does not do

- **No network I/O.** It will not fetch a JWKS for you. Discovery is where SSRF
  lives, and your egress policy is a deployment decision. Resolve keys and hand
  them in.
- **No async runtime**, no HTTP client, no server.
- **No storage.** Replay guards, `jti` records, and retention are yours.
- **Ed25519 only for AAuth-native signing.** Multi-algorithm verification of
  third-party IdP assertions (RS256, ES256…) lives in the consumer — `apd` keeps
  it in its own `enrollment::anyjwk`.

## Versioning and draft tracking

**Read this before depending on it.**

AAuth is an evolving Internet-Draft. This crate tracks specific revisions, and
those revisions make breaking wire changes. Recent example: `-10` replaced
`EdDSA` with `Ed25519` in every JOSE `alg`, which is a breaking change on the
wire, not merely in the API.

Policy:

- The crate version tracks the `apd` release that carries it.
- A wire-format change from a new draft is a **minor** bump before 1.0, and the
  changelog names the draft revision.
- **Pin a version.** `aauth-core = "0.4"` is right; a floating dependency will
  eventually change what your service accepts on the wire.
- The tracked revisions are listed in every `apd` release and printed at its
  startup.

Current: `draft-hardt-oauth-aauth-protocol-11`,
`draft-hardt-httpbis-signature-key-08`.

## Known users

- [`apd`](https://agentprovider.dev) — Agent Provider
- `psd` — Person Server (planned; see the implementation RFC)

## License

MIT OR Apache-2.0.
