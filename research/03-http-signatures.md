# HTTP Message Signatures & Signature-Key — Implementation Notes

> Sources: RFC 9421 (HTTP Message Signatures), RFC 8941 (Structured Fields),
> `draft-hardt-httpbis-signature-key-08`, and the AAuth protocol's
> "HTTP Message Signatures Profile" section. This is the wire-level layer every AAuth
> party implements; the AP verifies these signatures on all ceremony endpoints and on
> event deliveries.

## 1. The three (four) headers

```http
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:BASE64-SIGNATURE-BYTES:
Signature-Key: sig=jwt;jwt="eyJ..."
```

- `Signature-Input` (RFC 9421): SF Dictionary; member value = Inner List of covered
  component identifiers + parameters (`created`, optionally `expires`, …).
- `Signature` (RFC 9421): SF Dictionary; member value = Byte Sequence (the signature).
- `Signature-Key` (signature-key draft): SF Dictionary keyed by the same **label**;
  member value = a Token naming the *scheme*, with scheme-specific parameters.
- Labels correlate all three by name equality. If a verifier tries to verify label L via
  Signature-Key and the member is missing → fail.

## 2. Signature base (RFC 9421 §2.5) — the exact bytes signed

For each covered component, one line `<component-identifier>: <value>`; then the final
line `"@signature-params": <the inner list serialization with parameters>`. Lines joined
with `\n` (no trailing newline). Component identifiers are serialized as SF strings
(lowercase, quoted). Example base for the header above:

```
"@method": POST
"@authority": sandbox.agentprovider.dev
"@path": /agent-token
"signature-key": sig=jwt;jwt="eyJ..."
"@signature-params": ("@method" "@authority" "@path" "signature-key");created=1730217600
```

Details that bite:

- `@method` is uppercase as sent. `@authority` is the Host (lowercased, default port
  elided). `@path` is the *target path* without query (query is `@query`, not mandated
  by AAuth).
- Header field values are canonicalized: OWS trimmed, internal multiple values joined
  with `, `. For `signature-key` the value line is the header value *as received*
  (we re-serialize carefully — safest is to use the raw header bytes).
- `@signature-params` value is the serialized Inner List **exactly as it appeared in
  `Signature-Input`** (order and parameters preserved). Easiest correct approach: take
  the raw member text from the header rather than re-serializing.

## 3. AAuth profile (normative deltas)

- Covered components MUST include: `@method`, `@authority`, `@path`, `signature-key`.
  Each closes a substitution attack (method/host/path/key). Servers MAY require more
  (e.g. `content-digest`, advertised via resource metadata
  `additional_signature_components`); a missing required component → 401 +
  `Signature-Error: error=invalid_input; required_input=(...)`.
- `created` REQUIRED, Integer, must be within the server's validity window of now
  (default **60 seconds**, configurable/advertised as `signature_window`). Outside →
  `invalid_signature`. `expires` optional; if present and past → reject.
- When `AAuth-Mission` is sent, `aauth-mission` MUST be covered. When
  `Authorization: AAuth <opaque>` is sent, `authorization` MUST be covered.
- Algorithms: **Ed25519 MUST**; ECDSA P-256 SHOULD. Every JWK MUST carry a
  *fully-specified* `alg` — the JOSE identifier `Ed25519` (RFC 9864), **not** the
  polymorphic `EdDSA`, and never `none`/symmetric (sig-key §3.3, Algorithm
  Determination). A verifier MUST reject a JWK/token whose `alg` is absent or
  polymorphic, and MUST NOT infer the algorithm from other key parameters.
  Two distinct `alg` namespaces coexist: the **JOSE** `alg` (`Ed25519`, in JWK
  members, JWT headers, and the `hwk` scheme) and the **RFC 9421 HTTP Message
  Signature** `alg` (`ed25519`, lowercase, in `Signature-Input`) — if
  `Signature-Input` carries the latter it must be consistent with the key.
- Replay: `created` window is the primary defense; verifiers MAY keep a short-lived
  dedupe cache keyed by `(key-thumbprint, created, @method, @authority, @path)` for
  state-changing endpoints. No nonces in the profile.

## 4. Signature-Key schemes (which we accept where)

| scheme | key comes from | AP usage |
|---|---|---|
| `hwk` | inline JWK params (`kty`,`crv`,`x`) **plus a required `alg="Ed25519"`** (sig-key §3.3); no `kid` | enrollment; single-key refresh |
| `jkt-jwt` | naming JWT: header `jwk` = durable key, `iss = urn:jkt:sha-256:<thumb>`, `cnf.jwk` = ephemeral key; HTTP sig by ephemeral key | two-key refresh |
| `jwt` | JWT's `cnf.jwk`; JWT verified via `{iss}/.well-known/{dwk}` JWKS | subscribe/inbox/sub-agent endpoints (agent token); **AAuth mandates agents use only this scheme toward resources/PS/AS** |
| `jwt` (dwk-without-cnf extension, events draft) | JWT has `dwk` but no `cnf` → the JWT's own signing key (by header `kid` from issuer JWKS) also verifies the HTTP signature | event deliveries (`aa-event+jwt`) to our `event_endpoint` |
| `jwks_uri` | `id` + `dwk` + `kid` params → issuer JWKS | PS→AS calls (not the AP's problem) |
| `x509` | cert chain | not used by AAuth |

### jkt-jwt verification (the two-key refresh path), spec order:

1. Parse JWT unverified; check `typ` ∈ {`jkt-s256+jwt`} (SHA-512 optional).
2. Extract header `jwk`; compute RFC 7638 thumbprint with the typ's hash; build
   `urn:jkt:sha-256:<thumb>`; string-compare against `iss` — **never trust `iss` alone**.
3. Verify JWT signature with the header `jwk`.
4. Validate `exp`/`iat` (we also require `exp-iat ≤ 300s` and single-use `jti`).
5. Take ephemeral key from `cnf.jwk`; verify the HTTP message signature with it.

### jwt scheme verification, spec order (fail cheap first):

1. Well-formed JWT → else `invalid_jwt`.
2. `typ` expected per endpoint policy (`aa-agent+jwt` / `aa-event+jwt` / …).
3. `exp` valid → else `expired_jwt`.
4. Required claims present (`cnf.jwk` — or the dwk-no-cnf extension for event tokens).
5. Resolve issuer key: `{iss}/.well-known/{dwk}` → metadata (`issuer` must match!) →
   `jwks_uri` → JWKS → `kid`. (For tokens *we* issued — agent/subscribe tokens — shortcut
   to our own local keys; never make a network call to verify our own tokens.)
6. Verify JWT signature; then claims per policy; then HTTP signature with `cnf.jwk`.

## 5. Signature-Error response header (SF Dictionary)

`Signature-Error: error=<token>[, members…]` — authoritative machine-readable error;
body SHOULD be problem+json with `type: urn:ietf:params:sig-error:<code>`. Status: 400
generally, 401 for recoverable (`unsupported_algorithm`, `invalid_input`). AAuth says
signature verification failures on its endpoints are 401 + Signature-Error; we use 401.

| error | extra | when |
|---|---|---|
| `unsupported_algorithm` | `Accept-Signature-Alg: Ed25519` response header (SHOULD) | key/alg we don't do; absent, polymorphic (`EdDSA`), or unsupported `alg` |
| `unsupported_scheme` | — | a `Signature-Key` scheme this endpoint doesn't accept |
| `invalid_signature` | — | missing sig headers, bad crypto, `created` outside window |
| `invalid_input` | `required_input=(...)` SHOULD | covered components missing required ones |
| `invalid_request` | — | malformed non-signature aspects |
| `invalid_key` | — | unparseable/untrusted key material (incl. `hwk` missing `alg`) |
| `unknown_key` | — | `kid` not in issuer JWKS (after one refetch) |
| `issuer_missing` / `issuer_mismatch` | — | discovered JWKS lacks / disagrees with the token issuer |
| `cache_miss` | — | a required cached key was not found |
| `invalid_jwt` | — | malformed JWT / JWT signature failure |
| `expired_jwt` | — | JWT `exp` past |

The `unsupported_algorithm` response no longer uses a `supported_algorithms`
member inside `Signature-Error`; sig-key §5.4 now defines a dedicated
`Accept-Signature-Alg` response header (§4.2) naming the fully-specified JOSE
algorithms the server accepts (`apd` is Ed25519-only → `Accept-Signature-Alg:
Ed25519`).

`403` (policy denial after successful authn) MUST NOT carry Signature-Error,
Accept-Signature, or Accept-Signature-Alg.

## 6. Accept-Signature `sigkey` parameter (server → client challenge)

`Accept-Signature: sig=("@method" "@authority" "@path");sigkey=uri` — tells a client what
kind of Signature-Key to bring: `jkt` (pseudonymous: hwk/jkt-jwt), `uri`
(jwks_uri/jwt/x509-with-URI-SAN), `x509`. Coexists with `WWW-Authenticate`. Useful on
401/402/429. `apd` does **not** emit `Accept-Signature` today — agents already know
which scheme each ceremony endpoint expects (documented in `docs/api.md`), and a
signature failure is reported via the `Signature-Error` header. Emitting
`Accept-Signature` challenges is a possible future addition.

`apd` **does** emit the narrower `Accept-Signature-Alg` header (sig-key §4.2) on
`unsupported_algorithm` responses, advertising the fully-specified algorithms it
accepts (`Ed25519`).

## 7. RFC 8941 structured fields — the subset we need

Parse: Dictionary (member = key [ "=" item-or-inner-list ] *(";" param)), Inner List,
Item types: Token, String (quoted, backslash escapes), Integer, Byte Sequence
(`:base64:`), Boolean. Keys: `[a-z*][a-z0-9_.*-]*`. We implement a strict subset parser
(no Decimals/Dates needed) + serializers for what we emit (`Signature-Error`,
`Accept-Signature`, `AAuth-Requirement` if ever needed). Robustness rule from the drafts:
ignore unknown dictionary members and unknown parameters; reject on syntax errors.

## 8. JWK / thumbprint specifics

- Ed25519 JWK: `{"kty":"OKP","crv":"Ed25519","x":"<b64url(32 bytes)>"}`.
- RFC 7638 thumbprint: SHA-256 over the JSON object with **only required members**
  (`crv`,`kty`,`x` for OKP — lexicographic order, no whitespace), base64url unpadded.
  Exact serialization for OKP: `{"crv":"Ed25519","kty":"OKP","x":"..."}`.
- JWKS: `{"keys":[{...,"kid":"...","alg":"Ed25519","use":"sig"}]}` — the
  fully-specified `alg` is REQUIRED on every published key (sig-key §3.3).
- base64url everywhere: unpadded, `-_` alphabet. Reject padding/invalid chars strictly
  in tokens.

## 9. Egress admission (SSRF defense) — MUST before any metadata/JWKS fetch

- https only; no cross-host redirects (we follow none at all);
- response caps (we use 64 KiB) and timeouts (10 s);
- reject private/loopback/link-local/multicast IPs unless explicitly allowed by config
  (needed for local dev), pin the resolved address for the connection (rebinding);
- per-issuer fetch floor: never more than once per minute; cache ≤24h regardless of
  cache headers; on unknown `kid` or same-`kid` failure: one refresh then fail.
