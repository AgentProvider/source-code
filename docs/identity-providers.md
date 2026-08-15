# Identity providers for the admin API

apd's admin API accepts a token from your identity provider, so administering a
provider uses the accounts and groups you already run. See
[configuration.md](configuration.md#admin-api-authentication) for the field
reference; this page is about making a specific IdP work.

apd speaks plain OIDC — there is no per-provider code path. Everything below is
about how each provider is configured and which of its defaults will surprise
you.

---

## Okta

```json
"admin_oidc": {
  "issuer": "https://acme.okta.com/oauth2/default",
  "audience": "api://apd-admin",
  "required_claims": { "groups": "apd-admins" },
  "principal_claim": "email"
}
```

### Use a custom authorization server, not the org one

Okta has two kinds of authorization server, and the difference decides whether
this works at all.

| | Issuer | Access-token `aud` |
|---|---|---|
| **Org** | `https://acme.okta.com` | the org URL — Okta's guidance is not to validate these in your own API |
| **Custom** | `https://acme.okta.com/oauth2/<id>` | whatever you set, e.g. `api://apd-admin` |

apd requires an audience — without one, a token Okta minted for your wiki would
administer your agent provider — so you need a **custom** authorization server.
Every developer org has one called `default` at
`https://acme.okta.com/oauth2/default`.

Custom authorization servers come with API Access Management. If your Okta tier
does not include it, see [no custom authorization server](#no-custom-authorization-server)
below.

### Add the groups claim — it is not there by default

**This is the failure to expect.** Okta does not put `groups` in a token unless
you configure a claim for it, so a perfectly correct `required_claims` denies
everyone.

In the Okta admin console: **Security → API → Authorization Servers →** your
server **→ Claims → Add Claim**.

| Field | Value |
|---|---|
| Name | `groups` |
| Include in token type | Access Token |
| Value type | Groups |
| Filter | `Matches regex` `.*`, or `Starts with` `apd-` to send only what matters |

Prefer a narrow filter. It keeps the token small and means the token does not
carry your whole directory structure to every service that sees it.

apd tells you which of the two problems you have:

```
admin token has no 'groups' claim; the identity provider is not sending it
admin token claim 'groups' does not have a permitted value
```

The first is this section. The second means the claim arrived and the operator
is genuinely not in the group.

### `principal_claim` — otherwise your audit log is unreadable

Okta's `sub` is an opaque ID (`00u1a2b3c4d5e6f7g8h9`). Left at the default, every
audit entry names people in a way nobody can read:

```json
{"event":"agent_revoked","actor":"oidc:00u1a2b3c4d5e6f7g8h9"}
```

Set `principal_claim: "email"`. Note that `email` reaches an *access* token only
through a claim mapping — add it the same way as `groups` (value `user.email`,
value type Expression). If the claim is missing apd falls back to `sub`, so this
fails readably rather than fatally.

### Do not gate on `Everyone`

Every Okta user is in the built-in `Everyone` group. `{"groups": "Everyone"}`
passes apd's "the gate must not be empty" check while authorizing your entire
directory. apd cannot detect this — the group is a normal group with a normal
name — so it is on you. Gate on a group that exists for this purpose.

### Custom domains change `iss`

If your org uses a custom domain, tokens are issued by `https://login.acme.com/...`,
not `https://acme.okta.com/...`, and apd compares `iss` exactly:

```
admin token was not issued by the trusted IdP
```

That message means an untrusted issuer, and reads like an attack when it is
really a copy-paste. Use whichever hostname your users actually authenticate
against.

### DPoP

If you enable DPoP, Okta issues sender-constrained access tokens carrying `cnf`.
apd refuses them:

```
this token is sender-constrained (cnf); apd validates bearer tokens only
```

This is deliberate. Accepting one as a plain bearer would silently undo the
proof-of-possession property you turned DPoP on to get. Use a non-DPoP client
for admin access.

### No custom authorization server

On Okta tiers without API Access Management there is no way to get an access
token with your own audience. Use an **ID token** instead — it is a normal OIDC
token and apd validates it identically. Set `audience` to your **client ID**:

```json
"admin_oidc": {
  "issuer": "https://acme.okta.com",
  "audience": "0oa9z8y7x6w5v4u3t2s1",
  "required_claims": { "groups": "apd-admins" },
  "principal_claim": "email"
}
```

Add the groups claim under **Applications →** your app **→ Sign On → OpenID
Connect ID Token → Groups claim filter** rather than on an authorization server.

An ID token is meant for the client rather than for an API, so this is the weaker
arrangement — it is a fallback, not the recommendation. It is sound when the
operator running the CLI *is* the client the token was issued to.

---

## Other providers

apd is not Okta-specific. The same three questions decide any provider: what is
the issuer, what goes in `audience`, and how do you get a group claim.

**Microsoft Entra ID.** Issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`
(the v2.0 suffix matters; v1.0 tokens have a different `iss`). Group claims need
an app-manifest change. One trap worth knowing before you rely on group gating:
**Entra omits `groups` entirely once a user is in roughly 150 groups**, replacing
it with `_claim_names`/`_claim_sources` pointing at Microsoft Graph. A group gate
therefore fails for exactly the most heavily-permissioned accounts, and apd will
correctly report the claim as absent. Use app roles instead, which do not overflow.

**Google Workspace.** Issuer `https://accounts.google.com`. There is no group
claim; gate on the hosted domain, `{"hd": "acme.com"}`, and be aware that this
authorizes everyone in the domain.

**Keycloak.** Issuer `https://kc.acme.example/realms/<realm>`. Add a group or
realm-role mapper to the client scope. `realm_access.roles` is reachable with a
dotted path.

**Auth0.** Issuer `https://acme.auth0.com/`, minus the trailing slash, which apd
refuses because discovery is appended to the issuer and `iss` is compared
exactly. Custom claims are namespaced, so the path is the whole URI:
`{"https://acme.com/groups": "apd-admins"}` — apd matches the full key before
splitting on dots, so this resolves.

---

## Checking a new tenant

apd's test suite pins the document shapes but cannot prove your tenant is
configured correctly. Once, against a real tenant:

1. **Get a token** the way an operator will, and decode it at `jwt.io` or with
   `jq -R 'split(".")[1] | @base64d | fromjson'`.
2. **Check four claims by eye**: `iss` matches `admin_oidc.issuer` exactly;
   `aud` contains your `audience`; the gate claim is present with the value you
   expect; your `principal_claim` is present and readable.
3. **Call a read-only endpoint** — `GET /admin/agents`. A 401 is authentication
   (issuer, audience, expiry, signature); a 403 is the claim gate, and the
   message says which of the two group problems you have.
4. **Confirm the audit log names you**, not an opaque ID:
   ```sh
   curl -sH "Authorization: Bearer $TOKEN" https://ap.example.com/admin/agents >/dev/null
   tail -1 /var/log/apd/audit.log   # actor should read oidc:you@acme.com
   ```
5. **Try a colleague who should not have access** and confirm they get a 403.
   A gate nobody has tested from the outside is not known to be a gate.

## Keeping the shared token during a migration

Configure `admin_token` and `admin_oidc` together and both work; the credential's
shape selects the path. Remove `admin_token` once everyone has moved. Until you
do, actions taken with it appear as `actor: "static-token"`, which is how you can
tell whether anyone is still using it:

```sh
grep -c '"actor":"static-token"' /var/log/apd/audit.log
```

Zero for a week is your signal that removing it is safe.
