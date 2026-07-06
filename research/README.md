# Research notes — AAuth spec family

Engineering notes distilled from the [AAuth](https://github.com/dickhardt/AAuth)
Internet-Drafts and the companion HTTP Signature Keys draft, written while
building this Agent Provider. They are the "why" behind the code and a
sufficient reading of the spec to connect **agents** and **resources/MCP** to an
AP without re-reading every draft. Normative statements carry the spec's
MUST/SHOULD meaning; design decisions specific to this implementation are called
out as such.

| Note | Covers | Read it if you're… |
|---|---|---|
| [01 — Protocol overview](01-aauth-protocol-overview.md) | Parties, tokens, the four access modes, every shared primitive (requirements, deferred responses, interaction codes, identifiers, JWKS discovery, revocation), missions & delegation at a glance | …new to AAuth, or want one document that maps the whole protocol |
| [02 — The Agent Provider role](02-agent-provider.md) | The AP's normative obligations, the two-key/single-key key model, identifier strategy, the endpoints this AP defines, multi-instance & security requirements | …working on `apd` itself, or writing another AP |
| [03 — HTTP signatures](03-http-signatures.md) | RFC 9421 signature base, the AAuth profile, every `Signature-Key` scheme (`hwk`/`jwt`/`jkt-jwt`/`jwks_uri`), `Signature-Error`, structured fields, JWK/thumbprint, egress admission | …implementing signing or verification |
| [04 — Connecting agents](04-connecting-agents.md) | End-to-end agent lifecycle: enroll → refresh → sign → talk to resources → PS flow → sub-agents → events, plus a failure-handling cheat sheet | …building an agent that uses this AP |
| [05 — Connecting resources & MCP](05-connecting-resources-mcp.md) | The resource adoption ladder, verifying agent identity, resource metadata, `AAuth-Access`, resource/auth tokens, and the MCP integration points | …putting AAuth in front of an API or MCP server |
| [06 — AAuth Events](06-events.md) | The AP-as-inbox model, subscribe/event tokens, the normative `/events` validation order, and AP→agent delivery patterns | …implementing async event delivery |

## Source drafts (as read, 2026-06)

- `draft-hardt-oauth-aauth-protocol-09` — the core protocol
- `draft-hardt-aauth-bootstrap-01` — informational AP enrollment/refresh patterns
- `draft-hardt-aauth-events-00` — event subscription & delivery
- `draft-hardt-httpbis-signature-key-05` — `Signature-Key`/`Signature-Error`/`Accept-Signature`
- `draft-hardt-aauth-r3-*` — Rich Resource Requests / vocabularies (directional; MCP mapping)
- `interop-demo-profile.md` — the five interop surfaces

AAuth is an evolving set of Internet-Drafts; check the upstream repo for newer
revisions before treating any detail here as final.
