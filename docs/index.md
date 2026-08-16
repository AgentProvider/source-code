# Documentation

**apd** is a self-hostable [AAuth](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
Agent Provider. It issues short-lived, signed, key-bound identities to AI agents —
no API keys and no shared secrets.

## Try it without installing anything

A public **[hosted sandbox](sandbox.md)** runs at
`https://sandbox.agentprovider.dev`. Enrollment is open, so there is no sign-up
and no credential. Point an agent at it and enroll in one signed request.

```sh
curl -s https://sandbox.agentprovider.dev/.well-known/aauth-agent.json
```

The sandbox is for development only. Its data is ephemeral and is wiped daily.
Read the [sandbox guide](sandbox.md) before you rely on it.

## Get started

| Guide | For |
|---|---|
| [Hosted sandbox](sandbox.md) | Building against a live provider, with no local setup |
| [Install & deploy](deployment.md) | Running your own provider |
| [Build an agent](guide-ai-agent-auth.md) | Agent developers |
| [Protect an MCP server](guide-mcp-server-auth.md) | Resource and MCP server developers |

## Enrollment

How an agent proves it may have an identity.

- [Overview & patterns](enrollment.md) — the four methods, and when to use each
- [Federated & workload identity](federated-enrollment.md) — Kubernetes, CI OIDC, SPIFFE, corporate PKI
- [Federated: design notes](federated-enrollment-design.md) — verification order and policy model

## Operate

- [Changelog](../CHANGELOG.md) — what changed in each release, security fixes called out
- [Implementation status](STATUS.md) — what is done, what is deliberately absent, and what has never met a real counterparty
- [Configuration](configuration.md) — every field, environment overrides, storage backends
- [Identity providers](identity-providers.md) — enterprise SSO for the admin API: Okta, Entra, Google, Keycloak, Auth0
- [HTTP API](api.md) — endpoints, request and response shapes, audit events
- [Deploy](deployment.md) — TLS, scaling, key rotation, the image and Helm chart

## The protocol

Notes behind the implementation.

1. [Protocol overview](../research/01-aauth-protocol-overview.md)
2. [The Agent Provider role](../research/02-agent-provider.md)
3. [HTTP signatures](../research/03-http-signatures.md)
4. [Connecting agents](../research/04-connecting-agents.md)
5. [Resources & MCP](../research/05-connecting-resources-mcp.md)
6. [AAuth Events](../research/06-events.md)

## Status

apd tracks IETF Internet-Drafts, and AAuth is not a released standard. The
provider announces **demo mode** at runtime. Pin a version, and expect wire
changes as the drafts mature.

Current release: **0.4.0** — tracking `draft-hardt-oauth-aauth-protocol-11` and
`draft-hardt-httpbis-signature-key-08`.
