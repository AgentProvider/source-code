# Commercial support

`apd` is free and open source, under the MIT and Apache-2.0 licences. It stays
that way. Nothing here is paywalled.

Commercial support exists for teams who run `apd` in production and want a
direct line to the people who wrote it.

## What it covers

- **Deployment and architecture review.** Your topology, storage backend, key
  handling, ingress, and scaling plan, reviewed before you go live.
- **Enrollment design.** Choosing and configuring the right method for your fleet
  — Kubernetes and CI OIDC, SPIFFE, corporate PKI, or operator-minted assertions.
- **Priority bug triage.** Your reports go to the front of the queue, with a
  named contact.
- **Draft-tracking upgrades.** AAuth is an evolving IETF Internet-Draft. When a
  revision lands, you get advance notice of breaking changes and a migration
  plan.
- **Integration help.** Both sides of the exchange: agents that enroll and sign,
  and resources or MCP servers that verify.

The draft-tracking item is the one that usually matters most. Version 0.2.0
changed the JOSE algorithm identifier from `EdDSA` to `Ed25519`, which broke
every client that had not been updated. That kind of change arrives with the
drafts, and it will happen again.

## What it does not cover

We would rather be clear now than disappoint you later.

- **No uptime guarantee for the hosted sandbox.** The [sandbox](sandbox.md) is a
  free development service. It is ephemeral, it has no SLA, and paid support does
  not change that. Run your own instance for anything that matters.
- **No promise that AAuth will become a standard.** It is a draft. Wire formats
  may change. We track the drafts closely, but we do not control them.
- **Not a managed service.** You run `apd`. We help you run it well.

## Get in touch

Write to **[operator@agentprovider.dev](mailto:operator@agentprovider.dev?subject=apd%20commercial%20support)**.

Scope and pricing depend on what you need, so tell us:

1. What you are building, and roughly how many agents.
2. Where `apd` runs, or will run — Kubernetes, virtual machines, or elsewhere.
3. Which enrollment method you expect to use.
4. Your timeline.

## Free help

Most questions do not need a contract. Start here:

- [Documentation](index.md) — guides, configuration, and the HTTP API
- [Hosted sandbox](sandbox.md) — build and test with no local setup
- [GitHub issues](https://github.com/AgentProvider/source-code/issues) — bugs and
  feature requests

Bug reports are welcome from everyone, whether or not you pay for anything.
