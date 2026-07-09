# apd Helm chart

Deploy the [apd AAuth Agent Provider](https://github.com/agentprovider/source-code)
on Kubernetes. Published as an **OCI chart** alongside the container image.

> Demo mode: AAuth is an IETF Internet-Draft, not a released standard. apd
> announces demo mode at runtime; pin a chart/image version.

## Install (OCI)

```sh
# 1. Create the AP signing keys (shared by all replicas) once:
apd keygen --keys apd-keys.json          # or: docker run --rm -v "$PWD:/d" ghcr.io/agentprovider/apd keygen --keys /d/apd-keys.json
kubectl create namespace apd
kubectl -n apd create secret generic apd-keys --from-file=apd-keys.json

# 2. Install the chart from GHCR:
helm install apd oci://ghcr.io/agentprovider/charts/apd \
  --namespace apd \
  --set issuer=https://ap.example.com \
  --set keys.existingSecret=apd-keys \
  --set ingress.enabled=true --set ingress.host=ap.example.com
```

Pin a version with `--version <x.y.z>`. List versions:
`helm show chart oci://ghcr.io/agentprovider/charts/apd --version <x.y.z>`.

## Signing keys (important)

apd signs every token with an Ed25519 key; **all replicas must share the same
keys**, and the keys must **persist across upgrades**. The chart never
auto-generates them (that would rotate identities on reinstall). Provide them:

- **Recommended:** create a Secret from `apd keygen` output and set
  `keys.existingSecret`.
- **Dev/quick-start:** paste the file contents into `keys.keysJson` and the
  chart creates the Secret.

Rotate with `apd keygen --keys apd-keys.json --rotate`, update the Secret, and
roll the Deployment; old public keys stay published until old tokens expire.

## TLS / issuer

`issuer` MUST be the exact HTTPS origin that serves
`/.well-known/aauth-agent.json` — i.e. what your Ingress/LB exposes. Enable the
built-in `ingress` (TLS terminates there) or front the Service with your own LB.
The signature covers `@authority` and `@path`, so the proxy must preserve Host
and path.

## Scaling

- Single replica: `storage.backend: memory` (or `file` with a PVC) is fine.
- **More than one replica** (or `autoscaling.enabled`) **requires**
  `storage.backend: redis` (bring your own Redis ≥ 6.2 via `storage.redis.addr`)
  **and** a shared `keys.existingSecret`. The chart fails the render otherwise.
  Verification is stateless — relying parties cache your JWKS — so you scale by
  adding replicas behind the Service.

## Federated / enterprise enrollment

Trusted issuers and other advanced config go under `extraConfig` (deep-merged
into `apd.json`):

```yaml
config:
  enrollment:
    methods: ["token", "federated"]
extraConfig:
  enrollment:
    trusted_issuers:
      - name: eks
        type: oidc
        issuer: https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLE
        required_claims: { sub: "system:serviceaccount:agents:*" }
        embed_claims: { kubernetes.io.namespace: k8s_namespace }
```

See [`docs/federated-enrollment.md`](https://agentprovider.dev/docs/federated-enrollment.html).

## Key values

| Key | Default | Notes |
|---|---|---|
| `replicaCount` | `1` | >1 needs redis + shared keys |
| `image.repository` / `image.tag` | `ghcr.io/agentprovider/apd` / chart appVersion | |
| `issuer` | `https://ap.example.com` | your real HTTPS origin |
| `keys.existingSecret` / `keys.keysJson` | — | signing keys (one is required) |
| `storage.backend` | `memory` | `memory` \| `file` \| `redis` |
| `storage.redis.addr` | — | external Redis for multi-instance |
| `config.enrollment.methods` | `["token"]` | `token`/`federated`/`allowlist`/`open` |
| `extraConfig` | `{}` | deep-merged into apd.json (trusted_issuers, metadata, …) |
| `admin.enabled` / `admin.value` | `false` / — | enables `/admin`; injected as `APD_ADMIN_TOKEN` |
| `staticEnrollToken.value` | — | dev static enrollment token (`APD_STATIC_ENROLL_TOKEN`) |
| `ingress.enabled` / `ingress.host` | `false` / — | TLS ingress serving the issuer origin |
| `autoscaling.enabled` | `false` | HPA (needs redis) |
| `resources` | 50m/64Mi → 1/256Mi | apd is light |

The pod runs as non-root (uid 65532) with a read-only root filesystem and all
capabilities dropped, matching the distroless image.

Full config reference: [`docs/configuration.md`](https://agentprovider.dev/docs/configuration.html).
