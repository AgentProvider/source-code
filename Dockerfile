# syntax=docker/dockerfile:1
# Multi-arch (linux/amd64, linux/arm64) build of the apd AAuth Agent Provider.
#
# Build with buildx (each target platform builds natively under emulation):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/agentprovider/apd:dev .
#
# The runtime image is distroless/cc (glibc, no shell, non-root) — apd needs
# no OpenSSL (TLS is rustls+ring) and no other system libraries.

FROM rust:1-bookworm AS builder
ARG TARGETARCH
WORKDIR /src

# BuildKit caches the cargo registry and a per-arch target dir across builds.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Every cache mount is keyed per architecture. The amd64 and arm64 stages
# build concurrently, and a shared registry mount lets two cargo processes
# unpack the same crate into the same directory — the loser dies with
# "failed to open .../.cargo-ok: File exists (os error 17)".
#
# `sharing=locked` also fixes the race but is the wrong trade here: it holds
# the lock for the whole RUN, so arm64 cannot start compiling until amd64 has
# finished, turning max(amd64, arm64) into their sum. arm64 under QEMU is
# already the long pole. Per-arch mounts cost one duplicated registry
# download, which BuildKit keeps warm across runs, and keep the two stages
# genuinely parallel.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=apd-cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/usr/local/cargo/git,id=apd-cargo-git-${TARGETARCH} \
    --mount=type=cache,target=/src/target,id=apd-target-${TARGETARCH} \
    cargo build --release --locked --bin apd \
    && strip target/release/apd \
    && cp target/release/apd /usr/local/bin/apd

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=builder /usr/local/bin/apd /usr/local/bin/apd

# apd reads its config (and, in prod, points keys_file/audit_log_file) under
# /etc/apd; the Helm chart mounts a ConfigMap + Secret there.
EXPOSE 8420
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/apd"]
CMD ["serve", "--config", "/etc/apd/apd.json"]

# OCI labels (repo/version/revision are also injected in CI via annotations).
LABEL org.opencontainers.image.title="apd" \
      org.opencontainers.image.description="Self-hostable AAuth Agent Provider" \
      org.opencontainers.image.source="https://github.com/agentprovider/source-code" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
