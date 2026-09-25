# syntax=docker/dockerfile:1
# ============================================================================
# Craton HSM — Multi-stage Production Dockerfile
#
# Builds the gRPC daemon (craton-hsm-daemon) and admin CLI (craton-hsm-admin)
# into a minimal distroless container. The PKCS#11 shared library
# (libcraton_hsm.so) is also included for in-container use.
#
# Build (the build context MUST be the repository root, where .dockerignore
# lives):
#   docker build -t craton-hsm:0.3.0 -f deploy/Dockerfile .
# Run (mount your own config and TLS material):
#   docker run -p 5696:5696 \
#     -v ./craton_hsm.toml:/etc/craton-hsm/craton_hsm.toml:ro \
#     -v ./tls:/etc/craton-hsm-tls:ro -v ./client-ca:/etc/craton-hsm-client-ca:ro \
#     craton-hsm:0.3.0
# ============================================================================

# ── Stage 1: Build ──────────────────────────────────────────────────────────
# Rust >= 1.89 is required by the locked dependency graph (e.g. redb 3.1).
# Base images are pinned by digest (multi-arch index) to prevent tag mutation.
# To update: crane digest rust:<tag>   /   crane digest gcr.io/distroless/cc-debian12:nonroot
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS builder

# protoc (required by tonic-prost-build) from the official release, verified
# against SHA-256 digests pinned here (not fetched from the same origin).
ARG PROTOC_VERSION=21.12
ARG PROTOC_SHA256_X86_64=3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8
ARG PROTOC_SHA256_AARCH_64=2dd17f75d66a682640b136e31848da9fb2eefe68d55303baf8b32617374f6711
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) PARCH=x86_64;  PSUM="${PROTOC_SHA256_X86_64}" ;; \
      arm64) PARCH=aarch_64; PSUM="${PROTOC_SHA256_AARCH_64}" ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/protoc.zip \
      "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${PARCH}.zip"; \
    echo "${PSUM}  /tmp/protoc.zip" | sha256sum -c -; \
    unzip -q -o /tmp/protoc.zip -d /usr/local bin/protoc 'include/*'; \
    rm -f /tmp/protoc.zip; \
    protoc --version

# grpc_health_probe for the Docker HEALTHCHECK, pinned by SHA-256.
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.28
ARG GRPC_HEALTH_PROBE_SHA256_AMD64=4b818d540683b1b97256c84714a51a095e54f19792b3d7f02ac78814be645a96
ARG GRPC_HEALTH_PROBE_SHA256_ARM64=1b1c1d02f68c439585901ac54bf79688350c35d1e5168a93b1a811e30b1f5124
RUN set -eu; \
    ARCH="$(dpkg --print-architecture)"; \
    case "${ARCH}" in \
      amd64) HSUM="${GRPC_HEALTH_PROBE_SHA256_AMD64}" ;; \
      arm64) HSUM="${GRPC_HEALTH_PROBE_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/grpc_health_probe \
      "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${ARCH}"; \
    echo "${HSUM}  /usr/local/bin/grpc_health_probe" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/grpc_health_probe

WORKDIR /build

# Copy only what the build needs — never the whole context. In particular
# rust-toolchain.toml is NOT copied, so the pinned toolchain of this image is
# used instead of downloading "stable".
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
COPY benches/ benches/
COPY craton-hsm-daemon/ craton-hsm-daemon/
COPY tools/ tools/

# Fetch first (hard failure on any integrity problem), then build. BuildKit
# cache mounts keep the registry and target directory between builds without
# a stub-based priming step that could hide failures.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fetch --locked

# Build, then require the known-answer self-tests to pass on the build platform.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    set -eu; \
    cargo build --release --locked -p craton-hsm -p craton-hsm-daemon -p craton-hsm-admin; \
    cargo test --release --locked -p craton-hsm --lib -- crypto::self_test; \
    mkdir -p /out/bin /out/lib /out/data; \
    cp target/release/craton-hsm-daemon target/release/craton-hsm-admin /out/bin/; \
    cp target/release/libcraton_hsm.so /out/lib/

# ── Stage 2: Runtime ────────────────────────────────────────────────────────
# Distroless: no shell, no package manager. The "cc" variant includes libgcc.
# ":nonroot" runs as UID/GID 65532.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

ARG IMAGE_VERSION=0.3.0
LABEL org.opencontainers.image.title="Craton HSM daemon" \
      org.opencontainers.image.description="PKCS#11 v2.40 software HSM — gRPC daemon" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.vendor="Craton Software Company" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/craton-co/craton-hsm-core"

# (A3-12) Licence and attribution notices ship with the binaries.
COPY --chmod=0444 LICENSE NOTICE /usr/share/doc/craton-hsm/

COPY --from=builder /out/bin/craton-hsm-daemon /usr/local/bin/
COPY --from=builder /out/bin/craton-hsm-admin  /usr/local/bin/
COPY --from=builder /out/lib/libcraton_hsm.so  /usr/local/lib/
COPY --from=builder /usr/local/bin/grpc_health_probe /usr/local/bin/

# Example configuration (TLS + mTLS required; mount certificates or your own
# config). World-readable, not writable.
COPY --chmod=0444 craton-hsm-daemon/craton_hsm.example.toml /etc/craton-hsm/craton_hsm.toml

# Working directory for relative storage/audit paths; mount a volume here.
COPY --from=builder --chown=65532:65532 /out/data /data
WORKDIR /data
VOLUME ["/data"]

EXPOSE 5696

# The example config serves grpc.health.v1 in plaintext on 127.0.0.1:5697
# (health_bind); the TLS port itself requires a client certificate.
HEALTHCHECK --interval=20s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/grpc_health_probe", "-addr=127.0.0.1:5697"]

# Non-root (distroless nonroot = 65532). The daemon handles SIGTERM itself
# (graceful drain + audit flush), so no init process is required.
USER 65532:65532
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/craton-hsm-daemon"]
CMD ["/etc/craton-hsm/craton_hsm.toml"]
