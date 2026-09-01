# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.98.0
ARG BUILD_REVISION=unknown

FROM rust:${RUST_VERSION}-bookworm AS builder

ARG BUILD_REVISION

WORKDIR /workspace

ENV SILICON_IAM_GIT_COMMIT=${BUILD_REVISION}

COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY migrations ./migrations
COPY src ./src
# The documentation surface embeds these at compile time via include_str!, so
# the build fails loudly if either is missing rather than shipping an image
# whose docs have drifted from its binary.
COPY openapi.yaml ./openapi.yaml
COPY docs ./docs

RUN --mount=type=cache,id=silicon-iam-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=silicon-iam-target,target=/workspace/target,sharing=locked \
    cargo build --locked --release --bins \
    && install -D -m 0755 target/release/iam-api /opt/silicon-iam/iam-api \
    && install -D -m 0755 target/release/iam-worker /opt/silicon-iam/iam-worker \
    && install -D -m 0755 target/release/iam-migrate /opt/silicon-iam/iam-migrate \
    && install -D -m 0755 target/release/iam-bootstrap-admin /opt/silicon-iam/iam-bootstrap-admin \
    && install -D -m 0755 target/release/iam-activate-key-version /opt/silicon-iam/iam-activate-key-version

FROM debian:bookworm-slim AS runtime

ARG BUILD_REVISION=unknown
ARG BUILD_VERSION=0.1.0

LABEL org.opencontainers.image.title="Silicon IAM" \
      org.opencontainers.image.description="Security-first Silicon IAM API, worker, and migrator" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.version="${BUILD_VERSION}"

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 silicon-iam \
    && useradd --system --uid 10001 --gid silicon-iam --no-create-home --home-dir /nonexistent silicon-iam

COPY --from=builder /opt/silicon-iam/iam-api /usr/local/bin/iam-api
COPY --from=builder /opt/silicon-iam/iam-worker /usr/local/bin/iam-worker
COPY --from=builder /opt/silicon-iam/iam-migrate /usr/local/bin/iam-migrate
COPY --from=builder /opt/silicon-iam/iam-bootstrap-admin /usr/local/bin/iam-bootstrap-admin
COPY --from=builder /opt/silicon-iam/iam-activate-key-version /usr/local/bin/iam-activate-key-version

USER 10001:10001

ENV RUST_BACKTRACE=0

EXPOSE 8080
STOPSIGNAL SIGTERM

CMD ["iam-api"]
