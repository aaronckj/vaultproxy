# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for vaultproxy.
#
# Stage 1 (builder): compiles the Rust binary with the `dashboard` feature.
# Stage 2 (runtime): minimal Debian slim image with just the binary and
#   the Node.js dashboard assets.
#
# Build:
#   docker build -t vaultproxy:latest .
#
# The published image (ghcr.io/aaronckj/vaultproxy:latest) is built from
# this file via the GitHub Actions workflow.
#
# Features compiled in:
#   dashboard — web management UI on 127.0.0.1:3202 (HTTPS)
#
# TPM sealing is intentionally NOT compiled into the default Docker image
# because it requires the TSS2 system libraries and a physical TPM device.
# To add TPM support, change the cargo build line to:
#   --features dashboard,tpm
# and install `libtss2-dev` in the builder stage.

# ---------------------------------------------------------------------------- #
# Stage 1: builder                                                              #
# ---------------------------------------------------------------------------- #
FROM rust:1.82-slim-bookworm AS builder

# Install build dependencies.
# - libssl-dev / pkg-config: required by reqwest's TLS stack (rustls) linking.
# - libsqlite3-dev: required by rusqlite unless `bundled` feature is active.
#   We use `bundled` in Cargo.toml so no system SQLite is needed, but having
#   the dev headers prevents confusing build errors on modified configs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency build: copy manifests first, compile a dummy main, then
# replace with real source. This layer is reused on source-only changes.
#
# iter-11: `2>/dev/null` suppresses stderr from the dummy-main compile.
# This is intentional: `fn main(){}` fails to link with some feature flags
# because required symbols are absent, but the dependency .rlib files are
# already compiled by that point, which is all we want from this step.
# The semicolon (`;`) rather than `&&` means `rm -rf src` always runs
# regardless of whether the dummy build succeeded — correct behaviour.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --features dashboard 2>/dev/null; \
    rm -rf src

# Copy real source and compile.
COPY src ./src
# Touch main.rs to force recompile (the dummy main above left stale artifacts).
RUN touch src/main.rs \
    && cargo build --release --features dashboard

# ---------------------------------------------------------------------------- #
# Stage 2: runtime                                                              #
# ---------------------------------------------------------------------------- #
FROM debian:bookworm-slim AS runtime

# curl: used by the Docker healthcheck defined in docker-compose.example.yml.
# ca-certificates: required for TLS validation against public Vaultwarden
#   instances and Bitwarden cloud.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage.
COPY --from=builder /build/target/release/vaultproxy /usr/local/bin/vaultproxy

# Create non-root user BEFORE copying application files so that COPY --chown
# can reference the user by name. Creating it first also means all subsequent
# RUN commands can use it immediately.
# iter-11: User must exist before COPY --chown references it.
RUN groupadd --gid 1001 vaultproxy \
    && useradd --uid 1001 --gid 1001 --no-create-home --shell /sbin/nologin vaultproxy

# The config directory is mounted at runtime via Docker volume.
# Create it here so the volume mount creates a directory (not a file)
# even if the host path doesn't exist yet. vault-proxy must be able to
# write keystore files into this directory.
RUN mkdir -p /config && chown vaultproxy:vaultproxy /config && chmod 700 /config

# Playwright browser agent assets (optional — only needed for browser rotation).
# Copied with --chown so the vaultproxy user can read the agent scripts at
# runtime. If the playwright/ directory doesn't exist at build time, the COPY
# silently skips it; the browser rotation feature simply won't be available.
# iter-11: Added --chown so runtime user can access the files.
COPY --chown=vaultproxy:vaultproxy playwright/ /app/playwright/

# Copy dashboard static assets (HTML/JS/CSS for the web UI).
# Also --chown so the server process can serve these files without privilege.
# iter-11: Added --chown.
COPY --chown=vaultproxy:vaultproxy dashboard/ /app/dashboard/

USER vaultproxy

# MCP proxy port (localhost-only; network_mode:host or explicit mapping needed)
EXPOSE 3201
# Dashboard port (HTTPS, localhost-only)
EXPOSE 3202

# Issue (iter-12): Add a HEALTHCHECK so `docker run` deployments get container
# health status without relying solely on the docker-compose.example.yml entry.
# Mirrors the healthcheck in docker-compose.example.yml exactly.
# --interval: check every 30 s; --timeout: give curl 5 s; --start-period: allow
# 15 s for the vault to unlock on first boot before counting failures.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://127.0.0.1:3201/vault/health || exit 1

ENTRYPOINT ["/usr/local/bin/vaultproxy"]
