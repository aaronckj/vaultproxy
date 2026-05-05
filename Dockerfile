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

# Playwright browser agent assets (optional — only needed for browser rotation).
# If the playwright/ directory doesn't exist, COPY will emit a warning and
# continue; the browser rotation feature simply won't be available at runtime.
COPY playwright/ /app/playwright/

# Copy dashboard static assets (HTML/JS/CSS for the web UI).
# If the dashboard/ directory doesn't exist (non-dashboard build), skip.
COPY dashboard/ /app/dashboard/

# The config directory is mounted at runtime via Docker volume.
# Create it here so the volume mount creates a directory (not a file)
# even if the host path doesn't exist yet.
RUN mkdir -p /config && chmod 700 /config

# vault-proxy writes no persistent state except to /config.
# Run as a non-root user for defence-in-depth.
RUN groupadd --gid 1001 vaultproxy \
    && useradd --uid 1001 --gid 1001 --no-create-home --shell /sbin/nologin vaultproxy \
    && chown vaultproxy:vaultproxy /config

USER vaultproxy

# MCP proxy port (localhost-only; network_mode:host or explicit mapping needed)
EXPOSE 3201
# Dashboard port (HTTPS, localhost-only)
EXPOSE 3202

ENTRYPOINT ["/usr/local/bin/vaultproxy"]
