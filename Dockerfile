# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for vaultproxy.
#
# Stage 1 (builder): compiles the Rust binary.  By default the build is
#   headless (no dashboard).  Pass --build-arg FEATURES=dashboard to opt in.
# Stage 2 (runtime): minimal Debian slim image with just the binary.
#
# Build (headless, default — recommended for production):
#   docker build -t vaultproxy:latest .
#
# Build with dashboard (opt-in — exposes port 3202):
#   docker build --build-arg FEATURES=dashboard -t vaultproxy:dashboard .
#
# The published image (ghcr.io/aaronckj/vaultproxy:latest) is built headless.
# Operators who want the web UI should build locally with --build-arg FEATURES=dashboard
# or use the docker-compose.example.yml build section with the build-arg set.
#
# TPM sealing is intentionally NOT compiled into the default Docker image
# because it requires the TSS2 system libraries and a physical TPM device.
# To add TPM support:
#   --build-arg FEATURES=tpm
#   or: --build-arg FEATURES=dashboard,tpm
# and install `libtss2-dev` in the builder stage.

# ---------------------------------------------------------------------------- #
# Stage 1: builder                                                              #
# ---------------------------------------------------------------------------- #
# iter-49: Use the rustup-managed `stable` channel instead of a pinned image
# tag so that Dockerfile and rust-toolchain.toml (channel = "stable") stay in
# sync automatically.  `rust:slim-bookworm` always ships the current stable;
# rustup then reads rust-toolchain.toml (copied below) and installs the exact
# channel/components declared there, making the build environment identical to
# local development and CI (dtolnay/rust-toolchain@master reads the same file).
#
# iter-50: Tradeoff note — `rust:slim-bookworm` is a moving tag and two local
# `docker build` runs weeks apart may pull different Rust toolchain versions.
# This is intentional: rust-toolchain.toml declares `channel = "stable"`, so
# both local dev and Docker always track the same moving target.  The build is
# therefore as reproducible as rust-toolchain.toml allows.
#
# To pin to a specific Rust release (e.g. for a production freeze):
#   1. In rust-toolchain.toml, set `channel = "1.87"` (or whatever release).
#   2. The Dockerfile needs no change — rustup reads the file and pins itself.
#   3. CI (dtolnay/rust-toolchain@master) reads the same file automatically.
# One file to update, three environments stay in sync.
FROM rust:slim-bookworm AS builder

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

# FEATURES build-arg controls which Cargo features are compiled in.
# Default = empty string (headless, no dashboard, no TPM).
# Pass --build-arg FEATURES=dashboard to enable the web UI on port 3202.
# Pass --build-arg FEATURES=dashboard,tpm for dashboard + TPM sealing.
# iter-59: Changed default from `--features dashboard` to headless so the
# published image does not expose port 3202 without operator opt-in.
ARG FEATURES=""

# Cache dependency build: copy manifests first, compile a dummy main, then
# replace with real source. This layer is reused on source-only changes.
#
# iter-11: `2>/dev/null` suppresses stderr from the dummy-main compile.
# This is intentional: `fn main(){}` fails to link with some feature flags
# because required symbols are absent, but the dependency .rlib files are
# already compiled by that point, which is all we want from this step.
# The semicolon (`;`) rather than `&&` means `rm -rf src` always runs
# regardless of whether the dummy build succeeded — correct behaviour.
#
# iter-49: Copy rust-toolchain.toml so rustup in this image reads the same
# channel declaration used by local dev and CI.  Without it the image ignores
# the file and would diverge if the Dockerfile FROM tag ever lagged behind.
COPY rust-toolchain.toml ./
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && if [ -n "$FEATURES" ]; then cargo build --release --features "$FEATURES" 2>/dev/null; \
       else cargo build --release 2>/dev/null; fi; \
    rm -rf src

# Copy real source and compile.
COPY src ./src
# Touch main.rs to force recompile (the dummy main above left stale artifacts).
RUN touch src/main.rs \
    && if [ -n "$FEATURES" ]; then cargo build --release --features "$FEATURES"; \
       else cargo build --release; fi

# ---------------------------------------------------------------------------- #
# Stage 2: runtime                                                              #
# ---------------------------------------------------------------------------- #
FROM debian:bookworm-slim AS runtime

# curl: required by the HEALTHCHECK instruction below AND by the healthcheck
#   defined in docker-compose.example.yml.  Both use `curl -sf` to probe
#   GET /vault/health.  Removing curl will silently break all health checks.
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

# NOTE: internal-token file permissions in multi-process deployments.
#
# vault-proxy generates $CONFIG_DIR/internal-token with 0o600 permissions
# (owner read/write only). This is correct when vault-proxy and the TypeScript
# Connecterr layer run as the *same* OS user (UID 1001 = vaultproxy).
#
# If your deployment runs the TypeScript side as a different user (e.g. the
# default Node.js container user, UID 1000), that process cannot read the token
# and all calls to /handshake, /vault/connecterr-secrets*, /rotate, and
# /browser/* will return 401. To fix this:
#
#   Option A (recommended): run both processes as the same user (UID 1001):
#     services:
#       connecterr:
#         user: "1001:1001"
#
#   Option B: use a shared group and 0o640 permissions. Add the Connecterr
#   user to the vaultproxy group, then chmod 640 /config/internal-token
#   in the container entrypoint or a startup script.
#
#   Option C: bind-mount the config dir so both containers share the same
#   volume, then follow Option A or B for UID/GID alignment.
#
# vault-proxy does not currently expose a --internal-token-group flag (option B
# above); if you need group-readable tokens, open an issue on the repository.

USER vaultproxy

# MCP proxy port (localhost-only; network_mode:host or explicit mapping needed)
EXPOSE 3201
# Dashboard port (HTTPS, localhost-only).
# Only relevant when the image is built with --build-arg FEATURES=dashboard.
# The headless default image (and the published ghcr.io image) does NOT start a
# listener on this port — EXPOSE 3202 is documentation-only metadata here.
# An operator running `docker run -p 3202:3202 ghcr.io/aaronckj/vaultproxy:latest`
# will get no dashboard (the feature was not compiled in) and no error.
# To get the dashboard, build locally: docker build --build-arg FEATURES=dashboard .
EXPOSE 3202

# HEALTHCHECK — used by plain `docker run` and any orchestrator that reads
# image-embedded health metadata (Portainer, Nomad, etc.).
# docker-compose.example.yml overrides this with an identical definition so that
# `docker compose ps` shows the status directly.
# --interval: probe every 30 s; --timeout: give curl 5 s to respond;
# --start-period: allow 15 s for vault unlock before counting failures.
# curl is installed above — do NOT remove it or this check silently breaks.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://127.0.0.1:3201/vault/health || exit 1

ENTRYPOINT ["/usr/local/bin/vaultproxy"]
