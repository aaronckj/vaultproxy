# Contributing to mcp-vault-proxy

## Minimum Rust version (MSRV)

The minimum supported Rust version is **1.88**. The MSRV is set by the
transitive dependency floor — several crates in the lockfile (`time 0.3.47`,
`time-core 0.1.8`, `cookie_store 0.22.1`) declare `rust-version = "1.88"`.

If `cargo check` fails with *"package requires rustc 1.88 or newer"*, run
`rustup update stable` to upgrade. Distro-packaged Rust (e.g. `apt install
rustc`) is often several releases behind; use `rustup` instead.

## Running tests

```bash
# Default features (all 228 unit + 2 integration tests):
cargo test --all-targets

# Full feature matrix (256 unit + 2 integration tests — required before opening a PR):
cargo test --all-targets --features browser,engine,dashboard
```

All tests must pass before opening a PR. The CI workflow runs
`cargo test --all-targets` and
`cargo test --all-targets --features browser,engine,dashboard`
on every pull request against `main`.

## Lint and formatting requirements

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

The project enforces both formatting and Clippy cleanliness.

- `cargo fmt --check` fails if any file is not `rustfmt`-formatted.  Run
  `cargo fmt` (without `--check`) to auto-fix formatting before pushing.
- `cargo clippy --all-targets -- -D warnings` treats every Clippy warning as
  an error.  `--all-targets` includes tests, benchmarks, and examples — not
  just the main library/binary.

Both checks run in CI on every pull request against `main`; a PR that fails
either check will be blocked from merge.

## Adding a new auth type

1. Add a variant to the `AuthType` enum in `src/proxy/registry.rs`.
2. Add a corresponding arm to the `inject_auth` function in `src/proxy/mod.rs`.
3. Add TOML parsing support in `ServiceConfig::from_toml` (same file as the registry).
4. Add at least one unit test in `tests/` (or inline in the module) covering the happy path and a missing-credential failure case.
5. Document the new fields in `services.example.toml` with a commented example block.

## PR process

1. Branch from `main`: `git checkout -b fix/my-description`.
2. Make changes and verify:
   ```bash
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all-targets
   cargo test --all-targets --features browser,engine,dashboard
   ```
3. Open a PR against `main`. The title should start with `fix:`, `feat:`, or `docs:`.
4. At least one passing CI run is required before merge.
5. Tag releases as `vX.Y.Z` (semver). The CI workflow publishes a Docker image to `ghcr.io/aaronckj/vaultproxy:<tag>` automatically on tag push.
