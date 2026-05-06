# Contributing to mcp-vault-proxy

## Running tests

```bash
cargo test
```

All tests must pass before opening a PR. The CI workflow runs `cargo test --workspace` on every pull request against `main`.

## Lint requirement

```bash
cargo clippy --all-targets -- -D warnings
```

The project treats every Clippy warning as an error. `--all-targets` includes tests, benchmarks, and examples — not just the main library/binary. Fix all warnings before submitting — the CI build will fail if any remain.

## Adding a new auth type

1. Add a variant to the `AuthType` enum in `src/proxy/registry.rs`.
2. Add a corresponding arm to the `inject_auth` function in `src/proxy/mod.rs`.
3. Add TOML parsing support in `ServiceConfig::from_toml` (same file as the registry).
4. Add at least one unit test in `tests/` (or inline in the module) covering the happy path and a missing-credential failure case.
5. Document the new fields in `services.example.toml` with a commented example block.

## PR process

1. Branch from `main`: `git checkout -b fix/my-description`.
2. Make changes and verify: `cargo test && cargo clippy -- -D warnings`.
3. Open a PR against `main`. The title should start with `fix:`, `feat:`, or `docs:`.
4. At least one passing CI run is required before merge.
5. Tag releases as `vX.Y.Z` (semver). The CI workflow publishes a Docker image to `ghcr.io/aaronckj/vaultproxy:<tag>` automatically on tag push.
