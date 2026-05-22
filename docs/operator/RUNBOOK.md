# Operator runbook

## vault-proxy won't start

Look for `STARTUP:` messages in the container log. Common causes:

- **`STARTUP: vault_folder 'X' was NOT FOUND in Vaultwarden`** — the folder name in `VAULT_FOLDER` doesn't match an existing Vaultwarden folder. Create the folder or correct the env var.
- **`failed to parse services.toml`** — TOML syntax error. Run `--check` to get a summary:
  ```bash
  docker run --rm -v ./config:/config vaultproxy --check
  ```
- **`keystore locked`** — run `--setup` or use the dashboard to unlock.

## `POST /proxy` returns 404 "unknown service"

The service name in your request doesn't match any entry in `services.toml`. Verify:

```bash
curl http://127.0.0.1:3201/vault/services
```

This returns the full list of registered services with their auth types and base URLs.

## Credentials stopped working (upstream returns 401/403)

The vault item may have changed in Vaultwarden. Force a re-sync:

```bash
curl -X POST http://127.0.0.1:3201/vault/resync
```

This re-fetches all vault items from Vaultwarden. For session-based services, the cached session token is invalidated on the next 401 and refreshed automatically.

## Services return 404 / `vault_item_count: 0` after a Vaultwarden folder rename

If you renamed the Vaultwarden folder that `VAULT_FOLDER` points to, vault-proxy loses track of all items in that folder until the configuration is corrected.

Diagnose with `GET /vault/health`:

```bash
curl http://127.0.0.1:3201/vault/health | jq '{vault_folder_found, vault_item_count}'
```

- `vault_folder_found: false` — the folder named in `VAULT_FOLDER` was not found. Rename the folder in Vaultwarden back to its original name **or** update `VAULT_FOLDER` and restart, then run `POST /vault/resync`.
- `vault_folder_found: true, vault_item_count: 0` — folder exists but is genuinely empty. This is legitimate; no action needed.

Without `vault_folder_found`, a `vault_item_count: 0` alert would be ambiguous between a folder rename and a legitimately empty vault. Use this field in monitoring queries to avoid false data-loss alerts on folder renames.

## Added a service to services.toml but it's not found

Send SIGHUP to reload `services.toml` without restarting:

```bash
docker kill --signal=HUP <container_name>
```

Then check `/vault/services` to confirm it loaded. If it's still missing, check the container log for a per-service rejection reason (SSRF violation, missing field, bad `base_url`, etc.). See [RELOAD.md](RELOAD.md).

## `--setup` hangs waiting for input

The setup wizard reads from stdin. If stdin is not a TTY (e.g. `docker run -d`), it will block forever. Run with `-it` to attach a TTY:

```bash
docker run --rm -it -v ./config:/config vaultproxy --setup
```

Or use the web dashboard (`--features dashboard`) to complete setup via browser.

## MCP server launched with `--launch` exits immediately

Launcher mode (`--launch <name>`) resolves credentials from Vaultwarden and `exec`s the configured command, replacing the vault-proxy process. If the launched process exits immediately, check the logs for:

- **`WARN vault_proxy::launcher: command not found`** — the `command` in `mcp-servers.toml` is not on `PATH` or is misspelled. Verify with `which <command>` inside the container.
- **`WARN vault_proxy::launcher`** — any other launcher warning. Run with `RUST_LOG=debug` for detailed output.
- **`vault item '...' not found`** — the `vault_item` in `mcp-servers.toml` does not match an item name in Vaultwarden. Check for typos and confirm the item is in the correct `vault_folder`.
- **MCP server itself crashes** — the MCP server process exited non-zero. Its stdout/stderr appears in the container log immediately after the `vault-proxy` output. Check for missing dependencies (`pip install`, `npm install`, etc.).

```bash
# Check launcher logs
docker logs <container_name> 2>&1 | grep -E "launcher|WARN|ERROR"

# Validate mcp-servers.toml syntax (--check only validates services.toml; mcp-servers.toml has no --check flag)
docker run --rm -v ./config:/config vaultproxy --launch <name>  # run interactively to see errors
```
