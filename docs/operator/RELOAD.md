# Hot-reloading `services.toml`

`services.toml` can be reloaded without restarting vault-proxy via SIGHUP or HTTP.

## SIGHUP

```bash
# In Docker
docker kill --signal=HUP <container_name>

# On bare metal
kill -HUP $(pidof vaultproxy)
```

vault-proxy will:
1. Re-parse `services.toml` and validate every entry (SSRF rules, required fields, PEM certs)
2. Rebuild per-service CA-cert HTTP clients
3. Atomically swap the new registry into place — in-flight requests see the old registry; new requests see the updated one

**Rollback safety:** if the reloaded file would produce zero services (parse error, all entries rejected), vault-proxy keeps the previous registry and logs a `SIGHUP: rolling back` warning. Fix the file and send SIGHUP again.

## HTTP (`POST /vault/reload-services`)

If you prefer a synchronous HTTP trigger over sending a Unix signal:

```bash
TOKEN=$(cat ./config/internal-token)
curl -X POST http://127.0.0.1:3201/vault/reload-services \
  -H "Authorization: Bearer $TOKEN"
```

Returns JSON confirming the before/after service counts:

```json
{
  "ok": true,
  "prev_service_count": 3,
  "new_service_count": 4,
  "services": ["ha_home", "sonarr", "radarr", "plex"],
  "note": "services.toml reloaded synchronously; CA-cert clients rebuilt. ..."
}
```

| Response | Meaning |
|---|---|
| `200` | Reload succeeded |
| `409` | Reload would drop to zero services (rollback safety, same as SIGHUP) |
| `503` + `Retry-After: 5` | Another reload is already in progress (mutex acquisition timed out after 5 s) — back off and retry |

Requires the internal bearer token (`Authorization: Bearer <token>` from `$CONFIG_DIR/internal-token`).
