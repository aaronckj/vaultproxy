# Quickstart

Fuller version of the 3-step quickstart in the README.

## Step 1 — Create your config directory

```bash
mkdir -p ./config
cp services.example.toml ./config/services.toml
# Edit ./config/services.toml to match your services and vault item names
```

## Step 2 — Set up Vaultwarden items

In Vaultwarden, create a folder named `vault-proxy` (or your `--vault-folder` value). Add one item per service, named to match the `vault_item` field in `services.toml`:

```
vault-proxy - Home Assistant    ← password field = Bearer token
vault-proxy - UniFi             ← password field = API key
vault-proxy - OPNsense          ← custom fields: key, secret
vault-proxy - Sonarr            ← password field = API key
vault-proxy - Tautulli          ← password field = API key
vault-proxy - Plex              ← password field = X-Plex-Token
```

The `vault_item` string in `services.toml` is only a reference — credentials never leave Vaultwarden.

## Step 3 — Run the setup wizard

```yaml
services:
  vaultproxy:
    # Pre-built image, published on every tagged release via the
    # GitHub Actions docker-publish workflow. Pin to a specific tag
    # (e.g. `:1.0.4`) for reproducible deploys; `:latest` always
    # points at the most recent release.
    image: ghcr.io/aaronckj/vaultproxy:latest
    # build: .   # uncomment to build from source instead
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config:/config
    environment:
      VAULT_FOLDER: vault-proxy
    command: ["--setup"]   # Remove after first-run setup completes
```

```bash
docker compose up
```

The wizard prompts for your Vaultwarden URL, email, and master password. Credentials are stored encrypted in `/config/keystore.json`.

## Step 4 — Run for real

Remove `command: ["--setup"]` from your compose file and restart:

```bash
docker compose up -d
```

Verify the proxy is running and `services.toml` loaded:

```bash
curl http://127.0.0.1:3201/vault/health
curl http://127.0.0.1:3201/vault/services
```

`GET /vault/services` returns the count and list of registered services — each entry includes the service `name`, `base_url`, `auth` type (`bearer`, `header`, `query_param`, `basic`, `session`, or `unifi_dual`), and auth-type-specific detail (header name, param name, token field, etc.). `vault_item` (the Vaultwarden credential name) is intentionally omitted. This endpoint requires no authentication token; it exposes no secrets.

## With TPM (bare metal)

```bash
cargo build --release --features tpm
```

See [SECURITY.md](../../SECURITY.md) for TPM threat model.

## Internal token

vault-proxy generates a 64-character hex bearer token at startup and writes it to `$CONFIG_DIR/internal-token` (mode 0600). Internal endpoints (`/vault/connecterr-secrets`, `/vault/connecterr-secrets/upsert`, `/browser/*`, `/vault/notes`, `/vault/reload-services`) require `Authorization: Bearer <token>`. The Connecterr TypeScript side reads this file automatically. For custom clients, read `$CONFIG_DIR/internal-token` and include it as `Authorization: Bearer <value>` on calls to those endpoints.

The token is separate from all Vaultwarden credentials and is rotated on every restart.
