# Dashboard

Built with `--features dashboard`. Listens on `127.0.0.1:3202` by default.

```bash
cargo build --release --features dashboard
# or
docker build --build-arg FEATURES=dashboard -t vaultproxy:dashboard .
```

## TLS cert persistence (`--persist-dashboard-cert`)

Dashboard users who were tired of the "certificate has changed" browser warning on every restart can opt in to cert persistence:

```bash
# Docker Compose — add to your service environment
PERSIST_DASHBOARD_CERT=1

# Bare metal
vaultproxy --persist-dashboard-cert
```

On the **first run** the cert is generated normally and written to `{config_dir}/dashboard.crt` and `{config_dir}/dashboard.key` (mode 0600, atomic write). On **subsequent runs** those files are loaded instead of generating a new cert — the browser warning disappears.

To **force regeneration** (cert rotation): delete both files, then restart. vault-proxy will generate a fresh cert and persist it in their place.

## Security stance

- Listens on localhost only by default
- Session-based auth with bcrypt password hashing
- Rate-limited login: 5 attempts per 5 minutes
- Never returns plaintext credentials — passwords masked as `"********"` in all API responses
- If exposed via a reverse proxy, place it behind strong forward authentication (e.g. Authentik)

See [SECURITY.md §Dashboard](../../SECURITY.md#dashboard---features-dashboard-1270013202).
