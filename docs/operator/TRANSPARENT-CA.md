# Installing the transparent HTTPS_PROXY CA

vault-proxy's transparent listener (port 3203 by default) presents a
freshly-signed leaf cert for every upstream host the agent reaches.
The leaf is signed by a CA that lives at
`$CONFIG_DIR/transparent-ca.{crt,key}`. Every agent host that uses
`HTTPS_PROXY=http://...:3203` must trust this CA, or every HTTPS
request will fail TLS validation.

## Finding the CA

vault-proxy prints the SHA-256 fingerprint to stderr on every start
where the transparent listener is enabled:

```
┌─────────────────────────────────────────────────────────────────────┐
│ TRANSPARENT PROXY CA  (auto-generated)
│ SHA-256: 5a:3b:c1:...:9e
│ File:    /config/transparent-ca.crt
│
│ Install on every agent host that uses HTTPS_PROXY=…3203.
│ Setup guide: docs/operator/TRANSPARENT-CA.md
└─────────────────────────────────────────────────────────────────────┘
```

The file is also available at `$CONFIG_DIR/transparent-ca.crt`
(mode 0644). The matching private key at `transparent-ca.key` is
mode 0600 — **never copy that file off the proxy host**.

## Per-platform install

### Linux (system-wide)

```bash
sudo cp transparent-ca.crt /usr/local/share/ca-certificates/vault-proxy.crt
sudo update-ca-certificates
```

System-wide install means every program on the host (browsers,
curl, system libraries) trusts the CA. Most invasive option.

### macOS (Keychain)

```bash
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain transparent-ca.crt
```

Or via the GUI: Keychain Access → drag the .crt in → set to
**Always Trust**.

### Windows (admin shell)

```powershell
certutil -addstore -f Root transparent-ca.crt
```

### Per-language / per-process trust (preferred — narrow blast radius)

If you only need a specific agent or runtime to trust the CA, use
its environment variable instead of system install.

| Runtime | Env var | Notes |
|---|---|---|
| Node.js | `NODE_EXTRA_CA_CERTS=/path/to/transparent-ca.crt` | Append-only; works with built-in `https`, `fetch`, undici. Some packages bundle their own roots; check the package. |
| Python `requests` | `REQUESTS_CA_BUNDLE=/path/to/transparent-ca.crt` | Replaces, not appends. To keep system roots: cat the system bundle + this CA into a single file and point at that. |
| Python stdlib + httpx | `SSL_CERT_FILE=/path/to/transparent-ca.crt` | Same caveat. |
| curl | `--cacert /path/to/transparent-ca.crt` or `CURL_CA_BUNDLE` | `--cacert` replaces; use `--cacert-bundle` (or build a combined file) to preserve system roots. |
| Go | `SSL_CERT_FILE=/path/to/transparent-ca.crt` | |
| Rust reqwest | `Certificate::from_pem()` + `.add_root_certificate()` | Appends. |
| Java | Import into `cacerts` keystore via `keytool -importcert`. | |

## BYO mode (operator-provided CA)

If you already have a corporate CA (or one from `mkcert` etc.), you
can skip vault-proxy's auto-generation:

```bash
vaultproxy \
    --transparent-listen 127.0.0.1:3203 \
    --transparent-ca-cert /path/to/corp-ca.crt \
    --transparent-ca-key  /path/to/corp-ca.key
```

vault-proxy validates the BYO files at startup:

- the cert must be a CA (`basicConstraints: CA:TRUE`)
- the key file must be mode `0600`

Fail-fast: vault-proxy refuses to start if either check fails. There
is no `--allow-insecure-ca` escape flag, and there will not be one.
A CA key with permissive perms is the entire ballgame.

## Rotation

Stop vault-proxy → delete `$CONFIG_DIR/transparent-ca.{crt,key}` →
restart. A fresh CA is generated, a new fingerprint is printed, and
**every agent host must re-install the new cert**. There is no
overlap / grace period — the old cert is gone the moment you delete
the file.

A planned rotation looks like:

1. Stop the proxy.
2. Delete the CA pair.
3. Start the proxy. Capture the new fingerprint from stderr.
4. Distribute the new `transparent-ca.crt` to every agent host
   (system trust store or per-runtime env var).
5. Verify each agent can `curl --cacert <new-ca> -x http://...:3203 https://example.com`
   before declaring rotation done.

## Threat model summary

- The CA can sign for any hostname. Key compromise = total MITM of
  every host that trusted it.
- Stored 0600. Never copy off the proxy host. Never check into a
  repo. Never include in a backup that isn't itself encrypted.
- Failure modes: a `--allow-root` running vault-proxy with this key
  is a high-value target. Run vault-proxy as a dedicated non-root
  user.

See `SECURITY.md` for the full project-wide threat model.
