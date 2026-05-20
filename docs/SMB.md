# SMB mount setup via vault-proxy

vault-proxy can install an SMB/CIFS mount on the host using credentials
stored in Vaultwarden — without ever exposing the password to the calling
MCP client. The caller asks vault-proxy to "set up share X using vault item
Y at mount point Z"; vault-proxy resolves the credential internally, hands
it off to a privileged helper over a single-shot stdin pipe, and the helper
writes `/etc/samba/vaultproxy-<slug>.credentials`, edits `/etc/fstab`, and
runs `mount`.

## Security model

- **vault-proxy is unprivileged.** It cannot write `/etc/samba/`, cannot edit
  `/etc/fstab`, and cannot call `mount(2)`. Those operations are delegated to
  a small setuid helper binary (`vaultproxy-mount-helper`, ~600 LOC,
  std-lib only).
- **Credentials never appear on the helper's argv or environment.** The
  helper reads a single JSON request on stdin (max 64 KiB), validates every
  field, performs the work, prints a one-line JSON response, and exits.
- **Tight allowlists** guard every caller-supplied input:
  - `slug` matches `[a-z0-9-]{1,32}` and may not start or end with `-`
  - `share` matches `//host/path` with a restricted character set
  - `mount_point` must begin with `<--smb-mount-root>/` (default `/mnt/`)
  - `creds_dir` is locked to `/etc/samba` or `/run/vaultproxy/smb`
  - `fs_options` are individually validated and reject the reserved keys
    `credentials`, `username`, `password`, `pass`, `user`
- **Atomic writes** for both the credentials file (0600 root:root) and the
  rewritten `/etc/fstab`. Each rewrite is tempfile + rename + dir fsync.
- **fstab isolation.** Each managed mount lives between
  `# BEGIN vaultproxy:<slug>` / `# END vaultproxy:<slug>` markers, so updates
  are idempotent and operator-authored lines outside the block are
  untouched. The helper refuses to add a block when a non-block fstab entry
  already references the same mount point.

## Install

1. Build the helper alongside vault-proxy:

   ```bash
   cargo build --release --bin vaultproxy-mount-helper
   ```

2. Install setuid-root, group-owned by vault-proxy's runtime group so only
   that user (and root) can execute it:

   ```bash
   sudo install -m 4750 -o root -g <vault-proxy-group> \
       target/release/vaultproxy-mount-helper \
       /usr/local/libexec/vaultproxy-mount-helper
   ```

3. Restart vault-proxy with the SMB flags wired:

   ```bash
   vaultproxy \
     --smb-helper-path /usr/local/libexec/vaultproxy-mount-helper \
     --smb-mount-root  /mnt \
     --smb-creds-dir   /etc/samba \
     ...
   ```

   Equivalent env vars: `SMB_HELPER_PATH`, `SMB_MOUNT_ROOT`, `SMB_CREDS_DIR`,
   `SMB_FSTAB_PATH`. If `--smb-helper-path` is empty, the SMB endpoints
   return `501 Not Implemented`.

## API

### `POST /vault/smb/mount`

```jsonc
{
  "vault_item_id": "703aab10-59a1-4de0-b021-8fedc978f507",
  "share":         "//10.0.0.30/screenshots",
  "mount_point":   "/mnt/screenshots",
  "slug":          "unraid-screens",
  "fs_options":    ["vers=3.0", "iocharset=utf8"]   // optional
}
```

Response on success: `200 OK` with `{"ok": true}`. On failure: `4xx`/`5xx`
with `{"ok": false, "error": "..."}`. The response never contains
credential content.

### `POST /vault/smb/unmount`

```jsonc
{
  "slug":        "unraid-screens",
  "mount_point": "/mnt/screenshots"
}
```

Performs `umount`, removes the matching `vaultproxy:<slug>` block from
`/etc/fstab`, and deletes `/etc/samba/vaultproxy-<slug>.credentials`.

### MCP tools

The same operations are exposed to MCP clients as `smb_mount` and
`smb_unmount`. Same shape, same security envelope — the MCP client passes a
vault item id, never a password.

## Example fstab block

```
# BEGIN vaultproxy:unraid-screens
//10.0.0.30/screenshots /mnt/screenshots cifs credentials=/etc/samba/vaultproxy-unraid-screens.credentials,vers=3.0,iocharset=utf8 0 0
# END vaultproxy:unraid-screens
```

## Failure modes

| Symptom                        | Likely cause                               |
|--------------------------------|--------------------------------------------|
| `501 disabled`                 | `--smb-helper-path` not set                |
| `slug must match [a-z0-9-]`    | Caller passed uppercase or whitespace      |
| `mount_point must begin with…` | Caller path outside `--smb-mount-root`     |
| `fs_option 'credentials' is reserved` | Caller tried to override creds         |
| `helper output unparseable`    | Helper binary missing or wrong permissions |
| `mount exited with status 32`  | Underlying CIFS error (check `dmesg`)      |
