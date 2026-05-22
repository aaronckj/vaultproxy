# Credential audit

vault-proxy includes a built-in credential health scanner that detects weak, reused, and compromised passwords across vault items in your `vault_folder`. Four HTTP endpoints control it.

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /vault/audit/run` | internal bearer | In-process password health scan. Decrypts every vault password transiently, computes HMAC fingerprints with an ephemeral key, and returns weak/reused groupings. No plaintext passwords appear in the response. Rate-limited to **2 req/60 s** (expensive — decrypts all vault passwords). Returns `503 Service Unavailable` with `Retry-After: 5` if the background audit task is already running (mutex acquisition timed out after 5 s). |
| `POST /audit/credaudit/scan/start` | public | Start a new audit run against the engine sidecar. Returns `{"run_id": "..."}`. Returns `409` if a scan is already running; `503` if the engine sidecar is unreachable. |
| `GET /audit/credaudit/review_pending/{run_id}` | public | Poll run status and retrieve flagged items awaiting review. Returns `200 [...]` on success. Returns `404` with `{"error": "run_id '...' not found — no scan has been started with this ID"}` for an unknown `run_id`. |
| `POST /audit/credaudit/apply` | public | Apply approved rotation recommendations. Body: `{"run_id": "...", "dry_run": true, "item_ids": [...], "confirm_bulk": false}`. `dry_run` defaults to `true` — you must explicitly pass `"dry_run": false` to write changes. Returns `404` for an unknown `run_id`. Requires `confirm_bulk: true` when applying more than 50 items without explicit `item_ids`. |

Results from the engine-sidecar endpoints are persisted in `$CONFIG_DIR/credential_audit.sqlite`. The scanner runs pass-1 (local weak/reuse detection) immediately and schedules pass-2 (HaveIBeenPwned k-anonymity check) asynchronously. No plaintext passwords leave the proxy — only the first 5 characters of each SHA-1 hash are sent to the HIBP API per the k-anonymity protocol.

## In-process health scan (`GET /vault/audit/run`)

```bash
curl -H "Authorization: Bearer $(cat /config/internal-token)" \
     http://127.0.0.1:3201/vault/audit/run
```

Returns a JSON object:

```json
{
  "total_items": 42,
  "weak_passwords": [
    {
      "name": "My Service",
      "username": "admin",
      "item_type": "login",
      "password_strength": "weak",
      "reason": "fewer than 8 characters — increase length to at least 8"
    }
  ],
  "reused_passwords": [
    [
      {
        "name": "Site A",
        "username": "user@example.com",
        "item_type": "login",
        "password_strength": "fair",
        "reason": "password shared with 1 other item: Site B"
      },
      {
        "name": "Site B",
        "username": "user@example.com",
        "item_type": "login",
        "password_strength": "fair",
        "reason": "password shared with 1 other item: Site A"
      }
    ]
  ],
  "fair_passwords_count": 3,
  "weak_threshold_len": 8,
  "scoring_note": "rule-based heuristic: length + character classes only; no dictionary check ..."
}
```

### Response field reference

- **`total_items`** — count of vault items that were scanned. The in-process audit (`src/audit.rs`) scans every item in `vault_folder` with no cap — `total_items` is the true vault count for that folder. (The engine-sidecar audit path in `src/credential_audit/vw_adapter.rs` enforces `SCAN_ITEM_CAP = 1_000`; that cap does not apply here.)
- **`weak_passwords`** — array of `AuditItem` objects whose password is shorter than `weak_threshold_len` characters (rule-based heuristic — not zxcvbn/HIBP). Each object has `name`, `username`, `item_type`, `password_strength` (`"weak"`), and `reason` (human-readable explanation, e.g. `"fewer than 8 characters — increase length to at least 8"`). Only items scored `"weak"` appear here; `"fair"` and `"strong"` items are excluded.
- **`reused_passwords`** — array of groups — each group is an array of two or more `AuditItem` objects that share the same password (detected via HMAC-SHA256 fingerprints with an ephemeral per-run key — no plaintext stored or returned). Items in reuse groups may have `password_strength` of `"weak"`, `"fair"`, or `"strong"`. The `reason` field for reuse-group items is overridden to describe the reuse: `"password shared with N other item: name"` (N=1, singular) or `"password shared with N other items: name1, name2, …"` (N≥2, plural). Names are capped at 5; `"... and N more"` suffix is appended when the group exceeds 5 other items.
- **Cross-list items (weak AND reused):** An item with a short password that is also shared with other items will appear in **both** `weak_passwords` and in a `reused_passwords` group — for two different reasons. Do not deduplicate when displaying.
- **`AuditItem.reason`** — human-readable explanation. Always a non-empty string. Use this to display actionable guidance without requiring operators to read source code.
- **`fair_passwords_count`** — count of vault items whose password scored `"fair"` (8–15 characters, or 16+ characters with fewer than 3 character classes). `"fair"` items are NOT included in `weak_passwords`. An operator whose entire vault scores `"fair"` would otherwise see `weak_passwords: []` and might incorrectly conclude all credentials are strong.
- **`password_strength`** values: `"weak"` (fewer than `weak_threshold_len` characters), `"fair"` (meets minimum length but not strong), `"strong"` (16+ characters with 3+ character classes: lowercase, uppercase, digit, symbol). Only `"weak"` items appear in `weak_passwords`; `"fair"` and `"strong"` items are excluded from that list but may appear in `reused_passwords`.
- **`weak_threshold_len`** — the minimum password length (exclusive) used to classify passwords as "weak". Currently `8`. Included so callers can interpret results without reading source code — e.g. "27 weak passwords (threshold: len < 8)".
- **`scoring_note`** — human-readable description of the scoring algorithm and its key limitation: no dictionary check. Common passwords like `"password123"` or `"Summer2024!"` may score `"fair"` if they meet the length threshold and will NOT appear in `weak_passwords`. The note embeds the actual `weak_threshold_len` value so it stays accurate if the threshold changes.

All decryption is transient; the ephemeral HMAC key and all password buffers are zeroized immediately after use. Scoped to `vault_folder` — only items inside the configured folder are scanned.

> **Scan item cap and pagination:** `SCAN_ITEM_CAP = 1_000` — the scan is hard-capped at 1,000 items. If your `vault_folder` contains more than 1,000 items, only the first 1,000 (in vault list order) are scanned; items 1,001 onward are silently excluded. There is no pagination or offset support. A `WARN` log is emitted when the cap is hit. To audit all items beyond the cap, split credentials across multiple vault folders and point separate `--vault-folder` instances at each, or raise `SCAN_ITEM_CAP` in `src/credential_audit/vw_adapter.rs` and recompile.

## Complete credential audit workflow

**Step 1 — Start a scan:**

```bash
RUN_ID=$(curl -sX POST http://127.0.0.1:3201/audit/credaudit/scan/start | jq -r .run_id)
```

**Step 2 — Poll until items appear:**

```bash
curl http://127.0.0.1:3201/audit/credaudit/review_pending/$RUN_ID
```

Returns a JSON array of flagged items. Each entry includes `item_id`, `status` (e.g. `"dead"`, `"weak"`, `"duplicate"`), `reason`, and `pass` number. An empty array (`[]`) means the scan is still running or found nothing to flag — poll again in a few seconds if the scan was just started. A `404` means the `run_id` is unknown.

**Step 3 — Dry-run apply (preview only):**

```bash
curl -sX POST http://127.0.0.1:3201/audit/credaudit/apply \
  -H 'Content-Type: application/json' \
  -d '{"run_id": "'$RUN_ID'", "dry_run": true}'
```

Returns `{"applied": 0, "would_apply": N, "failed": 0}`. No vault changes are made.

**Step 4 — Apply to specific items (or all flagged items):**

```bash
# Apply to specific items only:
curl -sX POST http://127.0.0.1:3201/audit/credaudit/apply \
  -H 'Content-Type: application/json' \
  -d '{"run_id": "'$RUN_ID'", "dry_run": false, "item_ids": ["<id1>", "<id2>"]}'

# Apply to all flagged items (>50 items requires confirm_bulk: true):
curl -sX POST http://127.0.0.1:3201/audit/credaudit/apply \
  -H 'Content-Type: application/json' \
  -d '{"run_id": "'$RUN_ID'", "dry_run": false, "confirm_bulk": true}'
```

`apply` moves each flagged vault item into a Vaultwarden folder named `<vault_folder>-review-delete` (e.g. `vault-proxy-review-delete` when `VAULT_FOLDER=vault-proxy`) and appends an audit marker block to its notes field. The folder is created automatically if it does not exist. Deployments with no `vault_folder` configured use the legacy name `_review-delete`. The `confirm_bulk: true` flag is required when applying to more than 50 items without specifying `item_ids`, as a safeguard against accidental bulk operations.

## Undo an apply

`apply` does not delete items — it only moves them. To undo, open Vaultwarden and move the items from `<vault_folder>-review-delete` back to their original folder (or `No Folder`). The audit marker block in the notes field is inert and can be deleted manually if desired. There is no automated undo endpoint.

## Migration note (iter-58 upgrade)

If you ran a credential-audit scan before upgrading to iter-58+, flagged items were placed in the old `_review-delete` folder. The `apply` endpoint now looks for `<vault_folder>-review-delete` and will not find those items. To recover: in Vaultwarden, rename `_review-delete` to `<your_vault_folder>-review-delete` (or move items manually). Deployments with `vault_folder = None` (unconfigured) are unaffected.
