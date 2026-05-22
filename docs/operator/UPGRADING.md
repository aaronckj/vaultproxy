# Upgrading from v0.2.x to v1.0.x

If you are upgrading from any v0.2.x release, the following breaking changes require updates to scripts or clients that call the vault-proxy HTTP API directly. The Connecterr TypeScript `SidecarClient` has been updated in the matching releases — no changes needed if you use the client library.

## Breaking: collection endpoints now return JSON objects

All collection endpoints changed from bare JSON arrays to `{"ok": true, "<key>": [...]}` envelope objects. Update any code that iterates the response body directly:

| Endpoint | Old shape | New shape | Key | Since |
|---|---|---|---|---|
| `GET /vault/items` | `[...]` | `{"ok":true,"items":[...]}` | `items` | v1.0.0-beta.4 / iter-109 |
| `GET /vault/folders` | `[...]` | `{"ok":true,"folders":[...]}` | `folders` | v1.0.0-beta.4 / iter-110 |
| `GET /vault/duplicates` | `[...]` | `{"ok":true,"groups":[...]}` | `groups` | v1.0.0-beta.4 / iter-110 |
| `GET /audit/credaudit/review_pending/:id` | `[...]` | `{"ok":true,"items":[...]}` | `items` | v1.0.0-beta.6 / iter-112 |

**Migration pattern:**

```diff
- const items = await res.json();             // v0.2.x: bare array
+ const { items } = await res.json();         // v1.0.0: {ok, items}

- const folders = await res.json();
+ const { folders } = await res.json();

- const groups = await res.json();
+ const { groups } = await res.json();
```

## Breaking: `"ok": true/false` sentinel on all responses

Every success response now includes `"ok": true` and every error response includes `"ok": false` plus an `"error"` string. Clients that check only HTTP status codes are unaffected. Clients that inspect the body should add a guard:

```diff
- if (body.items) { ... }
+ if (body.ok && body.items) { ... }
```

## Non-breaking changes from v0.2.x

- `GET /vault/items/untracked` — now returns `{"ok": true, "count": N, "items": [...]}` (was bare array). Key is `items`.
- `GET /vault/audit/run` — response is `{"ok": true, "n_weak": N, "n_reused": N, ...}` (unchanged since v0.2.x, but documented here for completeness).
- All mutation endpoints (`POST /vault/items`, `POST /vault/items/update`, etc.) now include `"ok": true` on success.
- `GET /vault/folders` (scoped, default `include_all=false`) — now also returns `"configured_vault_folder": "<name>"` alongside `"folders": [...]`. Callers that only read `body.folders` are unaffected.

## New in v1.0.0-beta.7: `--persist-dashboard-cert`

See [DASHBOARD.md](DASHBOARD.md#tls-cert-persistence---persist-dashboard-cert).
