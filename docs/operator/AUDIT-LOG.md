# Audit log

vault-proxy writes an audit trail to `$CONFIG_DIR/audit-log.json` (default `/config/audit-log.json`). The file is a JSON array of objects (newest entry first), capped at 1 000 entries:

```json
[
  {
    "timestamp":      "2026-05-05T12:34:56.789Z",   // RFC 3339 UTC
    "tool_name":      "ha_home__get",                // <service>__<method>
    "args_summary":   "method=GET, path=/api/states", // truncated at 200 chars
    "result_summary": "states=[...]",                 // truncated; sensitive fields masked
    "permission":     "Log",                          // Allow | Log | Ask | Block
    "trigger":        "proxy"                         // always "proxy" for /proxy calls
  }
]
```

Sensitive field values (`password`, `token`, `api_key`, `secret`, `bearer`, `cookie`, and related names) are replaced with `***` before writing so raw credentials never appear in the log.

The file is written to disk every 10 entries or on process shutdown (whichever comes first). To ship it to a SIEM, tail the file or mount the config directory and read it directly — there is no syslog or stdout output of audit events yet (planned for v1.3; see [../ROADMAP.md](../ROADMAP.md)).

## Transparent-mode entries (v1.1+)

Entries originating from the transparent HTTPS_PROXY listener carry `trigger = "transparent"` plus six per-request telemetry fields:

```json
{
  "timestamp":         "2026-05-24T22:34:56.789Z",
  "tool_name":         "transparent::host_inject::api.github.com",
  "args_summary":      "host=api.github.com mode=host_inject",
  "result_summary":    "status=200 bytes_in=4231 bytes_out=187",
  "permission":        "Log",
  "trigger":           "transparent",
  "transparent_mode":  "host_inject",        // or "placeholder" / "passthrough"
  "upstream_host":     "api.github.com",
  "upstream_status":   200,
  "bytes_in":          4231,                  // upstream → agent
  "bytes_out":         187,                   // agent → upstream
  "duration_ms":       234
}
```

The transparent fields are `Option<>` in serde: they're omitted on `/proxy` entries so the file shape stays backwards-compatible with v1.0.x readers.

## Archive (v1.2.2+)

When the in-memory ring buffer hits its 1 000-entry cap, evicted entries get appended (one JSON object per line) to `$CONFIG_DIR/audit-log.json.archive`. The live `.json` file keeps the most-recent 1 000 entries for fast reads; full history lives in the JSONL archive.

This matters most under transparent-mode traffic: a busy agent can fill 1 000 entries in minutes. Without the archive, evicted entries were silently lost. With it, you can `tail -f audit-log.json.archive | jq` to follow history beyond the cap.

The archive is append-only. There is no automatic rotation of the archive itself; operators who care about disk growth should set up a rotator (e.g. logrotate) on the `*.archive` file. A typical homelab deployment with under 10 000 transparent requests per day produces under 5 MB of archive per day.
