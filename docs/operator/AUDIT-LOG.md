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

The file is written to disk every 10 entries or on process shutdown (whichever comes first). To ship it to a SIEM, tail the file or mount the config directory and read it directly — there is no syslog or stdout output of audit events yet (planned for v1.1; see [../ROADMAP.md](../ROADMAP.md)).
