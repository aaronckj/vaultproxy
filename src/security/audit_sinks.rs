//! SIEM-friendly audit sinks. Each `AuditLog::log()` call fans out to
//! the configured sinks in addition to the on-disk JSON file. Sinks are
//! best-effort: a sink failure is logged at WARN and never blocks the
//! live audit path.
//!
//! v1.5.0-alpha ships `stdout`, `stderr`, and `syslog`. Network sinks
//! (OTLP, Datadog, Splunk HEC) are tracked in docs/ROADMAP.md.
//!
//! Format: each emitted line is a single-line JSON object — the same
//! `AuditEntry` shape that the on-disk file uses. SIEM tools that ship
//! a JSON parser can ingest the stream verbatim.
//!
//! Operators select sinks via `--audit-sink=<spec>` /
//! `AUDIT_SINK=<spec>`. Spec is a comma-separated list of sink names;
//! repeat names are deduplicated. Empty spec = no sinks (file-only,
//! the v1.4.x behaviour).

use crate::security::audit_log::AuditEntry;

/// SIEM-friendly emitter. Implementors MUST be `Send + Sync` because
/// `AuditLog` is shared across tokio worker threads.
pub trait AuditSink: Send + Sync {
    /// Best-effort emit. Errors should be logged at WARN by the impl —
    /// returning from `emit` MUST NOT block subsequent writers.
    fn emit(&self, entry: &AuditEntry);
}

/// Parse a `--audit-sink` spec into a list of constructed sinks.
/// Unknown sink names are logged at WARN and skipped (rather than
/// aborting startup) so a typo in one entry doesn't take the whole
/// audit pipeline offline.
///
/// Network sinks (`otlp`, `datadog`, `splunk`) require an `http`
/// client argument since they spawn a background flusher that POSTs
/// batches over HTTP. Caller supplies the shared `reqwest::Client`
/// so connection pools are reused across sinks. The non-network
/// `parse_spec` shim below stays for tests and any code path that
/// only needs stdout/stderr/syslog.
pub fn parse_spec_with_http(spec: &str, http: &reqwest::Client) -> Vec<Box<dyn AuditSink>> {
    use crate::security::audit_sinks_http::{HttpSink, HttpTransport};

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sinks: Vec<Box<dyn AuditSink>> = Vec::new();
    for raw in spec.split(',') {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        match name.as_str() {
            "stdout" => sinks.push(Box::new(StdoutSink)),
            "stderr" => sinks.push(Box::new(StderrSink)),
            "syslog" => match SyslogSink::open() {
                Ok(s) => sinks.push(Box::new(s)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "audit sink 'syslog' unavailable on this platform — skipping",
                    );
                }
            },
            "otlp" => match HttpTransport::from_env_otlp() {
                Ok(t) => sinks.push(Box::new(HttpSink::spawn(t, http.clone()))),
                Err(e) => tracing::warn!(error = %e, "audit sink 'otlp' skipped"),
            },
            "datadog" => match HttpTransport::from_env_datadog() {
                Ok(t) => sinks.push(Box::new(HttpSink::spawn(t, http.clone()))),
                Err(e) => tracing::warn!(error = %e, "audit sink 'datadog' skipped"),
            },
            "splunk" => match HttpTransport::from_env_splunk() {
                Ok(t) => sinks.push(Box::new(HttpSink::spawn(t, http.clone()))),
                Err(e) => tracing::warn!(error = %e, "audit sink 'splunk' skipped"),
            },
            other => {
                tracing::warn!(
                    sink = %other,
                    "unknown audit sink — valid: stdout | stderr | syslog | otlp | datadog | splunk",
                );
            }
        }
    }
    sinks
}

/// Shim that constructs only the synchronous sinks (no HTTP client
/// required). Used by tests and by paths that don't want to pay for
/// the network-sink machinery. Network sink names log a WARN and are
/// skipped.
#[allow(dead_code)]
pub fn parse_spec(spec: &str) -> Vec<Box<dyn AuditSink>> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sinks: Vec<Box<dyn AuditSink>> = Vec::new();
    for raw in spec.split(',') {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        match name.as_str() {
            "stdout" => sinks.push(Box::new(StdoutSink)),
            "stderr" => sinks.push(Box::new(StderrSink)),
            "syslog" => match SyslogSink::open() {
                Ok(s) => sinks.push(Box::new(s)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "audit sink 'syslog' unavailable on this platform — skipping",
                    );
                }
            },
            "otlp" | "datadog" | "splunk" => {
                tracing::warn!(
                    sink = %name,
                    "network audit sink requested without an http client — use parse_spec_with_http",
                );
            }
            other => {
                tracing::warn!(
                    sink = %other,
                    "unknown audit sink — valid: stdout | stderr | syslog | otlp | datadog | splunk",
                );
            }
        }
    }
    sinks
}

fn serialise_line(entry: &AuditEntry) -> Option<String> {
    serde_json::to_string(entry).ok()
}

/// Newline-delimited JSON to stdout. Pairs well with systemd
/// `StandardOutput=journal` and any log collector that scrapes stdout.
pub struct StdoutSink;

impl AuditSink for StdoutSink {
    fn emit(&self, entry: &AuditEntry) {
        use std::io::Write;
        if let Some(line) = serialise_line(entry) {
            let mut out = std::io::stdout().lock();
            if let Err(e) = writeln!(out, "{line}") {
                tracing::warn!(error = %e, "audit sink 'stdout' write failed");
            }
        }
    }
}

/// Same as `StdoutSink` but to stderr. Useful when stdout is reserved
/// for MCP framing (rare for the proxy daemon but matters for the
/// `--mcp` bin).
pub struct StderrSink;

impl AuditSink for StderrSink {
    fn emit(&self, entry: &AuditEntry) {
        use std::io::Write;
        if let Some(line) = serialise_line(entry) {
            let mut out = std::io::stderr().lock();
            if let Err(e) = writeln!(out, "{line}") {
                tracing::warn!(error = %e, "audit sink 'stderr' write failed");
            }
        }
    }
}

/// Unix syslog via `libc::syslog`. Opens the connection lazily once
/// (via `openlog`) and emits each entry at `LOG_INFO` with the
/// "vaultproxy" ident. Disabled on non-Unix targets (open() returns
/// Err so the sink is skipped at startup).
pub struct SyslogSink {
    // Hold the C-string ident alive for the lifetime of the sink so the
    // pointer we passed to openlog() stays valid.
    _ident: std::ffi::CString,
}

impl SyslogSink {
    #[cfg(target_family = "unix")]
    fn open() -> anyhow::Result<Self> {
        let ident = std::ffi::CString::new("vaultproxy")?;
        // SAFETY: openlog accepts a const char*, LOG_PID|LOG_NDELAY,
        // and a facility int. We keep `ident` alive in self so the
        // pointer stays valid for the life of the sink.
        unsafe {
            libc::openlog(
                ident.as_ptr(),
                libc::LOG_PID | libc::LOG_NDELAY,
                libc::LOG_USER,
            );
        }
        Ok(Self { _ident: ident })
    }
    #[cfg(not(target_family = "unix"))]
    fn open() -> anyhow::Result<Self> {
        anyhow::bail!("syslog sink is only available on unix targets")
    }
}

#[cfg(target_family = "unix")]
impl AuditSink for SyslogSink {
    fn emit(&self, entry: &AuditEntry) {
        if let Some(line) = serialise_line(entry) {
            // SAFETY: syslog() format string is a fixed "%s"; line is
            // CString-converted so the C side sees NUL-terminated data.
            // The thread-unsafe parts of syslog are guarded by the C
            // implementation's internal mutex.
            if let Ok(c) = std::ffi::CString::new(line) {
                unsafe {
                    libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), c.as_ptr());
                }
            }
        }
    }
}

#[cfg(not(target_family = "unix"))]
impl AuditSink for SyslogSink {
    fn emit(&self, _entry: &AuditEntry) {
        // open() returns Err on non-unix so this impl is never instantiated.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spec_empty_returns_nothing() {
        assert_eq!(parse_spec("").len(), 0);
        assert_eq!(parse_spec("  ").len(), 0);
    }

    #[test]
    fn parse_spec_unknown_skipped() {
        // datadog/otlp aren't shipped yet — must be skipped, not panic.
        let sinks = parse_spec("stdout,datadog,otlp");
        assert_eq!(sinks.len(), 1, "only stdout should be constructed");
    }

    #[test]
    fn parse_spec_dedup() {
        let sinks = parse_spec("stdout,stdout,stderr,stderr");
        assert_eq!(sinks.len(), 2);
    }
}
