//! Tera-backed template renderer. Renders a config file template with
//! `{{ vault(item="...", field="...") }}` / `{{ env(name="...") }}` /
//! `{{ b64(value="...") }}` placeholders. Output is written atomically
//! via `tempfile::NamedTempFile::persist` and forced to mode 0600 so
//! credentials in the rendered file are not exposed to other users.
//!
//! `vault()` calls go over the daemon's local credential socket, which
//! picks up the TTL'd cache + access-log entries from earlier waves.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tera::{Tera, Value};

#[derive(Default, Clone, Debug)]
pub struct RenderContext {
    pub socket_path: Option<PathBuf>,
}

pub struct Renderer {
    base_tera: Tera,
}

impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}

impl Renderer {
    pub fn new() -> Self {
        let mut tera = Tera::default();
        tera.register_function("env", env_fn());
        tera.register_function("b64", b64_fn());
        // `vault` is registered per-render so each instance can capture
        // its own socket_path; see render_with().
        Self { base_tera: tera }
    }

    pub fn render_string(&self, body: &str, ctx: &RenderContext) -> Result<String> {
        let mut tera = self.base_tera.clone();
        tera.register_function("vault", vault_fn(ctx.socket_path.clone()));
        let tctx = tera::Context::new();
        let mut tera_mut = tera;
        tera_mut
            .add_raw_template("__inline__", body)
            .map_err(|e| anyhow!("tera add_raw_template: {}", flatten_tera_err(&e)))?;
        tera_mut
            .render("__inline__", &tctx)
            .map_err(|e| anyhow!("tera render: {}", flatten_tera_err(&e)))
    }

    pub fn render_file(&self, tmpl_path: &Path, out_path: &Path, ctx: &RenderContext) -> Result<()> {
        // Refuse world-writable templates — they could be tampered with by
        // any local user, defeating the point of writing the output 0600.
        let meta = std::fs::metadata(tmpl_path)
            .with_context(|| format!("stat {}", tmpl_path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o002 != 0 {
            bail!(
                "template {} is world-writable (mode {:o}); refusing to render",
                tmpl_path.display(),
                mode
            );
        }

        let body = std::fs::read_to_string(tmpl_path)
            .with_context(|| format!("read template {}", tmpl_path.display()))?;
        let rendered = self.render_string(&body, ctx)?;

        // Atomic write: tempfile in the OUTPUT's parent dir, written with
        // mode 0600 from creation, then renamed into place.
        let parent = out_path
            .parent()
            .ok_or_else(|| anyhow!("output path {} has no parent dir", out_path.display()))?;
        let tmp = tempfile::Builder::new()
            .prefix(".vaultproxy-render-")
            .tempfile_in(parent)
            .with_context(|| format!("create tempfile in {}", parent.display()))?;
        {
            use std::io::Write;
            // Drop to a write-handle to write + sync; tighten perms BEFORE
            // any data lands so a concurrent reader can't snapshot plaintext.
            std::fs::set_permissions(tmp.path(), Permissions::from_mode(0o600))
                .with_context(|| format!("chmod tempfile {}", tmp.path().display()))?;
            let mut f = tmp.as_file();
            f.write_all(rendered.as_bytes())
                .with_context(|| format!("write tempfile {}", tmp.path().display()))?;
            f.sync_data()
                .with_context(|| format!("fsync tempfile {}", tmp.path().display()))?;
        }
        tmp.persist(out_path).map_err(|e| {
            anyhow!(
                "persist {} -> {}: {}",
                e.file.path().display(),
                out_path.display(),
                e.error
            )
        })?;
        // Defensive re-chmod on the final path (tempfile::persist preserves
        // perms on Linux, but document the intent).
        std::fs::set_permissions(out_path, Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", out_path.display()))?;
        Ok(())
    }
}

fn env_fn() -> impl tera::Function {
    move |args: &HashMap<String, Value>| -> tera::Result<Value> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("env(): `name` argument required"))?;
        match std::env::var(name) {
            Ok(v) => Ok(Value::String(v)),
            Err(_) => {
                if let Some(d) = args.get("default").and_then(Value::as_str) {
                    Ok(Value::String(d.to_string()))
                } else {
                    Err(tera::Error::msg(format!(
                        "env(): variable {name} is unset and no default was provided"
                    )))
                }
            }
        }
    }
}

fn b64_fn() -> impl tera::Function {
    use base64::{engine::general_purpose::STANDARD, Engine};
    move |args: &HashMap<String, Value>| -> tera::Result<Value> {
        let v = args
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("b64(): `value` argument required"))?;
        Ok(Value::String(STANDARD.encode(v.as_bytes())))
    }
}

/// Walk a tera::Error's source chain into a single `:`-separated string so the
/// underlying cause (e.g. our env() / vault() error) survives the wrap in
/// anyhow! — Tera's Display only shows the top-level "Failed to render '...'".
fn flatten_tera_err(e: &tera::Error) -> String {
    use std::error::Error as _;
    let mut parts = vec![e.to_string()];
    let mut cur: Option<&(dyn std::error::Error + 'static)> = e.source();
    while let Some(src) = cur {
        parts.push(src.to_string());
        cur = src.source();
    }
    parts.join(": ")
}

fn vault_fn(socket: Option<PathBuf>) -> impl tera::Function {
    move |args: &HashMap<String, Value>| -> tera::Result<Value> {
        let item = args
            .get("item")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("vault(): `item` argument required"))?;
        let field = args
            .get("field")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("vault(): `field` argument required"))?;
        let sock = socket
            .clone()
            .unwrap_or_else(crate::local_socket::default_socket_path);
        let v = crate::local_socket::client::get_field_sync(&sock, item, field)
            .map_err(|e| tera::Error::msg(format!("vault({item}, {field}): {e}")))?;
        Ok(Value::String(v))
    }
}
