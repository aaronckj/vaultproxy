//! Setuid helper invoked by vault-proxy to install SMB mounts.
//!
//! Protocol (JSON via stdin → JSON via stdout):
//!
//!   request  = { action, slug, share?, mount_point?, username?, password?,
//!                fs_options?, creds_path?, fstab_path?, allowed_mount_root? }
//!   response = { ok: bool, error?: string }
//!
//! All inputs are validated against tight allowlists. Credentials never appear
//! on argv, in environment variables, or in any log line. Stderr is silent on
//! the password content path; non-sensitive errors are reported via stdout.
//!
//! Build: `cargo build --release --bin vaultproxy-mount-helper`
//! Install:
//!   install -m 4750 -o root -g <vault-proxy-group> \
//!     target/release/vaultproxy-mount-helper /usr/local/libexec/

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

const MARKER_BEGIN: &str = "# BEGIN vaultproxy:";
const MARKER_END: &str = "# END vaultproxy:";
const DEFAULT_CREDS_DIR: &str = "/etc/samba";
const DEFAULT_FSTAB: &str = "/etc/fstab";
const DEFAULT_MOUNT_ROOT: &str = "/mnt";
const MAX_INPUT_BYTES: usize = 64 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!(r#"{{"ok":true}}"#);
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Never include creds content in error strings — `e` is built from
            // validated inputs + syscall errnos only.
            let body = serde_escape(&e);
            println!("{{\"ok\":false,\"error\":\"{body}\"}}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut stdin = std::io::stdin().lock();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stdin
            .read(&mut chunk)
            .map_err(|e| format!("read stdin: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_INPUT_BYTES {
            return Err("request too large".into());
        }
    }

    let req = parse_request(&buf)?;
    match req.action.as_str() {
        "mount" => do_mount(&req),
        "unmount" => do_unmount(&req),
        other => Err(format!("unknown action: {other}")),
    }
}

// ----------------------------------------------------------------------- //
// Request parsing                                                          //
// ----------------------------------------------------------------------- //

#[derive(Default)]
struct Request {
    action: String,
    slug: String,
    share: String,
    mount_point: String,
    username: String,
    password: String,
    fs_options: Vec<String>,
    creds_dir: String,
    fstab_path: String,
    #[allow(dead_code)] // retained for audit / log inspection by caller
    allowed_mount_root: String,
}

fn parse_request(buf: &[u8]) -> Result<Request, String> {
    let s = std::str::from_utf8(buf).map_err(|_| "request must be utf-8")?;
    let v: MiniJson = MiniJson::parse(s)?;
    let obj = v.as_object().ok_or("request must be a JSON object")?;

    let action = obj.string("action").ok_or("missing action")?;
    let slug = obj.string("slug").ok_or("missing slug")?;
    let share = obj.string("share").unwrap_or_default();
    let mount_point = obj.string("mount_point").unwrap_or_default();
    let username = obj.string("username").unwrap_or_default();
    let password = obj.string("password").unwrap_or_default();
    let fs_options: Vec<String> = obj.string_array("fs_options").unwrap_or_default();
    let creds_dir = obj
        .string("creds_dir")
        .unwrap_or_else(|| DEFAULT_CREDS_DIR.into());
    let fstab_path = obj
        .string("fstab_path")
        .unwrap_or_else(|| DEFAULT_FSTAB.into());
    let allowed_mount_root = obj
        .string("allowed_mount_root")
        .unwrap_or_else(|| DEFAULT_MOUNT_ROOT.into());

    validate_slug(&slug)?;
    validate_creds_dir(&creds_dir)?;
    validate_abs_path(&fstab_path, "fstab_path")?;
    validate_abs_path(&allowed_mount_root, "allowed_mount_root")?;

    if action == "mount" {
        validate_share(&share)?;
        validate_mount_point(&mount_point, &allowed_mount_root)?;
        validate_username(&username)?;
        validate_password(&password)?;
        validate_fs_options(&fs_options)?;
    } else if action == "unmount" {
        validate_mount_point(&mount_point, &allowed_mount_root)?;
    }

    Ok(Request {
        action,
        slug,
        share,
        mount_point,
        username,
        password,
        fs_options,
        creds_dir,
        fstab_path,
        allowed_mount_root,
    })
}

// ----------------------------------------------------------------------- //
// Validation                                                               //
// ----------------------------------------------------------------------- //

fn validate_slug(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 32 {
        return Err("slug length must be 1..=32".into());
    }
    if !s
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err("slug must match [a-z0-9-]".into());
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err("slug must not start or end with '-'".into());
    }
    Ok(())
}

fn validate_share(s: &str) -> Result<(), String> {
    if !s.starts_with("//") {
        return Err("share must start with //".into());
    }
    let rest = &s[2..];
    let (host, path) = rest.split_once('/').ok_or("share must be //host/path")?;
    if host.is_empty() || path.is_empty() {
        return Err("share host and path required".into());
    }
    if !host
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
    {
        return Err("share host has invalid characters".into());
    }
    if !path
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'/'))
    {
        return Err("share path has invalid characters".into());
    }
    if path.contains("..") {
        return Err("share path must not contain ..".into());
    }
    if s.len() > 256 {
        return Err("share too long".into());
    }
    Ok(())
}

fn validate_abs_path(s: &str, field: &str) -> Result<(), String> {
    if !s.starts_with('/') {
        return Err(format!("{field} must be absolute"));
    }
    let p = Path::new(s);
    for c in p.components() {
        if matches!(c, Component::ParentDir) {
            return Err(format!("{field} must not contain .."));
        }
    }
    Ok(())
}

fn validate_creds_dir(s: &str) -> Result<(), String> {
    validate_abs_path(s, "creds_dir")?;
    // Lock to a known safe directory family.
    if !(s == "/etc/samba" || s.starts_with("/etc/samba/") || s == "/run/vaultproxy/smb") {
        return Err("creds_dir must be /etc/samba or /run/vaultproxy/smb".into());
    }
    Ok(())
}

fn validate_mount_point(mp: &str, allowed_root: &str) -> Result<(), String> {
    validate_abs_path(mp, "mount_point")?;
    let root = allowed_root.trim_end_matches('/');
    if mp == root {
        return Err("mount_point must be a subdirectory of allowed_mount_root".into());
    }
    let expected_prefix = format!("{root}/");
    if !mp.starts_with(&expected_prefix) {
        return Err(format!("mount_point must begin with {expected_prefix}"));
    }
    if mp.len() > 256 {
        return Err("mount_point too long".into());
    }
    // No shell-meta and no whitespace in path.
    if mp
        .bytes()
        .any(|b| !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'/'))
    {
        return Err("mount_point has invalid characters".into());
    }
    Ok(())
}

fn validate_username(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 64 {
        return Err("username length must be 1..=64".into());
    }
    if !s
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'@'))
    {
        return Err("username has invalid characters".into());
    }
    Ok(())
}

fn validate_password(p: &str) -> Result<(), String> {
    if p.is_empty() {
        return Err("password missing".into());
    }
    if p.len() > 512 {
        return Err("password too long".into());
    }
    // Reject control characters / newlines (would break creds file).
    if p.bytes().any(|b| b == b'\n' || b == b'\r' || b == 0) {
        return Err("password contains forbidden bytes".into());
    }
    Ok(())
}

fn validate_fs_options(opts: &[String]) -> Result<(), String> {
    if opts.len() > 32 {
        return Err("too many fs_options".into());
    }
    // Reserved options the caller cannot pass — vault-proxy controls creds.
    let reserved: BTreeSet<&str> = ["credentials", "username", "password", "pass", "user"]
        .into_iter()
        .collect();
    for o in opts {
        if o.is_empty() || o.len() > 128 {
            return Err("fs_option length must be 1..=128".into());
        }
        if !o.bytes().all(|b| {
            matches!(
                b,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'=' | b':' | b'/'
            )
        }) {
            return Err("fs_option has invalid characters".to_string());
        }
        let key = o.split('=').next().unwrap_or(o);
        if reserved.contains(&key) {
            return Err(format!("fs_option '{key}' is reserved"));
        }
        if o.contains(',') || o.contains(' ') {
            return Err("fs_option must not contain ',' or whitespace".into());
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------- //
// Mount / unmount actions                                                  //
// ----------------------------------------------------------------------- //

fn do_mount(req: &Request) -> Result<(), String> {
    let creds_path = creds_path_for(&req.creds_dir, &req.slug);
    write_creds_file(&creds_path, &req.username, &req.password)?;
    ensure_mount_dir(Path::new(&req.mount_point))?;
    let line = build_fstab_line(req, &creds_path);
    write_fstab_block(Path::new(&req.fstab_path), &req.slug, Some(&line))?;
    mount_path(&req.mount_point)?;
    Ok(())
}

fn do_unmount(req: &Request) -> Result<(), String> {
    // Best-effort umount; ignore "not mounted".
    let _ = umount_path(&req.mount_point);
    write_fstab_block(Path::new(&req.fstab_path), &req.slug, None)?;
    let creds_path = creds_path_for(&req.creds_dir, &req.slug);
    if creds_path.exists() {
        fs::remove_file(&creds_path).map_err(|e| format!("remove creds: {e}"))?;
    }
    Ok(())
}

fn creds_path_for(dir: &str, slug: &str) -> PathBuf {
    PathBuf::from(format!("{dir}/vaultproxy-{slug}.credentials"))
}

fn write_creds_file(path: &Path, username: &str, password: &str) -> Result<(), String> {
    let parent = path.parent().ok_or("creds path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir creds dir: {e}"))?;
    let tmp = path.with_extension("credentials.tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("open creds tmp: {e}"))?;
        let body = format!("username={username}\npassword={password}\n");
        f.write_all(body.as_bytes())
            .map_err(|e| format!("write creds: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync creds: {e}"))?;
    }
    // Ensure mode in case umask interfered.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod creds: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename creds: {e}"))?;
    Ok(())
}

fn ensure_mount_dir(p: &Path) -> Result<(), String> {
    if !p.exists() {
        fs::create_dir_all(p).map_err(|e| format!("mkdir mount: {e}"))?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod mount: {e}"))?;
    }
    if !p.is_dir() {
        return Err("mount_point exists and is not a directory".into());
    }
    Ok(())
}

fn build_fstab_line(req: &Request, creds_path: &Path) -> String {
    let mut opts = vec![format!("credentials={}", creds_path.display())];
    opts.extend(req.fs_options.iter().cloned());
    let opts_joined = opts.join(",");
    format!(
        "{share} {mp} cifs {opts} 0 0",
        share = req.share,
        mp = req.mount_point,
        opts = opts_joined,
    )
}

/// Idempotently replace (or remove when `line == None`) the vault-proxy block
/// for `slug` inside `fstab`. Bounded by `# BEGIN vaultproxy:<slug>` /
/// `# END vaultproxy:<slug>`. The whole file is rewritten atomically.
fn write_fstab_block(fstab: &Path, slug: &str, line: Option<&str>) -> Result<(), String> {
    let begin = format!("{MARKER_BEGIN}{slug}");
    let end = format!("{MARKER_END}{slug}");
    let original = match fs::read_to_string(fstab) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("read fstab: {e}")),
    };
    let mut out = String::with_capacity(original.len() + 256);
    let mut in_block = false;
    for raw in original.lines() {
        let trimmed = raw.trim();
        if trimmed == begin {
            in_block = true;
            continue;
        }
        if in_block {
            if trimmed == end {
                in_block = false;
            }
            continue;
        }
        out.push_str(raw);
        out.push('\n');
    }
    if in_block {
        return Err("fstab contains unterminated vaultproxy block".into());
    }
    // Reject if a non-block entry already references this mount_point to avoid
    // shadowing operator-authored lines.
    if let Some(new_line) = line {
        let mp = new_line.split_whitespace().nth(1).unwrap_or("");
        for raw in out.lines() {
            let t = raw.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            if let Some(existing_mp) = t.split_whitespace().nth(1) {
                if existing_mp == mp {
                    return Err(format!(
                        "mount_point {mp} already present in fstab outside vaultproxy block"
                    ));
                }
            }
        }
    }
    if let Some(new_line) = line {
        if !out.ends_with('\n') && !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&begin);
        out.push('\n');
        out.push_str(new_line);
        out.push('\n');
        out.push_str(&end);
        out.push('\n');
    }
    atomic_write(fstab, out.as_bytes(), 0o644)
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let dir = path.parent().ok_or("path has no parent")?;
    let mut tmp_name: OsString = path
        .file_name()
        .ok_or("path has no filename")?
        .to_os_string();
    tmp_name.push(".vaultproxy.tmp");
    let tmp = dir.join(tmp_name);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| format!("open tmp: {e}"))?;
        f.write_all(data).map_err(|e| format!("write tmp: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync tmp: {e}"))?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod tmp: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename tmp: {e}"))?;
    // fsync the directory so the rename is durable.
    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}

fn mount_path(mp: &str) -> Result<(), String> {
    let status = Command::new("/bin/mount")
        .arg(mp)
        .status()
        .map_err(|e| format!("spawn mount: {e}"))?;
    if !status.success() {
        return Err(format!("mount {mp} exited with {status}"));
    }
    Ok(())
}

fn umount_path(mp: &str) -> Result<(), String> {
    let status = Command::new("/bin/umount")
        .arg(mp)
        .status()
        .map_err(|e| format!("spawn umount: {e}"))?;
    if !status.success() {
        return Err(format!("umount {mp} exited with {status}"));
    }
    Ok(())
}

// ----------------------------------------------------------------------- //
// Tiny dependency-free JSON parser                                          //
// Only supports: objects with string/array(string) values, no nesting.      //
// ----------------------------------------------------------------------- //

struct MiniJson {
    obj: Option<Obj>,
}

#[derive(Default)]
struct Obj {
    fields: Vec<(String, Value)>,
}

enum Value {
    String(String),
    StringArray(Vec<String>),
}

impl MiniJson {
    fn parse(s: &str) -> Result<MiniJson, String> {
        let mut p = Parser {
            src: s.as_bytes(),
            i: 0,
        };
        p.skip_ws();
        let obj = p.parse_object()?;
        p.skip_ws();
        if p.i != p.src.len() {
            return Err("trailing content after JSON object".into());
        }
        Ok(MiniJson { obj: Some(obj) })
    }
    fn as_object(&self) -> Option<&Obj> {
        self.obj.as_ref()
    }
}

impl Obj {
    fn string(&self, key: &str) -> Option<String> {
        for (k, v) in &self.fields {
            if k == key {
                if let Value::String(s) = v {
                    return Some(s.clone());
                }
            }
        }
        None
    }
    fn string_array(&self, key: &str) -> Option<Vec<String>> {
        for (k, v) in &self.fields {
            if k == key {
                if let Value::StringArray(a) = v {
                    return Some(a.clone());
                }
            }
        }
        None
    }
}

struct Parser<'a> {
    src: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.src.len() {
            match self.src[self.i] {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), String> {
        self.skip_ws();
        if self.i < self.src.len() && self.src[self.i] == c {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}'", c as char))
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.src.get(self.i).copied()
    }

    fn parse_object(&mut self) -> Result<Obj, String> {
        self.expect(b'{')?;
        let mut obj = Obj::default();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(obj);
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.expect(b':')?;
            let val = self.parse_value()?;
            obj.fields.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected , or } in object".into()),
            }
        }
        Ok(obj)
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b'[') => Ok(Value::StringArray(self.parse_string_array()?)),
            Some(b'n') => {
                if self.src.get(self.i..self.i + 4) == Some(b"null") {
                    self.i += 4;
                    Ok(Value::String(String::new()))
                } else {
                    Err("invalid literal".into())
                }
            }
            _ => Err("only string and string-array values are supported".into()),
        }
    }

    fn parse_string_array(&mut self) -> Result<Vec<String>, String> {
        self.expect(b'[')?;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(out);
        }
        loop {
            self.skip_ws();
            out.push(self.parse_string()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    continue;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected , or ] in array".into()),
            }
        }
        Ok(out)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        while self.i < self.src.len() {
            let b = self.src[self.i];
            self.i += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.i >= self.src.len() {
                        return Err("trailing backslash".into());
                    }
                    let esc = self.src[self.i];
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            if self.i + 4 > self.src.len() {
                                return Err("short \\u escape".into());
                            }
                            let hex = std::str::from_utf8(&self.src[self.i..self.i + 4])
                                .map_err(|_| "bad \\u escape")?;
                            let cp =
                                u32::from_str_radix(hex, 16).map_err(|_| "bad \\u escape hex")?;
                            self.i += 4;
                            if let Some(c) = char::from_u32(cp) {
                                out.push(c);
                            } else {
                                return Err("invalid codepoint".into());
                            }
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => out.push(b as char),
            }
        }
        Err("unterminated string".into())
    }
}

/// Escape a string for inclusion as a JSON string value (we emit a single
/// `error` field manually because the helper has no JSON serializer dep).
fn serde_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ----------------------------------------------------------------------- //
// Tests                                                                    //
// ----------------------------------------------------------------------- //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rejects_bad() {
        assert!(validate_slug("").is_err());
        assert!(validate_slug("-foo").is_err());
        assert!(validate_slug("Foo").is_err());
        assert!(validate_slug("foo bar").is_err());
        assert!(validate_slug(&"a".repeat(33)).is_err());
        assert!(validate_slug("ok-slug-1").is_ok());
    }

    #[test]
    fn share_validation() {
        assert!(validate_share("//host/share").is_ok());
        assert!(validate_share("//10.0.0.30/data/sub").is_ok());
        assert!(validate_share("/host/share").is_err());
        assert!(validate_share("//host").is_err());
        assert!(validate_share("//host/../etc").is_err());
        assert!(validate_share("//host/sh are").is_err());
    }

    #[test]
    fn mount_point_must_be_under_root() {
        assert!(validate_mount_point("/mnt/a", "/mnt").is_ok());
        assert!(validate_mount_point("/mnt", "/mnt").is_err());
        assert!(validate_mount_point("/etc/passwd", "/mnt").is_err());
        assert!(validate_mount_point("/mnt/../etc", "/mnt").is_err());
        assert!(validate_mount_point("/mnt2/x", "/mnt").is_err());
    }

    #[test]
    fn fs_options_reject_reserved() {
        assert!(validate_fs_options(&["credentials=/x".into()]).is_err());
        assert!(validate_fs_options(&["username=foo".into()]).is_err());
        assert!(validate_fs_options(&["vers=3.0".into(), "iocharset=utf8".into()]).is_ok());
        assert!(validate_fs_options(&["vers=3.0,iocharset=utf8".into()]).is_err());
    }

    #[test]
    fn password_rejects_newline() {
        assert!(validate_password("good").is_ok());
        assert!(validate_password("bad\nthing").is_err());
        assert!(validate_password("").is_err());
    }

    #[test]
    fn fstab_block_insert_and_remove() {
        let dir = tempdir();
        let fstab = dir.join("fstab");
        fs::write(&fstab, "UUID=root / ext4 defaults 0 1\n").unwrap();
        // insert
        write_fstab_block(
            &fstab,
            "demo",
            Some("//h/s /mnt/demo cifs credentials=/x 0 0"),
        )
        .unwrap();
        let body = fs::read_to_string(&fstab).unwrap();
        assert!(body.contains("# BEGIN vaultproxy:demo"));
        assert!(body.contains("//h/s /mnt/demo cifs"));
        assert!(body.contains("# END vaultproxy:demo"));
        assert_eq!(body.matches("# BEGIN vaultproxy:demo").count(), 1);
        // replace (idempotent)
        write_fstab_block(
            &fstab,
            "demo",
            Some("//h/s2 /mnt/demo cifs credentials=/x 0 0"),
        )
        .unwrap();
        let body = fs::read_to_string(&fstab).unwrap();
        assert!(body.contains("//h/s2 /mnt/demo cifs"));
        assert!(!body.contains("//h/s /mnt/demo cifs"));
        assert_eq!(body.matches("# BEGIN vaultproxy:demo").count(), 1);
        // remove
        write_fstab_block(&fstab, "demo", None).unwrap();
        let body = fs::read_to_string(&fstab).unwrap();
        assert!(!body.contains("vaultproxy:demo"));
        assert!(body.contains("UUID=root"));
    }

    #[test]
    fn fstab_refuses_to_shadow_existing_mp() {
        let dir = tempdir();
        let fstab = dir.join("fstab");
        fs::write(&fstab, "/dev/sda1 /mnt/demo ext4 defaults 0 1\n").unwrap();
        let err = write_fstab_block(
            &fstab,
            "demo",
            Some("//h/s /mnt/demo cifs credentials=/x 0 0"),
        )
        .unwrap_err();
        assert!(err.contains("already present"), "got: {err}");
    }

    #[test]
    fn json_parses_strings_and_arrays() {
        let s = r#"{ "a": "hi", "b": ["x","y"], "c": null }"#;
        let j = MiniJson::parse(s).unwrap();
        let o = j.as_object().unwrap();
        assert_eq!(o.string("a").as_deref(), Some("hi"));
        assert_eq!(o.string_array("b").unwrap(), vec!["x", "y"]);
        assert_eq!(o.string("c").as_deref(), Some(""));
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "vaultproxy-mount-helper-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }
}
