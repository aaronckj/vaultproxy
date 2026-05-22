use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use vaultproxy::hooks::RotationHook;

/// Write a fixed-mode script and return its path. Closes any lingering
/// writer handle before chmod so Linux doesn't refuse the subsequent exec
/// with ETXTBSY when tests run in parallel — `std::fs::write` already
/// drops its File at end-of-scope, but on tmpfs under parallel load the
/// kernel can briefly still see the inode as having open writers; a
/// File::sync_all() with an explicit open+write avoids the race.
fn write_exec_script(path: &std::path::Path, body: &str) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .unwrap();
    f.write_all(body.as_bytes()).unwrap();
    f.sync_all().unwrap();
    drop(f);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn fires_script_with_args_and_env() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("fired");
    let script = dir.path().join("hook.sh");
    write_exec_script(
        &script,
        &format!(
            "#!/usr/bin/env bash\n\
             set -euo pipefail\n\
             echo \"$1 $2 $VP_ROTATION_SERVICE $VP_ROTATION_ITEM_ID\" > {}\n",
            marker.display(),
        ),
    );

    let hook = RotationHook::new(script);
    hook.fire("wi-mcp", "item-abc-123").await.unwrap();

    let body = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(
        body.trim(),
        "wi-mcp item-abc-123 wi-mcp item-abc-123",
        "args and env vars both populated"
    );
}

#[tokio::test]
async fn non_zero_exit_does_not_error() {
    // The hook protocol intentionally swallows non-zero exits (logs a
    // warning) — the rotation has already happened and we don't want to
    // bubble a failed post-step up to the rotate HTTP response.
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fail.sh");
    write_exec_script(&script, "#!/usr/bin/env bash\nexit 7\n");

    let hook = RotationHook::new(script);
    let res = hook.fire("svc", "id").await;
    assert!(
        res.is_ok(),
        "non-zero exit should log a warning, not propagate"
    );
}

#[tokio::test]
async fn spawn_failure_propagates() {
    // A missing script path should produce an Err so the operator notices a
    // misconfigured --on-rotation flag. (Logging only, no surface in the
    // rotation response — caller wraps with let _ = / tracing::error!.)
    let hook = RotationHook::new(PathBuf::from("/nonexistent/path/to/hook"));
    let res = hook.fire("svc", "id").await;
    assert!(res.is_err());
    let msg = format!("{}", res.unwrap_err());
    assert!(
        msg.contains("spawn rotation hook"),
        "expected spawn-error context, got: {msg}"
    );
}

#[tokio::test]
async fn timeout_kills_long_running_hook() {
    // 30s default is too long for a unit test. We construct a hook that
    // sleeps far beyond the timeout window. The fire() future must resolve
    // to an Err within ~30s; we wrap it in tokio::time::timeout(60s) so a
    // truly stuck hook fails the test rather than hanging CI forever.
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("slow.sh");
    write_exec_script(&script, "#!/usr/bin/env bash\nsleep 120\n");

    let hook = RotationHook::new(script);
    let outer = tokio::time::timeout(
        std::time::Duration::from_secs(40),
        hook.fire("svc", "id"),
    )
    .await;
    let inner = outer.expect("outer timeout — fire() did not return within 40s");
    assert!(inner.is_err(), "fire() should error on hook timeout");
    let msg = format!("{}", inner.unwrap_err());
    assert!(
        msg.contains("timed out"),
        "expected timeout error, got: {msg}"
    );
}
