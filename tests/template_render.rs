use vaultproxy::template::{RenderContext, Renderer};

#[test]
fn env_lookup_resolves() {
    std::env::set_var("VP_TEST_TEMPLATE_FOO", "bar-value");
    let r = Renderer::new();
    let ctx = RenderContext::default();
    let out = r
        .render_string("x = {{ env(name=\"VP_TEST_TEMPLATE_FOO\") }}", &ctx)
        .unwrap();
    assert_eq!(out, "x = bar-value");
}

#[test]
fn env_default_used_when_unset() {
    let r = Renderer::new();
    let ctx = RenderContext::default();
    let out = r
        .render_string(
            "x = {{ env(name=\"VP_DEFINITELY_UNSET_XYZ\", default=\"fallback\") }}",
            &ctx,
        )
        .unwrap();
    assert_eq!(out, "x = fallback");
}

#[test]
fn env_missing_without_default_errors() {
    let r = Renderer::new();
    let ctx = RenderContext::default();
    let res = r.render_string("x = {{ env(name=\"VP_DEFINITELY_UNSET_XYZ_2\") }}", &ctx);
    let err = res.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.to_lowercase().contains("unset"),
        "expected 'unset' in error, got: {msg}"
    );
}

#[test]
fn b64_encodes() {
    let r = Renderer::new();
    let ctx = RenderContext::default();
    let out = r
        .render_string("k = {{ b64(value=\"hello\") }}", &ctx)
        .unwrap();
    assert_eq!(out, "k = aGVsbG8=");
}

#[test]
fn refuses_world_writable_template() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let tmpl = dir.path().join("t.tmpl");
    std::fs::write(&tmpl, "no secrets here").unwrap();
    std::fs::set_permissions(&tmpl, std::fs::Permissions::from_mode(0o666)).unwrap();

    let r = Renderer::new();
    let out_path = dir.path().join("out");
    let res = r.render_file(&tmpl, &out_path, &RenderContext::default());
    let err = res.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("world-writable"),
        "expected world-writable refusal, got: {msg}"
    );
}

#[test]
fn output_file_is_chmod_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let tmpl = dir.path().join("t.tmpl");
    std::fs::write(&tmpl, "static content").unwrap();
    std::fs::set_permissions(&tmpl, std::fs::Permissions::from_mode(0o644)).unwrap();

    let r = Renderer::new();
    let out_path = dir.path().join("out");
    r.render_file(&tmpl, &out_path, &RenderContext::default())
        .unwrap();

    let mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "output must be 0600, got {:o}", mode);
    let body = std::fs::read_to_string(&out_path).unwrap();
    assert_eq!(body, "static content");
}
