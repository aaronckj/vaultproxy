//! Live integration smoke for the wi-mcp rotation strategy. Marked
//! `#[ignore]` because it requires:
//!   - A real Vaultwarden with the "WI MCP - Admin" item populated
//!   - SSH access to `unraid` with key auth
//!   - The wi-mcp container running on Tower
//!
//! Run manually: `cargo test --test rotate_wi_mcp -- --ignored --nocapture`

use std::time::Duration;

#[tokio::test]
#[ignore]
async fn live_rotate_wi_mcp() {
    let config_dir = std::env::var("CONFIG_DIR")
        .expect("CONFIG_DIR env var required for live test");
    let token_path = format!("{}/internal-token", config_dir);
    let internal_token = std::fs::read_to_string(&token_path)
        .expect("read internal-token")
        .trim()
        .to_string();
    let vp_url = std::env::var("VP_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3201".to_string());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();

    let rotate_resp = client
        .post(format!("{}/rotate", vp_url))
        .header("Authorization", format!("Bearer {}", internal_token))
        .json(&serde_json::json!({"service":"wi-mcp","strategy":"api"}))
        .send()
        .await
        .expect("rotate request");
    let status = rotate_resp.status();
    let body: serde_json::Value = rotate_resp.json().await.unwrap();
    assert_eq!(status, 200, "rotate body: {}", body);
    assert_eq!(body["ok"], true);

    let probe = client
        .post("https://wi-mcp.splendidus.live/mcp")
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .send()
        .await
        .expect("probe wi-mcp");
    // We don't have the bearer here; we expect 401 (missing token) NOT
    // a 5xx — the point is wi-mcp is reachable and the rotation didn't
    // break the upstream. End-to-end-with-bearer coverage requires running
    // `claude mcp list` (out of scope for this assertion).
    assert!(
        probe.status() == 401 || probe.status() == 200,
        "wi-mcp returned {} after rotation",
        probe.status()
    );
}
