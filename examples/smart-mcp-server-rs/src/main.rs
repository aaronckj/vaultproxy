//! Minimal smart MCP server that calls Home Assistant via vault-proxy.
//!
//! Hand-rolled stdio JSON-RPC MCP transport. Implements only the surface
//! needed to expose one tool (`ha_call_service`) over the MCP `initialize`,
//! `tools/list`, and `tools/call` methods.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const SERVER_NAME: &str = "smart-mcp-server-rs";
const SERVER_VERSION: &str = "0.1.0";

fn vault_proxy_url() -> String {
    std::env::var("VAULT_PROXY_URL").unwrap_or_else(|_| "http://127.0.0.1:3201".into())
}

fn caller_id() -> String {
    std::env::var("VAULT_PROXY_CALLER_ID").unwrap_or_else(|_| SERVER_NAME.into())
}

#[derive(Serialize)]
struct ProxyRequest<'a> {
    service: &'a str,
    method: &'a str,
    path: String,
    body: Value,
}

async fn call_proxy(client: &reqwest::Client, req: ProxyRequest<'_>) -> anyhow::Result<Value> {
    let url = format!("{}/proxy", vault_proxy_url());
    let res = client
        .post(&url)
        .header("X-Caller-Id", caller_id())
        .json(&req)
        .send()
        .await?;
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        anyhow::bail!("vault-proxy {}: {}", status, text);
    }
    Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[derive(Deserialize)]
struct Rpc {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

fn ok(id: Option<Value>, result: Value) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
    .unwrap()
}

fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    }))
    .unwrap()
}

fn tools_descriptor() -> Value {
    json!([{
        "name": "ha_call_service",
        "description": "Call a Home Assistant service via vault-proxy. Example: turn a light on or off.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":    { "type": "string", "description": "HA domain, e.g. 'light'" },
                "service":   { "type": "string", "description": "HA service, e.g. 'turn_on'" },
                "entity_id": { "type": "string", "description": "HA entity id" }
            },
            "required": ["domain", "service", "entity_id"]
        }
    }])
}

async fn handle_tool_call(client: &reqwest::Client, args: &Value) -> anyhow::Result<Value> {
    let domain = args.get("domain").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("missing 'domain'"))?;
    let service = args.get("service").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("missing 'service'"))?;
    let entity_id = args.get("entity_id").and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("missing 'entity_id'"))?;

    let result = call_proxy(
        client,
        ProxyRequest {
            service: "ha_home",
            method: "POST",
            path: format!("/api/services/{}/{}", domain, service),
            body: json!({ "entity_id": entity_id }),
        },
    )
    .await?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result).unwrap_or_default()
        }]
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = reqwest::Client::builder().build()?;
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let rpc: Rpc = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = err(None, -32700, format!("parse error: {e}"));
                stdout.write_all(resp.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                continue;
            }
        };
        if rpc.jsonrpc != "2.0" {
            let resp = err(rpc.id, -32600, "expected jsonrpc 2.0");
            stdout.write_all(resp.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            continue;
        }

        let response = match rpc.method.as_str() {
            "initialize" => ok(
                rpc.id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
                }),
            ),
            "tools/list" => ok(rpc.id, json!({ "tools": tools_descriptor() })),
            "tools/call" => {
                let name = rpc.params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = rpc.params.get("arguments").cloned().unwrap_or(json!({}));
                if name != "ha_call_service" {
                    err(rpc.id, -32602, format!("unknown tool: {name}"))
                } else {
                    match handle_tool_call(&client, &args).await {
                        Ok(result) => ok(rpc.id, result),
                        Err(e) => err(rpc.id, -32000, format!("tool error: {e}")),
                    }
                }
            }
            // Notifications (no id) are silently ignored.
            other if rpc.id.is_none() => {
                eprintln!("ignoring notification: {other}");
                continue;
            }
            other => err(rpc.id, -32601, format!("method not found: {other}")),
        };

        stdout.write_all(response.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}
