//! Read-only MCP server on stdio for outside AI agents.

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL: &str = "2025-06-18";
const MAX_LOG_LINES: u64 = 300;

/// Serves MCP over stdin and stdout until stdin closes
pub async fn serve(state_dir: &str) -> anyhow::Result<()> {
    if !crate::mcp_access::enabled() {
        anyhow::bail!("MCP access is turned off on this server");
    }
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let Ok(request) = serde_json::from_str::<Value>(&line) else { continue };
        if let Some(reply) = answer(&request, state_dir).await {
            out.write_all(format!("{reply}\n").as_bytes()).await?;
            out.flush().await?;
        }
    }
    Ok(())
}

async fn answer(request: &Value, state_dir: &str) -> Option<Value> {
    let id = request.get("id")?.clone();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "gryonixnexusd", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Read-only view of one server: its services, state, metrics, security and logs. Nothing here changes the server."
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => call(request.get("params").cloned().unwrap_or_default(), state_dir).await,
        _ => Err((-32601, format!("unknown method {method}"))),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    })
}

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object", "properties": properties, "required": required },
        "annotations": { "readOnlyHint": true }
    })
}

fn tools() -> Vec<Value> {
    vec![
        tool("server_state", "The agent's view of this server: host, services and their status.", json!({}), &[]),
        tool("list_services", "Scans the services installed on this server now.", json!({}), &[]),
        tool("host_metrics", "CPU, memory, swap, disk and network right now.", json!({}), &[]),
        tool("security_status", "CrowdSec and firewall state of this server.", json!({}), &[]),
        tool(
            "service_logs",
            "The last log lines of one service; secrets are cut out.",
            json!({
                "service_id": { "type": "string", "description": "Service id as list_services gives it" },
                "lines": { "type": "integer", "minimum": 1, "maximum": MAX_LOG_LINES }
            }),
            &["service_id"],
        ),
    ]
}

async fn call(params: Value, state_dir: &str) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or_default();
    let text = match name {
        "server_state" => server_state(state_dir),
        "list_services" => crate::discover::scan().await.map(|r| to_json(&r)).map_err(|e| e.to_string()),
        "host_metrics" => Ok(host_metrics().await),
        "security_status" => Ok(to_json(&crate::security::status().await)),
        "service_logs" => service_logs(&args).await,
        _ => return Err((-32602, format!("unknown tool {name}"))),
    };
    Ok(match text {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
        Err(why) => json!({ "content": [{ "type": "text", "text": why }], "isError": true }),
    })
}

fn to_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

fn server_state(state_dir: &str) -> Result<String, String> {
    let store = crate::state::Store::open(std::path::Path::new(state_dir).join("state.db")).map_err(|e| e.to_string())?;
    store.snapshot().map(|state| to_json(&state)).map_err(|e| e.to_string())
}

async fn host_metrics() -> String {
    let mut sampler = crate::metrics::Sampler::new();
    sampler.sample();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    to_json(&sampler.sample())
}

async fn service_logs(args: &Value) -> Result<String, String> {
    let id = args.get("service_id").and_then(Value::as_str).ok_or("service_id is required")?;
    let lines = args.get("lines").and_then(Value::as_u64).unwrap_or(100).clamp(1, MAX_LOG_LINES);
    let text = if let Some(native) = crate::native::find(id) {
        native.run("logs").await.unwrap_or_else(|err| err)
    } else {
        let containers = crate::discover::containers_of_service(id).await.map_err(|e| e.to_string())?;
        let mut all = String::new();
        for name in containers {
            let output = tokio::process::Command::new("docker")
                .args(["logs", "--tail", &lines.to_string(), &name])
                .output()
                .await
                .map_err(|e| e.to_string())?;
            all.push_str(&format!("== {name}\n{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)));
        }
        all
    };
    let tail: Vec<&str> = text.lines().collect();
    let start = tail.len().saturating_sub(lines as usize * 4);
    Ok(redact(&tail[start..].join("\n")))
}

/// Cuts values that look like passwords, tokens or keys
pub fn redact(text: &str) -> String {
    const MARKERS: &[&str] = &["password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "authorization"];
    text.lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            let Some(at) = MARKERS.iter().filter_map(|m| lower.find(m).map(|i| i + m.len())).min() else {
                return line.to_string();
            };
            let rest = &line[at..];
            let Some(sep) = rest.find([':', '=']) else { return line.to_string() };
            format!("{}{} [hidden]", &line[..at], &rest[..=sep])
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_handshake_and_tool_list_answer_and_unknown_methods_fail() {
        let init = answer(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}), "/nonexistent").await.unwrap();
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL);
        let listed = answer(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}), "/nonexistent").await.unwrap();
        let names: Vec<&str> = listed["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["server_state", "list_services", "host_metrics", "security_status", "service_logs"]);
        assert!(listed["result"]["tools"].as_array().unwrap().iter().all(|t| t["annotations"]["readOnlyHint"] == true));
        assert!(answer(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}), "/x").await.is_none());
        let bad = answer(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"restart"}}), "/x").await.unwrap();
        assert_eq!(bad["error"]["code"], -32602);
    }

    #[test]
    fn secrets_are_cut_from_log_lines() {
        assert_eq!(redact("DB_PASSWORD=hunter2 extra"), "DB_PASSWORD= [hidden]");
        assert_eq!(redact("Authorization: Bearer abc"), "Authorization: [hidden]");
        assert_eq!(redact("started on port 80"), "started on port 80");
    }
}
