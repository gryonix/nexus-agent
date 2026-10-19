//! Opens a first-visitor site once its first account exists

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::install::caddy::{FIRST_VISITOR_ADMIN, SETUP_GUARD_DIR};

const CHECK_EVERY: Duration = Duration::from_secs(30);
const MAX_ANSWER: u64 = 256 * 1024;

/// Where a site says whether it has an account yet
pub fn probe(owner: &str) -> Option<(u16, &'static str)> {
    use crate::install::{anythingllm, home_assistant, immich, jellyfin, n8n, open_webui};
    match owner {
        "immich" => Some((immich::WEB_UI_PORT, "/api/server/config")),
        "jellyfin" => Some((jellyfin::WEB_UI_PORT, "/System/Info/Public")),
        "home-assistant" => Some((home_assistant::WEB_UI_PORT, "/api/onboarding")),
        "n8n" => Some((n8n::WEB_UI_PORT, "/rest/settings")),
        "open-webui" => Some((open_webui::WEB_UI_PORT, "/api/config")),
        "anythingllm" => Some((anythingllm::WEB_UI_PORT, "/api/setup-complete")),
        _ => None,
    }
}

/// Whether the answer shows a claimed site; unknown stays guarded
pub fn is_claimed(owner: &str, answer: &Value) -> bool {
    let flag = |pointer: &str| answer.pointer(pointer).and_then(Value::as_bool);
    match owner {
        "immich" => flag("/isInitialized") == Some(true),
        "jellyfin" => flag("/StartupWizardCompleted") == Some(true),
        "home-assistant" => answer.as_array().is_some_and(|steps| {
            steps.iter().any(|step| step["step"] == "user" && step["done"] == true)
        }),
        "n8n" => flag("/data/userManagement/showSetupOnFirstLoad") == Some(false),
        "open-webui" => answer.get("status").is_some() && flag("/onboarding") != Some(true),
        "anythingllm" => {
            flag("/results/MultiUserMode") == Some(true) || flag("/results/RequiresAuth") == Some(true)
        }
        _ => false,
    }
}

/// The JSON body of a plain local GET
async fn get_json(port: u16, path: &str) -> Option<Value> {
    let fetch = async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        let request = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nAccept: application/json\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut raw = Vec::new();
        stream.take(MAX_ANSWER).read_to_end(&mut raw).await.ok()?;
        let text = String::from_utf8_lossy(&raw);
        let (head, body) = text.split_once("\r\n\r\n")?;
        if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
            return None;
        }
        serde_json::from_str(body).ok()
    };
    tokio::time::timeout(Duration::from_secs(10), fetch).await.ok().flatten()
}

async fn reload_caddy() {
    let _ = tokio::process::Command::new("systemctl").args(["reload", "caddy"]).status().await;
}

/// Lifts every guard whose site now has its account
async fn sweep(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut lifted = false;
    for entry in entries.flatten() {
        let owner = entry.file_name().to_string_lossy().into_owned();
        if !FIRST_VISITOR_ADMIN.contains(&owner.as_str()) {
            continue;
        }
        let Some((port, path)) = probe(&owner) else { continue };
        let Some(answer) = get_json(port, path).await else { continue };
        if is_claimed(&owner, &answer) && std::fs::remove_file(entry.path()).is_ok() {
            tracing::info!(%owner, "first account exists, site opened beyond the VPN");
            lifted = true;
        }
    }
    if lifted {
        reload_caddy().await;
    }
}

pub fn spawn() {
    tokio::spawn(async {
        loop {
            sweep(Path::new(SETUP_GUARD_DIR)).await;
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_first_visitor_site_has_a_probe() {
        for owner in FIRST_VISITOR_ADMIN {
            assert!(probe(owner).is_some(), "{owner}");
        }
    }

    #[test]
    fn fresh_answers_keep_the_guard() {
        let fresh = [
            ("immich", json!({"isInitialized": false, "isOnboarded": false})),
            ("jellyfin", json!({"Version": "10.11.11", "StartupWizardCompleted": false})),
            ("home-assistant", json!([{"step": "user", "done": false}, {"step": "core_config", "done": false}])),
            ("n8n", json!({"data": {"userManagement": {"showSetupOnFirstLoad": true}}})),
            ("open-webui", json!({"onboarding": true, "status": true, "name": "Open WebUI"})),
            ("anythingllm", json!({"results": {"RequiresAuth": false, "MultiUserMode": false}})),
        ];
        for (owner, answer) in fresh {
            assert!(!is_claimed(owner, &answer), "{owner}");
        }
    }

    #[test]
    fn claimed_answers_lift_it() {
        let claimed = [
            ("immich", json!({"isInitialized": true})),
            ("jellyfin", json!({"StartupWizardCompleted": true})),
            ("home-assistant", json!([{"step": "user", "done": true}, {"step": "core_config", "done": false}])),
            ("n8n", json!({"data": {"userManagement": {"showSetupOnFirstLoad": false}}})),
            ("open-webui", json!({"status": true, "name": "Open WebUI"})),
            ("anythingllm", json!({"results": {"RequiresAuth": true, "MultiUserMode": false}})),
            ("anythingllm", json!({"results": {"RequiresAuth": false, "MultiUserMode": true}})),
        ];
        for (owner, answer) in claimed {
            assert!(is_claimed(owner, &answer), "{owner}");
        }
    }

    #[test]
    fn an_unexpected_answer_is_not_a_claim() {
        for owner in FIRST_VISITOR_ADMIN {
            assert!(!is_claimed(owner, &json!({"error": "starting"})), "{owner}");
        }
    }

    #[tokio::test]
    async fn a_local_answer_is_read_as_json() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"StartupWizardCompleted":true}"#;
            let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            socket.write_all(reply.as_bytes()).await.unwrap();
        });
        let answer = get_json(port, "/System/Info/Public").await.unwrap();
        assert!(is_claimed("jellyfin", &answer));
        assert!(get_json(1, "/").await.is_none());
    }
}
