//! Turns the read-only MCP door on and off: one key, one sudo line.

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const SUDOERS_FILE: &str = "/etc/sudoers.d/gryonixmcp";
const KEY_TAG: &str = "gnx-mcp";
const BINARY: &str = "/usr/local/bin/gryonixnexusd";

fn sudoers_path() -> String {
    std::env::var("GRYONIXNEXUSD_MCP_SUDOERS").unwrap_or_else(|_| SUDOERS_FILE.to_string())
}

/// The command the key is held to
pub fn forced_command() -> String {
    format!("sudo -n {BINARY} mcp")
}

/// On while the sudo line exists
pub fn enabled() -> bool {
    std::path::Path::new(&sudoers_path()).exists()
}

/// The sudo lines for these accounts
pub fn sudoers_text(users: &[String]) -> String {
    let mut text = String::from("# Managed by gryonixNexus: read-only MCP access.\n");
    for user in users {
        text.push_str(&format!("{user} ALL=(root) NOPASSWD: {BINARY} mcp\n"));
    }
    text
}

fn state() -> pb::McpAccessState {
    pb::McpAccessState {
        enabled: enabled(),
        users: crate::ssh_watch::control_users(),
        command: forced_command(),
    }
}

fn encode(codec: Codec, state: &pb::McpAccessState) -> Resp {
    codec.encode(state).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn get_mcp_access(codec: Codec, _req: pb::GetMcpAccessRequest) -> Resp {
    encode(codec, &state())
}

pub async fn set_mcp_access(codec: Codec, req: pb::SetMcpAccessRequest) -> Resp {
    let outcome = if req.enabled { turn_on(&req.public_key).await } else { turn_off().await };
    match outcome {
        Ok(()) => encode(codec, &state()),
        Err(why) => connect_error(StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition", &why),
    }
}

async fn turn_on(public_key: &str) -> Result<(), String> {
    let (kind, blob) = crate::device_keys::split_key(public_key).ok_or("the MCP key is not an ed25519 public key")?;
    let users = crate::ssh_watch::control_users();
    if users.is_empty() {
        return Err("this server has no control account to hold the key".into());
    }
    write_sudoers(&users).await?;
    for user in &users {
        let code = crate::device_keys::run_ctl(&["add-forced", user, KEY_TAG, kind, blob, &forced_command()]).await?;
        if code != 0 {
            let _ = turn_off().await;
            return Err(format!("the key helper failed for {user} ({code})"));
        }
    }
    Ok(())
}

async fn turn_off() -> Result<(), String> {
    for user in crate::ssh_watch::control_users() {
        let _ = crate::device_keys::run_ctl(&["remove", &user, KEY_TAG]).await;
    }
    match std::fs::remove_file(sudoers_path()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("could not remove {}: {err}", sudoers_path())),
    }
}

async fn write_sudoers(users: &[String]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let path = sudoers_path();
    let staged = format!("{path}.new");
    std::fs::write(&staged, sudoers_text(users)).map_err(|err| format!("could not write {staged}: {err}"))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o440)).map_err(|err| err.to_string())?;
    let checked = tokio::process::Command::new("visudo").args(["-cf", &staged]).output().await;
    if !checked.is_ok_and(|out| out.status.success()) {
        let _ = std::fs::remove_file(&staged);
        return Err("visudo refused the MCP sudo line".into());
    }
    std::fs::rename(&staged, &path).map_err(|err| format!("could not place {path}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sudo_line_allows_only_the_mcp_command() {
        let text = sudoers_text(&["admin".to_string()]);
        assert!(text.ends_with("admin ALL=(root) NOPASSWD: /usr/local/bin/gryonixnexusd mcp\n"), "{text}");
        assert_eq!(forced_command(), "sudo -n /usr/local/bin/gryonixnexusd mcp");
    }
}
