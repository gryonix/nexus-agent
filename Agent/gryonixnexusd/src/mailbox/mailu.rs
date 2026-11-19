//! Mailu mailboxes via flask mailu; passwords travel on stdin through config-import

use anyhow::Result;
use serde_json::{json, Value};

use super::{human, mailbox, redact, run_exec, EngineFailure};
use crate::install::mail::mailu::{ADMIN_RUN_AS_USER, CONFIG_IMPORT_ARGS, SERVICE_ID};
use crate::{discover, pb};

const EXPORT_USERS_ARGS: &[&str] = &["flask", "mailu", "config-export", "-j", "user"];
const DELETE_ARGS: &[&str] = &["flask", "mailu", "user-delete", "-r"];

/// The Mailu admin container, resolved from the host's OWN report
pub(super) async fn find() -> Result<Option<String>> {
    let Some(service) = discover::service_snapshot(SERVICE_ID).await? else {
        return Ok(None);
    };
    let picked = service
        .containers
        .iter()
        .find(|c| c.image.to_lowercase().contains("mailu/admin"))
        .or_else(|| service.containers.iter().find(|c| c.name.contains("admin")));
    Ok(picked.map(|c| c.name.clone()))
}

/// Parse `config-export -j user`
fn parse_list(text: &str) -> Result<Vec<pb::Mailbox>, String> {
    let value: Value = serde_json::from_str(text).map_err(|_| "Mailu sent an unreadable user list".to_string())?;
    let users = value["user"].as_array().or_else(|| value.as_array());
    let Some(users) = users else { return Ok(Vec::new()) };
    let mut mailboxes: Vec<pb::Mailbox> = Vec::new();
    for user in users {
        let Some(address) = user["email"].as_str() else { continue };
        if mailboxes.iter().any(|m| m.address == address) {
            continue;
        }
        mailboxes.push(mailbox(address, &detail_of(user)));
    }
    Ok(mailboxes)
}

fn detail_of(user: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(quota) = user["quota_bytes"].as_u64().filter(|bytes| *bytes > 0) {
        parts.push(format!("( {} )", human(quota)));
    }
    if user["enabled"] == Value::Bool(false) {
        parts.push("disabled".to_string());
    }
    parts.join(" ")
}

fn import_payload(address: &str, password: &str) -> String {
    json!({"user": [{"email": address, "password": password, "hash_password": true}]}).to_string()
}

pub(super) async fn list(admin: &str) -> Result<Vec<pb::Mailbox>, EngineFailure> {
    let output = run_exec(admin, Some(ADMIN_RUN_AS_USER), EXPORT_USERS_ARGS, None)
        .await
        .map_err(EngineFailure::Unreachable)?;
    if !output.status_ok {
        return Err(EngineFailure::Refused(output.stderr));
    }
    parse_list(&output.stdout).map_err(EngineFailure::Refused)
}

async fn import(admin: &str, payload: &str, password: &str) -> Result<(), EngineFailure> {
    let output = run_exec(admin, Some(ADMIN_RUN_AS_USER), CONFIG_IMPORT_ARGS, Some(payload))
        .await
        .map_err(EngineFailure::Unreachable)?;
    if output.status_ok {
        Ok(())
    } else {
        Err(EngineFailure::Refused(redact(password, &output.stderr)))
    }
}

pub(super) async fn create(admin: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let existing = list(admin).await?;
    if existing.iter().any(|m| m.address.eq_ignore_ascii_case(address)) {
        return Err(EngineFailure::Refused("this mailbox already exists".to_string()));
    }
    import(admin, &import_payload(address, password), password).await
}

pub(super) async fn set_password(admin: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let existing = list(admin).await?;
    if !existing.iter().any(|m| m.address.eq_ignore_ascii_case(address)) {
        return Err(EngineFailure::Refused("this mailbox does not exist".to_string()));
    }
    import(admin, &import_payload(address, password), password).await
}

pub(super) async fn delete(admin: &str, address: &str) -> Result<(), EngineFailure> {
    let mut args: Vec<&str> = DELETE_ARGS.to_vec();
    args.push(address);
    let output = run_exec(admin, Some(ADMIN_RUN_AS_USER), &args, None)
        .await
        .map_err(EngineFailure::Unreachable)?;
    if output.status_ok {
        Ok(())
    } else {
        Err(EngineFailure::Refused(output.stderr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = r#"{"user":[
      {"email":"admin@example.com","comment":"","quota_bytes":1073741824,"global_admin":true,"enabled":true,"displayed_name":"Admin"},
      {"email":"off@example.com","quota_bytes":0,"enabled":false},
      {"email":"admin@example.com"},
      {"comment":"no email"}
    ]}"#;

    #[test]
    fn the_export_gives_addresses_quota_and_state() {
        let mailboxes = parse_list(EXPORT).unwrap();
        assert_eq!(
            mailboxes.iter().map(|m| m.address.as_str()).collect::<Vec<_>>(),
            ["admin@example.com", "off@example.com"]
        );
        assert_eq!(mailboxes[0].detail, "( 1.0G )");
        assert_eq!(mailboxes[1].detail, "disabled");
        assert!(mailboxes.iter().all(|m| m.manageable));
    }

    #[test]
    fn no_users_is_an_empty_list_and_garbage_is_a_refusal() {
        assert!(parse_list(r#"{"user":[]}"#).unwrap().is_empty());
        assert!(parse_list("{}").unwrap().is_empty());
        assert!(parse_list("Traceback (most recent call last):").is_err());
        assert!(parse_list("").is_err());
    }

    #[test]
    fn the_password_goes_into_the_stdin_payload_and_is_escaped() {
        let payload = import_payload("anna@example.com", "pa\"ss\\w0rd");
        let parsed: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["user"][0]["email"], "anna@example.com");
        assert_eq!(parsed["user"][0]["password"], "pa\"ss\\w0rd");
        assert_eq!(parsed["user"][0]["hash_password"], true);
        assert!(parsed["user"][0].get("raw_password").is_none());
    }

    #[test]
    fn delete_really_deletes_instead_of_disabling() {
        assert!(DELETE_ARGS.contains(&"-r"));
    }

    #[test]
    fn no_command_line_holds_a_password() {
        for args in [CONFIG_IMPORT_ARGS, EXPORT_USERS_ARGS, DELETE_ARGS] {
            assert!(!args.iter().any(|arg| arg.contains("s3cr3t")));
            assert!(!args.contains(&"password"), "the password command takes it as an argument");
            assert!(!args.contains(&"user") || args.contains(&"config-export"));
        }
        assert_eq!(CONFIG_IMPORT_ARGS, ["flask", "mailu", "config-import", "-q", "-u"]);
    }

    #[test]
    fn the_engine_is_addressed_through_the_same_catalog_gate_as_everything_else() {
        assert!(discover::known_service(SERVICE_ID).is_some());
    }
}
