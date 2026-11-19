//! Mailboxes of the mailcow engine, through its local HTTP API

use serde_json::{json, Value};

use super::{human, mailbox, redact, run_command, EngineFailure};
use crate::install::mail::mailcow::{api_base, curl_config, read_conf_value, SERVICE_ID};
use crate::{discover, pb};

/// Mailbox quota in MiB for a new mailbox
const DEFAULT_QUOTA_MB: u32 = 3072;

const CONF_FILE: &str = "mailcow.conf";
const API_TIMEOUT_SECS: &str = "20";

/// What the API calls need: the key mailcow.conf holds
pub(super) struct Access {
    key: String,
}

impl Access {
    fn from_conf(conf: &str) -> Option<Access> {
        read_conf_value(conf, "API_KEY")
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .map(|key| Access { key })
    }
}

pub(super) async fn find() -> Result<Option<Access>, EngineFailure> {
    let dir = discover::directory_of_service(SERVICE_ID).await.map_err(EngineFailure::Unreachable)?;
    let Some(dir) = dir else { return Ok(None) };
    let conf = tokio::fs::read_to_string(dir.join(CONF_FILE)).await;
    match conf.ok().as_deref().and_then(Access::from_conf) {
        Some(access) => Ok(Some(access)),
        None => Err(EngineFailure::Refused(
            "mailcow has no API key in mailcow.conf, so its mailboxes cannot be managed".to_string(),
        )),
    }
}

// ─────────────────────────── Request bodies ───────────────────────────

fn add_body(address: &str, password: &str) -> Value {
    let (local, domain) = address.split_once('@').unwrap_or((address, ""));
    json!({
        "local_part": local,
        "domain": domain,
        "name": local,
        "quota": DEFAULT_QUOTA_MB.to_string(),
        "password": password,
        "password2": password,
        "active": "1",
        "force_pw_update": "0",
    })
}

fn password_body(address: &str, password: &str) -> Value {
    json!({
        "items": [address],
        "attr": {"password": password, "password2": password},
    })
}

fn delete_body(address: &str) -> Value {
    json!([address])
}

// ─────────────────────────── Answers ───────────────────────────

fn number(value: &Value) -> u64 {
    match value {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn is_disabled(entry: &Value) -> bool {
    let flag = if entry["active_int"].is_null() { &entry["active"] } else { &entry["active_int"] };
    matches!(flag, Value::Bool(false)) || matches!(flag, Value::Number(n) if n.as_u64() == Some(0))
        || matches!(flag, Value::String(text) if text == "0")
}

fn detail_of(entry: &Value) -> String {
    let used = human(number(&entry["quota_used"]));
    let quota = number(&entry["quota"]);
    let limit = if quota == 0 { "~".to_string() } else { human(quota) };
    let percent = number(&entry["percent_in_use"]);
    let mut detail = format!("( {used} / {limit} ) [{percent}%]");
    if is_disabled(entry) {
        detail.push_str(" disabled");
    }
    detail
}

/// Parse `get/mailbox/all`
fn parse_list(text: &str) -> Result<Vec<pb::Mailbox>, String> {
    let value: Value = serde_json::from_str(text).map_err(|_| "mailcow sent an unreadable answer".to_string())?;
    check_answer(&value)?;
    let Some(entries) = value.as_array() else { return Ok(Vec::new()) };
    let mut mailboxes: Vec<pb::Mailbox> = Vec::new();
    for entry in entries {
        let Some(address) = entry["username"].as_str() else { continue };
        if mailboxes.iter().any(|m| m.address == address) {
            continue;
        }
        mailboxes.push(mailbox(address, &detail_of(entry)));
    }
    Ok(mailboxes)
}

fn message_of(entry: &Value) -> String {
    match &entry["msg"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .map(|part| part.as_str().map(str::to_string).unwrap_or_else(|| part.to_string()))
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

fn is_failure(entry: &Value) -> bool {
    matches!(entry["type"].as_str(), Some("danger" | "error"))
}

fn check_answer(value: &Value) -> Result<(), String> {
    let failures: Vec<String> = match value {
        Value::Array(items) => items.iter().filter(|item| is_failure(item)).map(message_of).collect(),
        other if is_failure(other) => vec![message_of(other)],
        _ => Vec::new(),
    };
    if failures.is_empty() {
        return Ok(());
    }
    let joined = failures.join("; ");
    Err(if joined.is_empty() { "mailcow refused the request".to_string() } else { joined })
}

fn check_text(text: &str) -> Result<(), String> {
    let value: Value = serde_json::from_str(text).map_err(|_| "mailcow sent an unreadable answer".to_string())?;
    check_answer(&value)
}

// ─────────────────────────── Calls ───────────────────────────

fn request_config(key: &str, body: Option<&Value>) -> String {
    let text = body.map(Value::to_string);
    let mut config = curl_config(key, text.as_deref());
    if body.is_some() {
        config.push_str("header = \"Content-Type: application/json\"\n");
    }
    config
}

async fn call(access: &Access, path: &str, body: Option<&Value>) -> Result<String, EngineFailure> {
    let mut command = tokio::process::Command::new("curl");
    command
        .args(["-sSk", "--max-time", API_TIMEOUT_SECS, "-K", "-"])
        .arg(format!("{}/{path}", api_base()));
    let config = request_config(&access.key, body);
    let output = run_command(command, Some(&config)).await.map_err(EngineFailure::Unreachable)?;
    if !output.status_ok {
        let reason = redact(&access.key, &output.stderr);
        return Err(EngineFailure::Refused(format!("the mailcow API did not answer: {reason}")));
    }
    Ok(output.stdout)
}

pub(super) async fn list(access: &Access) -> Result<Vec<pb::Mailbox>, EngineFailure> {
    let text = call(access, "get/mailbox/all", None).await?;
    parse_list(&text).map_err(EngineFailure::Refused)
}

async fn mutate(access: &Access, path: &str, body: &Value, password: &str) -> Result<(), EngineFailure> {
    let text = call(access, path, Some(body)).await?;
    check_text(&text).map_err(|reason| EngineFailure::Refused(redact(password, &reason)))
}

pub(super) async fn create(access: &Access, address: &str, password: &str) -> Result<(), EngineFailure> {
    mutate(access, "add/mailbox", &add_body(address, password), password).await
}

pub(super) async fn set_password(access: &Access, address: &str, password: &str) -> Result<(), EngineFailure> {
    mutate(access, "edit/mailbox", &password_body(address, password), password).await
}

pub(super) async fn delete(access: &Access, address: &str) -> Result<(), EngineFailure> {
    mutate(access, "delete/mailbox", &delete_body(address), "").await
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"[
      {"username":"admin@example.com","name":"Admin","active":1,"quota":3221225472,"quota_used":6144,"percent_in_use":0,"domain":"example.com"},
      {"username":"off@example.com","active":0,"quota":0,"quota_used":0,"percent_in_use":null},
      {"username":"admin@example.com","active":1},
      {"name":"no username"}
    ]"#;

    #[test]
    fn the_listing_reads_address_quota_and_state() {
        let mailboxes = parse_list(LIST).unwrap();
        assert_eq!(
            mailboxes.iter().map(|m| m.address.as_str()).collect::<Vec<_>>(),
            ["admin@example.com", "off@example.com"]
        );
        assert_eq!(mailboxes[0].detail, "( 6.0K / 3.0G ) [0%]");
        assert_eq!(mailboxes[1].detail, "( 0B / ~ ) [0%] disabled");
        assert!(mailboxes.iter().all(|m| m.manageable));
    }

    #[test]
    fn the_active_flag_reads_as_number_string_or_active_int() {
        assert!(is_disabled(&json!({"active": 0})));
        assert!(is_disabled(&json!({"active": "0"})));
        assert!(is_disabled(&json!({"active": "1", "active_int": 0})));
        assert!(!is_disabled(&json!({"active": 1})));
        assert!(!is_disabled(&json!({"active": "Yes"})));
        assert!(!is_disabled(&json!({})));
    }

    #[test]
    fn an_empty_answer_is_no_mailboxes() {
        assert!(parse_list("[]").unwrap().is_empty());
        assert!(parse_list("{}").unwrap().is_empty());
    }

    #[test]
    fn a_refused_key_is_a_refusal_not_an_empty_list() {
        let denied = r#"{"type":"error","msg":"authentication failed"}"#;
        assert_eq!(parse_list(denied).unwrap_err(), "authentication failed");
        assert!(parse_list("<html>502</html>").is_err());
    }

    #[test]
    fn a_danger_entry_in_a_mutation_answer_is_a_refusal() {
        let ok = r#"[{"type":"success","log":["mailbox","add"],"msg":["mailbox_added","a@example.com"]}]"#;
        assert!(check_text(ok).is_ok());
        let bad = r#"[{"type":"danger","log":[],"msg":["domain_not_found","example.org"]}]"#;
        assert_eq!(check_text(bad).unwrap_err(), "domain_not_found, example.org");
        assert!(check_text("not json").is_err());
    }

    #[test]
    fn the_new_mailbox_body_splits_the_address() {
        let body = add_body("anna@example.com", "s3cr3t");
        assert_eq!(body["local_part"], "anna");
        assert_eq!(body["domain"], "example.com");
        assert_eq!(body["password"], body["password2"]);
        assert_eq!(body["quota"], "3072");
    }

    #[test]
    fn the_other_bodies_name_the_mailbox() {
        assert_eq!(delete_body("a@b.c").to_string(), r#"["a@b.c"]"#);
        let body = password_body("a@b.c", "pw");
        assert_eq!(body["items"][0], "a@b.c");
        assert_eq!(body["attr"]["password2"], "pw");
    }

    #[test]
    fn the_key_and_the_password_travel_on_stdin_never_in_arguments() {
        let body = add_body("anna@example.com", "s3cr3t\"x");
        let config = request_config("k3y", Some(&body));
        assert!(config.contains("X-API-Key: k3y"));
        assert!(config.contains("Content-Type: application/json"));
        assert!(config.contains("s3cr3t"));
        let get = request_config("k3y", None);
        assert!(!get.contains("Content-Type"));
        let args = ["-sSk", "--max-time", API_TIMEOUT_SECS, "-K", "-"];
        assert!(!args.iter().any(|arg| arg.contains("k3y") || arg.contains("s3cr3t")));
    }

    #[test]
    fn the_key_comes_from_the_conf_and_a_missing_one_is_none() {
        let conf = "MAILCOW_HOSTNAME=mail.example.com\nAPI_KEY=abc-123\nAPI_ALLOW_FROM=172.22.1.1,127.0.0.1\n";
        assert_eq!(Access::from_conf(conf).unwrap().key, "abc-123");
        assert!(Access::from_conf("FOO=1\n").is_none());
        assert!(Access::from_conf("API_KEY=\n").is_none());
    }

    #[test]
    fn the_engine_is_addressed_through_the_same_catalog_gate_as_everything_else() {
        assert!(discover::known_service(SERVICE_ID).is_some());
    }
}
