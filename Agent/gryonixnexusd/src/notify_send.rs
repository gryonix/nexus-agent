//! Delivery of alerts: a signed gryonixPush relay request or an ntfy post

use std::path::PathBuf;
use std::process::Stdio;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::health_watch::{Kind, Problem};

fn curl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_NOTIFY_CURL_BIN").unwrap_or_else(|_| "curl".to_string()))
}

/// One alert, ready for either channel
#[derive(Clone, Debug, PartialEq)]
pub struct Alert {
    pub job_id: Option<String>,
    /// The remote address a block button would ban
    pub address: Option<String>,
    /// When the event happened, unix seconds
    pub at: Option<i64>,
    pub key: String,
    pub args: Vec<String>,
    pub title: String,
    pub body: String,
}

#[derive(Debug, PartialEq)]
pub enum Sent {
    Ok,
    /// The relay is paused; its message
    Paused(String),
    Failed(String),
}

/// Sends a request and returns the status and body
pub async fn http(method: &str, url: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, String), String> {
    let mut command = tokio::process::Command::new(curl_bin());
    command.args(["-sS", "--max-time", "20", "-X", method, "-w", "\n%{http_code}", "--data-binary", "@-"]);
    for (name, value) in headers {
        command.arg("-H").arg(format!("{name}: {value}"));
    }
    command.arg(url).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = command.spawn().map_err(|err| format!("curl: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(body).await.map_err(|err| err.to_string())?;
    }
    let out = child.wait_with_output().await.map_err(|err| err.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    Ok((code.trim().parse().unwrap_or(0), body.to_string()))
}

/// The bytes the relay expects signed
pub fn signed_message(method: &str, path: &str, timestamp: i64, body: &[u8]) -> Vec<u8> {
    let digest: String = Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
    format!("{method}\n{path}\n{timestamp}\n{digest}").into_bytes()
}

pub fn public_key(seed: &[u8; 32]) -> String {
    B64.encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}

/// Signs and sends one request to the relay
pub async fn relay(base: &str, seed: &[u8; 32], method: &str, path: &str, body: &[u8], now: i64) -> Sent {
    let signature = B64.encode(SigningKey::from_bytes(seed).sign(&signed_message(method, path, now, body)).to_bytes());
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("x-gryonix-timestamp".to_string(), now.to_string()),
        ("x-gryonix-signature".to_string(), signature),
    ];
    let url = format!("{}{path}", base.trim_end_matches('/'));
    match http(method, &url, &headers, body).await {
        Ok((200..=299, _)) => Sent::Ok,
        Ok((503, answer)) => Sent::Paused(error_text(&answer, "maintenance")),
        Ok((code, answer)) => Sent::Failed(format!("relay {code}: {}", error_text(&answer, "error"))),
        Err(why) => Sent::Failed(why),
    }
}

fn error_text(answer: &str, field: &str) -> String {
    serde_json::from_str::<serde_json::Value>(answer)
        .ok()
        .and_then(|v| v[field].as_str().map(String::from))
        .unwrap_or_else(|| answer.chars().take(120).collect())
}

pub fn event_body(alert: &Alert, server_id: &str) -> Vec<u8> {
    let mut data = json!({ "server_id": server_id, "kind": alert.key, "args": alert.args });
    if let Some(job_id) = &alert.job_id {
        data["job_id"] = json!(job_id);
    }
    if let Some(address) = &alert.address {
        data["address"] = json!(address);
    }
    data["at"] = json!(alert.at.unwrap_or_else(crate::notify::now));
    json!({ "title": alert.title, "body": alert.body, "data": data }).to_string().into_bytes()
}

/// The ntfy emoji for the kind of alert
fn tag(key: &str) -> &'static str {
    match key {
        "gnx.alert.test" => "bell",
        k if k.ends_with(".ok") => "white_check_mark",
        _ => "warning",
    }
}

fn header_text(text: &str) -> String {
    use base64::Engine;
    let one_line = text.replace(['\r', '\n'], " ");
    if one_line.is_ascii() {
        return one_line;
    }
    format!("=?UTF-8?B?{}?=", base64::engine::general_purpose::STANDARD.encode(one_line.as_bytes()))
}

/// Posts to an ntfy topic
pub async fn ntfy(base: &str, topic: &str, alert: &Alert) -> Sent {
    let headers = vec![
        ("Title".to_string(), header_text(&alert.title)),
        ("Tags".to_string(), tag(&alert.key).to_string()),
    ];
    let url = format!("{}/{topic}", base.trim_end_matches('/'));
    match http("POST", &url, &headers, alert.body.as_bytes()).await {
        Ok((200..=299, _)) => Sent::Ok,
        Ok((code, answer)) => Sent::Failed(format!("ntfy {code}: {}", error_text(&answer, "error"))),
        Err(why) => Sent::Failed(why),
    }
}

/// The alert for a problem appearing or clearing
pub fn alert(problem: &Problem, appeared: bool, host: &str, russian: bool) -> Alert {
    let base = match problem.kind {
        Kind::Raid => "gnx.alert.raid",
        Kind::Smart => "gnx.alert.smart",
        Kind::Space => "gnx.alert.space",
        Kind::Service => "gnx.alert.service",
        Kind::Backup => "gnx.alert.backup",
        Kind::AgentUpdate => "gnx.alert.agent_update",
        Kind::DriveStale => "gnx.alert.drive_stale",
        Kind::DriveReadOnly => "gnx.alert.drive_readonly",
    };
    let key = if appeared { base.to_string() } else { format!("{base}.ok") };
    let (title, body) = texts(&key, russian);
    let detail = state_words(&problem.detail, russian);
    let fill = |text: &str| text.replace("{host}", host).replace("{subject}", &problem.subject).replace("{detail}", detail);
    let body = match (appeared, problem.reason.is_empty()) {
        (true, false) => format!("{} {}", fill(body), problem.reason),
        _ => fill(body),
    };
    Alert {
        job_id: None,
        address: None,
        at: None,
        args: vec![host.to_string(), problem.subject.clone(), problem.detail.clone()],
        title: fill(title),
        body,
        key,
    }
}

/// A container state said the way people say it
pub fn state_words(state: &str, russian: bool) -> &str {
    match (state, russian) {
        ("restarting", false) => "keeps restarting",
        ("restarting", true) => "перезапускается по кругу",
        ("stopped", false) => "stopped with an error",
        ("stopped", true) => "остановился с ошибкой",
        ("unhealthy", false) => "fails its health check",
        ("unhealthy", true) => "не проходит проверку здоровья",
        _ => state,
    }
}

/// A one-off event: an ended run or an SSH sign-in
pub fn event_alert(key: &str, host: &str, subject: &str, detail: &str, russian: bool) -> Alert {
    let (title, body) = texts(key, russian);
    let fill = |text: &str| text.replace("{host}", host).replace("{subject}", subject).replace("{detail}", detail);
    Alert {
        job_id: None,
        address: None,
        at: None,
        args: vec![host.to_string(), subject.to_string(), detail.to_string()],
        title: fill(title),
        body: fill(body),
        key: key.to_string(),
    }
}

pub fn test_alert(host: &str, russian: bool) -> Alert {
    let (title, body) = texts("gnx.alert.test", russian);
    Alert {
        job_id: None,
        address: None,
        at: None,
        key: "gnx.alert.test".into(),
        args: vec![host.to_string()],
        title: title.replace("{host}", host),
        body: body.to_string(),
    }
}

type AlertText = (&'static str, &'static str);

/// Alert keys with English and Russian title and body
const TEXTS: &[(&str, AlertText, AlertText)] = &[
    ("gnx.alert.raid", ("RAID problem on {host}", "{subject} is {detail}. Replace or re-add the failed disk."), ("Проблема RAID на {host}", "{subject}: {detail}. Замените или верните выпавший диск.")),
    ("gnx.alert.raid.ok", ("RAID recovered on {host}", "{subject} is healthy again."), ("RAID восстановлен на {host}", "{subject} снова в порядке.")),
    ("gnx.alert.smart", ("Disk failing on {host}", "{subject} failed its SMART check. Back up its data."), ("Диск выходит из строя на {host}", "{subject} не прошёл проверку SMART. Сохраните данные.")),
    ("gnx.alert.smart.ok", ("Disk check passes on {host}", "{subject} passes its SMART check again."), ("Диск в порядке на {host}", "{subject} снова проходит проверку SMART.")),
    ("gnx.alert.space", ("Disk almost full on {host}", "{subject} is {detail}% full."), ("Диск почти заполнен на {host}", "{subject} заполнен на {detail}%.")),
    ("gnx.alert.space.ok", ("Space freed on {host}", "{subject} is below the limit again."), ("Место освободилось на {host}", "{subject} снова ниже порога.")),
    ("gnx.alert.service", ("Service down on {host}", "{subject} {detail}."), ("Сервис не работает на {host}", "{subject} {detail}.")),
    ("gnx.alert.service.ok", ("Service back on {host}", "{subject} runs again."), ("Сервис снова работает на {host}", "{subject} снова запущен.")),
    ("gnx.alert.backup", ("Backup failed on {host}", "{subject}: {detail}"), ("Резервная копия не удалась на {host}", "{subject}: {detail}")),
    ("gnx.alert.backup.ok", ("Backup works again on {host}", "{subject} backed up successfully."), ("Резервная копия снова работает на {host}", "{subject}: копия сделана.")),
    ("gnx.alert.drive_stale", ("Backup drive {subject} is out of date on {host}", "No new copy reached it for {detail} days. Plug it in or check it."), ("Накопитель {subject} давно без копий на {host}", "Новых копий на нём нет уже {detail} дн. Подключите его или проверьте.")),
    ("gnx.alert.drive_stale.ok", ("Backup drive {subject} is up to date on {host}", "A fresh copy is on it."), ("Накопитель {subject} снова с копиями на {host}", "На нём свежая копия.")),
    ("gnx.alert.drive_readonly", ("Backup drive {subject} went read-only on {host}", "Its filesystem found errors and stopped writing. Check the drive in the app."), ("Накопитель {subject} только для чтения на {host}", "Файловая система нашла ошибки и перестала писать. Проверьте накопитель в приложении.")),
    ("gnx.alert.drive_readonly.ok", ("Backup drive {subject} is writable again on {host}", "It takes copies again."), ("Накопитель {subject} снова записывается на {host}", "Копии на него снова пишутся.")),
    ("gnx.alert.agent_update", ("Agent update for {host}", "Version {subject} is out. Update it from the app."), ("Обновление агента для {host}", "Вышла версия {subject}. Обновите её из приложения.")),
    ("gnx.alert.operation", ("Finished on {host}", "{detail}: {subject}"), ("Готово на {host}", "{detail}: {subject}")),
    ("gnx.alert.operation.started", ("{detail} started on {host}", "{subject}. Tap to follow it."), ("{detail} запущено на {host}", "{subject}. Нажмите, чтобы следить.")),
    ("gnx.alert.operation.failed", ("Failed on {host}", "{detail}: {subject}"), ("Ошибка на {host}", "{detail}: {subject}")),
    ("gnx.alert.ssh_login", ("SSH sign-in on {host}", "{subject} from {detail}"), ("Вход по SSH на {host}", "{subject} с адреса {detail}")),
];

const TEST_TEXT: (AlertText, AlertText) = (
    ("Test from {host}", "Notifications from this server work."),
    ("Проверка от {host}", "Уведомления с этого сервера работают."),
);

fn texts(key: &str, russian: bool) -> AlertText {
    let (en, ru) = TEXTS
        .iter()
        .find(|(name, _, _)| *name == key)
        .map_or(TEST_TEXT, |(_, en, ru)| (*en, *ru));
    if russian { ru } else { en }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_run_alert_carries_the_job_to_open() {
        let mut alert = event_alert("gnx.alert.operation.started", "orion", "nextcloud", "Update", false);
        alert.job_id = Some("job-1".to_string());
        let body: serde_json::Value = serde_json::from_slice(&event_body(&alert, "srv")).unwrap();
        assert_eq!(body["data"]["job_id"], "job-1");
        assert_eq!(body["title"], "Update started on orion");
        let plain: serde_json::Value = serde_json::from_slice(&event_body(&test_alert("h", false), "srv")).unwrap();
        assert!(plain["data"].get("job_id").is_none());
        assert!(plain["data"].get("address").is_none());
        let mut login = event_alert("gnx.alert.ssh_login", "gvps", "root", "1.2.3.4 by key", false);
        login.address = Some("1.2.3.4".into());
        let body: serde_json::Value = serde_json::from_slice(&event_body(&login, "srv")).unwrap();
        assert_eq!(body["data"]["address"], "1.2.3.4");
        login.at = Some(1_700_000_000);
        let body: serde_json::Value = serde_json::from_slice(&event_body(&login, "srv")).unwrap();
        assert_eq!(body["data"]["at"], 1_700_000_000);
        assert!(plain["data"]["at"].as_i64().unwrap() > 1_700_000_000);
    }

    #[test]
    fn a_non_ascii_title_travels_as_an_encoded_word() {
        assert_eq!(super::header_text("Disk full"), "Disk full");
        assert_eq!(super::header_text("Диск"), "=?UTF-8?B?0JTQuNGB0Lo=?=");
        assert_eq!(super::header_text("a\nb"), "a b");
    }

    #[test]
    fn a_looping_service_reads_plainly_in_both_languages() {
        use crate::health_watch::{Kind, Problem};
        let problem = Problem { id: "service:xray".into(), kind: Kind::Service, subject: "xray".into(), detail: "restarting".into(), reason: String::new() };
        assert_eq!(alert(&problem, true, "vps", true).body, "xray перезапускается по кругу.");
        assert_eq!(alert(&problem, true, "vps", false).body, "xray keeps restarting.");
    }
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn the_signature_verifies_against_the_public_key() {
        let seed = [9u8; 32];
        let message = signed_message("POST", "/v1/servers/abc/events", 1000, b"{}");
        let signing = SigningKey::from_bytes(&seed);
        let signature = signing.sign(&message);
        let key_bytes: [u8; 32] = B64.decode(public_key(&seed)).unwrap().try_into().unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).unwrap();
        assert!(key.verify(&message, &Signature::from_bytes(&signature.to_bytes())).is_ok());
    }

    #[test]
    fn the_message_matches_the_relay_format() {
        let text = String::from_utf8(signed_message("PUT", "/v1/servers/x", 7, b"")).unwrap();
        assert_eq!(text, "PUT\n/v1/servers/x\n7\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn alerts_in_both_languages() {
        let problem = Problem { id: "space:/".into(), kind: Kind::Space, subject: "/".into(), detail: "93".into(), reason: String::new() };
        let en = alert(&problem, true, "orion", false);
        assert_eq!((en.key.as_str(), en.title.as_str(), en.body.as_str()), ("gnx.alert.space", "Disk almost full on orion", "/ is 93% full."));
        let ru = alert(&problem, false, "orion", true);
        assert_eq!((ru.key.as_str(), ru.title.as_str()), ("gnx.alert.space.ok", "Место освободилось на orion"));
        assert_eq!(ru.args, vec!["orion", "/", "93"]);
    }

    #[test]
    fn ntfy_tags_follow_the_kind() {
        assert_eq!((tag("gnx.alert.test"), tag("gnx.alert.raid.ok"), tag("gnx.alert.smart")), ("bell", "white_check_mark", "warning"));
    }

    #[test]
    fn the_event_carries_the_key_and_the_server() {
        let body: serde_json::Value = serde_json::from_slice(&event_body(&test_alert("h", false), "srv")).unwrap();
        assert_eq!(body["data"]["kind"], "gnx.alert.test");
        assert!(body.get("loc_key").is_none());
        assert_eq!(body["data"]["server_id"], "srv");
    }
}
