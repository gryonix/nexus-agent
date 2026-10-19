//! SSH sign-in alerts: follows sshd's journal as it is written.
//!
//! Sign-ins with an app's own key stay quiet. Until an app sends
//! its key, the control user's sign-ins stay quiet too.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::notify::{self, Config};
use crate::notify_send::{self, Sent};
use crate::pb;
use crate::state::Store;

const FIRST_LOOK: Duration = Duration::from_secs(5);
/// How often settings are re-read while following
const RECHECK: Duration = Duration::from_secs(20);
const RESTART_PAUSE: Duration = Duration::from_secs(5);
const ALERTS_PER_LOOK: usize = 5;
/// Window in which at most a few alerts go out
const FLOOD_WINDOW_SECS: i64 = 60;
const QUIET_KEYS_KEPT: usize = 16;
const SUDOERS_DIR: &str = "/etc/sudoers.d";

/// One accepted sshd sign-in
#[derive(Clone, Debug, PartialEq)]
pub struct SignIn {
    pub user: String,
    pub ip: String,
    pub method: String,
    pub fingerprint: String,
}

/// `Accepted METHOD for USER from IP …` lines, local ones skipped
pub fn sign_ins(journal: &str) -> Vec<SignIn> {
    journal.lines().filter_map(parse_line).filter(|s| s.ip != "127.0.0.1" && s.ip != "::1").collect()
}

fn parse_line(line: &str) -> Option<SignIn> {
    let rest = &line[line.find("Accepted ")?..];
    let mut words = rest.split_whitespace().skip(1);
    let method = words.next()?.to_string();
    (words.next()? == "for").then_some(())?;
    let user = words.next()?.to_string();
    (words.next()? == "from").then_some(())?;
    let ip = words.next()?.to_string();
    let fingerprint = rest.split_whitespace().find(|w| w.starts_with("SHA256:")).unwrap_or_default().to_string();
    Some(SignIn { user, ip, method, fingerprint })
}

/// The `SHA256:…` fingerprint sshd logs for a public key
pub fn fingerprint(public_key: &str) -> Option<String> {
    let blob = STANDARD.decode(public_key.split_whitespace().nth(1)?).ok()?;
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))))
}

/// Keeps an app key, without its comment
pub fn remember_key(keys: &mut Vec<String>, public_key: &str) {
    if fingerprint(public_key).is_none() {
        return;
    }
    let key: String = public_key.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    keys.retain(|k| *k != key);
    keys.push(key);
    let excess = keys.len().saturating_sub(QUIET_KEYS_KEPT);
    keys.drain(..excess);
}

/// Whether a sign-in is the app's own connection
pub fn is_quiet(sign_in: &SignIn, quiet_fingerprints: &[String], control_users: &[String]) -> bool {
    if quiet_fingerprints.is_empty() {
        return control_users.contains(&sign_in.user);
    }
    quiet_fingerprints.contains(&sign_in.fingerprint)
}

/// Sign-ins worth an alert, at most a few
pub fn to_report(found: Vec<SignIn>, quiet_keys: &[String], control_users: &[String]) -> Vec<SignIn> {
    let quiet: Vec<String> = quiet_keys.iter().filter_map(|k| fingerprint(k)).collect();
    let loud = found.into_iter().filter(|s| !is_quiet(s, &quiet, control_users));
    loud.take(ALERTS_PER_LOOK).collect()
}

/// Users the app's sudoers drop-ins name
pub fn control_users() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(SUDOERS_DIR) else { return Vec::new() };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("gryonixnexus-"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|text| crate::install::host::provision::control_user(&text))
        .collect()
}

/// How the sign-in proved itself, in words
pub fn method_words(method: &str, russian: bool) -> String {
    match (method, russian) {
        ("publickey", false) => "by key".into(),
        ("publickey", true) => "по ключу".into(),
        (m, false) if m == "password" || m.starts_with("keyboard-interactive") => "by password".into(),
        (m, true) if m == "password" || m.starts_with("keyboard-interactive") => "по паролю".into(),
        (m, false) => format!("via {m}"),
        (m, true) => format!("через {m}"),
    }
}

/// Arguments that follow sshd from the saved position
pub fn follow_args(cursor: &str, checked_at: i64) -> Vec<String> {
    let mut args: Vec<String> =
        ["-f", "-o", "json", "--no-pager", "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"]
            .map(String::from)
            .to_vec();
    if !cursor.is_empty() {
        args.extend(["--after-cursor".to_string(), cursor.to_string()]);
    } else if checked_at > 0 {
        args.extend(["--since".to_string(), format!("@{checked_at}")]);
    } else {
        args.extend(["-n".to_string(), "0".to_string()]);
    }
    args
}

/// One JSON journal line: message, cursor, unix seconds
pub fn entry(line: &str) -> Option<(String, String, i64)> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let cursor = value["__CURSOR"].as_str()?.to_string();
    let micros = value["__REALTIME_TIMESTAMP"].as_str().and_then(|t| t.parse::<i64>().ok());
    let at = micros.map_or_else(notify::now, |m| m / 1_000_000);
    Some((value["MESSAGE"].as_str().unwrap_or_default().to_string(), cursor, at))
}

/// Whether an alert may go out now, floods capped
pub fn admit(recent: &mut Vec<i64>, now: i64) -> bool {
    recent.retain(|at| now - at < FLOOD_WINDOW_SECS);
    if recent.len() >= ALERTS_PER_LOOK {
        return false;
    }
    recent.push(now);
    true
}

fn watching(config: &Config) -> bool {
    config.ssh_logins && config.channel() != pb::NotifyChannel::Off
}

/// Sends one sign-in unless it is the app's own
async fn report(store: &Arc<Mutex<Store>>, sign_in: SignIn, at: i64) {
    let mut config = notify::load(store);
    if to_report(vec![sign_in.clone()], &config.quiet_keys, &control_users()).is_empty() {
        return;
    }
    let detail = format!("{} {}", sign_in.ip, method_words(&sign_in.method, config.russian()));
    let mut alert = notify_send::event_alert("gnx.alert.ssh_login", &notify::host(), &sign_in.user, &detail, config.russian());
    alert.address = Some(sign_in.ip.clone());
    alert.at = Some(at);
    let sent = notify::deliver(&mut config, &alert).await;
    notify::record(&mut config, &sent);
    if let Sent::Failed(why) = &sent {
        tracing::warn!("ssh sign-in notification not sent: {why}");
    }
    let mut latest = notify::load(store);
    latest.last_error = config.last_error;
    latest.relay_maintenance = config.relay_maintenance;
    latest.registered_at = config.registered_at;
    latest.server_id = config.server_id;
    latest.seed = config.seed;
    notify::save(store, &latest);
}

/// Saves the journal position
fn save_position(store: &Arc<Mutex<Store>>, cursor: Option<String>) {
    let mut latest = notify::load(store);
    if let Some(cursor) = cursor {
        latest.ssh_cursor = cursor;
    }
    latest.ssh_checked_at = notify::now();
    notify::save(store, &latest);
}

/// Follows the journal while alerts stay on
async fn follow(store: &Arc<Mutex<Store>>, config: &Config) {
    use tokio::io::AsyncBufReadExt;
    let Ok(mut child) = tokio::process::Command::new("journalctl")
        .args(follow_args(&config.ssh_cursor, config.ssh_checked_at))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return;
    };
    let Some(out) = child.stdout.take() else { return };
    let mut lines = tokio::io::BufReader::new(out).lines();
    let mut recent = Vec::new();
    let mut unsaved: Option<String> = None;
    let mut tick = tokio::time::interval(RECHECK);
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { break };
                let Some((message, cursor, at)) = entry(&line) else { continue };
                unsaved = Some(cursor);
                for sign_in in sign_ins(&message) {
                    if admit(&mut recent, notify::now()) {
                        report(store, sign_in, at).await;
                        save_position(store, unsaved.take());
                    }
                }
            }
            _ = tick.tick() => {
                save_position(store, unsaved.take());
                if !watching(&notify::load(store)) {
                    break;
                }
            }
        }
    }
    save_position(store, unsaved);
}

/// Turning alerts on later starts from that moment
fn forget_position(store: &Arc<Mutex<Store>>) {
    let mut latest = notify::load(store);
    latest.ssh_cursor.clear();
    latest.ssh_checked_at = 0;
    notify::save(store, &latest);
}

pub fn spawn(store: Arc<Mutex<Store>>) {
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_LOOK).await;
        loop {
            let config = notify::load(&store);
            if watching(&config) {
                follow(&store, &config).await;
                tokio::time::sleep(RESTART_PAUSE).await;
                continue;
            }
            if !config.ssh_cursor.is_empty() || config.ssh_checked_at != 0 {
                forget_position(&store);
            }
            tokio::time::sleep(RECHECK).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMjhZbMLa1yPZt87ATUHLO4OUNZoQu6+22Re+KW7HKUl phone";
    const KEY_PRINT: &str = "SHA256:ta89y9+snohktxGwZFLoH2WPhSVEShH7e4s79HEcJqo";

    fn sign_in(user: &str, ip: &str, method: &str, print: &str) -> SignIn {
        SignIn { user: user.into(), ip: ip.into(), method: method.into(), fingerprint: print.into() }
    }

    #[test]
    fn sshd_lines_are_read_and_local_ones_skipped() {
        let journal = format!(
            "Accepted publickey for admin from 192.168.178.20 port 50212 ssh2: ED25519 {KEY_PRINT}\n\
             Failed password for root from 1.2.3.4 port 1 ssh2\n\
             Accepted password for bob from 2a02:8108::1 port 2 ssh2\n\
             Accepted publickey for admin from 127.0.0.1 port 3 ssh2: ED25519 SHA256:x\n\
             -- cursor: s=abc;i=1\n"
        );
        assert_eq!(sign_ins(&journal), vec![
            sign_in("admin", "192.168.178.20", "publickey", KEY_PRINT),
            sign_in("bob", "2a02:8108::1", "password", ""),
        ]);
    }

    #[test]
    fn the_fingerprint_matches_ssh_keygen() {
        assert_eq!(fingerprint(KEY).as_deref(), Some(KEY_PRINT));
        assert_eq!(fingerprint("not a key"), None);
    }

    #[test]
    fn app_keys_are_kept_once_without_comment() {
        let mut keys = Vec::new();
        remember_key(&mut keys, KEY);
        remember_key(&mut keys, KEY);
        remember_key(&mut keys, "");
        assert_eq!(keys, vec![KEY.trim_end_matches(" phone").to_string()]);
    }

    #[test]
    fn the_apps_own_sign_ins_stay_quiet() {
        let app = sign_in("server-user", "10.0.0.2", "publickey", KEY_PRINT);
        let owner = sign_in("server-user", "10.0.0.2", "publickey", "SHA256:other");
        let users = vec!["server-user".to_string()];
        assert!(is_quiet(&owner, &[], &users), "before any app key, the control user is quiet");
        assert!(is_quiet(&app, &[KEY_PRINT.to_string()], &users));
        assert!(!is_quiet(&owner, &[KEY_PRINT.to_string()], &users));
    }

    #[test]
    fn repeats_all_count_and_the_count_is_capped() {
        let mut found = vec![sign_in("bob", "1.1.1.1", "password", ""); 3];
        found.extend((0..9).map(|i| sign_in("eve", &format!("2.2.2.{i}"), "password", "")));
        found.push(sign_in("server-user", "3.3.3.3", "publickey", KEY_PRINT));
        let report = to_report(found, &[KEY.to_string()], &[]);
        assert_eq!(report.len(), ALERTS_PER_LOOK);
        assert_eq!(report.iter().filter(|s| s.user == "bob").count(), 3);
        assert!(report.iter().all(|s| s.user != "server-user"));
    }

    #[test]
    fn journal_entries_are_read_and_methods_read_plainly() {
        let line = r#"{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1700000000123456","MESSAGE":"Accepted password for bob from 1.2.3.4 port 2 ssh2"}"#;
        let (message, cursor, at) = entry(line).unwrap();
        assert_eq!(cursor, "s=1;i=2");
        assert_eq!(at, 1_700_000_000);
        assert_eq!(sign_ins(&message), vec![sign_in("bob", "1.2.3.4", "password", "")]);
        assert_eq!(entry("not json"), None);
        assert_eq!(entry(r#"{"MESSAGE":"x"}"#), None);
        assert_eq!(method_words("publickey", true), "по ключу");
        assert_eq!(method_words("keyboard-interactive/pam", false), "by password");
    }

    #[test]
    fn following_starts_where_it_stopped_or_from_now() {
        assert!(follow_args("s=1", 0).ends_with(&["--after-cursor".to_string(), "s=1".to_string()]));
        assert!(follow_args("", 1700).ends_with(&["--since".to_string(), "@1700".to_string()]));
        let fresh = follow_args("", 0);
        assert!(fresh.contains(&"-f".to_string()) && fresh.ends_with(&["-n".to_string(), "0".to_string()]));
    }

    #[test]
    fn every_sign_in_alerts_until_the_flood_cap() {
        let mut recent = Vec::new();
        assert!(admit(&mut recent, 100));
        assert!(admit(&mut recent, 105));
        for at in [106, 107, 108] {
            assert!(admit(&mut recent, at));
        }
        assert!(!admit(&mut recent, 109));
        assert!(!admit(&mut recent, 159));
        assert!(admit(&mut recent, 161));
        assert_eq!(recent.len(), ALERTS_PER_LOOK);
    }
}
