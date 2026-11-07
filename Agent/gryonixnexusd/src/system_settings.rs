//! The host's time zone, host name and time sync, driven through systemd.

use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const COMMAND_TIMEOUT_SECS: u64 = 20;
const HOSTS_PATH: &str = "/etc/hosts";
const HOSTNAME_PATH: &str = "/etc/hostname";
const KERNEL_HOSTNAME_PATH: &str = "/proc/sys/kernel/hostname";

pub fn valid_host_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

pub fn valid_time_zone(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 64
        && !zone.starts_with('/')
        && !zone.starts_with('-')
        && !zone.contains("..")
        && zone.split('/').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+'))
        })
}

pub fn set_time_zone_args(zone: &str) -> Vec<String> {
    vec!["set-timezone".into(), zone.into()]
}

pub fn set_host_name_args(name: &str) -> Vec<String> {
    vec!["set-hostname".into(), "--static".into(), name.into()]
}

pub fn set_time_sync_args(enabled: bool) -> Vec<String> {
    vec!["set-ntp".into(), if enabled { "true" } else { "false" }.into()]
}

/// Reads `timedatectl show` output: zone, NTP switch and sync state.
pub fn parse_time_show(output: &str) -> (String, bool, bool) {
    let mut zone = String::new();
    let (mut enabled, mut synchronized) = (false, false);
    for line in output.lines() {
        match line.split_once('=') {
            Some(("Timezone", value)) => zone = value.trim().to_string(),
            Some(("NTP", value)) => enabled = value.trim() == "yes",
            Some(("NTPSynchronized", value)) => synchronized = value.trim() == "yes",
            _ => {}
        }
    }
    (zone, enabled, synchronized)
}

pub fn rewrite_hosts(contents: &str, name: &str) -> String {
    let line = format!("127.0.1.1\t{name}");
    let mut replaced = false;
    let mut lines: Vec<String> = Vec::new();
    for existing in contents.lines() {
        if existing.split_whitespace().next() == Some("127.0.1.1") {
            if !replaced {
                lines.push(line.clone());
            }
            replaced = true;
        } else {
            lines.push(existing.to_string());
        }
    }
    if !replaced {
        lines.push(line);
    }
    lines.join("\n") + "\n"
}

async fn run(program: &str, args: &[String]) -> Result<String, String> {
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run {program}: {err}"))?;
    let output = tokio::time::timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS), child.wait_with_output())
        .await
        .map_err(|_| format!("{program} did not answer in time"))?
        .map_err(|err| format!("{program} failed: {err}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
}

fn current_host_name() -> String {
    [HOSTNAME_PATH, KERNEL_HOSTNAME_PATH]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|text| text.trim().to_string())
        .find(|text| !text.is_empty())
        .unwrap_or_default()
}

async fn known_zones() -> Vec<String> {
    let args = vec!["list-timezones".to_string()];
    let listing = run("timedatectl", &args).await.unwrap_or_default();
    listing.lines().map(str::trim).filter(|zone| !zone.is_empty()).map(String::from).collect()
}

async fn read_settings() -> Result<pb::SystemSettings, String> {
    let args: Vec<String> = ["show", "-p", "Timezone", "-p", "NTP", "-p", "NTPSynchronized"]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
    let (time_zone, ntp_enabled, ntp_synchronized) = parse_time_show(&run("timedatectl", &args).await?);
    Ok(pb::SystemSettings {
        time_zone,
        host_name: current_host_name(),
        ntp_enabled,
        ntp_synchronized,
        time_zones: known_zones().await,
    })
}

fn encode(codec: Codec, result: Result<pb::SystemSettings, String>) -> Resp {
    match result {
        Ok(settings) => codec
            .encode(&settings)
            .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())),
        Err(why) => connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &why),
    }
}

fn rejected(message: &str) -> Resp {
    connect_error(StatusCode::BAD_REQUEST, "invalid_argument", message)
}

pub async fn get(codec: Codec) -> Resp {
    encode(codec, read_settings().await)
}

pub async fn set_time_zone(codec: Codec, req: pb::SetTimeZoneRequest) -> Resp {
    if !valid_time_zone(&req.time_zone) || !known_zones().await.contains(&req.time_zone) {
        return rejected("the time zone is not valid");
    }
    if let Err(why) = run("timedatectl", &set_time_zone_args(&req.time_zone)).await {
        return encode(codec, Err(why));
    }
    encode(codec, read_settings().await)
}

pub async fn set_host_name(codec: Codec, req: pb::SetHostNameRequest) -> Resp {
    if !valid_host_name(&req.host_name) {
        return rejected("the host name is not valid");
    }
    if let Err(why) = run("hostnamectl", &set_host_name_args(&req.host_name)).await {
        return encode(codec, Err(why));
    }
    let _ = update_hosts_file(HOSTS_PATH, &req.host_name);
    encode(codec, read_settings().await)
}

pub async fn set_time_sync(codec: Codec, req: pb::SetTimeSyncRequest) -> Resp {
    if let Err(why) = run("timedatectl", &set_time_sync_args(req.enabled)).await {
        return encode(codec, Err(why));
    }
    encode(codec, read_settings().await)
}

fn update_hosts_file(path: &str, name: &str) -> std::io::Result<()> {
    use std::io::Write;
    let rewritten = rewrite_hosts(&std::fs::read_to_string(path)?, name);
    let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(rewritten.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_follow_rfc_1123_labels() {
        for good in ["orion", "a", "web-01", "0abc", &"a".repeat(63)] {
            assert!(valid_host_name(good), "{good}");
        }
        let long = "a".repeat(64);
        for bad in ["", "-a", "a-", "Orion", "a.b", "a b", "a_b", "a;b", "$(x)", "é", long.as_str()] {
            assert!(!valid_host_name(bad), "{bad}");
        }
    }

    #[test]
    fn time_zones_reject_paths_and_odd_characters() {
        for good in ["UTC", "Europe/Berlin", "America/Argentina/Buenos_Aires", "Etc/GMT+5"] {
            assert!(valid_time_zone(good), "{good}");
        }
        for bad in ["", "/etc/passwd", "../x", "Europe//Berlin", "Europe/Berlin/", "a b", "a;b", "$(x)", "-h"] {
            assert!(!valid_time_zone(bad), "{bad}");
        }
    }

    #[test]
    fn commands_carry_each_value_as_one_argument() {
        assert_eq!(set_time_zone_args("Europe/Berlin"), ["set-timezone", "Europe/Berlin"]);
        assert_eq!(set_host_name_args("orion"), ["set-hostname", "--static", "orion"]);
        assert_eq!(set_time_sync_args(true), ["set-ntp", "true"]);
        assert_eq!(set_time_sync_args(false), ["set-ntp", "false"]);
    }

    #[test]
    fn timedatectl_output_is_read() {
        let shown = "Timezone=Europe/Berlin\nNTP=yes\nNTPSynchronized=no\n";
        assert_eq!(parse_time_show(shown), ("Europe/Berlin".to_string(), true, false));
        assert_eq!(parse_time_show(""), (String::new(), false, false));
    }

    #[test]
    fn the_hosts_line_follows_the_new_name() {
        let before = "127.0.0.1 localhost\n127.0.1.1 old.example.net old\n::1 localhost\n";
        let after = rewrite_hosts(before, "orion");
        assert_eq!(after, "127.0.0.1 localhost\n127.0.1.1\torion\n::1 localhost\n");
        assert_eq!(rewrite_hosts(&after, "orion"), after);
    }

    #[test]
    fn a_missing_hosts_line_is_added() {
        assert_eq!(rewrite_hosts("127.0.0.1 localhost\n", "orion"), "127.0.0.1 localhost\n127.0.1.1\torion\n");
    }

    #[test]
    fn the_hosts_file_is_rewritten_in_place() {
        let dir = std::env::temp_dir().join(format!("hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n127.0.1.1 old\n").unwrap();
        update_hosts_file(path.to_str().unwrap(), "orion").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "127.0.0.1 localhost\n127.0.1.1\torion\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
