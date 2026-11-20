//! Writes Mosquitto, Zigbee2MQTT and Home Assistant settings into their files.

use std::path::Path;

use super::app_settings::{is_changed, value};
use super::config_edit::{rewrite, set_conf_line, set_yaml_scalar};
use super::context::Input;
use super::execute::EventSink;
use super::{home_assistant, mosquitto, zigbee2mqtt};
use crate::service_users::docker::{self, Call};

/// The stored value, even when it equals the default
fn stored<'a>(input: &'a Input, key: &str) -> Option<&'a str> {
    input.app_settings.contains_key(key).then(|| value(input, key))
}

/// The broker file; the default text when nothing changed
pub fn mosquitto_conf(input: &Input) -> String {
    let mut text = format!("{}\n", mosquitto::BROKER_CONFIGURATION);
    let mut changed = false;
    for (key, name) in [
        ("mosquitto_max_connections", "max_connections"),
        ("mosquitto_message_size_limit", "message_size_limit"),
        ("mosquitto_persistence", "persistence"),
        ("mosquitto_connection_messages", "connection_messages"),
        ("mosquitto_max_queued", "max_queued_messages"),
        ("mosquitto_client_expiration", "persistent_client_expiration"),
    ] {
        if is_changed(input, key) {
            text = set_conf_line(&text, name, value(input, key));
            changed = true;
        }
    }
    if is_changed(input, "mosquitto_log_level") {
        changed = true;
        match value(input, "mosquitto_log_level") {
            "quiet" => text.push_str("log_type error\nlog_type warning\n"),
            _ => text.push_str("log_type all\n"),
        }
    }
    if !changed {
        return mosquitto::BROKER_CONFIGURATION.to_string();
    }
    text.trim_end_matches('\n').to_string()
}

/// Turns a block's on/off value into `key:` + `enabled:`
fn set_flag(text: &str, key: &str, on: &str) -> String {
    let prefix = format!("{key}:");
    let scalar = text.lines().any(|line| {
        line.strip_prefix(&prefix).is_some_and(|rest| !rest.trim().is_empty() && !rest.trim().starts_with('#'))
    });
    if !scalar {
        return set_yaml_scalar(text, &[key, "enabled"], on);
    }
    let lines: Vec<String> = text
        .lines()
        .flat_map(|line| {
            if line.starts_with(&prefix) {
                vec![prefix.clone(), format!("  enabled: {on}")]
            } else {
                vec![line.to_string()]
            }
        })
        .collect();
    lines.join("\n") + "\n"
}

/// Zigbee2MQTT's settings file with the stored settings applied
pub fn zigbee2mqtt_yaml(input: &Input, text: &str) -> String {
    let mut out = text.to_string();
    for (key, path) in [
        ("zigbee2mqtt_log_level", ["advanced", "log_level"]),
        ("zigbee2mqtt_last_seen", ["advanced", "last_seen"]),
        ("zigbee2mqtt_channel", ["advanced", "channel"]),
    ] {
        if let Some(chosen) = stored(input, key) {
            out = set_yaml_scalar(&out, &path, chosen);
        }
    }
    for (key, name) in [("zigbee2mqtt_homeassistant", "homeassistant"), ("zigbee2mqtt_availability", "availability")] {
        if let Some(chosen) = stored(input, key) {
            out = set_flag(&out, name, chosen);
        }
    }
    out
}

/// Home Assistant's configuration.yaml with the stored settings applied
pub fn home_assistant_yaml(input: &Input, text: &str) -> String {
    let mut out = text.to_string();
    for (key, path) in [
        ("home_assistant_keep_days", ["recorder", "purge_keep_days"]),
        ("home_assistant_commit_interval", ["recorder", "commit_interval"]),
        ("home_assistant_log_level", ["logger", "default"]),
    ] {
        if let Some(chosen) = stored(input, key) {
            out = set_yaml_scalar(&out, &path, chosen);
        }
    }
    out
}

/// Restarts a container and reports it
pub async fn restart(container: &str, sink: &EventSink) {
    match docker::run(&Call::new(&["restart", container])).await {
        Ok(_) => {
            let _ = sink.step(format!("restarted {container} to read its configuration file")).await;
        }
        Err(refusal) => {
            let _ = sink.warn(format!("{container}: configuration file changed but the restart failed ({})", refusal.code())).await;
        }
    }
}

async fn apply_file(path: &Path, container: &str, change: impl Fn(&str) -> String, sink: &EventSink) {
    let Ok(before) = std::fs::read_to_string(path) else { return };
    if change(&before) == before {
        return;
    }
    let _ = docker::run(&Call::new(&["stop", container])).await;
    match rewrite(path, &change) {
        Ok(_) => {
            let _ = sink.step(format!("wrote settings into {}", path.display())).await;
        }
        Err(err) => {
            let _ = sink.warn(format!("{container}: could not write {}: {err}", path.display())).await;
        }
    }
    if let Err(refusal) = docker::run(&Call::new(&["start", container])).await {
        let _ = sink.warn(format!("{container}: did not start again ({})", refusal.code())).await;
    }
}

pub async fn zigbee2mqtt_apply(input: &Input, sink: &EventSink) {
    let path = Path::new(&input.zigbee2mqtt_path).join("data/configuration.yaml");
    apply_file(&path, zigbee2mqtt::CONTAINER, |text| zigbee2mqtt_yaml(input, text), sink).await;
}

pub async fn home_assistant_apply(input: &Input, sink: &EventSink) {
    let path = Path::new(&input.home_assistant_path).join("config/configuration.yaml");
    apply_file(&path, home_assistant::CONTAINER, |text| home_assistant_yaml(input, text), sink).await;
}

#[cfg(test)]
mod tests {
    use super::super::app_settings::accept;
    use super::*;

    fn with(pairs: &[(&str, &str)]) -> Input {
        let map = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Input { app_settings: accept(&map), ..Input::default() }
    }

    const Z2M: &str = "mqtt:\n  server: mqtt://127.0.0.1:1883\n  user: zigbee2mqtt\nserial:\n  port: /dev/ttyACM0\nfrontend:\n  enabled: true\n  host: 127.0.0.1\n  port: 8103\nadvanced:\n  network_key:\n    - 1\n    - 2\n  channel: 11\n";

    #[test]
    fn defaults_leave_every_file_byte_identical() {
        let input = Input::default();
        assert_eq!(mosquitto_conf(&input), mosquitto::BROKER_CONFIGURATION);
        assert_eq!(zigbee2mqtt_yaml(&input, Z2M), Z2M);
        assert_eq!(home_assistant_yaml(&input, home_assistant::INITIAL_CONFIGURATION), home_assistant::INITIAL_CONFIGURATION);
        let written = with(&[("mosquitto_persistence", "true"), ("mosquitto_max_connections", "-1")]);
        assert_eq!(mosquitto_conf(&written), mosquitto::BROKER_CONFIGURATION);
    }

    #[test]
    fn the_broker_file_takes_changed_settings() {
        let input = with(&[
            ("mosquitto_persistence", "false"), ("mosquitto_max_connections", "100"),
            ("mosquitto_message_size_limit", "1048576"), ("mosquitto_log_level", "quiet"),
            ("mosquitto_client_expiration", "1w"),
        ]);
        let text = mosquitto_conf(&input);
        assert!(text.starts_with("listener 1883\nallow_anonymous false\npassword_file /mosquitto/config/passwd\npersistence false\n"));
        for line in ["max_connections 100", "message_size_limit 1048576", "persistent_client_expiration 1w", "log_type error", "log_type warning"] {
            assert!(text.lines().any(|l| l == line), "{line}");
        }
        assert!(!text.ends_with('\n'));
        assert!(mosquitto_conf(&with(&[("mosquitto_log_level", "debug")])).ends_with("log_type all"));
    }

    #[test]
    fn zigbee2mqtt_settings_land_in_their_blocks() {
        let input = with(&[
            ("zigbee2mqtt_log_level", "debug"), ("zigbee2mqtt_last_seen", "epoch"), ("zigbee2mqtt_channel", "20"),
            ("zigbee2mqtt_homeassistant", "true"), ("zigbee2mqtt_availability", "true"),
        ]);
        let out = zigbee2mqtt_yaml(&input, Z2M);
        assert!(out.contains("  channel: 20\n"));
        assert!(out.contains("  log_level: debug\n"));
        assert!(out.contains("  last_seen: epoch\n"));
        assert!(out.contains("homeassistant:\n  enabled: true\n"));
        assert!(out.contains("availability:\n  enabled: true\n"));
        assert!(out.contains("network_key:\n    - 1\n    - 2\n"));
        assert!(!out.contains("permit_join"));
    }

    #[test]
    fn a_legacy_scalar_block_becomes_an_object() {
        let input = with(&[("zigbee2mqtt_homeassistant", "false")]);
        let out = zigbee2mqtt_yaml(&input, "homeassistant: true\nmqtt:\n  server: x\n");
        assert_eq!(out, "homeassistant:\n  enabled: false\nmqtt:\n  server: x\n");
        assert_eq!(zigbee2mqtt_yaml(&input, &out), out);
    }

    #[test]
    fn home_assistant_keeps_its_include_lines() {
        let input = with(&[("home_assistant_keep_days", "30"), ("home_assistant_log_level", "info"), ("home_assistant_commit_interval", "15")]);
        let out = home_assistant_yaml(&input, home_assistant::INITIAL_CONFIGURATION);
        assert!(out.contains("themes: !include_dir_merge_named themes"));
        assert!(out.contains("automation: !include automations.yaml"));
        assert!(out.contains("recorder:\n  purge_keep_days: 30\n  commit_interval: 15\n"));
        assert!(out.contains("logger:\n  default: info\n"));
        assert_eq!(home_assistant_yaml(&input, &out), out);
    }

    #[test]
    fn an_existing_logger_block_keeps_its_other_keys() {
        let input = with(&[("home_assistant_log_level", "debug")]);
        let text = "default_config:\n\nlogger:\n  default: warning\n  logs:\n    homeassistant.core: info\n";
        assert_eq!(home_assistant_yaml(&input, text), "default_config:\n\nlogger:\n  default: debug\n  logs:\n    homeassistant.core: info\n");
    }
}
