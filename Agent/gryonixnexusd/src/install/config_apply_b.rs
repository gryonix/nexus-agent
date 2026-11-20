//! Writes Headscale and Authelia settings into their config files.

use std::path::{Path, PathBuf};

use super::app_settings::{is_changed, value};
use super::config_edit::set_yaml_scalar;
use super::context::Input;
use super::execute::EventSink;
use crate::service_users::docker::{self, Call};

const HEADSCALE_KEYS: &[(&str, &[&str])] = &[
    ("headscale_log_level", &["log", "level"]),
    ("headscale_magic_dns", &["dns", "magic_dns"]),
    ("headscale_node_expiry", &["node", "expiry"]),
    ("headscale_ephemeral_timeout", &["node", "ephemeral", "inactivity_timeout"]),
    ("headscale_ip_allocation", &["prefixes", "allocation"]),
    ("headscale_taildrop", &["taildrop", "enabled"]),
];

const AUTHELIA_KEYS: &[(&str, &[&str])] = &[
    ("authelia_theme", &["theme"]),
    ("authelia_log_level", &["log", "level"]),
    ("authelia_session_expiration", &["session", "expiration"]),
    ("authelia_session_inactivity", &["session", "inactivity"]),
    ("authelia_remember_me", &["session", "remember_me"]),
    ("authelia_max_retries", &["regulation", "max_retries"]),
    ("authelia_ban_time", &["regulation", "ban_time"]),
];

const STAMP_FILE: &str = ".gnx-applied-config";

fn apply_keys(text: &str, input: &Input, keys: &[(&str, &[&str])]) -> String {
    let mut out = text.to_string();
    for (key, path) in keys {
        if is_changed(input, key) {
            out = set_yaml_scalar(&out, path, value(input, key));
        }
    }
    out
}

/// Headscale config with the changed settings applied
pub fn headscale_yaml(text: String, input: &Input) -> String {
    apply_keys(&text, input, HEADSCALE_KEYS)
}

/// Authelia config with the changed settings applied
pub fn authelia_yaml(text: String, input: &Input) -> String {
    apply_keys(&text, input, AUTHELIA_KEYS)
}

fn any_changed(input: &Input, keys: &[(&str, &[&str])]) -> bool {
    keys.iter().any(|(key, _)| is_changed(input, key))
}

/// True when the file moved from what the service runs
pub fn restart_due(current: &str, stamp: Option<&str>, has_changes: bool) -> bool {
    match stamp {
        Some(previous) => previous != current,
        None => has_changes,
    }
}

async fn restart_when_due(name: &str, container: &str, config: &Path, dir: &Path, has_changes: bool, sink: &EventSink) {
    let Ok(current) = std::fs::read_to_string(config) else { return };
    let stamp_path: PathBuf = dir.join(STAMP_FILE);
    let stamp = std::fs::read_to_string(&stamp_path).ok();
    if !restart_due(&current, stamp.as_deref(), has_changes) {
        if stamp.is_none() {
            let _ = std::fs::write(&stamp_path, &current);
        }
        return;
    }
    match docker::run(&Call::new(&["restart", container])).await {
        Ok(_) => {
            let _ = std::fs::write(&stamp_path, &current);
            let _ = sink.step(format!("restarted {name} to load its configuration file")).await;
        }
        Err(refusal) => {
            let _ = sink
                .warn(format!("{name}: configuration file settings are written but it could not be restarted ({}); restart it once it is up", refusal.code()))
                .await;
        }
    }
}

pub async fn headscale(input: &Input, sink: &EventSink) {
    let dir = Path::new(&input.headscale_path);
    let config = dir.join("config").join("config.yaml");
    restart_when_due("Headscale", super::headscale::CONTAINER, &config, dir, any_changed(input, HEADSCALE_KEYS), sink).await;
}

pub async fn authelia(input: &Input, sink: &EventSink) {
    let dir = Path::new(&input.authelia_path);
    let config = dir.join("config").join("configuration.yml");
    restart_when_due("Authelia", super::authelia::CONTAINER, &config, dir, any_changed(input, AUTHELIA_KEYS), sink).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::app_settings::accept;
    use std::collections::HashMap;

    fn with(pairs: &[(&str, &str)]) -> Input {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        input.app_settings = accept(&map);
        assert_eq!(input.app_settings.len(), pairs.len());
        input
    }

    #[test]
    fn defaults_leave_the_headscale_file_byte_identical() {
        let plain = super::super::headscale::config_yaml(&Input { domain: "example.com".to_string(), ..Input::default() });
        let stored = with(&[("headscale_log_level", "info"), ("headscale_node_expiry", "0"), ("headscale_taildrop", "true")]);
        assert_eq!(super::super::headscale::config_yaml(&stored), plain);
    }

    #[test]
    fn headscale_values_land_in_their_own_blocks() {
        let input = with(&[
            ("headscale_log_level", "debug"), ("headscale_magic_dns", "false"), ("headscale_node_expiry", "90d"),
            ("headscale_ephemeral_timeout", "1h"), ("headscale_ip_allocation", "random"), ("headscale_taildrop", "false"),
        ]);
        let yaml = super::super::headscale::config_yaml(&input);
        assert!(yaml.contains("log:\n  level: debug\n"));
        assert!(yaml.contains("dns:\n  magic_dns: false\n"));
        assert!(yaml.contains("node:\n  expiry: 90d\n  ephemeral:\n    inactivity_timeout: 1h\n"));
        assert!(yaml.contains("  allocation: random\n"));
        assert!(yaml.ends_with("taildrop:\n  enabled: false\n"));
        assert!(yaml.contains("derp:\n  server:\n"));
        assert!(yaml.contains("    enabled: true\n    region_id: 999"));
    }

    #[test]
    fn defaults_leave_the_authelia_file_byte_identical() {
        let services = vec!["authelia".to_string()];
        let plain = super::super::authelia::configuration_yaml(&Input { domain: "example.com".to_string(), ..Input::default() }, &services);
        let stored = with(&[("authelia_theme", "light"), ("authelia_ban_time", "5m"), ("authelia_remember_me", "1M")]);
        assert_eq!(super::super::authelia::configuration_yaml(&stored, &services), plain);
    }

    #[test]
    fn authelia_values_land_in_their_own_blocks() {
        let input = with(&[
            ("authelia_theme", "dark"), ("authelia_log_level", "debug"), ("authelia_session_expiration", "12h"),
            ("authelia_session_inactivity", "1h"), ("authelia_remember_me", "-1"), ("authelia_max_retries", "10"),
            ("authelia_ban_time", "1d"),
        ]);
        let yaml = super::super::authelia::configuration_yaml(&input, &["authelia".to_string()]);
        assert!(yaml.starts_with("---\ntheme: dark\n"));
        assert!(yaml.contains("log:\n  level: debug\n"));
        assert!(yaml.contains("      authelia_url: 'https://auth.example.com'\n  expiration: 12h\n  inactivity: 1h\n  remember_me: -1\n"));
        assert!(yaml.contains("storage:"));
        assert!(yaml.ends_with("regulation:\n  max_retries: 10\n  ban_time: 1d\n"));
        assert!(yaml.contains("notifier:\n"));
    }

    #[test]
    fn a_restart_is_due_only_when_the_file_moved_from_what_ran() {
        assert!(!restart_due("a", None, false));
        assert!(restart_due("a", None, true));
        assert!(!restart_due("a", Some("a"), true));
        assert!(restart_due("b", Some("a"), false));
    }
}
