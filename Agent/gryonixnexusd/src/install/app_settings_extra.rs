//! More app settings, all plain compose environment lines.
//! Each line appears only when the value differs from the default.

use super::app_settings::{self, Allowed, Spec, Validator};
use super::context::Input;

const KEEP_ALIVE: &[&str] = &["5m", "30m", "1h", "24h", "-1"];
const LOADED_MODELS: &[&str] = &["0", "1", "2", "3", "4"];
const PARALLEL: &[&str] = &["0", "1", "2", "4"];
pub const TIMEZONES: &[&str] = &[
    "UTC", "Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Madrid", "Europe/Kiev", "Europe/Moscow",
    "America/New_York", "America/Chicago", "America/Los_Angeles", "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney",
];
const PRUNE_AGES: &[&str] = &["168", "336", "720", "2160"];
const LOCALES: &[&str] = &["en", "de"];
const LOG_LEVELS: &[&str] = &["verbose", "debug", "log", "warn", "error"];

pub const SPECS: &[Spec] = &[
    Spec { key: "ollama_keep_alive", default: "5m", allowed: Allowed::Choices(KEEP_ALIVE) },
    Spec { key: "ollama_max_loaded_models", default: "0", allowed: Allowed::Choices(LOADED_MODELS) },
    Spec { key: "ollama_num_parallel", default: "0", allowed: Allowed::Choices(PARALLEL) },
    Spec { key: "ollama_flash_attention", default: "false", allowed: Allowed::Switch },
    Spec { key: "n8n_timezone", default: "UTC", allowed: Allowed::Choices(TIMEZONES) },
    Spec { key: "n8n_prune_executions", default: "true", allowed: Allowed::Switch },
    Spec { key: "n8n_prune_max_age", default: "336", allowed: Allowed::Choices(PRUNE_AGES) },
    Spec { key: "n8n_locale", default: "en", allowed: Allowed::Choices(LOCALES) },
    Spec { key: "passbolt_registration_public", default: "false", allowed: Allowed::Switch },
    Spec { key: "photoprism_readonly", default: "false", allowed: Allowed::Switch },
    Spec { key: "photoprism_disable_webdav", default: "false", allowed: Allowed::Switch },
    Spec { key: "photoprism_disable_settings", default: "false", allowed: Allowed::Switch },
    Spec { key: "photoprism_detect_nsfw", default: "false", allowed: Allowed::Switch },
    Spec { key: "photoprism_upload_nsfw", default: "false", allowed: Allowed::Switch },
    Spec { key: "immich_log_level", default: "log", allowed: Allowed::Choices(LOG_LEVELS) },
    Spec { key: "jellyfin_published_url", default: "", allowed: Allowed::Text(200, Validator::Line) },
    Spec { key: "anythingllm_disable_telemetry", default: "false", allowed: Allowed::Switch },
];

fn line(name: &str, value: &str) -> String {
    format!("\n      {name}: \"{value}\"")
}

/// The line for a choice that differs from its default
fn changed(input: &Input, key: &str, name: &str) -> String {
    if app_settings::is_changed(input, key) { line(name, app_settings::value(input, key)) } else { String::new() }
}

fn when_on(input: &Input, key: &str, name: &str, shown: &str) -> String {
    if app_settings::is_on(input, key) { line(name, shown) } else { String::new() }
}

pub fn ollama_lines(input: &Input) -> String {
    changed(input, "ollama_keep_alive", "OLLAMA_KEEP_ALIVE")
        + &changed(input, "ollama_max_loaded_models", "OLLAMA_MAX_LOADED_MODELS")
        + &changed(input, "ollama_num_parallel", "OLLAMA_NUM_PARALLEL")
        + &when_on(input, "ollama_flash_attention", "OLLAMA_FLASH_ATTENTION", "1")
}

pub fn n8n_timezone(input: &Input) -> String {
    app_settings::value(input, "n8n_timezone").to_string()
}

/// Pruning, age and language lines, after the time zone
pub fn n8n_lines(input: &Input) -> String {
    let prune = if app_settings::is_on(input, "n8n_prune_executions") {
        String::new()
    } else {
        line("EXECUTIONS_DATA_PRUNE", "false")
    };
    prune
        + &changed(input, "n8n_prune_max_age", "EXECUTIONS_DATA_MAX_AGE")
        + &changed(input, "n8n_locale", "N8N_DEFAULT_LOCALE")
}

pub fn passbolt_lines(input: &Input) -> String {
    when_on(input, "passbolt_registration_public", "PASSBOLT_REGISTRATION_PUBLIC", "true")
}

pub fn photoprism_lines(input: &Input) -> String {
    [
        ("photoprism_readonly", "PHOTOPRISM_READONLY"),
        ("photoprism_disable_webdav", "PHOTOPRISM_DISABLE_WEBDAV"),
        ("photoprism_disable_settings", "PHOTOPRISM_DISABLE_SETTINGS"),
        ("photoprism_detect_nsfw", "PHOTOPRISM_DETECT_NSFW"),
        ("photoprism_upload_nsfw", "PHOTOPRISM_UPLOAD_NSFW"),
    ]
    .iter()
    .map(|(key, name)| when_on(input, key, name, "true"))
    .collect()
}

pub fn immich_lines(input: &Input) -> String {
    changed(input, "immich_log_level", "IMMICH_LOG_LEVEL")
}

pub fn jellyfin_url(input: &Input, hostname: &str) -> String {
    match app_settings::value(input, "jellyfin_published_url") {
        "" => format!("https://{hostname}"),
        custom => custom.to_string(),
    }
}

pub fn anythingllm_lines(input: &Input) -> String {
    when_on(input, "anythingllm_disable_telemetry", "DISABLE_TELEMETRY", "true")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn input(pairs: &[(&str, &str)]) -> Input {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Input { app_settings: app_settings::accept(&map), ..Input::default() }
    }

    #[test]
    fn defaults_emit_nothing() {
        let none = Input::default();
        assert_eq!(ollama_lines(&none), "");
        assert_eq!(n8n_lines(&none), "");
        assert_eq!(n8n_timezone(&none), "UTC");
        assert_eq!(passbolt_lines(&none) + &photoprism_lines(&none) + &immich_lines(&none), "");
        assert_eq!(anythingllm_lines(&none), "");
        assert_eq!(jellyfin_url(&none, "h.example.com"), "https://h.example.com");
    }

    #[test]
    fn a_default_written_out_emits_nothing() {
        assert_eq!(ollama_lines(&input(&[("ollama_keep_alive", "5m"), ("n8n_prune_executions", "true")])), "");
    }

    #[test]
    fn changed_values_become_environment_lines() {
        let text = ollama_lines(&input(&[("ollama_keep_alive", "-1"), ("ollama_flash_attention", "true")]));
        assert_eq!(text, "\n      OLLAMA_KEEP_ALIVE: \"-1\"\n      OLLAMA_FLASH_ATTENTION: \"1\"");
        let n8n = n8n_lines(&input(&[("n8n_prune_executions", "false"), ("n8n_locale", "de")]));
        assert_eq!(n8n, "\n      EXECUTIONS_DATA_PRUNE: \"false\"\n      N8N_DEFAULT_LOCALE: \"de\"");
    }

    #[test]
    fn bad_choices_are_dropped() {
        let bad = input(&[("n8n_timezone", "Mars/Base"), ("immich_log_level", "trace"), ("ollama_num_parallel", "3")]);
        assert!(bad.app_settings.is_empty());
    }

    #[test]
    fn a_custom_jellyfin_address_replaces_the_host_name() {
        let custom = input(&[("jellyfin_published_url", "http://10.0.0.5:8096")]);
        assert_eq!(jellyfin_url(&custom, "x"), "http://10.0.0.5:8096");
    }
}
