//! Writes app settings into Seafile, Psono, SearXNG and LiteLLM config files.

use std::path::Path;

use super::app_settings::{is_on, value};
use super::config_edit::{rewrite, set_py_assign, set_yaml_scalar};
use super::context::Input;
use super::execute::EventSink;
use super::{litellm, psono, searxng, seafile};
use crate::service_users::docker::{self, Call};

fn stored(input: &Input, key: &str) -> bool {
    input.app_settings.contains_key(key)
}

fn py_bool(on: bool) -> &'static str {
    if on { "True" } else { "False" }
}

/// Seahub settings lines for every stored Seafile setting
pub fn seafile_settings(text: &str, input: &Input) -> String {
    let mut out = text.to_string();
    let mut put = |key: &str, literal: String| out = set_py_assign(&out, key, &literal);
    let name = value(input, "seafile_site_name");
    if stored(input, "seafile_site_name") && !name.is_empty() {
        put("SITE_NAME", format!("'{name}'"));
    }
    let plain = [
        ("seafile_language", "LANGUAGE_CODE", "'"),
        ("seafile_timezone", "TIME_ZONE", "'"),
        ("seafile_share_link_expire_days", "SHARE_LINK_EXPIRE_DAYS_DEFAULT", ""),
        ("seafile_login_remember_days", "LOGIN_REMEMBER_DAYS", ""),
    ];
    for (key, setting, quote) in plain {
        if stored(input, key) {
            put(setting, format!("{quote}{}{quote}", value(input, key)));
        }
    }
    if stored(input, "seafile_enable_signup") {
        put("ENABLE_SIGNUP", py_bool(is_on(input, "seafile_enable_signup")).to_string());
    }
    if stored(input, "seafile_file_preview_mb") {
        put("FILE_PREVIEW_MAX_SIZE", format!("{} * 1024 * 1024", value(input, "seafile_file_preview_mb")));
    }
    out
}

fn yaml_list(csv: &str) -> String {
    let items: Vec<String> = csv.split(',').map(str::trim).filter(|item| !item.is_empty()).map(|item| format!("'{item}'")).collect();
    format!("[{}]", items.join(", "))
}

/// Psono settings.yaml with every stored Psono setting applied
pub fn psono_settings(text: &str, input: &Input) -> String {
    let mut out = text.to_string();
    let mut put = |key: &str, literal: String| out = set_yaml_scalar(&out, &[key], &literal);
    let switches = [
        ("psono_allow_registration", "ALLOW_REGISTRATION"),
        ("psono_allow_lost_password", "ALLOW_LOST_PASSWORD"),
        ("psono_enforce_matching_email", "ENFORCE_MATCHING_USERNAME_AND_EMAIL"),
        ("psono_user_search_by_email", "ALLOW_USER_SEARCH_BY_EMAIL"),
    ];
    for (key, setting) in switches {
        if stored(input, key) {
            put(setting, py_bool(is_on(input, key)).to_string());
        }
    }
    let numbers = [("psono_session_seconds", "DEFAULT_TOKEN_TIME_VALID")];
    for (key, setting) in numbers {
        if stored(input, key) {
            put(setting, value(input, key).to_string());
        }
    }
    if stored(input, "psono_registration_domains") {
        put("REGISTRATION_EMAIL_FILTER", yaml_list(value(input, "psono_registration_domains")));
    }
    out
}

/// SearXNG settings.yml with the stored search settings added
pub fn searxng_settings(base: String, input: &Input) -> String {
    let mut out = base;
    let safe = value(input, "searxng_safe_search");
    if safe != "0" {
        out += &format!("\n  safe_search: {safe}");
    }
    let complete = value(input, "searxng_autocomplete");
    if complete != "off" {
        out += &format!("\n  autocomplete: \"{complete}\"");
    }
    let language = value(input, "searxng_default_lang");
    if language != "none" {
        out += &format!("\n  default_lang: \"{language}\"");
    }
    let name = value(input, "searxng_instance_name");
    if !name.is_empty() {
        out += &format!("\n\ngeneral:\n  instance_name: \"{name}\"");
    }
    if is_on(input, "searxng_image_proxy") {
        out += "\n\nserver:\n  image_proxy: true";
    }
    out
}

/// LiteLLM config.yaml with the stored proxy settings added
pub fn litellm_config(base: String, input: &Input) -> String {
    let mut out = base;
    if is_on(input, "litellm_disable_spend_logs") {
        out += "\n  disable_spend_logs: true";
    }
    let mut lines = Vec::new();
    if is_on(input, "litellm_drop_params") {
        lines.push("  drop_params: true".to_string());
    }
    let timeout = value(input, "litellm_request_timeout");
    if timeout != "6000" {
        lines.push(format!("  request_timeout: {timeout}"));
    }
    let retries = value(input, "litellm_num_retries");
    if retries != "0" {
        lines.push(format!("  num_retries: {retries}"));
    }
    if is_on(input, "litellm_json_logs") {
        lines.push("  json_logs: true".to_string());
    }
    if !lines.is_empty() {
        out += &format!("\nlitellm_settings:\n{}", lines.join("\n"));
    }
    out
}

async fn restart(container: &str, name: &str, sink: &EventSink) {
    match docker::run(&Call::new(&["restart", container])).await {
        Ok(_) => {
            let _ = sink.step(format!("restarted {name} to read its configuration file")).await;
        }
        Err(refusal) => {
            let _ = sink.warn(format!("{name}: configuration file written but the restart failed ({})", refusal.code())).await;
        }
    }
}

/// Restarts a container when its regenerated file changed
pub async fn restart_if_changed(container: &str, name: &str, before: Option<&str>, after: &str, sink: &EventSink) {
    if before.is_some_and(|old| old.trim_end() != after.trim_end()) {
        restart(container, name, sink).await;
    }
}

async fn edit_file(path: &Path, container: &str, name: &str, sink: &EventSink, change: impl FnOnce(&str) -> String) {
    match rewrite(path, change) {
        Ok(true) => restart(container, name, sink).await,
        Ok(false) => {}
        Err(err) => {
            let _ = sink.warn(format!("{name}: could not update {} ({err}); re-apply once it is up", path.display())).await;
        }
    }
}

fn any_stored(input: &Input, prefix: &str) -> bool {
    input.app_settings.keys().any(|key| key.starts_with(prefix))
}

/// Applies config file settings for one service after its install
pub async fn after_install(label: &str, input: &Input, sink: &EventSink) {
    match label {
        seafile::SERVICE_ID if any_stored(input, "seafile_") => {
            let path = Path::new(&seafile::data_path(input)).join(seafile::SEAHUB_SETTINGS_RELATIVE_PATH);
            edit_file(&path, seafile::CONTAINER, "Seafile", sink, |text| seafile_settings(text, input)).await;
        }
        psono::SERVICE_ID if any_stored(input, "psono_") => {
            let path = std::path::PathBuf::from(psono::settings_path(input));
            edit_file(&path, psono::CONTAINER, "Psono", sink, |text| psono_settings(text, input)).await;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(pairs: &[(&str, &str)]) -> Input {
        let mut input = Input::default();
        input.app_settings = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        input
    }

    const SEAHUB: &str = "SECRET_KEY = \"abc\"\nSITE_BASE = 'http://x'\nTIME_ZONE = 'Etc/UTC'\nFILE_SERVER_ROOT = 'https://s/seafhttp'\nCSRF_TRUSTED_ORIGINS = ['https://s']\n";

    #[test]
    fn seafile_defaults_stored_nothing_change_nothing() {
        assert_eq!(seafile_settings(SEAHUB, &Input::default()), SEAHUB);
    }

    #[test]
    fn seafile_values_replace_or_append_python_assignments() {
        let input = with(&[
            ("seafile_site_name", "Our Files"), ("seafile_language", "de"), ("seafile_timezone", "Europe/Berlin"),
            ("seafile_enable_signup", "true"), ("seafile_file_preview_mb", "50"),
            ("seafile_share_link_expire_days", "14"), ("seafile_login_remember_days", "30"),
        ]);
        let out = seafile_settings(SEAHUB, &input);
        assert!(out.contains("TIME_ZONE = 'Europe/Berlin'\n") && !out.contains("Etc/UTC"));
        for line in ["SITE_NAME = 'Our Files'", "LANGUAGE_CODE = 'de'", "ENABLE_SIGNUP = True",
            "FILE_PREVIEW_MAX_SIZE = 50 * 1024 * 1024", "SHARE_LINK_EXPIRE_DAYS_DEFAULT = 14", "LOGIN_REMEMBER_DAYS = 30"] {
            assert!(out.lines().any(|l| l == line), "{line}");
        }
        assert_eq!(seafile_settings(&out, &input), out);
    }

    #[test]
    fn an_empty_site_name_is_left_alone() {
        assert_eq!(seafile_settings(SEAHUB, &with(&[("seafile_site_name", "")])), SEAHUB);
    }

    const PSONO: &str = "SECRET_KEY: 'k'\nWEB_CLIENT_URL: 'https://v'\nALLOWED_DOMAINS: ['example.com']\nALLOW_REGISTRATION: False\nALLOW_LOST_PASSWORD: False\nDEBUG: False\nDATABASES:\n  default:\n    'HOST': 'db'\n";

    #[test]
    fn psono_defaults_stored_nothing_change_nothing() {
        assert_eq!(psono_settings(PSONO, &Input::default()), PSONO);
    }

    #[test]
    fn psono_values_replace_in_place_or_append_at_top_level() {
        let input = with(&[
            ("psono_allow_registration", "true"), ("psono_enforce_matching_email", "true"),
            ("psono_registration_domains", "a.com, b.org"), ("psono_session_seconds", "3600"),
        ]);
        let out = psono_settings(PSONO, &input);
        assert!(out.contains("ALLOW_REGISTRATION: True\nALLOW_LOST_PASSWORD: False\n"));
        assert!(out.contains("\nENFORCE_MATCHING_USERNAME_AND_EMAIL: True\n"));
        assert!(out.contains("\nREGISTRATION_EMAIL_FILTER: ['a.com', 'b.org']\n"));
        assert!(out.contains("\nDEFAULT_TOKEN_TIME_VALID: 3600\n"));
        assert!(out.contains("DATABASES:\n  default:\n    'HOST': 'db'\n"));
        assert_eq!(psono_settings(&out, &input), out);
    }

    #[test]
    fn an_empty_domain_list_clears_the_filter() {
        let out = psono_settings(PSONO, &with(&[("psono_registration_domains", "")]));
        assert!(out.contains("REGISTRATION_EMAIL_FILTER: []\n"));
    }

    #[test]
    fn searxng_defaults_are_byte_identical() {
        let base = searxng::settings_file();
        assert_eq!(searxng_settings(base.clone(), &Input::default()), base);
        assert_eq!(searxng_settings(base.clone(), &with(&[("searxng_safe_search", "0"), ("searxng_autocomplete", "off")])), base);
    }

    #[test]
    fn searxng_values_land_in_their_own_blocks() {
        let input = with(&[
            ("searxng_safe_search", "2"), ("searxng_autocomplete", "brave"), ("searxng_default_lang", "de"),
            ("searxng_instance_name", "Our Search"), ("searxng_image_proxy", "true"),
        ]);
        let out = searxng_settings(searxng::settings_file(), &input);
        assert!(out.contains("    - json\n  safe_search: 2\n  autocomplete: \"brave\"\n  default_lang: \"de\""));
        assert!(out.ends_with("\n\ngeneral:\n  instance_name: \"Our Search\"\n\nserver:\n  image_proxy: true"));
    }

    #[test]
    fn litellm_defaults_are_byte_identical() {
        let base = litellm::config_yaml(&[]);
        assert_eq!(litellm_config(base.clone(), &Input::default()), base);
        assert_eq!(litellm_config(base.clone(), &with(&[("litellm_request_timeout", "6000"), ("litellm_num_retries", "0")])), base);
    }

    #[test]
    fn litellm_values_extend_general_and_add_a_block() {
        let input = with(&[
            ("litellm_drop_params", "true"), ("litellm_request_timeout", "600"), ("litellm_num_retries", "3"),
            ("litellm_json_logs", "true"), ("litellm_disable_spend_logs", "true"),
        ]);
        let out = litellm_config(litellm::config_yaml(&[]), &input);
        assert!(out.contains("master_key: os.environ/LITELLM_MASTER_KEY\n  disable_spend_logs: true\nlitellm_settings:\n  drop_params: true\n  request_timeout: 600\n  num_retries: 3\n  json_logs: true"));
    }
}
