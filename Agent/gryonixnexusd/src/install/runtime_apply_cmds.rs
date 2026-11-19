//! Builds the commands that push settings into running services.

use serde_json::{json, Value};

use super::app_settings::{self, SECRET_CLEAR};
use super::app_settings_runtime::WEBUI_TOGGLES;
use super::context::Input;
use crate::service_users::docker::Call;
use crate::service_users::http::Request;

const OCC_USER: &str = "www-data";
const PASSWORD_SCRIPT: &str = "exec php occ config:system:set mail_smtppassword --value=\"$(cat)\"";
const MAIL_KEYS: &[&str] = &[
    "mail_smtpmode", "mail_smtphost", "mail_smtpport", "mail_smtpsecure", "mail_smtpauth",
    "mail_smtpname", "mail_smtppassword", "mail_from_address", "mail_domain",
];

fn stored<'a>(input: &'a Input, key: &str) -> Option<&'a str> {
    input.app_settings.get(key).map(String::as_str)
}

fn occ(container: &str, words: &[&str]) -> Call {
    let mut args = vec!["exec", "-u", OCC_USER, container, "php", "occ"];
    args.extend_from_slice(words);
    Call::new(&args)
}

fn occ_set(container: &str, name: &str, value: &str, integer: bool) -> Call {
    let value = format!("--value={value}");
    let mut words = vec!["config:system:set", name, value.as_str()];
    if integer {
        words.push("--type=integer");
    }
    occ(container, &words)
}

fn occ_delete(container: &str, name: &str) -> Call {
    occ(container, &["config:system:delete", name])
}

/// A password call whose secret arrives on stdin
fn occ_password(container: &str, password: &str) -> Call {
    let args = ["exec", "-i", "-u", OCC_USER, container, "sh", "-c", PASSWORD_SCRIPT];
    Call::new(&args).with_stdin(password.to_string())
}

fn secure_value(choice: &str) -> &'static str {
    match choice {
        "ssl" => "ssl",
        "none" => "",
        _ => "tls",
    }
}

/// Nextcloud mail calls; none until a host is stored
pub fn nextcloud_mail_calls(container: &str, input: &Input) -> Vec<Call> {
    let Some(host) = stored(input, "nextcloud_smtp_host") else { return Vec::new() };
    if host.is_empty() {
        return MAIL_KEYS.iter().map(|name| occ_delete(container, name)).collect();
    }
    let value = |name: &str| app_settings::value(input, &format!("nextcloud_smtp_{name}"));
    let mut calls = vec![
        occ_set(container, "mail_smtpmode", "smtp", false),
        occ_set(container, "mail_smtphost", host, false),
        occ_set(container, "mail_smtpport", value("port"), true),
        occ_set(container, "mail_smtpsecure", secure_value(value("security")), false),
    ];
    calls.extend(auth_calls(container, input, value("username")));
    calls.extend(from_calls(container, value("from")));
    calls
}

fn auth_calls(container: &str, input: &Input, username: &str) -> Vec<Call> {
    if username.is_empty() {
        return vec![
            occ_set(container, "mail_smtpauth", "0", true),
            occ_delete(container, "mail_smtpname"),
            occ_delete(container, "mail_smtppassword"),
        ];
    }
    let mut calls = vec![occ_set(container, "mail_smtpauth", "1", true), occ_set(container, "mail_smtpname", username, false)];
    match stored(input, "nextcloud_smtp_password") {
        Some(SECRET_CLEAR) => calls.push(occ_delete(container, "mail_smtppassword")),
        Some(secret) => calls.push(occ_password(container, secret)),
        None => {}
    }
    calls
}

fn from_calls(container: &str, from: &str) -> Vec<Call> {
    match from.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => vec![
            occ_set(container, "mail_from_address", local, false),
            occ_set(container, "mail_domain", domain, false),
        ],
        _ => vec![occ_delete(container, "mail_from_address"), occ_delete(container, "mail_domain")],
    }
}

const NEXTCLOUD_EXTRAS: &[(&str, &str, bool)] = &[
    ("nextcloud_default_phone_region", "default_phone_region", false),
    ("nextcloud_maintenance_window_start", "maintenance_window_start", true),
    ("nextcloud_default_language", "default_language", false),
    ("nextcloud_default_timezone", "default_timezone", false),
];

/// Calls for the occ extras the user touched
pub fn nextcloud_extra_calls(container: &str, input: &Input) -> Vec<Call> {
    NEXTCLOUD_EXTRAS
        .iter()
        .filter_map(|(key, name, integer)| {
            let value = stored(input, key)?;
            Some(if value.is_empty() || value == "none" {
                occ_delete(container, name)
            } else {
                occ_set(container, name, value, *integer)
            })
        })
        .collect()
}

/// The gitlab-rails arguments for the stored settings
pub fn gitlab_settings_args(input: &Input) -> Option<Vec<String>> {
    let mut fields: Vec<String> = Vec::new();
    if let Some(limit) = stored(input, "gitlab_default_projects_limit") {
        fields.push(format!("default_projects_limit: {limit}"));
    }
    for (key, name) in [("gitlab_require_admin_approval", "require_admin_approval_after_user_signup"),
                        ("gitlab_gravatar", "gravatar_enabled")] {
        if let Some(on) = stored(input, key) {
            fields.push(format!("{name}: {on}"));
        }
    }
    if let Some(mode) = stored(input, "gitlab_email_confirmation") {
        fields.push(format!("email_confirmation_setting: '{mode}'"));
    }
    if fields.is_empty() {
        return None;
    }
    let script = format!("ApplicationSetting.last.update!({})", fields.join(", "));
    Some(vec!["gitlab-rails".to_string(), "runner".to_string(), script])
}

/// The Open WebUI toggles the user touched
pub fn webui_toggles(input: &Input) -> Vec<(&'static str, bool)> {
    WEBUI_TOGGLES.iter().filter_map(|(key, name)| Some((*name, stored(input, key)? == "true"))).collect()
}

/// Sets the toggles in an admin config, leaving other keys
pub fn apply_toggles(config: &mut Value, toggles: &[(&str, bool)]) {
    if let Some(map) = config.as_object_mut() {
        for (name, on) in toggles {
            map.insert((*name).to_string(), json!(on));
        }
    }
}

/// One AdGuard change to make
#[derive(Debug, PartialEq, Eq)]
pub enum AdguardChange {
    /// POST /control/<area>/enable or disable
    Toggle(&'static str, bool),
    /// Read an object, set `enabled`, write it back
    Merge { read: &'static str, write: &'static str, on: bool },
}

/// AdGuard changes for the stored settings
pub fn adguard_changes(input: &Input) -> Vec<AdguardChange> {
    let on = |key: &str| stored(input, key).map(|value| value == "true");
    let mut out = Vec::new();
    if let Some(value) = on("adguard_safe_browsing") {
        out.push(AdguardChange::Toggle("safebrowsing", value));
    }
    if let Some(value) = on("adguard_parental_control") {
        out.push(AdguardChange::Toggle("parental", value));
    }
    if let Some(value) = on("adguard_safe_search") {
        out.push(AdguardChange::Merge { read: "/control/safesearch/status", write: "/control/safesearch/settings", on: value });
    }
    if let Some(value) = on("adguard_query_log") {
        out.push(AdguardChange::Merge { read: "/control/querylog/config", write: "/control/querylog/config/update", on: value });
    }
    out
}

pub fn adguard_request(auth: &str, method: &'static str, port: u16, path: &str, body: Option<String>) -> Request {
    Request {
        method,
        url: format!("http://127.0.0.1:{port}{path}"),
        headers: vec![("Authorization".into(), auth.to_string()), ("Content-Type".into(), "application/json".into())],
        body,
    }
}

pub fn toggle_path(area: &str, on: bool) -> String {
    format!("/control/{area}/{}", if on { "enable" } else { "disable" })
}

/// The object read from AdGuard with `enabled` set
pub fn with_enabled(current: &str, on: bool) -> Option<String> {
    let mut value: Value = serde_json::from_str(current.trim()).ok()?;
    value.as_object_mut()?.insert("enabled".into(), json!(on));
    Some(value.to_string())
}

/// The Jellyfin server flags the user touched
pub fn jellyfin_flags(input: &Input) -> Vec<(&'static str, bool)> {
    stored(input, "jellyfin_quick_connect").map(|value| vec![("QuickConnectAvailable", value == "true")]).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn input(pairs: &[(&str, &str)]) -> Input {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Input { app_settings: app_settings::accept(&map), ..Input::default() }
    }

    fn words(call: &Call) -> String {
        call.args[6..].join(" ")
    }

    #[test]
    fn no_mail_call_is_made_until_a_host_is_stored() {
        assert!(nextcloud_mail_calls("nc", &input(&[("nextcloud_smtp_port", "25")])).is_empty());
    }

    #[test]
    fn an_empty_host_returns_mail_to_the_default() {
        let calls = nextcloud_mail_calls("nc", &input(&[("nextcloud_smtp_host", "")]));
        assert_eq!(calls.len(), MAIL_KEYS.len());
        assert_eq!(words(&calls[0]), "config:system:delete mail_smtpmode");
    }

    #[test]
    fn mail_is_set_key_by_key_with_the_secret_on_stdin_only() {
        let given = input(&[("nextcloud_smtp_host", "mx.example.com"), ("nextcloud_smtp_security", "ssl"),
            ("nextcloud_smtp_username", "me"), ("nextcloud_smtp_password", "s3cret"),
            ("nextcloud_smtp_from", "noreply@example.com")]);
        let calls = nextcloud_mail_calls("nc", &given);
        let text: Vec<String> = calls.iter().filter(|call| call.stdin.is_none()).map(words).collect();
        assert!(text.contains(&"config:system:set mail_smtpport --value=587 --type=integer".to_string()));
        assert!(text.contains(&"config:system:set mail_smtpsecure --value=ssl".to_string()));
        assert!(text.contains(&"config:system:set mail_from_address --value=noreply".to_string()));
        assert!(text.contains(&"config:system:set mail_domain --value=example.com".to_string()));
        assert!(calls.iter().all(|call| call.args.iter().all(|arg| !arg.contains("s3cret"))));
        let password = calls.iter().find(|call| call.stdin.is_some()).unwrap();
        assert_eq!(password.stdin.as_deref(), Some("s3cret"));
        assert_eq!(password.args[..4], ["exec", "-i", "-u", "www-data"]);
        assert_eq!(password.args[5..7], ["sh", "-c"]);
    }

    #[test]
    fn starttls_maps_to_tls_and_none_to_empty() {
        assert_eq!(secure_value("starttls"), "tls");
        assert_eq!(secure_value("none"), "");
    }

    #[test]
    fn without_a_username_sign_in_is_switched_off_and_the_password_kept_out() {
        let calls = nextcloud_mail_calls("nc", &input(&[("nextcloud_smtp_host", "h"), ("nextcloud_smtp_password", "x")]));
        let text: Vec<String> = calls.iter().map(words).collect();
        assert!(text.contains(&"config:system:set mail_smtpauth --value=0 --type=integer".to_string()));
        assert!(calls.iter().all(|call| call.stdin.is_none()));
    }

    #[test]
    fn a_cleared_secret_deletes_the_stored_password() {
        let given = input(&[("nextcloud_smtp_host", "h"), ("nextcloud_smtp_username", "u"), ("nextcloud_smtp_password", SECRET_CLEAR)]);
        let text: Vec<String> = nextcloud_mail_calls("nc", &given).iter().map(words).collect();
        assert!(text.contains(&"config:system:delete mail_smtppassword".to_string()));
    }

    #[test]
    fn extras_apply_only_when_stored_and_none_deletes() {
        assert!(nextcloud_extra_calls("nc", &Input::default()).is_empty());
        let given = input(&[("nextcloud_default_phone_region", "DE"), ("nextcloud_maintenance_window_start", "3"),
                            ("nextcloud_default_language", "none"), ("nextcloud_default_timezone", "Europe/Berlin")]);
        let text: Vec<String> = nextcloud_extra_calls("nc", &given).iter().map(words).collect();
        assert_eq!(text, ["config:system:set default_phone_region --value=DE",
            "config:system:set maintenance_window_start --value=3 --type=integer",
            "config:system:delete default_language",
            "config:system:set default_timezone --value=Europe/Berlin"]);
    }

    #[test]
    fn the_gitlab_script_holds_only_whitelisted_values() {
        assert!(gitlab_settings_args(&Input::default()).is_none());
        let given = input(&[("gitlab_default_projects_limit", "10"), ("gitlab_gravatar", "false"),
                            ("gitlab_email_confirmation", "hard"), ("gitlab_require_admin_approval", "true")]);
        let args = gitlab_settings_args(&given).unwrap();
        assert_eq!(args[2], "ApplicationSetting.last.update!(default_projects_limit: 10, require_admin_approval_after_user_signup: true, gravatar_enabled: false, email_confirmation_setting: 'hard')");
        assert!(input(&[("gitlab_default_projects_limit", "10); system('x')")]).app_settings.is_empty());
    }

    #[test]
    fn only_touched_webui_toggles_reach_the_config() {
        let given = input(&[("open_webui_api_keys", "true"), ("open_webui_channels", "false")]);
        let toggles = webui_toggles(&given);
        assert_eq!(toggles, [("ENABLE_API_KEYS", true), ("ENABLE_CHANNELS", false)]);
        let mut config = json!({ "ENABLE_FOLDERS": true, "ENABLE_API_KEYS": false });
        apply_toggles(&mut config, &toggles);
        assert_eq!(config, json!({ "ENABLE_FOLDERS": true, "ENABLE_API_KEYS": true, "ENABLE_CHANNELS": false }));
        assert!(webui_toggles(&Input::default()).is_empty());
    }

    #[test]
    fn adguard_changes_follow_the_stored_keys() {
        assert!(adguard_changes(&Input::default()).is_empty());
        let given = input(&[("adguard_safe_browsing", "true"), ("adguard_parental_control", "false"),
                            ("adguard_safe_search", "true"), ("adguard_query_log", "false")]);
        let changes = adguard_changes(&given);
        assert_eq!(changes[0], AdguardChange::Toggle("safebrowsing", true));
        assert_eq!(changes[1], AdguardChange::Toggle("parental", false));
        assert_eq!(toggle_path("parental", false), "/control/parental/disable");
        assert_eq!(changes[3], AdguardChange::Merge {
            read: "/control/querylog/config", write: "/control/querylog/config/update", on: false });
    }

    #[test]
    fn an_adguard_object_keeps_its_fields_and_changes_enabled() {
        let body = with_enabled("{\"enabled\":false,\"interval\":2160000,\"ignored\":[\"a\"]}", true).unwrap();
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value, json!({ "enabled": true, "interval": 2160000, "ignored": ["a"] }));
        assert!(with_enabled("[1]", true).is_none());
    }

    #[test]
    fn the_adguard_secret_stays_in_a_header_not_the_url() {
        let request = adguard_request("Basic abc", "POST", 8087, "/control/parental/enable", None);
        assert!(!request.url.contains("abc"));
        assert_eq!(request.headers[0].1, "Basic abc");
    }

    #[test]
    fn the_jellyfin_flag_is_sent_only_when_stored() {
        assert!(jellyfin_flags(&Input::default()).is_empty());
        assert_eq!(jellyfin_flags(&input(&[("jellyfin_quick_connect", "false")])), [("QuickConnectAvailable", false)]);
    }
}
