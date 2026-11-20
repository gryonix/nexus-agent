//! Seafile, Psono, SearXNG and LiteLLM settings stored in their config files.

use super::app_settings::{Allowed, Spec, Validator, TIMEZONES};

const SEAFILE_LANGUAGES: &[&str] = &["en", "de", "fr", "es", "it", "nl", "pl", "pt-br", "ru", "uk", "cs", "ja", "zh-cn"];
const PREVIEW_MB: &[&str] = &["10", "30", "50", "100", "200"];
const EXPIRE_DAYS: &[&str] = &["0", "7", "14", "30", "90"];
const REMEMBER_DAYS: &[&str] = &["1", "7", "30", "90"];
const SESSION_SECONDS: &[&str] = &["3600", "28800", "86400", "604800"];
const SAFE_SEARCH: &[&str] = &["0", "1", "2"];
const AUTOCOMPLETE: &[&str] = &["off", "duckduckgo", "google", "brave", "startpage", "wikipedia", "qwant"];
const SEARCH_LANGUAGES: &[&str] = &["none", "auto", "en", "de", "fr", "es", "it", "nl", "pl", "pt", "ru", "uk", "cs", "ja", "zh"];
const TIMEOUTS: &[&str] = &["60", "300", "600", "1800", "6000"];
const RETRIES: &[&str] = &["0", "1", "2", "3", "5"];

const fn switch(key: &'static str, default: &'static str) -> Spec {
    Spec { key, default, allowed: Allowed::Switch }
}

const fn choice(key: &'static str, default: &'static str, options: &'static [&'static str]) -> Spec {
    Spec { key, default, allowed: Allowed::Choices(options) }
}

const fn text(key: &'static str, max: usize, validator: Validator) -> Spec {
    Spec { key, default: "", allowed: Allowed::Text(max, validator) }
}

pub const SPECS: &[Spec] = &[
    text("seafile_site_name", 59, Validator::Name),
    choice("seafile_language", "en", SEAFILE_LANGUAGES),
    choice("seafile_timezone", "Etc/UTC", TIMEZONES),
    switch("seafile_enable_signup", "false"),
    choice("seafile_file_preview_mb", "30", PREVIEW_MB),
    choice("seafile_share_link_expire_days", "0", EXPIRE_DAYS),
    choice("seafile_login_remember_days", "7", REMEMBER_DAYS),
    switch("psono_allow_registration", "false"),
    switch("psono_allow_lost_password", "false"),
    switch("psono_enforce_matching_email", "false"),
    text("psono_registration_domains", 300, Validator::HostList),
    choice("psono_session_seconds", "86400", SESSION_SECONDS),
    switch("psono_user_search_by_email", "false"),
    text("searxng_instance_name", 59, Validator::Name),
    choice("searxng_safe_search", "0", SAFE_SEARCH),
    choice("searxng_autocomplete", "off", AUTOCOMPLETE),
    choice("searxng_default_lang", "none", SEARCH_LANGUAGES),
    switch("searxng_image_proxy", "false"),
    switch("litellm_drop_params", "false"),
    choice("litellm_request_timeout", "6000", TIMEOUTS),
    choice("litellm_num_retries", "0", RETRIES),
    switch("litellm_json_logs", "false"),
    switch("litellm_disable_spend_logs", "false"),
];
