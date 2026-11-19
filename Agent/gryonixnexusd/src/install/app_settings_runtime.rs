//! Settings applied to a running service, never written to compose.

use super::app_settings::{Allowed, Spec, Validator, SECURITY, SMTP_PORTS};

const HOURS: &[&str] = &[
    "none", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
    "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23",
];
const LANGUAGES: &[&str] = &["none", "en", "de", "fr", "es", "it", "nl", "pl", "pt_BR", "ru", "uk", "cs", "ja", "zh_CN"];
const ZONES: &[&str] = &[
    "none", "Etc/UTC", "Europe/London", "Europe/Berlin", "Europe/Kyiv", "Europe/Moscow", "America/New_York",
    "America/Chicago", "America/Denver", "America/Los_Angeles", "Asia/Dubai", "Asia/Kolkata", "Asia/Tokyo",
    "Australia/Sydney",
];
const PROJECT_LIMITS: &[&str] = &["0", "10", "100", "100000"];
const CONFIRMATION: &[&str] = &["off", "soft", "hard"];

const fn text(key: &'static str, max: usize, validator: Validator) -> Spec {
    Spec { key, default: "", allowed: Allowed::Text(max, validator) }
}

const fn switch(key: &'static str, default: &'static str) -> Spec {
    Spec { key, default, allowed: Allowed::Switch }
}

const fn choice(key: &'static str, default: &'static str, options: &'static [&'static str]) -> Spec {
    Spec { key, default, allowed: Allowed::Choices(options) }
}

pub const SPECS: &[Spec] = &[
    text("nextcloud_smtp_host", 253, Validator::Host),
    choice("nextcloud_smtp_port", "587", SMTP_PORTS),
    choice("nextcloud_smtp_security", "starttls", SECURITY),
    text("nextcloud_smtp_username", 254, Validator::Line),
    Spec { key: "nextcloud_smtp_password", default: "", allowed: Allowed::Secret },
    text("nextcloud_smtp_from", 254, Validator::Line),
    text("nextcloud_default_phone_region", 2, Validator::Region),
    choice("nextcloud_maintenance_window_start", "none", HOURS),
    choice("nextcloud_default_language", "none", LANGUAGES),
    choice("nextcloud_default_timezone", "none", ZONES),
    switch("open_webui_community_sharing", "true"),
    switch("open_webui_message_rating", "true"),
    switch("open_webui_api_keys", "false"),
    switch("open_webui_folders", "true"),
    switch("open_webui_memories", "true"),
    switch("open_webui_channels", "false"),
    choice("gitlab_default_projects_limit", "100000", PROJECT_LIMITS),
    switch("gitlab_require_admin_approval", "false"),
    choice("gitlab_email_confirmation", "off", CONFIRMATION),
    switch("gitlab_gravatar", "true"),
    switch("adguard_safe_browsing", "false"),
    switch("adguard_parental_control", "false"),
    switch("adguard_safe_search", "false"),
    switch("adguard_query_log", "true"),
    switch("jellyfin_quick_connect", "true"),
];

/// Open WebUI admin-config keys behind each toggle
pub const WEBUI_TOGGLES: &[(&str, &str)] = &[
    ("open_webui_community_sharing", "ENABLE_COMMUNITY_SHARING"),
    ("open_webui_message_rating", "ENABLE_MESSAGE_RATING"),
    ("open_webui_api_keys", "ENABLE_API_KEYS"),
    ("open_webui_folders", "ENABLE_FOLDERS"),
    ("open_webui_memories", "ENABLE_MEMORIES"),
    ("open_webui_channels", "ENABLE_CHANNELS"),
];
