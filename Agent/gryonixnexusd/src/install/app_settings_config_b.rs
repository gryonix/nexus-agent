//! Headscale and Authelia settings kept in their own config files.

use super::app_settings::{Allowed, Spec};

const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug"];
const NODE_EXPIRY: &[&str] = &["0", "30d", "90d", "180d", "365d"];
const EPHEMERAL_TIMEOUT: &[&str] = &["5m", "30m", "1h", "24h"];
const ALLOCATION: &[&str] = &["sequential", "random"];
const THEMES: &[&str] = &["light", "dark", "grey", "auto"];
const SESSION_LENGTH: &[&str] = &["1h", "4h", "12h", "1d"];
const SESSION_IDLE: &[&str] = &["5m", "15m", "30m", "1h"];
const REMEMBER_ME: &[&str] = &["-1", "1w", "1M", "3M"];
const RETRIES: &[&str] = &["3", "5", "10"];
const BAN_TIME: &[&str] = &["5m", "15m", "1h", "1d"];

const fn choice(key: &'static str, default: &'static str, options: &'static [&'static str]) -> Spec {
    Spec { key, default, allowed: Allowed::Choices(options) }
}

pub const SPECS: &[Spec] = &[
    choice("headscale_log_level", "info", LOG_LEVELS),
    Spec { key: "headscale_magic_dns", default: "true", allowed: Allowed::Switch },
    choice("headscale_node_expiry", "0", NODE_EXPIRY),
    choice("headscale_ephemeral_timeout", "30m", EPHEMERAL_TIMEOUT),
    choice("headscale_ip_allocation", "sequential", ALLOCATION),
    Spec { key: "headscale_taildrop", default: "true", allowed: Allowed::Switch },
    choice("authelia_theme", "light", THEMES),
    choice("authelia_log_level", "info", LOG_LEVELS),
    choice("authelia_session_expiration", "1h", SESSION_LENGTH),
    choice("authelia_session_inactivity", "5m", SESSION_IDLE),
    choice("authelia_remember_me", "1M", REMEMBER_ME),
    choice("authelia_max_retries", "3", RETRIES),
    choice("authelia_ban_time", "5m", BAN_TIME),
];
