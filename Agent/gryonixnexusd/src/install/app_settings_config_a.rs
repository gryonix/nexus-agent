//! Settings stored in Mosquitto, Zigbee2MQTT, Home Assistant files and Qdrant env.

use super::app_settings::{Allowed, Spec};

const MQTT_CONNECTIONS: &[&str] = &["-1", "50", "100", "500", "1000"];
const MQTT_MESSAGE_SIZES: &[&str] = &["0", "65536", "1048576", "10485760", "104857600"];
const MQTT_LOG_LEVELS: &[&str] = &["default", "quiet", "debug"];
const MQTT_EXPIRATIONS: &[&str] = &["never", "1d", "1w", "1m"];
const MQTT_QUEUES: &[&str] = &["100", "1000", "10000"];
const Z2M_LOG_LEVELS: &[&str] = &["debug", "info", "warning", "error"];
const Z2M_LAST_SEEN: &[&str] = &["disable", "ISO_8601", "ISO_8601_local", "epoch"];
const Z2M_CHANNELS: &[&str] = &["11", "15", "20", "25"];
const HA_KEEP_DAYS: &[&str] = &["3", "5", "10", "30", "90"];
const HA_COMMIT: &[&str] = &["1", "5", "15", "30"];
const HA_LOG_LEVELS: &[&str] = &["critical", "error", "warning", "info", "debug"];
const QDRANT_LOG_LEVELS: &[&str] = &["ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
const QDRANT_REQUEST_MB: &[&str] = &["32", "64", "128", "256", "512"];
const QDRANT_THREADS: &[&str] = &["0", "1", "2", "4", "8"];

pub const SPECS: &[Spec] = &[
    Spec { key: "mosquitto_max_connections", default: "-1", allowed: Allowed::Choices(MQTT_CONNECTIONS) },
    Spec { key: "mosquitto_message_size_limit", default: "0", allowed: Allowed::Choices(MQTT_MESSAGE_SIZES) },
    Spec { key: "mosquitto_persistence", default: "true", allowed: Allowed::Switch },
    Spec { key: "mosquitto_connection_messages", default: "true", allowed: Allowed::Switch },
    Spec { key: "mosquitto_log_level", default: "default", allowed: Allowed::Choices(MQTT_LOG_LEVELS) },
    Spec { key: "mosquitto_client_expiration", default: "never", allowed: Allowed::Choices(MQTT_EXPIRATIONS) },
    Spec { key: "mosquitto_max_queued", default: "1000", allowed: Allowed::Choices(MQTT_QUEUES) },
    Spec { key: "zigbee2mqtt_log_level", default: "info", allowed: Allowed::Choices(Z2M_LOG_LEVELS) },
    Spec { key: "zigbee2mqtt_last_seen", default: "disable", allowed: Allowed::Choices(Z2M_LAST_SEEN) },
    Spec { key: "zigbee2mqtt_homeassistant", default: "false", allowed: Allowed::Switch },
    Spec { key: "zigbee2mqtt_availability", default: "false", allowed: Allowed::Switch },
    Spec { key: "zigbee2mqtt_channel", default: "11", allowed: Allowed::Choices(Z2M_CHANNELS) },
    Spec { key: "home_assistant_keep_days", default: "10", allowed: Allowed::Choices(HA_KEEP_DAYS) },
    Spec { key: "home_assistant_commit_interval", default: "5", allowed: Allowed::Choices(HA_COMMIT) },
    Spec { key: "home_assistant_log_level", default: "warning", allowed: Allowed::Choices(HA_LOG_LEVELS) },
    Spec { key: "qdrant_log_level", default: "INFO", allowed: Allowed::Choices(QDRANT_LOG_LEVELS) },
    Spec { key: "qdrant_telemetry_disabled", default: "false", allowed: Allowed::Switch },
    Spec { key: "qdrant_max_request_mb", default: "32", allowed: Allowed::Choices(QDRANT_REQUEST_MB) },
    Spec { key: "qdrant_enable_cors", default: "true", allowed: Allowed::Switch },
    Spec { key: "qdrant_max_search_threads", default: "0", allowed: Allowed::Choices(QDRANT_THREADS) },
];

pub const QDRANT_ENV: &[(&str, &str)] = &[
    ("QDRANT__LOG_LEVEL", "qdrant_log_level"),
    ("QDRANT__TELEMETRY_DISABLED", "qdrant_telemetry_disabled"),
    ("QDRANT__SERVICE__MAX_REQUEST_SIZE_MB", "qdrant_max_request_mb"),
    ("QDRANT__SERVICE__ENABLE_CORS", "qdrant_enable_cors"),
    ("QDRANT__STORAGE__PERFORMANCE__MAX_SEARCH_THREADS", "qdrant_max_search_threads"),
];
