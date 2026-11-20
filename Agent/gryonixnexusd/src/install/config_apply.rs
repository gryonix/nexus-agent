//! Writes app settings into a service's configuration file after install.

use super::context::Input;
use super::execute::EventSink;

/// Runs after a service install or re-apply finished
pub async fn after_install(label: &str, input: &Input, sink: &EventSink) {
    match label {
        "zigbee2mqtt" => super::config_apply_a::zigbee2mqtt_apply(input, sink).await,
        "home-assistant" => super::config_apply_a::home_assistant_apply(input, sink).await,
        "headscale" => super::config_apply_b::headscale(input, sink).await,
        "authelia" => super::config_apply_b::authelia(input, sink).await,
        "seafile" | "psono" => super::config_apply_c::after_install(label, input, sink).await,
        _ => {}
    }
}
