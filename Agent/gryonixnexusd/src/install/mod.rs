pub mod adguard;
pub mod authelia;
pub mod ai_network;
pub mod ollama;
pub mod open_webui;
pub mod litellm;
pub mod anythingllm;
pub mod n8n;
pub mod qdrant;
pub mod searxng;
/// The assistant that answers in somebody's messengers
pub mod openclaw;
pub mod llm_keys;
pub mod catalog;
pub mod homepage;
pub mod pihole;
pub mod cloudflared;
pub mod headscale;
pub mod tailscale;
pub mod caddy;
pub mod caddy_check;
#[cfg(test)]
mod caddy_check_tests;
pub mod caddy_upstream;
pub mod context;
pub mod hostnames;
pub mod execute;
pub mod journal;
pub mod plan;
pub mod packages;
pub mod crowdsec;
pub mod ssh_password;
pub mod firewall;
pub mod home_network;
pub mod firewall_base;
pub mod firewall_relay;
pub mod relay_routes;
pub mod ports;
pub mod forgejo;
pub mod gitlab;
pub mod immich;
pub mod crafty;
pub mod jellyfin;
pub mod home_assistant;
pub mod mosquitto;
pub mod zigbee2mqtt;
pub mod minecraft;
pub mod nextcloud;
pub mod passbolt;
pub mod photoprism;
pub mod psono;
pub mod seafile;
pub mod vaultwarden;
pub mod vpn;
pub mod mail;
#[allow(dead_code)]
pub mod host;

pub const HOME_ONLY_SERVICE_IDS: &[&str] = &["home-assistant", "mosquitto", "zigbee2mqtt"];

/// The hub's add-ons, which are refused without it.
pub const SMART_HOME_ADD_ON_IDS: &[&str] = &["mosquitto", "zigbee2mqtt"];

pub fn requires_home_machine(service_id: &str) -> bool {
    HOME_ONLY_SERVICE_IDS.contains(&service_id)
}

pub fn any_requires_home_machine(services: &[String]) -> bool {
    services.iter().any(|id| requires_home_machine(id))
}
