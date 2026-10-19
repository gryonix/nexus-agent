//! Home Assistant's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/HomeAssistantService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;

pub const SERVICE_ID: &str = "home-assistant";

pub const IMAGE: &str = "homeassistant/home-assistant:2026.9.3";
pub const COMPOSE_PROJECT: &str = "home-assistant";
pub const CONTAINER: &str = "homeassistant";
pub const WEB_UI_PORT: u16 = 8123;

/// A port of `HomeAssistantService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.home_assistant_hostname.is_empty() {
        super::hostnames::default_hostname(SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.home_assistant_hostname.clone()
    }
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.home_assistant_path;
    let devices = device_lines(input);
    format!(
        "services:\n  homeassistant:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # Discovery (mDNS, SSDP) only works on the home network itself.\n    network_mode: host\n    volumes:\n      - {path}/config:/config\n      - /etc/localtime:/etc/localtime:ro\n      # Bluetooth devices, through the host's BlueZ.\n      - /run/dbus:/run/dbus:ro{devices}"
    )
}

/// A port of `HomeAssistantService.deviceLines(_:)`
fn device_lines(input: &Input) -> String {
    let device = input.home_assistant_usb_device.trim();
    if device.is_empty() {
        return String::new();
    }
    format!("\n    devices:\n      - {device}:{device}")
}

/// A port of `HomeAssistantService.initialConfiguration`
pub const INITIAL_CONFIGURATION: &str = "# Loads the default set of integrations.\ndefault_config:\n\nfrontend:\n  themes: !include_dir_merge_named themes\n\nautomation: !include automations.yaml\nscript: !include scripts.yaml\nscene: !include scenes.yaml";

pub const INITIAL_HTTP_STORE: &str = "{\n  \"version\": 2,\n  \"minor_version\": 2,\n  \"key\": \"http\",\n  \"data\": {\n    \"stable\": {\n      \"server_port\": 8123,\n      \"server_host\": [\n        \"127.0.0.1\"\n      ],\n      \"use_x_forwarded_for\": true,\n      \"trusted_proxies\": [\n        \"127.0.0.1/32\"\n      ],\n      \"cors_allowed_origins\": [\n        \"https://cast.home-assistant.io\"\n      ],\n      \"login_attempts_threshold\": -1,\n      \"ip_ban_enabled\": true,\n      \"ssl_profile\": \"modern\",\n      \"use_x_frame_options\": true,\n      \"created_at\": \"2026-09-24T00:00:00+00:00\",\n      \"error\": null,\n      \"error_message\": null\n    },\n    \"pending\": null,\n    \"yaml_migration_done\": true\n  }\n}";

/// A port of `HomeAssistantService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn http_store_needs_repair(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    let data = &value["data"];
    let pending = &data["pending"];
    pending["error"] == "not_promoted"
        && pending["server_host"] == serde_json::json!(["127.0.0.1"])
        && data["stable"]["use_x_forwarded_for"] != serde_json::Value::Bool(true)
}

#[cfg(test)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `HomeAssistantService.webIngress(_:)`.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

/// The Caddy site NAMES this ingress publishes — see `adguard::caddy_site_names`
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the Home Assistant slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    let site = caddy::site(
        SERVICE_ID,
        &joined,
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        input.local_only,
    );
    caddy::with_setup_guard(SERVICE_ID, &input.installed_services, site)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn only_the_store_a_dropped_migration_left_is_repaired() {
        let broken = r#"{"version": 2, "minor_version": 2, "key": "http", "data": {
            "stable": {"server_port": 8123, "ip_ban_enabled": true, "error": null},
            "pending": {"server_port": 8123, "server_host": ["127.0.0.1"],
                        "use_x_forwarded_for": true, "trusted_proxies": ["127.0.0.1/32"],
                        "error": "not_promoted", "error_message": null},
            "yaml_migration_done": true}}"#;
        assert!(http_store_needs_repair(broken));
        assert!(!http_store_needs_repair(INITIAL_HTTP_STORE));
        assert!(!http_store_needs_repair(&broken.replace("not_promoted", "apply_failed")));
        assert!(!http_store_needs_repair(&broken.replace("127.0.0.1\"]", "0.0.0.0\"]")));
        assert!(!http_store_needs_repair("not json"));
    }

    #[test]
    fn hostname_defaults_to_home_subdomain() {
        assert_eq!(hostname(&base("example.com")), "home.example.com");
    }

    #[test]
    fn the_container_is_on_the_host_network_and_publishes_no_ports() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("network_mode: host"));
        assert!(!compose.contains("ports:"));
    }

    /// No stick, no `devices:` block at all — the default case.
    #[test]
    fn a_host_with_no_stick_gets_no_devices_block() {
        assert!(!compose_contents(&base("example.com")).contains("devices:"));
    }

    #[test]
    fn the_first_configuration_trusts_only_this_machine() {
        assert!(!INITIAL_CONFIGURATION.contains("http:"));
        assert!(INITIAL_HTTP_STORE.contains("\"server_host\": [\n        \"127.0.0.1\"\n      ]"));
        assert!(INITIAL_HTTP_STORE.contains("\"trusted_proxies\": [\n        \"127.0.0.1/32\"\n      ]"));
        assert!(INITIAL_HTTP_STORE.contains("\"pending\": null"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — same discipline as `jellyfin::fixture_parity`
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(caddy_site(input), fixture(&format!("{scenario}__caddy-site.txt")), "{scenario}: caddy-site.txt");
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
        assert_eq!(
            INITIAL_CONFIGURATION,
            fixture(&format!("{scenario}__configuration.yaml")),
            "{scenario}: configuration.yaml"
        );
        assert_eq!(INITIAL_HTTP_STORE, fixture("ha-http-store.json"), "http store");
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "ha-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "ha-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "ha-localonly-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.home_assistant_path = "/srv/home-assistant".to_string();
        assert_parity(&input, "ha-custompath-public-en");
    }

    #[test]
    fn stick_public_en() {
        let mut input = base("example.com");
        input.home_assistant_usb_device =
            "/dev/serial/by-id/usb-ITead_Sonoff_Zigbee_3.0_USB_Dongle_Plus-if00-port0".to_string();
        assert_parity(&input, "ha-stick-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.home_assistant_hostname = "home.other-company.net".to_string();
        assert_parity(&input, "ha-foreignhost-mirrored-public-en");
    }
}
