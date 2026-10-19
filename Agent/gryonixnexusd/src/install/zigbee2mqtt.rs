//! Zigbee2MQTT's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/Zigbee2MQTTService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::mosquitto;

pub const SERVICE_ID: &str = "zigbee2mqtt";

pub const IMAGE: &str = "koenkk/zigbee2mqtt:2.14.1";
pub const COMPOSE_PROJECT: &str = "zigbee2mqtt";
pub const CONTAINER: &str = "zigbee2mqtt";
pub const WEB_UI_PORT: u16 = 8103;
/// The broker account this one signs in with.
pub const MQTT_USER: &str = "zigbee2mqtt";

/// A port of `Zigbee2MQTTService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.zigbee2mqtt_hostname.is_empty() {
        super::hostnames::default_hostname(SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.zigbee2mqtt_hostname.clone()
    }
}

/// A port of `Zigbee2MQTTService.composeFile(_:).composeContents`
pub fn compose_contents(input: &Input) -> String {
    let path = &input.zigbee2mqtt_path;
    let stick = &input.home_assistant_usb_device;
    format!(
        "services:\n  zigbee2mqtt:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    volumes:\n      - {path}/data:/app/data\n      # Device names as udev knows them.\n      - /run/udev:/run/udev:ro\n    devices:\n      - {stick}:{stick}\n    # The broker it publishes to and the page it serves are both\n    # on the host's own network; published ports would be ignored.\n    network_mode: host"
    )
}

/// A port of `Zigbee2MQTTService.initialConfiguration(stick:password:)`
pub fn initial_configuration(stick: &str, password: &str) -> String {
    let broker_port = mosquitto::BROKER_PORT;
    let user = MQTT_USER;
    format!(
        "mqtt:\n  server: mqtt://127.0.0.1:{broker_port}\n  user: {user}\n  password: {password}\nserial:\n  port: {stick}\nfrontend:\n  enabled: true\n  host: 127.0.0.1\n  port: {WEB_UI_PORT}"
    )
}

/// A port of `Zigbee2MQTTService.dnsHostnames(_:)`.
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `Zigbee2MQTTService.webIngress(_:)`.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

/// The Caddy site NAMES this ingress publishes.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the Zigbee2MQTT slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(
        SERVICE_ID,
        &joined,
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        input.local_only,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input {
            domain: "example.com".to_string(),
            home_assistant_usb_device: "/dev/ttyACM0".to_string(),
            ..Input::default()
        }
    }

    #[test]
    fn hostname_defaults_to_the_zigbee_subdomain() {
        assert_eq!(hostname(&base()), "zigbee.example.com");
    }

    #[test]
    fn the_stick_is_passed_through_and_no_port_is_published() {
        let text = compose_contents(&base());
        assert!(text.contains("- /dev/ttyACM0:/dev/ttyACM0"));
        assert!(text.contains("network_mode: host"));
        assert!(!text.contains("ports:"));
    }

    #[test]
    fn the_settings_file_points_at_the_broker_and_binds_to_loopback() {
        let text = initial_configuration("/dev/ttyACM0", "secret");
        assert!(text.contains(&format!("server: mqtt://127.0.0.1:{}", mosquitto::BROKER_PORT)));
        assert!(text.contains("user: zigbee2mqtt"));
        assert!(text.contains("password: secret"));
        assert!(text.contains("port: /dev/ttyACM0"));
        assert!(text.contains("host: 127.0.0.1"));
        assert!(text.contains(&format!("port: {WEB_UI_PORT}")));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base() -> Input {
        Input {
            domain: "example.com".to_string(),
            home_assistant_usb_device:
                "/dev/serial/by-id/usb-ITead_Sonoff_Zigbee_3.0_USB_Dongle_Plus-if00-port0"
                    .to_string(),
            ..Input::default()
        }
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            hostname(input),
            fixture(&format!("{scenario}__hostname.txt")),
            "{scenario}: hostname.txt"
        );
        assert_eq!(
            initial_configuration(&input.home_assistant_usb_device, "__MQTT_PASSWORD__"),
            fixture(&format!("{scenario}__configuration.yaml")),
            "{scenario}: configuration.yaml"
        );
        assert_eq!(
            caddy_site(input),
            fixture(&format!("{scenario}__caddy-site.txt")),
            "{scenario}: caddy-site.txt"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base(), "z2m-default-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base();
        input.domain = "home.local".to_string();
        input.local_only = true;
        assert_parity(&input, "z2m-localonly-en");
    }
}
