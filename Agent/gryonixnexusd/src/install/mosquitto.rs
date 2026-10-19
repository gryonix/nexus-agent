//! Mosquitto's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/MosquittoService.swift`, declarative half only

use super::context::Input;

/// The catalog id this module installs
#[allow(dead_code)]
pub const SERVICE_ID: &str = "mosquitto";

pub const IMAGE: &str = "eclipse-mosquitto:2.0.22";
pub const COMPOSE_PROJECT: &str = "mosquitto";
pub const CONTAINER: &str = "mosquitto";
pub const BROKER_PORT: u16 = 1883;
pub const USERS: &[&str] = &["homeassistant", "zigbee2mqtt"];

/// A port of `MosquittoService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.mosquitto_path;
    format!(
        "services:\n  mosquitto:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    volumes:\n      - {path}/config:/mosquitto/config\n      - {path}/data:/mosquitto/data\n    ports:\n      # The devices in the house speak to it directly.\n      - \"{BROKER_PORT}:1883\""
    )
}

/// A port of `MosquittoService.brokerConfiguration`.
pub const BROKER_CONFIGURATION: &str = "listener 1883\nallow_anonymous false\npassword_file /mosquitto/config/passwd\npersistence true\npersistence_location /mosquitto/data/";

/// A port of `MosquittoService.composeFile(_:).envTemplate`
pub fn env_template() -> String {
    "MQTT_PASSWORD=__RANDOM__".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn the_port_is_published_to_the_network_and_anonymous_clients_are_refused() {
        assert!(compose_contents(&base()).contains("\"1883:1883\""));
        assert!(BROKER_CONFIGURATION.contains("allow_anonymous false"));
        assert!(BROKER_CONFIGURATION.contains("password_file /mosquitto/config/passwd"));
    }

    #[test]
    fn both_clients_get_an_account() {
        assert_eq!(USERS, &["homeassistant", "zigbee2mqtt"]);
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

    #[test]
    fn default_public_en() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        assert_eq!(
            compose_contents(&input),
            fixture("mq-default-public-en__docker-compose.yml"),
            "docker-compose.yml"
        );
        assert_eq!(
            BROKER_CONFIGURATION,
            fixture("mq-default-public-en__mosquitto.conf"),
            "mosquitto.conf"
        );
        assert_eq!(env_template(), fixture("mq-default-public-en__env.template"), "env.template");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.mosquitto_path = "/srv/mosquitto".to_string();
        assert_eq!(
            compose_contents(&input),
            fixture("mq-custompath-public-en__docker-compose.yml"),
            "docker-compose.yml"
        );
    }
}
