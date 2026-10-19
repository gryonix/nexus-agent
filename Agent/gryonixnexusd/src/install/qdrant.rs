//! Qdrant's declarative install artifacts — a port of `QdrantService.swift`, declarative half only

use super::context::Input;

pub const SERVICE_ID: &str = "qdrant";

pub const IMAGE: &str = "qdrant/qdrant:v1.19.1";
pub const COMPOSE_PROJECT: &str = "qdrant";
pub const CONTAINER: &str = "qdrant";
/// The REST API and the dashboard, on loopback.
pub const API_PORT: u16 = 6333;

/// The API key this store and its reader share
pub const API_KEY_PATH: &str = "/etc/gryonixnexus/qdrant.key";

/// A port of `QdrantService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    compose_services(input) + super::ai_network::COMPOSE_TAIL
}

/// The services block, before the shared network joins it
fn compose_services(input: &Input) -> String {
    let path = &input.qdrant_path;
    format!("services:\n  qdrant:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Read from the shared key file by the setup step below. Set\n      # here rather than baked into a config file so that rotating\n      # it is one file and one restart.\n      QDRANT__SERVICE__API_KEY: ${{QDRANT_API_KEY}}\n    volumes:\n      - {path}/storage:/qdrant/storage\n    ports:\n      # Loopback, and only the REST port. The dashboard rides on\n      # the same port; whoever reaches it has the documents.\n      - \"127.0.0.1:{API_PORT}:6333\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    /// Loopback, and nothing else
    #[test]
    fn the_api_is_bound_to_loopback_only() {
        let text = compose_contents(&base());
        assert!(text.contains(&format!("\"127.0.0.1:{API_PORT}:6333\"")));
        assert!(!text.contains("0.0.0.0"));
    }

    #[test]
    fn the_store_takes_a_key() {
        assert!(compose_contents(&base()).contains("QDRANT__SERVICE__API_KEY"));
    }

    #[test]
    fn the_grpc_port_is_not_published() {
        assert!(!compose_contents(&base()).contains("6334"));
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
            fixture("qdrant-default-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn custompath_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.qdrant_path = "/srv/qdrant".to_string();
        assert_eq!(
            compose_contents(&input),
            fixture("qdrant-custompath-public-en__docker-compose.yml")
        );
    }
}
