//! Ollama's declarative install artifacts — a port of `OllamaService.swift`, declarative half only

use super::context::Input;

/// The catalog id this module installs
pub const SERVICE_ID: &str = "ollama";

/// Pinned release
pub const IMAGE: &str = "ollama/ollama:0.33.3";
pub const COMPOSE_PROJECT: &str = "ollama";
pub const CONTAINER: &str = "ollama";
pub const API_PORT: u16 = 11434;

/// Where the weights live INSIDE the container
pub const MODELS_MOUNT: &str = "/root/.ollama";

pub const GPU_KEY_URL: &str = "https://nvidia.github.io/libnvidia-container/gpgkey";
pub const GPU_SOURCE_LIST_URL: &str =
    "https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list";
pub const GPU_KEYRING_PATH: &str = "/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg";
pub const GPU_SOURCE_LIST_PATH: &str = "/etc/apt/sources.list.d/nvidia-container-toolkit.list";

pub fn gpu_override_path(input: &Input) -> String {
    format!("{}/docker-compose.override.yml", input.ollama_path)
}

/// A port of `OllamaService.gpuOverrideContents`.
pub fn gpu_override_contents() -> String {
    "services:\n  ollama:\n    deploy:\n      resources:\n        reservations:\n          devices:\n            # Every card on the host. The engine loads one model at a time\n            # and picks the device itself; enumerating them here would be a\n            # list to keep in step with the hardware.\n            - driver: nvidia\n              count: all\n              capabilities: [gpu]".to_string()
}

/// A port of `OllamaService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    compose_services(input) + super::ai_network::COMPOSE_TAIL
}

/// The services block, before the shared network joins it
fn compose_services(input: &Input) -> String {
    let path = &input.ollama_path;
    format!(
        "services:\n  ollama:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Answer requests from the other containers on this host, not\n      # only from inside its own. The port is still bound to\n      # loopback below, so this widens nothing the outside can see.\n      OLLAMA_HOST: \"0.0.0.0:{API_PORT}\"\n    volumes:\n      # Models. The one bind mount in this catalog that is expected\n      # to reach tens of gigabytes.\n      - {path}/models:/root/.ollama\n    ports:\n      - \"127.0.0.1:{API_PORT}:{API_PORT}\""
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn the_api_listens_widely_inside_and_is_published_narrowly_outside() {
        let text = compose_contents(&base());
        assert!(text.contains(&format!("OLLAMA_HOST: \"0.0.0.0:{API_PORT}\"")));
        assert!(text.contains(&format!("- \"127.0.0.1:{API_PORT}:{API_PORT}\"")));
    }

    #[test]
    fn models_live_under_the_configured_path() {
        let mut input = base();
        input.ollama_path = "/srv/models".to_string();
        assert!(compose_contents(&input).contains("- /srv/models/models:/root/.ollama"));
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
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn default_public_en() {
        assert_eq!(
            compose_contents(&base()),
            fixture("ollama-default-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn custom_path_public_en() {
        let mut input = base();
        input.ollama_path = "/srv/ollama".to_string();
        assert_eq!(
            compose_contents(&input),
            fixture("ollama-custompath-public-en__docker-compose.yml")
        );
    }

    /// The override the card branch writes
    #[test]
    fn gpu_override_public_en() {
        assert_eq!(
            gpu_override_contents(),
            fixture("ollama-gpu-public-en__compose-override.yml")
        );
    }
}
