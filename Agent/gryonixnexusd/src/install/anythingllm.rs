//! AnythingLLM's declarative install artifacts — a port of `AnythingLLMService.swift`, declarative half only

use super::context::Input;
use super::litellm;
use super::ollama;
use super::qdrant;
use super::caddy::{self, WebIngress};

pub const SERVICE_ID: &str = "anythingllm";

/// Pinned release
pub const IMAGE: &str = "mintplexlabs/anythingllm:1.16.1";
pub const COMPOSE_PROJECT: &str = "anythingllm";
pub const CONTAINER: &str = "anythingllm";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8100;
/// The port inside the container.
pub const CONTAINER_PORT: u16 = 3001;

/// A port of `AnythingLLMService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.anythingllm_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.anythingllm_hostname.clone()
    }
}

/// The settings file the container reads and writes.
pub fn env_path(input: &Input) -> String {
    format!("{}/anythingllm.env", input.anythingllm_path)
}

/// Which model backend this deployment gives it, mirroring `AnythingLLMService.ModelSource`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelSource {
    Gateway,
    Engine,
}

pub fn model_source(services: &[String]) -> Option<ModelSource> {
    if services.iter().any(|id| id == litellm::SERVICE_ID) {
        return Some(ModelSource::Gateway);
    }
    if services.iter().any(|id| id == ollama::SERVICE_ID) {
        return Some(ModelSource::Engine);
    }
    None
}

pub fn uses_qdrant(services: &[String]) -> bool {
    services.iter().any(|id| id == qdrant::SERVICE_ID)
}

pub fn seeded_settings(services: &[String]) -> Vec<String> {
    let mut lines = vec!["EMBEDDING_ENGINE='native'".to_string()];
    if uses_qdrant(services) {
        lines.push("VECTOR_DB='qdrant'".to_string());
        lines.push(format!(
            "QDRANT_ENDPOINT='{}'",
            super::ai_network::url(qdrant::CONTAINER, qdrant::API_PORT)
        ));
    } else {
        lines.push("VECTOR_DB='lancedb'".to_string());
    }
    match model_source(services) {
        Some(ModelSource::Gateway) => {
            lines.push("LLM_PROVIDER='litellm'".to_string());
            lines.push(format!(
                "LITE_LLM_BASE_PATH='{}'",
                super::ai_network::url(litellm::CONTAINER, litellm::CONTAINER_PORT)
            ));
        }
        Some(ModelSource::Engine) => {
            lines.push("LLM_PROVIDER='ollama'".to_string());
            lines.push(format!(
                "OLLAMA_BASE_PATH='{}'",
                super::ai_network::url(ollama::CONTAINER, ollama::API_PORT)
            ));
        }
        None => {}
    }
    lines
}

/// A port of `AnythingLLMService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    compose_services(input) + super::ai_network::COMPOSE_TAIL
}

/// The services block, before the shared network joins it
fn compose_services(input: &Input) -> String {
    let path = &input.anythingllm_path;
    format!("services:\n  anythingllm:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # uid 1000, matching the directories the setup step creates.\n    # Spelled out rather than left to the image so that the host\n    # side and the container side cannot drift apart.\n    user: \"1000:1000\"\n    environment:\n      # The only two settings the UI must not be able to move.\n      # Everything else lives in the mounted settings file, which\n      # the container owns — see the type comment.\n      STORAGE_DIR: \"/app/server/storage\"\n      SERVER_PORT: {CONTAINER_PORT}\n      # Chromium's own sandbox needs namespace calls docker's\n      # default seccomp profile blocks, so upstream's documented\n      # runs all add a capability instead. This buys the same\n      # feature for a far smaller grant — see the service comment.\n      ANYTHINGLLM_CHROMIUM_ARGS: \"--no-sandbox\"\n    volumes:\n      - {path}/storage:/app/server/storage\n      - {path}/anythingllm.env:/app/server/.env\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\"")
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `AnythingLLMService.webIngress(_:)`
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

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

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_the_plain_ai_name_when_it_is_alone() {
        assert_eq!(hostname(&base()), "ai.example.com");
        let mut crowded = base();
        crowded.installed_services = vec![SERVICE_ID.to_string(), "open-webui".to_string()];
        assert_eq!(hostname(&crowded), "anythingllm.example.com");
    }

    /// The gateway wins over the engine, and neither is invented.
    #[test]
    fn the_model_backend_is_derived_and_the_gateway_leads() {
        let engine = vec!["anythingllm".to_string(), "ollama".to_string()];
        assert_eq!(model_source(&engine), Some(ModelSource::Engine));

        let both = vec!["anythingllm".to_string(), "ollama".to_string(), "litellm".to_string()];
        assert_eq!(model_source(&both), Some(ModelSource::Gateway));

        assert_eq!(model_source(&["anythingllm".to_string()]), None);
    }

    #[test]
    fn no_backend_writes_no_provider() {
        let alone = seeded_settings(&["anythingllm".to_string()]);
        assert!(!alone.iter().any(|line| line.starts_with("LLM_PROVIDER")));
        assert!(alone.iter().any(|line| line == "EMBEDDING_ENGINE='native'"));
        assert!(alone.iter().any(|line| line == "VECTOR_DB='lancedb'"));
    }

    #[test]
    fn the_vector_store_is_used_only_when_installed() {
        let with = seeded_settings(&["anythingllm".to_string(), "qdrant".to_string()]);
        assert!(with.iter().any(|line| line == "VECTOR_DB='qdrant'"));
        assert!(with.iter().any(|line| line.contains(&qdrant::API_PORT.to_string())));

        let without = seeded_settings(&["anythingllm".to_string()]);
        assert!(without.iter().any(|line| line == "VECTOR_DB='lancedb'"));
        assert!(!without.iter().any(|line| line.contains("QDRANT")));
    }

    #[test]
    fn no_model_is_named() {
        let lines = seeded_settings(&["anythingllm".to_string(), "ollama".to_string()]);
        assert!(!lines.iter().any(|line| line.contains("MODEL_PREF")));
    }

    #[test]
    fn the_compose_file_sets_nothing_the_ui_owns() {
        let text = compose_contents(&base());
        assert!(text.contains("STORAGE_DIR"));
        assert!(text.contains("SERVER_PORT"));
        assert!(!text.contains("LLM_PROVIDER"));
        assert!(!text.contains("VECTOR_DB"));
    }

    #[test]
    fn no_capability_is_granted_and_the_browser_still_runs() {
        let text = compose_contents(&base());
        assert!(!text.contains("cap_add"), "no capability is added to this container");
        assert!(!text.contains("privileged"));
        assert!(text.contains("ANYTHINGLLM_CHROMIUM_ARGS: \"--no-sandbox\""));
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

    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}\npublicPaths={}",
            ingress.hostname,
            ingress.upstream_port,
            ingress.admin_guard,
            ingress.upstream_https,
            ingress.public_paths.join(" ")
        )
    }

    fn assert_parity(input: &Input, services: &[String], scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames"
        );
        assert_eq!(
            caddy_site(input),
            fixture(&format!("{scenario}__caddy-site.txt")),
            "{scenario}: caddy-site"
        );
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress"
        );
        assert_eq!(
            seeded_settings(services).join("\n"),
            fixture(&format!("{scenario}__settings.env")),
            "{scenario}: seeded settings"
        );
    }

    fn with_engine() -> Vec<String> {
        vec!["anythingllm".to_string(), "ollama".to_string()]
    }

    #[test]
    fn engine_public_en() {
        assert_parity(&base(), &with_engine(), "allm-engine-public-en");
    }

    #[test]
    fn gateway_public_en() {
        assert_parity(
            &base(),
            &["anythingllm".to_string(), "litellm".to_string()],
            "allm-gateway-public-en",
        );
    }

    #[test]
    fn alone_public_en() {
        assert_parity(&base(), &["anythingllm".to_string()], "allm-alone-public-en");
    }

    #[test]
    fn qdrant_public_en() {
        assert_parity(
            &base(),
            &["anythingllm".to_string(), "ollama".to_string(), "qdrant".to_string()],
            "allm-qdrant-public-en",
        );
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, &with_engine(), "allm-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base();
        input.domain = "home.local".to_string();
        input.local_only = true;
        assert_parity(&input, &with_engine(), "allm-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base();
        input.anythingllm_hostname = "kb.example.com".to_string();
        input.anythingllm_path = "/srv/anythingllm".to_string();
        assert_parity(&input, &with_engine(), "allm-customhost-public-en");
    }
}
