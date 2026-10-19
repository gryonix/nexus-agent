//! Open WebUI's declarative install artifacts — a port of `OpenWebUIService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::litellm;
use super::ollama;
use super::searxng;

pub const SERVICE_ID: &str = "open-webui";

/// Pinned release
pub const IMAGE: &str = "ghcr.io/open-webui/open-webui:v0.11.3";
pub const COMPOSE_PROJECT: &str = "open-webui";
pub const CONTAINER: &str = "open-webui";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8097;
/// The port inside the container
pub const CONTAINER_WEB_PORT: u16 = 8080;

/// A port of `OpenWebUIService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.open_webui_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.open_webui_hostname.clone()
    }
}

pub fn engine_url(services: &[String]) -> Option<String> {
    services
        .iter()
        .any(|id| id == ollama::SERVICE_ID)
        .then(|| super::ai_network::url(ollama::CONTAINER, ollama::API_PORT))
}

pub fn gateway_url(services: &[String]) -> Option<String> {
    services
        .iter()
        .any(|id| id == litellm::SERVICE_ID)
        .then(|| super::ai_network::url(litellm::CONTAINER, litellm::CONTAINER_PORT) + "/v1")
}

pub fn search_url(services: &[String]) -> Option<String> {
    services
        .iter()
        .any(|id| id == searxng::SERVICE_ID)
        .then(searxng::query_url)
}

pub fn stored_address_keys(services: &[String]) -> Vec<&'static str> {
    let mut keys = Vec::new();
    if engine_url(services).is_some() {
        keys.push("ollama.base_urls");
    }
    if gateway_url(services).is_some() {
        keys.extend(["openai.api_base_urls", "openai.api_keys"]);
    }
    if search_url(services).is_some() {
        keys.extend(["web.search.enable", "web.search.engine", "web.search.searxng_query_url"]);
    }
    keys
}

/// Deletes the named settings from the chat's database
pub const FORGET_KEYS_SCRIPT: &str = "import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); \
db.executemany(\"delete from config where key = ?\", [(k,) for k in sys.argv[2:]]); db.commit()";

/// A port of `OpenWebUIService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input, services: &[String]) -> String {
    compose_services(input, services) + super::ai_network::COMPOSE_TAIL
}

/// The services block, before the shared network joins it
fn compose_services(input: &Input, services: &[String]) -> String {
    let path = &input.open_webui_path;
    let host = hostname(input);
    let signups = if input.open_webui_allow_signups { "true" } else { "false" };
    let engine = engine_url(services)
        .map(|url| format!("\n      OLLAMA_BASE_URL: \"{url}\""))
        .unwrap_or_default();
    let gateway = gateway_url(services)
        .map(|url| format!("\n      OPENAI_API_BASE_URL: \"{url}\"\n      OPENAI_API_KEY: ${{LLM_GATEWAY_KEY}}"))
        .unwrap_or_default();
    let search = search_url(services)
        .map(|url| format!("\n      ENABLE_WEB_SEARCH: \"true\"\n      WEB_SEARCH_ENGINE: \"searxng\"\n      SEARXNG_QUERY_URL: \"{url}\""))
        .unwrap_or_default();
    format!(
        "services:\n  open-webui:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      WEBUI_URL: \"https://{host}\"\n      # Session signing key. Generated on the server — regenerating\n      # it on every start would sign every existing session out.\n      WEBUI_SECRET_KEY: ${{WEBUI_SECRET_KEY}}\n      ENABLE_SIGNUP: \"{signups}\"{engine}{gateway}{search}\n    volumes:\n      - {path}/data:/app/backend/data\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}\""
    )
}

/// A port of `OpenWebUIService.composeFile(_:).envTemplate`.
pub fn env_template() -> String {
    "WEBUI_SECRET_KEY=__RANDOM__".to_string()
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `OpenWebUIService.webIngress(_:)`
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
        let mut quiet = base();
        quiet.installed_services =
            vec![SERVICE_ID.to_string(), "ollama".to_string(), "qdrant".to_string()];
        assert_eq!(hostname(&quiet), "ai.example.com");
        let mut crowded = base();
        crowded.installed_services = vec![SERVICE_ID.to_string(), "openclaw".to_string()];
        assert_eq!(hostname(&crowded), "openwebui.example.com");
    }

    /// Only the neighbours present have their stored copies dropped
    #[test]
    fn stored_addresses_are_forgotten_only_for_present_neighbours() {
        let ids = |list: &[&str]| list.iter().map(|id| id.to_string()).collect::<Vec<_>>();
        assert!(stored_address_keys(&ids(&[SERVICE_ID])).is_empty());
        assert_eq!(stored_address_keys(&ids(&[SERVICE_ID, "ollama"])), ["ollama.base_urls"]);
        let all = stored_address_keys(&ids(&[SERVICE_ID, "ollama", "litellm", "searxng"]));
        assert_eq!(all.len(), 6);
        assert!(all.contains(&"web.search.searxng_query_url"));
        assert!(FORGET_KEYS_SCRIPT.contains("delete from config where key = ?"));
    }

    /// Derived from the neighbours, never typed
    #[test]
    fn the_engine_is_configured_only_when_it_is_installed() {
        let input = base();
        let wired = compose_contents(&input, &["open-webui".to_string(), "ollama".to_string()]);
        assert!(wired.contains("OLLAMA_BASE_URL"));
        assert!(wired.contains(&ollama::API_PORT.to_string()));

        let alone = compose_contents(&input, &["open-webui".to_string()]);
        assert!(!alone.contains("OLLAMA_BASE_URL"));
    }

    #[test]
    fn registration_is_closed_by_default_and_openable() {
        let mut input = base();
        assert!(compose_contents(&input, &[]).contains("ENABLE_SIGNUP: \"false\""));
        input.open_webui_allow_signups = true;
        assert!(compose_contents(&input, &[]).contains("ENABLE_SIGNUP: \"true\""));
    }

    #[test]
    fn the_session_key_is_server_generated() {
        assert_eq!(env_template().trim(), "WEBUI_SECRET_KEY=__RANDOM__");
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
            compose_contents(input, services),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(env_template(), fixture(&format!("{scenario}__env.template")), "{scenario}: env");
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
    }

    fn with_engine() -> Vec<String> {
        vec!["open-webui".to_string(), "ollama".to_string()]
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base(), &with_engine(), "owui-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, &with_engine(), "owui-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base();
        input.domain = "home.local".to_string();
        input.local_only = true;
        assert_parity(&input, &with_engine(), "owui-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base();
        input.open_webui_hostname = "ai.example.com".to_string();
        input.open_webui_path = "/srv/open-webui".to_string();
        assert_parity(&input, &with_engine(), "owui-customhost-public-en");
    }

    #[test]
    fn no_engine_public_en() {
        assert_parity(&base(), &["open-webui".to_string()], "owui-noengine-public-en");
    }

    #[test]
    fn gateway_public_en() {
        let services = vec![
            "open-webui".to_string(),
            "ollama".to_string(),
            "litellm".to_string(),
        ];
        assert_parity(&base(), &services, "owui-gateway-public-en");
    }

    #[test]
    fn search_public_en() {
        let services = vec![
            "open-webui".to_string(),
            "ollama".to_string(),
            "searxng".to_string(),
        ];
        assert_parity(&base(), &services, "owui-search-public-en");
    }

    #[test]
    fn signups_closed_public_en() {
        let mut input = base();
        input.open_webui_allow_signups = false;
        assert_parity(&input, &with_engine(), "owui-nosignup-public-en");
    }
}
