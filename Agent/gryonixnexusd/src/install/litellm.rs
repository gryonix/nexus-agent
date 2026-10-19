//! LiteLLM's declarative install artifacts — a port of `LiteLLMService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::llm_keys;
use super::ollama;

pub const SERVICE_ID: &str = "litellm";

/// Exact pinned tag; the index carries linux/amd64 and linux/arm64.
pub const IMAGE: &str = "ghcr.io/berriai/litellm:v1.100.0";
pub const COMPOSE_PROJECT: &str = "litellm";
pub const CONTAINER: &str = "litellm";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8098;
/// The port inside the container.
pub const CONTAINER_PORT: u16 = 4000;

/// The shared secret the gateway checks and the chat presents
pub const GATEWAY_KEY_PATH: &str = "/etc/gryonixnexus/llm-gateway.key";
pub const DATABASE_SERVICE: &str = "database";
pub const DATABASE_IMAGE: &str = "postgres:16-alpine";
pub const DATABASE_NAME: &str = "litellm";
pub const APP_KEYS_DIRECTORY: &str = "/etc/gryonixnexus/llm-keys";
/// The apps that present a key of their own
pub const KEYED_APPS: [&str; 2] = ["open-webui", "anythingllm"];

pub fn app_key_path(app: &str) -> String {
    format!("{APP_KEYS_DIRECTORY}/{app}.key")
}

/// A curl `-K -` config, so no key reaches argv
pub fn curl_config(master_key: &str, endpoint: &str, body: Option<&serde_json::Value>) -> String {
    let quote = |text: &str| text.replace('\\', "\\\\").replace('"', "\\\"");
    let mut config = format!(
        "header = \"Authorization: Bearer {}\"\nheader = \"Content-Type: application/json\"\nurl = \"http://127.0.0.1:{WEB_UI_PORT}/{}\"\n",
        quote(master_key),
        quote(endpoint)
    );
    if let Some(body) = body {
        config.push_str(&format!("data = \"{}\"\n", quote(&body.to_string())));
    }
    config
}

pub fn key_delete_body(app: &str) -> serde_json::Value {
    serde_json::json!({ "key_aliases": [app] })
}

pub fn key_generate_body(app: &str, key: &str) -> serde_json::Value {
    serde_json::json!({ "key": key, "key_alias": app })
}

/// A port of `LiteLLMService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.litellm_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.litellm_hostname.clone()
    }
}

/// A port of `LiteLLMService.configYAML(_:)`
pub fn config_yaml(services: &[String]) -> String {
    let mut lines = vec!["model_list:".to_string()];
    for provider in llm_keys::PROVIDERS {
        lines.push(format!(
            "  - model_name: \"{id}/*\"\n    litellm_params:\n      model: \"{id}/*\"\n      api_key: os.environ/{env}",
            id = provider.id,
            env = provider.environment_key
        ));
    }
    if services.iter().any(|id| id == ollama::SERVICE_ID) {
        lines.push(format!(
            "  - model_name: \"ollama/*\"\n    litellm_params:\n      model: \"ollama/*\"\n      api_base: {}",
            super::ai_network::url(ollama::CONTAINER, ollama::API_PORT)
        ));
    }
    lines.push("general_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY".to_string());
    lines.join("\n")
}

/// A port of `LiteLLMService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let net = super::ai_network::NAME;
    format!(
        "{}\n    networks:\n      - default\n      - {net}\n  {DATABASE_SERVICE}:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      POSTGRES_DB: {DATABASE_NAME}\n      POSTGRES_USER: {DATABASE_NAME}\n      POSTGRES_PASSWORD: ${{DB_PASSWORD}}\n    volumes:\n      - {}/postgres:/var/lib/postgresql/data\nnetworks:\n  {net}:\n    external: true",
        compose_services(input),
        input.litellm_path
    )
}

/// The services block, before the shared network joins it
fn compose_services(input: &Input) -> String {
    let path = &input.litellm_path;
    let keys = llm_keys::KEYS_ENV_PATH;
    format!(
        "services:\n  litellm:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - {DATABASE_SERVICE}\n    command: [\"--config\", \"/app/config.yaml\", \"--port\", \"{CONTAINER_PORT}\"]\n    environment:\n      LITELLM_MASTER_KEY: ${{LITELLM_MASTER_KEY}}\n      DATABASE_URL: postgresql://{DATABASE_NAME}:${{DB_PASSWORD}}@{DATABASE_SERVICE}:5432/{DATABASE_NAME}\n    # The provider keys, rendered by the agent from its own store.\n    # A separate file from .env because nothing on the device ever\n    # writes it and nothing here ever reads it back.\n    env_file:\n      - {keys}\n    volumes:\n      - {path}/config.yaml:/app/config.yaml:ro\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\""
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `LiteLLMService.webIngress(_:)`
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
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn app_key_requests_keep_keys_quoted_inside_the_config() {
        let config = curl_config("sk-master", "key/generate", Some(&key_generate_body("open-webui", "sk-app")));
        assert!(config.contains("header = \"Authorization: Bearer sk-master\"\n"));
        assert!(config.contains("url = \"http://127.0.0.1:8098/key/generate\"\n"));
        assert!(config.contains(r#"data = "{\"key\":\"sk-app\",\"key_alias\":\"open-webui\"}""#));
        assert!(!curl_config("a\"b", "key/info", None).contains("a\"b"));
    }

    #[test]
    fn hostname_defaults_to_the_plain_ai_name_when_it_is_alone() {
        assert_eq!(hostname(&base()), "ai.example.com");
        let mut crowded = base();
        crowded.installed_services = vec![SERVICE_ID.to_string(), "open-webui".to_string()];
        assert_eq!(hostname(&crowded), "litellm.example.com");
    }

    #[test]
    fn every_provider_the_keys_file_can_carry_has_a_route() {
        let yaml = config_yaml(&[]);
        for provider in llm_keys::PROVIDERS {
            assert!(yaml.contains(&format!("model_name: \"{}/*\"", provider.id)), "{}", provider.id);
            assert!(yaml.contains(&format!("os.environ/{}", provider.environment_key)));
        }
    }

    #[test]
    fn the_local_engine_is_routed_only_when_it_is_installed() {
        assert!(!config_yaml(&[]).contains("ollama/*"));
        assert!(config_yaml(&["ollama".to_string()]).contains("ollama/*"));
    }

    #[test]
    fn the_keys_file_is_the_fixed_path_and_not_under_the_service_directory() {
        let mut input = base();
        input.litellm_path = "/srv/litellm".to_string();
        let text = compose_contents(&input);
        assert!(text.contains(llm_keys::KEYS_ENV_PATH));
        assert!(!text.contains("/srv/litellm/keys"));
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
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    fn assert_parity(input: &Input, services: &[String], scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            config_yaml(services),
            fixture(&format!("{scenario}__config.yaml")),
            "{scenario}: config.yaml"
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
    }

    fn with_engine() -> Vec<String> {
        vec!["open-webui".to_string(), "ollama".to_string(), "litellm".to_string()]
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base(), &with_engine(), "litellm-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, &with_engine(), "litellm-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base();
        input.domain = "home.local".to_string();
        input.local_only = true;
        assert_parity(&input, &with_engine(), "litellm-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base();
        input.litellm_hostname = "gateway.example.com".to_string();
        input.litellm_path = "/srv/litellm".to_string();
        assert_parity(&input, &with_engine(), "litellm-customhost-public-en");
    }

    #[test]
    fn no_engine_public_en() {
        assert_parity(&base(), &["litellm".to_string()], "litellm-noengine-public-en");
    }
}
