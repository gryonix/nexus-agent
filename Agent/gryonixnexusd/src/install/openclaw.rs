//! OpenClaw's declarative install artifacts — a port of `OpenClawService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;
use super::litellm;
use super::ollama;

pub const SERVICE_ID: &str = "openclaw";

pub const IMAGE: &str = "ghcr.io/openclaw/openclaw:2026.9.2";
pub const COMPOSE_PROJECT: &str = "openclaw";
pub const CONTAINER: &str = "openclaw";
/// Loopback port Caddy proxies to.
pub const WEB_UI_PORT: u16 = 8102;
pub const GATEWAY_PORT: u16 = 18789;

pub const SEEDED_CONFIG: &str = r#"{"gateway":{"mode":"local","trustedProxies":["127.0.0.1","::1"]}}"#;

/// The config trusting loopback and the network gateway alone
pub fn with_trusted_proxies(config: &str, network_gateway: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(config).ok()?;
    let gateway = value.as_object_mut()?.entry("gateway").or_insert_with(|| serde_json::json!({}));
    gateway.as_object_mut()?.insert(
        "trustedProxies".to_string(),
        serde_json::json!(["127.0.0.1", "::1", network_gateway]),
    );
    serde_json::to_string_pretty(&value).ok().map(|text| text + "\n")
}

/// A port of `OpenClawService.configPath(_:)`
pub fn config_path(input: &Input) -> String {
    format!("{}/state/openclaw.json", input.openclaw_path)
}

/// A port of `OpenClawService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.openclaw_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.openclaw_hostname.clone()
    }
}

pub fn model_endpoint(services: &[String]) -> Option<String> {
    if services.iter().any(|id| id == litellm::SERVICE_ID) {
        return Some(super::ai_network::url(litellm::CONTAINER, litellm::CONTAINER_PORT) + "/v1");
    }
    if services.iter().any(|id| id == ollama::SERVICE_ID) {
        return Some(super::ai_network::url(ollama::CONTAINER, ollama::API_PORT));
    }
    None
}

/// A port of `OpenClawService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    compose_services(input) + super::ai_network::COMPOSE_TAIL
}

/// The services block, before the shared network joins it
fn compose_services(input: &Input) -> String {
    let path = &input.openclaw_path;
    format!("services:\n  openclaw:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # PID 1 that reaps: this process spawns browsers and helpers,\n    # and upstream's own compose asks for the same.\n    init: true\n    # Upstream's own posture, kept rather than trimmed: a service\n    # that talks to strangers' messengers has no use for raw\n    # sockets or for interface administration inside its namespace.\n    cap_drop:\n      - NET_RAW\n      - NET_ADMIN\n    security_opt:\n      - no-new-privileges:true\n    environment:\n      # Guards the gateway and its web UI. Generated on the server\n      # — see the report for where to read it.\n      OPENCLAW_GATEWAY_TOKEN: ${{OPENCLAW_GATEWAY_TOKEN}}\n      OPENCLAW_GATEWAY_PORT: \"{GATEWAY_PORT}\"\n      OPENCLAW_STATE_DIR: /home/node/.openclaw\n      OPENCLAW_CONFIG_DIR: /home/node/.openclaw\n      OPENCLAW_CONFIG_PATH: /home/node/.openclaw/openclaw.json\n      OPENCLAW_WORKSPACE_DIR: /home/node/.openclaw/workspace\n    volumes:\n      # One mount, because the workspace above lives inside the\n      # state directory: two mounts of nested paths would be two\n      # things to keep in step for no second lifetime.\n      - {path}/state:/home/node/.openclaw\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{GATEWAY_PORT}\"\n    command:\n      - node\n      - dist/index.js\n      - gateway\n      - --bind\n      - lan\n      - --port\n      - \"{GATEWAY_PORT}\"")
}

/// A port of `OpenClawService.composeFile(_:).envTemplate`.
pub fn env_template() -> String {
    "OPENCLAW_GATEWAY_TOKEN=__RANDOM__".to_string()
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
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
    caddy::site_overwriting_forwarded_for(
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
    fn hostname_defaults_to_the_plain_ai_name_and_never_to_agent() {
        assert_eq!(hostname(&base()), "ai.example.com");
        let mut crowded = base();
        crowded.installed_services = vec![SERVICE_ID.to_string(), "open-webui".to_string()];
        assert_eq!(hostname(&crowded), "openclaw.example.com");
    }

    /// The gateway wins over the engine, and neither is invented.
    #[test]
    fn the_model_endpoint_is_derived_and_the_gateway_leads() {
        let engine = vec!["openclaw".to_string(), "ollama".to_string()];
        assert!(model_endpoint(&engine).unwrap().ends_with(&ollama::API_PORT.to_string()));

        let both = vec!["openclaw".to_string(), "ollama".to_string(), "litellm".to_string()];
        assert!(model_endpoint(&both).unwrap().ends_with("/v1"));

        assert_eq!(model_endpoint(&["openclaw".to_string()]), None);
    }

    #[test]
    fn the_gateway_stays_behind_the_admin_guard() {
        assert!(web_ingress(&base()).admin_guard);
    }

    #[test]
    fn no_messenger_token_is_written_here() {
        let text = compose_contents(&base());
        for token in ["TELEGRAM", "DISCORD", "WHATSAPP", "BOT_TOKEN"] {
            assert!(!text.contains(token), "{token} belongs to the person, in their own UI");
        }
        assert!(text.contains("OPENCLAW_GATEWAY_TOKEN"));
    }

    #[test]
    fn the_install_trusts_the_network_gateway_alone() {
        let owned = r#"{"gateway":{"mode":"local","trustedProxies":["192.168.0.0/16"]},"channels":{"x":1}}"#;
        let text = with_trusted_proxies(owned, "192.168.64.1").unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["gateway"]["trustedProxies"], serde_json::json!(["127.0.0.1", "::1", "192.168.64.1"]));
        assert_eq!(value["gateway"]["mode"], "local");
        assert_eq!(value["channels"]["x"], 1);
        assert_eq!(with_trusted_proxies("{ // json5\n}", "192.168.64.1"), None);
        assert!(with_trusted_proxies(SEEDED_CONFIG, "10.0.0.1").is_some());
    }

    #[test]
    fn the_gateway_binds_where_the_published_port_can_reach_it() {
        let text = compose_contents(&base());
        assert!(text.contains("--bind\n      - lan"));
        assert!(text.contains(&format!("\"127.0.0.1:{WEB_UI_PORT}:{GATEWAY_PORT}\"")));
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

    fn check(name: &str, input: &Input) {
        assert_eq!(compose_contents(input), fixture(&format!("{name}__docker-compose.yml")));
        assert_eq!(hostname(input), fixture(&format!("{name}__hostname.txt")));
        assert_eq!(dns_hostnames(input).join("\n"), fixture(&format!("{name}__dns-hostnames.txt")));
        assert_eq!(caddy_site(input), fixture(&format!("{name}__caddy-site.txt")));
        let ingress = web_ingress(input);
        let rendered = format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}\npublicPaths={}",
            ingress.hostname,
            ingress.upstream_port,
            ingress.admin_guard,
            ingress.upstream_https,
            ingress.public_paths.join(" ")
        );
        assert_eq!(rendered, fixture(&format!("{name}__ingress.txt")));
        assert_eq!(env_template(), fixture(&format!("{name}__env.template")));
    }

    #[test]
    fn default_public_en() {
        check("openclaw-default-public-en", &Input { domain: "example.com".to_string(), ..Input::default() });
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        check("openclaw-mirrored-public-en", &input);
    }

    #[test]
    fn localonly_en() {
        let mut input = Input { domain: "home.local".to_string(), ..Input::default() };
        input.local_only = true;
        check("openclaw-localonly-en", &input);
    }

    #[test]
    fn customhost_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.openclaw_path = "/srv/openclaw".to_string();
        input.openclaw_hostname = "claw.example.com".to_string();
        check("openclaw-customhost-public-en", &input);
    }
}
