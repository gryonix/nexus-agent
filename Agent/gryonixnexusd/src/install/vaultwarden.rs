//! Vaultwarden's declarative install artifacts — a port of
//! `Packages/gryonixNexus/Sources/ServiceCatalog/Services/VaultwardenService.swift`,
//! declarative half only (compose file, env template, hostname, DNS
//! hostnames, Caddy ingress). The imperative half — the `config.json` sync
//! that keeps the app's signups toggle authoritative — lives in
//! `execute.rs`, next to AdGuard's, because that is where the executor is.

use super::caddy::{self, WebIngress};
use super::context::Input;

pub const SERVICE_ID: &str = "vaultwarden";

pub const IMAGE: &str = "vaultwarden/server:latest";
pub const COMPOSE_PROJECT: &str = "vaultwarden";
pub const COMPOSE_DIRECTORY: &str = "/opt/vaultwarden";
/// Loopback port Caddy proxies to — distinct from every other service's.
pub const WEB_UI_PORT: u16 = 8082;

/// A port of `VaultwardenService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.vaultwarden_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.vaultwarden_hostname.clone()
    }
}

fn signups(input: &Input) -> &'static str {
    if input.vaultwarden_allow_signups {
        "true"
    } else {
        "false"
    }
}

/// A port of `VaultwardenService.composeFile(_:).composeContents`
pub fn compose_contents(input: &Input) -> String {
    let container = &input.vaultwarden_container;
    let data_path = &input.vaultwarden_data_path;
    let signups = signups(input);
    let host = hostname(input);
    format!(
        "services:\n  vaultwarden:\n    image: {IMAGE}\n    container_name: {container}\n    restart: unless-stopped\n    environment:\n      DOMAIN: \"https://{host}\"\n      SIGNUPS_ALLOWED: \"{signups}\"\n      ADMIN_TOKEN: ${{ADMIN_TOKEN}}\n      IP_HEADER: X-Forwarded-For\n    volumes:\n      - {data_path}:/data\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    )
}

/// A port of `VaultwardenService.composeFile(_:).envTemplate`
pub fn env_template() -> String {
    "ADMIN_TOKEN=__RANDOM__".to_string()
}

/// A port of `VaultwardenService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

pub const BITWARDEN_API_PATHS: [&str; 8] = [
    "/api/*",
    "/identity/*",
    "/notifications/*",
    "/icons/*",
    "/attachments/*",
    "/.well-known/*",
    "/alive",
    "/app-id.json",
];

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: BITWARDEN_API_PATHS.iter().map(|path| path.to_string()).collect(),
    }
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the Vaultwarden slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site_with_public_paths(
        SERVICE_ID,
        &joined,
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        input.local_only,
        false,
        &ingress.public_paths,
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn the_bitwarden_api_is_open_and_the_web_vault_and_admin_are_guarded() {
        let site = caddy_site(&base("example.com"));
        assert!(site.contains("@gryonixnexus_open path /api/* /identity/* /notifications/* /icons/* /attachments/* /.well-known/* /alive /app-id.json"));
        let (open, guarded) = site.split_once("    handle {\n").unwrap();
        assert!(!open.contains("admin-guard"));
        assert!(guarded.contains("admin-guard"));
    }

    #[test]
    fn hostname_defaults_to_vault_subdomain() {
        assert_eq!(hostname(&base("example.com")), "vault.example.com");
    }

    #[test]
    fn compose_names_the_configured_container_not_the_project() {
        let mut input = base("example.com");
        input.vaultwarden_container = "vw".to_string();
        assert!(compose_contents(&input).contains("container_name: vw"));
    }

    #[test]
    fn compose_carries_the_signups_toggle_as_a_quoted_string() {
        let mut input = base("example.com");
        input.vaultwarden_allow_signups = false;
        assert!(compose_contents(&input).contains("SIGNUPS_ALLOWED: \"false\""));
    }

    #[test]
    fn compose_keeps_the_admin_token_placeholder_for_compose_to_expand() {
        assert!(compose_contents(&base("example.com")).contains("ADMIN_TOKEN: ${ADMIN_TOKEN}"));
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::language::Language;

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
        assert_eq!(env_template(), fixture(&format!("{scenario}__env.template")), "{scenario}: env.template");
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
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "vw-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "vw-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "vw-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.vaultwarden_hostname = "pass.example.com".to_string();
        assert_parity(&input, "vw-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.vaultwarden_container = "vw".to_string();
        input.vaultwarden_data_path = "/srv/vault/data".to_string();
        assert_parity(&input, "vw-custompath-public-en");
    }

    #[test]
    fn signups_closed_en() {
        let mut input = base("example.com");
        input.vaultwarden_allow_signups = false;
        assert_parity(&input, "vw-signups-closed-en");
    }

    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.vaultwarden_hostname = "vault.other-company.net".to_string();
        assert_parity(&input, "vw-foreignhost-mirrored-public-en");
    }

    #[test]
    fn language_does_not_change_the_declarative_artifacts() {
        let mut ru = base("example.com");
        ru.language = Language::Ru;
        assert_eq!(compose_contents(&ru), compose_contents(&base("example.com")));
        assert_eq!(caddy_site(&ru), caddy_site(&base("example.com")));
    }
}
