use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact pinned tag
pub const SERVICE_ID: &str = "adguard-home";

pub const IMAGE: &str = "adguard/adguardhome:v0.107.78";
pub const COMPOSE_PROJECT: &str = "adguardhome";
pub const CONTAINER: &str = "adguardhome";
pub const WEB_UI_PORT: u16 = 8087;
pub const CONTAINER_WEB_PORT: u16 = 3000;

/// A port of `AdGuardHomeService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.adguard_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.adguard_hostname.clone()
    }
}

/// A port of `AdGuardHomeService.composeFile(_:).composeContents`
pub fn compose_contents(input: &Input) -> String {
    let path = &input.adguard_path;
    format!(
        "services:\n  adguardhome:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    volumes:\n      - {path}/conf:/opt/adguardhome/conf\n      - {path}/work:/opt/adguardhome/work\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}\"\n      # Loopback ONLY — see the type comment. A published port is\n      # reachable from the internet regardless of our nftables\n      # ruleset, so an open resolver is prevented here or nowhere.\n      - \"127.0.0.1:53:53/tcp\"\n      - \"127.0.0.1:53:53/udp\""
    )
}

/// A port of `AdGuardHomeService.composeFile(_:).envTemplate`
pub fn env_template() -> String {
    "ADGUARD_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `AdGuardHomeService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
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
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_dns_subdomain() {
        assert_eq!(hostname(&base("example.com")), "dns.example.com");
    }

    #[test]
    fn hostname_prefers_a_custom_value() {
        let mut input = base("example.com");
        input.adguard_hostname = "filter.example.com".to_string();
        assert_eq!(hostname(&input), "filter.example.com");
    }

    #[test]
    fn web_ingress_defaults_admin_guard_true_and_https_false() {
        let ingress = web_ingress(&base("example.com"));
        assert!(ingress.admin_guard);
        assert!(!ingress.upstream_https);
        assert_eq!(ingress.upstream_port, WEB_UI_PORT);
    }

    #[test]
    fn caddy_site_mirrors_the_hostname_onto_additional_domains() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert!(caddy_site(&input).starts_with("dns.example.com, dns.example.org {"));
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
        assert_parity(&base("example.com"), "default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.adguard_hostname = "filter.example.com".to_string();
        assert_parity(&input, "customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.adguard_path = "/srv/adguard".to_string();
        assert_parity(&input, "custompath-public-en");
    }

    #[test]
    fn mirrored_localonly_ru() {
        let mut input = base("home.local");
        input.local_only = true;
        input.additional_domains = vec!["home.lan".to_string()];
        input.language = Language::Ru;
        input.admin_username = "operator".to_string();
        assert_parity(&input, "mirrored-localonly-ru");
    }

    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.adguard_hostname = "dns.other-company.net".to_string();
        assert_parity(&input, "foreignhost-mirrored-public-en");
    }
}
