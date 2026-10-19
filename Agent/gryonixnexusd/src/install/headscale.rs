//! Headscale's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/HeadscaleService.swift`

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact pinned tag
pub const SERVICE_ID: &str = "headscale";

pub const IMAGE: &str = "headscale/headscale:v0.29.3";
pub const COMPOSE_PROJECT: &str = "headscale";
pub const CONTAINER: &str = "headscale";
/// Loopback port Caddy proxies to — distinct from every other upstream.
pub const WEB_UI_PORT: u16 = 8091;
/// Port headscale serves on INSIDE the container.
pub const CONTAINER_PORT: u16 = 8080;
/// STUN for the embedded DERP relay
pub const STUN_PORT: u16 = 3478;
pub const EXTRA_RECORDS_IN_CONTAINER: &str = "/etc/headscale/extra-records.json";
/// Its file name on the host, under the config directory.
pub const EXTRA_RECORDS_FILE: &str = "extra-records.json";

/// A port of `HeadscaleService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.headscale_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.headscale_hostname.clone()
    }
}

/// A port of `HeadscaleService.baseDomain(_:)` — the MagicDNS suffix
pub fn base_domain(input: &Input) -> String {
    if input.headscale_base_domain.is_empty() {
        format!("ts.{}", input.domain)
    } else {
        input.headscale_base_domain.clone()
    }
}

/// A port of `HeadscaleService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.headscale_path;
    format!(
        "services:\n  headscale:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    \
         restart: unless-stopped\n    command: serve\n    volumes:\n      - {path}/config:/etc/headscale\n      \
         - {path}/data:/var/lib/headscale\n    ports:\n      \
         # Loopback only: Caddy terminates TLS in front of it, which\n      \
         # also puts it under the lockdown guard like every other UI.\n      \
         # The clients REQUIRE the control server over HTTPS, and the\n      \
         # certificate is Caddy's.\n      \
         - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\"\n      \
         # Public on purpose — STUN for the embedded DERP relay. A\n      \
         # relay only reachable from this host relays nothing.\n      \
         - \"{STUN_PORT}:{STUN_PORT}/udp\"",
    )
}

/// The server's own `config.yaml`
pub fn config_yaml(input: &Input) -> String {
    let host = hostname(input);
    let base = base_domain(input);
    format!(
        "server_url: https://{host}\n\
         listen_addr: 0.0.0.0:{CONTAINER_PORT}\n\
         metrics_listen_addr: 127.0.0.1:9090\n\
         noise:\n  private_key_path: /var/lib/headscale/noise_private.key\n\
         prefixes:\n  v4: 100.64.0.0/10\n  v6: fd7a:115c:a1e0::/48\n  allocation: sequential\n\
         derp:\n  server:\n    \
         # The point of self-hosting: without this, a node that cannot\n    \
         # reach its peer directly falls back to Tailscale's public\n    \
         # relays. Measured — a lab node reported a relay region abroad\n    \
         # while this was off.\n    \
         enabled: true\n    region_id: 999\n    region_code: \"gryonix\"\n    \
         region_name: \"{host}\"\n    stun_listen_addr: \"0.0.0.0:{STUN_PORT}\"\n    \
         private_key_path: /var/lib/headscale/derp_server_private.key\n  \
         # No public relay map: everything stays on this host.\n  urls: []\n  \
         auto_update_enabled: false\n\
         database:\n  type: sqlite\n  sqlite:\n    path: /var/lib/headscale/db.sqlite\n\
         log:\n  level: info\n\
         dns:\n  magic_dns: true\n  base_domain: {base}\n  \
         # Service names inside the mesh, pointed at this server's own\n  \
         # mesh address. A separate FILE rather than an inline\n  \
         # `extra_records` block (the two are mutually exclusive) because\n  \
         # the addresses are not known now: a node's mesh address is\n  \
         # handed out when it joins, which is after this file is written.\n  \
         extra_records_path: {EXTRA_RECORDS_IN_CONTAINER}\n  \
         nameservers:\n    global:\n      - 1.1.1.1\n\
         policy:\n  mode: database\n"
    )
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: false, upstream_https: false, public_paths: Vec::new() }
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

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/mesh/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn config_from_setup_steps(steps: &str) -> String {
        let start = steps.find("<<'EOF_HEADSCALE'\n").expect("heredoc opener") + "<<'EOF_HEADSCALE'\n".len();
        let rest = &steps[start..];
        let end = rest.find("\nEOF_HEADSCALE").expect("heredoc terminator");
        format!("{}\n", &rest[..end])
    }

    fn scenario(name: &str) -> Input {
        let mut input = Input::default();
        match name {
            "default-public-en" | "default-public-ru" => input.domain = "example.com".to_string(),
            "custom-public-en" => {
                input.domain = "example.com".to_string();
                input.headscale_path = "/srv/mesh".to_string();
                input.headscale_hostname = "control.example.com".to_string();
                input.headscale_base_domain = "mesh.internal".to_string();
            }
            "subdomain-public-en" => {
                input.domain = "b5.example.net".to_string();
                input.additional_domains = vec!["b6.example.net".to_string()];
            }
            other => panic!("unknown scenario {other}"),
        }
        input
    }

    const SCENARIOS: &[&str] =
        &["default-public-en", "default-public-ru", "custom-public-en", "subdomain-public-en"];

    #[test]
    fn fixture_parity_compose() {
        for name in SCENARIOS {
            assert_eq!(
                compose_contents(&scenario(name)),
                fixture(&format!("headscale-{name}__docker-compose.yml")),
                "{name}"
            );
        }
    }

    #[test]
    fn fixture_parity_config_yaml() {
        for name in SCENARIOS {
            let steps = fixture(&format!("headscale-{name}__setup-steps.txt"));
            assert_eq!(config_yaml(&scenario(name)), config_from_setup_steps(&steps), "{name}");
        }
    }

    fn base(domain: &str) -> Input {
        let mut input = Input::default();
        input.domain = domain.to_string();
        input
    }

    #[test]
    fn the_defaults_are_the_swift_ones() {
        let input = base("example.com");
        assert_eq!(hostname(&input), "mesh.example.com");
        assert_eq!(base_domain(&input), "ts.example.com");
        assert_eq!(input.headscale_path, "/opt/headscale");
    }

    #[test]
    fn a_custom_hostname_and_base_domain_win() {
        let mut input = base("example.com");
        input.headscale_hostname = "vpn-control.example.com".to_string();
        input.headscale_base_domain = "mesh.internal".to_string();
        assert_eq!(hostname(&input), "vpn-control.example.com");
        assert_eq!(base_domain(&input), "mesh.internal");
    }

    #[test]
    fn the_magic_dns_suffix_is_a_branch_of_its_own() {
        let input = base("example.com");
        assert_ne!(base_domain(&input), input.domain);
        assert!(base_domain(&input).ends_with(&input.domain));
        assert!(config_yaml(&input).contains("base_domain: ts.example.com"));
    }

    #[test]
    fn the_embedded_relay_is_enabled_and_serves_its_own_map() {
        let yaml = config_yaml(&base("example.com"));
        assert!(yaml.contains("enabled: true"), "the embedded DERP server must be on");
        assert!(yaml.contains("urls: []"), "no public relay map may be pulled in");
        assert!(yaml.contains(&format!("stun_listen_addr: \"0.0.0.0:{STUN_PORT}\"")));
        assert!(compose_contents(&base("example.com")).contains(&format!("\"{STUN_PORT}:{STUN_PORT}/udp\"")),
                "the STUN port has to be published publicly or the relay is unreachable");
    }

    #[test]
    fn the_control_server_is_not_behind_the_vpn_guard() {
        let input = base("example.com");
        assert!(!web_ingress(&input).admin_guard);
        assert!(!caddy_site(&input).contains("gryonixnexus-admin-guard"));
    }

    #[test]
    fn the_web_port_is_loopback_only() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains(&format!("\"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\"")));
    }

    #[test]
    fn a_foreign_hostname_is_not_mirrored() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.headscale_hostname = "mesh.other-company.net".to_string();
        assert_eq!(caddy_site_names(&input), vec!["mesh.other-company.net".to_string()]);
    }
}
