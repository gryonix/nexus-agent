use super::caddy::{self, WebIngress};
use super::context::Input;
use super::firewall;

/// Exact pinned tag
pub const SERVICE_ID: &str = "pihole";

pub const IMAGE: &str = "pihole/pihole:2026.07.2";
pub const COMPOSE_PROJECT: &str = "pihole";
pub const CONTAINER: &str = "pihole";
pub const WEB_UI_PORT: u16 = 8092;
/// Port the admin interface binds INSIDE the container
pub const CONTAINER_WEB_PORT: u16 = 80;

/// A port of `PiholeService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.pihole_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.pihole_hostname.clone()
    }
}

/// A port of `PiholeService.composeFile(_:).composeContents`
fn container_dns(upstreams: &str) -> String {
    let servers: Vec<&str> =
        upstreams.split(';').map(str::trim).filter(|s| !s.is_empty() && !s.contains('#')).collect();
    if servers.is_empty() {
        return String::new();
    }
    let list: String = servers.iter().map(|s| format!("\n      - {s}")).collect();
    format!("\n    # Blocklist downloads resolve here, not at the router\n    dns:{list}")
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.pihole_path;
    let upstreams = &input.pihole_upstreams;
    let bind = if input.pihole_serves_network { "" } else { "127.0.0.1:" };
    let dns = container_dns(upstreams);
    format!(
        "services:\n  pihole:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped{dns}\n    environment:\n      # Read by FTL itself: every `FTLCONF_<section>_<key>` maps to\n      # the matching key of pihole.toml. Verified in the pinned\n      # image's own `bash_functions.sh`, not assumed.\n      FTLCONF_webserver_api_password: ${{PIHOLE_ADMIN_PASSWORD}}\n      # `local` — FTL's default — answers only the subnets of its\n      # own interfaces, and inside a container that is the docker\n      # bridge alone: every forwarded query would be refused, which\n      # reads as \"the filter does not work\" rather than as a bind\n      # setting. What is actually reachable is decided by the\n      # published address below.\n      FTLCONF_dns_listeningMode: all\n      FTLCONF_dns_upstreams: {upstreams}\n    volumes:\n      - {path}/etc-pihole:/etc/pihole\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}/tcp\"\n      # See the type comment: a published port is reachable\n      # regardless of our nftables ruleset, so an open resolver is\n      # prevented by the bind address or nowhere.\n      - \"{bind}53:53/tcp\"\n      - \"{bind}53:53/udp\""
    )
}

/// A port of `PiholeService.composeFile(_:).envTemplate`
pub fn env_template() -> String {
    "PIHOLE_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `PiholeService.firewallPorts(_:)`
pub fn firewall_ports(input: &Input) -> Vec<firewall::Port> {
    if input.pihole_serves_network {
        vec![firewall::Port::tcp(53), firewall::Port::udp(53)]
    } else {
        vec![]
    }
}

/// A port of `PiholeService.dnsHostnames(_:)`
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

    fn input() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn plain_dns_is_loopback_only_until_the_network_is_asked_for() {
        let quiet = compose_contents(&input());
        assert!(quiet.contains("\"127.0.0.1:53:53/tcp\""), "{quiet}");
        assert!(quiet.contains("\"127.0.0.1:53:53/udp\""), "{quiet}");
        assert!(!quiet.contains("\"53:53/tcp\""), "an open resolver must not be the default: {quiet}");

        let mut wide = input();
        wide.pihole_serves_network = true;
        let served = compose_contents(&wide);
        assert!(served.contains("\"53:53/tcp\""), "{served}");
        assert!(served.contains("\"53:53/udp\""), "{served}");
        assert!(!served.contains("127.0.0.1:53:53"), "{served}");
    }

    /// The firewall drop-in follows the same switch
    #[test]
    fn firewall_ports_follow_the_same_switch() {
        assert!(firewall_ports(&input()).is_empty());
        let mut wide = input();
        wide.pihole_serves_network = true;
        assert_eq!(firewall_ports(&wide), vec![firewall::Port::tcp(53), firewall::Port::udp(53)]);
    }

    #[test]
    fn the_default_hostname_is_the_shelf_name() {
        assert_eq!(hostname(&input()), "dns.example.com");
        let mut custom = input();
        custom.pihole_hostname = "filter.example.net".to_string();
        assert_eq!(hostname(&custom), "filter.example.net");
    }

    #[test]
    fn the_admin_password_is_a_generated_template_not_a_literal() {
        assert_eq!(env_template(), "PIHOLE_ADMIN_PASSWORD=__RANDOM__");
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;

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

    fn ports_text(ports: &[firewall::Port]) -> String {
        ports
            .iter()
            .map(|p| format!("{}/{}", p.proto, p.port))
            .collect::<Vec<_>>()
            .join("\n")
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
        assert_eq!(
            ports_text(&firewall_ports(input)),
            fixture(&format!("{scenario}__firewall-ports.txt")),
            "{scenario}: firewall-ports.txt"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "pihole-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "pihole-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "pihole-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.pihole_hostname = "filter.example.com".to_string();
        assert_parity(&input, "pihole-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.pihole_path = "/srv/pihole".to_string();
        assert_parity(&input, "pihole-custompath-public-en");
    }

    /// THE scenario of this service
    #[test]
    fn servesnetwork_public_en() {
        let mut input = base("example.com");
        input.pihole_serves_network = true;
        assert_parity(&input, "pihole-servesnetwork-public-en");
    }

    #[test]
    fn upstreams_public_en() {
        let mut input = base("example.com");
        input.pihole_upstreams = "9.9.9.9;149.112.112.112".to_string();
        assert_parity(&input, "pihole-upstreams-public-en");
    }

    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.pihole_hostname = "dns.other-company.net".to_string();
        assert_parity(&input, "pihole-foreignhost-mirrored-public-en");
    }
}
