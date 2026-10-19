use super::super::caddy;
use super::super::context::Input;

pub const SERVICE_ID: &str = "vpn";

pub const COMPOSE_PROJECT: &str = "vpnpanel";
pub const CONTAINER: &str = "vpnpanel";
pub const PATH: &str = "/opt/gryonix-vpn-panel";
/// Loopback-only port the panel binds; Caddy reverse-proxies `vpn.<domain>` to it
pub const WEB_UI_PORT: u16 = 51900;
pub const IMAGE: &str = "gryonix-vpn-panel:local";
pub const WG_SUBNET: &str = "10.9.0.0/24";
pub const LOCKDOWN_SCRIPT_PATH: &str = "/opt/gryonixnexus-admin-lockdown.sh";

pub const DOCKERFILE: &str = include_str!("assets/Dockerfile");
pub const APP_PY: &str = include_str!("assets/app.py");
pub const INDEX_HTML: &str = include_str!("assets/index.html");
pub const LOGIN_HTML: &str = include_str!("assets/login.html");
pub const RESET_HTML: &str = include_str!("assets/reset.html");
pub const ADMIN_LOCKDOWN_SH: &str = include_str!("assets/admin-lockdown.sh");

pub fn build_files() -> [(&'static str, &'static str); 5] {
    [
        ("Dockerfile", DOCKERFILE),
        ("app.py", APP_PY),
        ("index.html", INDEX_HTML),
        ("login.html", LOGIN_HTML),
        ("reset.html", RESET_HTML),
    ]
}

/// The VPN protocols the panel can present
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    WireGuard,
    AmneziaWG,
    Shadowsocks,
    XrayReality,
    OpenVPN,
}

impl Protocol {
    /// The Swift `ServiceID.rawValue` a client names it by.
    pub fn service_id(self) -> &'static str {
        match self {
            Protocol::WireGuard => "wireguard-vpn",
            Protocol::AmneziaWG => "amnezia-wg",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::XrayReality => "xray-reality",
            Protocol::OpenVPN => "openvpn",
        }
    }

    fn json_id(self) -> &'static str {
        match self {
            Protocol::WireGuard => "wireguard",
            Protocol::AmneziaWG => "amneziawg",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::XrayReality => "xray",
            Protocol::OpenVPN => "openvpn",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Protocol::WireGuard => "WireGuard",
            Protocol::AmneziaWG => "AmneziaWG",
            Protocol::Shadowsocks => "Shadowsocks",
            Protocol::XrayReality => "VLESS / Reality",
            Protocol::OpenVPN => "OpenVPN",
        }
    }

    /// The transport label the panel prints next to the endpoint.
    fn transport(self) -> &'static str {
        match self {
            Protocol::WireGuard | Protocol::AmneziaWG | Protocol::OpenVPN => "UDP",
            Protocol::Shadowsocks => "TCP+UDP",
            Protocol::XrayReality => "TCP",
        }
    }

    fn port(self, input: &Input) -> u16 {
        match self {
            Protocol::WireGuard => input.wireguard_vpn_port,
            Protocol::AmneziaWG => input.amnezia_wg_port,
            Protocol::Shadowsocks => input.shadowsocks_port,
            Protocol::XrayReality => input.xray_reality_port,
            Protocol::OpenVPN => input.openvpn_port,
        }
    }

    pub fn firewall_ports(self, input: &Input) -> Vec<super::super::firewall::Port> {
        use super::super::firewall::Port;
        let port = self.port(input);
        match self {
            Protocol::WireGuard | Protocol::AmneziaWG | Protocol::OpenVPN => vec![Port::udp(port)],
            Protocol::XrayReality => vec![Port::tcp(port)],
            Protocol::Shadowsocks => vec![Port::tcp(port), Port::udp(port)],
        }
    }
}

/// A port of `VPNPanelService.hostname`.
pub fn hostname(input: &Input) -> String {
    if input.vpn_hostname.is_empty() {
        format!("vpn.{}", input.domain)
    } else {
        input.vpn_hostname.clone()
    }
}

/// A port of `VPNPanelService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let wg_port = input.wireguard_vpn_port;
    format!(
        "services:
  vpnpanel:
    build: {PATH}/build
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
    env_file:
      - {PATH}/.env
    volumes:
      - {PATH}/data:/data
      # The agent's broker restarts and inspects the protocol
      # containers; the panel holds no docker socket. Config
      # dirs below; unused mounts are harmless empty dirs.
      - /run/gryonixnexus-panel:/run/gryonixnexus-panel
      - {shadowsocks}:/protocols/shadowsocks
      - {xray}:/protocols/xray
      - {openvpn}/data:/protocols/openvpn
      - {amnezia}/data:/protocols/amneziawg
      # Read-only: lets the panel find mailcow's database
      # credentials so it can offer the existing mailboxes as the
      # sender for password-reset mail. The DIRECTORY is
      # mounted, not mailcow.conf itself — docker materialises a
      # missing bind source, and an empty mailcow.conf directory
      # would make mailcow's own \"already configured?\" guard skip
      # generate_config.sh on a later install. An empty directory
      # is harmless: git clone still populates it.
      - {mailcow}:/protocols/mailcow:ro
    extra_hosts:
      # Reaching the host's SMTP listener (mailcow's Postfix) from
      # inside the container.
      - \"host.docker.internal:host-gateway\"
    ports:
      - \"127.0.0.1:{WEB_UI_PORT}:80\"
      # WireGuard (only listens when WireGuard is among the enabled
      # protocols; harmless otherwise).
      - \"{wg_port}:{wg_port}/udp\"",
        shadowsocks = input.shadowsocks_path,
        xray = input.xray_reality_path,
        openvpn = input.openvpn_path,
        amnezia = input.amnezia_wg_path,
        mailcow = input.mailcow_path,
    )
}

pub fn env_contents(input: &Input, password: &str) -> String {
    format!(
        "ADMIN_USER={}\nADMIN_PASSWORD={}\nWG_HOST={}\nWG_PORT={}\nWG_SUBNET={}\n",
        input.admin_username,
        password,
        hostname(input),
        input.wireguard_vpn_port,
        WG_SUBNET
    )
}

pub fn services_json(input: &Input, protocols: &[Protocol]) -> String {
    let host = hostname(input);
    let entries: Vec<String> = [
        Protocol::WireGuard,
        Protocol::AmneziaWG,
        Protocol::Shadowsocks,
        Protocol::XrayReality,
        Protocol::OpenVPN,
    ]
    .into_iter()
    .filter(|p| protocols.contains(p))
    .map(|p| {
        let shared = super::port_share::shared_port(input, protocols).filter(|_| p == Protocol::AmneziaWG);
        let port = shared.unwrap_or(p.port(input));
        format!(
            "{{\"id\":\"{}\",\"name\":\"{}\",\"endpoint\":\"{host}:{port} · {}\",\"host\":\"{host}\",\"port\":\"{port}\"}}",
            p.json_id(),
            p.display_name(),
            p.transport()
        )
    })
    .collect();
    format!("{{\"services\":[{}]}}\n", entries.join(","))
}

pub fn web_ingress(input: &Input) -> caddy::WebIngress {
    caddy::WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

/// Does this deployment publish the panel's page at all?
pub fn publishes_site(input: &Input) -> bool {
    input.vpn_client_access != "app"
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    if !publishes_site(input) {
        return Vec::new();
    }
    input.served_hostnames(&hostname(input))
}

pub fn caddy_site(input: &Input) -> String {
    if !publishes_site(input) {
        return String::new();
    }
    let ingress = web_ingress(input);
    caddy::site_overwriting_forwarded_for(
        SERVICE_ID,
        &caddy_site_names(input).join(", "),
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        false,
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/vpn/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    // ─────────────────── assets: drift against the REAL script ───────────────────

    #[test]
    fn every_panel_asset_matches_the_generators_own_bytes() {
        for (name, embedded) in [
            ("Dockerfile", DOCKERFILE),
            ("app.py", APP_PY),
            ("index.html", INDEX_HTML),
            ("login.html", LOGIN_HTML),
            ("reset.html", RESET_HTML),
            ("admin-lockdown.sh", ADMIN_LOCKDOWN_SH),
        ] {
            assert_eq!(embedded, fixture(&format!("assets/{name}")), "{name} drifted from the generator");
        }
    }

    #[test]
    fn the_lockdown_wrapper_is_the_script_lockdown_rs_calls() {
        assert_eq!(LOCKDOWN_SCRIPT_PATH, crate::lockdown::WRAPPER_PATH);
        assert!(ADMIN_LOCKDOWN_SH.starts_with("#!/bin/bash\n"));
        assert!(ADMIN_LOCKDOWN_SH.contains(caddy::ADMIN_GUARD_PATH));
        for verb in ["on)", "only)", "off)", "status)"] {
            assert!(ADMIN_LOCKDOWN_SH.contains(verb), "the wrapper lost its {verb} arm");
        }
    }

    // ─────────────────────────── fixture parity ───────────────────────────

    #[test]
    fn compose_matches_the_generator_on_defaults() {
        assert_eq!(compose_contents(&base()), fixture("vpn-default-public-en__docker-compose.yml"));
    }

    #[test]
    fn compose_matches_the_generator_with_every_path_and_the_port_moved() {
        let input = Input {
            admin_username: "operator".to_string(),
            mailcow_path: "/srv/mailcow".to_string(),
            wireguard_vpn_port: 51999,
            amnezia_wg_path: "/srv/awg".to_string(),
            shadowsocks_path: "/srv/ss".to_string(),
            xray_reality_path: "/srv/xray".to_string(),
            openvpn_path: "/srv/ovpn".to_string(),
            ..base()
        };
        assert_eq!(compose_contents(&input), fixture("vpn-custompaths-public-en__docker-compose.yml"));
    }

    #[test]
    fn compose_matches_the_bytes_a_real_generated_script_wrote() {
        let input = Input { wireguard_vpn_port: 51821, ..base() };
        for scenario in [
            "vpn-wg-public-en",
            "vpn-awg-public-en",
            "vpn-ss-public-en",
            "vpn-xray-public-en",
            "vpn-ovpn-public-en",
            "vpn-mirrored-public-en",
            "vpn-relay-home-en",
        ] {
            assert_eq!(
                format!("{}\n", compose_contents(&input)),
                fixture(&format!("{scenario}__docker-compose.yml")),
                "{scenario}"
            );
        }
    }

    #[test]
    fn hostname_and_dns_records_match_the_generator() {
        assert_eq!(hostname(&base()), fixture("vpn-default-public-en__hostname.txt"));
        assert_eq!(dns_hostnames(&base()).join("\n"), fixture("vpn-default-public-en__dns-hostnames.txt"));

        let custom = Input { vpn_hostname: "tunnel.example.com".to_string(), ..base() };
        assert_eq!(hostname(&custom), fixture("vpn-customhost-mirrored-public-en__hostname.txt"));
    }

    #[test]
    fn caddy_site_matches_the_generator_on_defaults_and_on_mirrors() {
        assert_eq!(caddy_site(&base()), fixture("vpn-default-public-en__caddy-site.txt"));

        let mirrored = Input {
            vpn_hostname: "tunnel.example.com".to_string(),
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            ..base()
        };
        assert_eq!(
            caddy_site_names(&mirrored).join(", "),
            fixture("vpn-customhost-mirrored-public-en__caddy-site-names.txt")
        );
        assert_eq!(caddy_site(&mirrored), fixture("vpn-customhost-mirrored-public-en__caddy-site.txt"));
    }

    #[test]
    fn a_foreign_panel_hostname_is_never_mirrored_onto_the_deployments_domains() {
        let input = Input {
            vpn_hostname: "vpn.other-company.net".to_string(),
            additional_domains: vec!["example.org".to_string()],
            ..base()
        };
        assert_eq!(
            caddy_site_names(&input).join(", "),
            fixture("vpn-foreignhost-mirrored-public-en__caddy-site-names.txt")
        );
        assert_eq!(caddy_site(&input), fixture("vpn-foreignhost-mirrored-public-en__caddy-site.txt"));
    }

    #[test]
    fn the_mirrored_script_scenario_reproduces_its_caddy_site() {
        let input = Input {
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            wireguard_vpn_port: 51821,
            ..base()
        };
        // Same heredoc newline as the compose fixtures above.
        assert_eq!(format!("{}\n", caddy_site(&input)), fixture("vpn-mirrored-public-en__caddy-site.txt"));
    }

    // ─────────────────────────── services.json ───────────────────────────

    /// One fixture per protocol, each from a real generated script
    #[test]
    fn services_json_matches_the_generator_for_every_protocol() {
        for (protocol, scenario, port) in [
            (Protocol::WireGuard, "vpn-wg-public-en", 51821),
            (Protocol::AmneziaWG, "vpn-awg-public-en", 51822),
            (Protocol::Shadowsocks, "vpn-ss-public-en", 8388),
            (Protocol::XrayReality, "vpn-xray-public-en", 8443),
            (Protocol::OpenVPN, "vpn-ovpn-public-en", 1194),
        ] {
            let input = Input {
                wireguard_vpn_port: port,
                amnezia_wg_port: port,
                shadowsocks_port: port,
                xray_reality_port: port,
                openvpn_port: port,
                ..base()
            };
            assert_eq!(
                services_json(&input, &[protocol]),
                fixture(&format!("{scenario}__services.json")),
                "{scenario}"
            );
        }
    }

    #[test]
    fn multiple_protocols_are_joined_in_the_generators_own_order() {
        let input = base();
        let json = services_json(&input, &[Protocol::OpenVPN, Protocol::WireGuard, Protocol::Shadowsocks]);
        let wireguard = json.find("\"wireguard\"").expect("wireguard entry");
        let shadowsocks = json.find("\"shadowsocks\"").expect("shadowsocks entry");
        let openvpn = json.find("\"openvpn\"").expect("openvpn entry");
        assert!(wireguard < shadowsocks && shadowsocks < openvpn, "{json}");
        assert_eq!(json.matches("},{").count(), 2, "entries are joined with a bare comma: {json}");
        assert!(!json.contains("amnezia"), "an unselected protocol must not appear: {json}");
    }

    #[test]
    fn no_protocol_at_all_is_the_empty_registry_the_setup_script_seeds() {
        assert_eq!(services_json(&base(), &[]), "{\"services\":[]}\n");
    }

    /// AmneziaWG clients are told the WireGuard port once both run
    #[test]
    fn amneziawg_is_advertised_on_the_wireguard_port_beside_it() {
        let both = services_json(&base(), &[Protocol::WireGuard, Protocol::AmneziaWG]);
        assert!(both.contains("\"id\":\"amneziawg\",\"name\":\"AmneziaWG\",\"endpoint\":\"vpn.example.com:51820 · UDP\""), "{both}");
        let alone = services_json(&base(), &[Protocol::AmneziaWG]);
        assert!(alone.contains("\"port\":\"51822\""), "{alone}");
    }

    // ─────────────────────────── .env ───────────────────────────

    #[test]
    fn env_matches_the_block_the_setup_script_actually_runs() {
        let input = Input { wireguard_vpn_port: 51821, ..base() };
        assert_eq!(env_contents(&input, "__PW__"), fixture("vpn-wg-public-en__env.txt"));
    }

    #[test]
    fn env_tracks_the_admin_username_and_the_custom_hostname() {
        let input = Input {
            admin_username: "operator".to_string(),
            vpn_hostname: "tunnel.example.com".to_string(),
            wireguard_vpn_port: 51999,
            ..base()
        };
        assert_eq!(
            env_contents(&input, "deadbeef"),
            "ADMIN_USER=operator\nADMIN_PASSWORD=deadbeef\nWG_HOST=tunnel.example.com\nWG_PORT=51999\nWG_SUBNET=10.9.0.0/24\n"
        );
    }

    // ─────────────────────────── firewall ports ───────────────────────────

    #[test]
    fn each_protocol_declares_the_ports_its_swift_service_declares() {
        use super::super::super::firewall::Port;
        let input = base();
        assert_eq!(Protocol::WireGuard.firewall_ports(&input), vec![Port::udp(51820)]);
        assert_eq!(Protocol::AmneziaWG.firewall_ports(&input), vec![Port::udp(51822)]);
        assert_eq!(Protocol::OpenVPN.firewall_ports(&input), vec![Port::udp(1194)]);
        assert_eq!(Protocol::XrayReality.firewall_ports(&input), vec![Port::tcp(8443)]);
        // Shadowsocks answers on both transports on the same port.
        assert_eq!(Protocol::Shadowsocks.firewall_ports(&input), vec![Port::tcp(8388), Port::udp(8388)]);
    }
}

#[cfg(test)]
mod client_access_tests {
    use super::*;

    fn input(access: &str) -> Input {
        Input {
            domain: "example.com".to_string(),
            vpn_client_access: access.to_string(),
            ..Input::default()
        }
    }

    #[test]
    fn both_and_panel_publish_the_page() {
        for access in ["both", "panel", "", "something-a-newer-app-sent"] {
            assert!(publishes_site(&input(access)), "{access} must publish");
            assert!(!caddy_site(&input(access)).is_empty());
            assert_eq!(caddy_site_names(&input(access)), vec!["vpn.example.com"]);
        }
    }

    /// App-only drops the site AND its name together
    #[test]
    fn app_only_drops_the_site_and_its_name_together() {
        let input = input("app");
        assert!(!publishes_site(&input));
        assert!(caddy_site(&input).is_empty());
        assert!(caddy_site_names(&input).is_empty());
    }
}
