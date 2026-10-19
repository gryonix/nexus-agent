//! The server's own mesh membership — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/TailscaleNodeService.swift`

use super::context::Input;

/// Exact pinned tag
pub const IMAGE: &str = "tailscale/tailscale:v1.102.2";
pub const COMPOSE_PROJECT: &str = "tailscale";
pub const CONTAINER: &str = "tailscale";
pub const MESH_USER: &str = "gryonixnexus";

/// A port of `TailscaleNodeService.nodeName(_:)`.
pub fn node_name(input: &Input) -> String {
    if !input.tailscale_node_name.is_empty() {
        return input.tailscale_node_name.clone();
    }
    input
        .domain
        .split('.')
        .next()
        .filter(|label| !label.is_empty())
        .unwrap_or("server")
        .to_string()
}

/// A port of `TailscaleNodeService.extraArgs(_:)`
pub fn extra_args(input: &Input) -> String {
    let login = input.tailscale_login_server.trim();
    if login.is_empty() {
        "--accept-dns=false".to_string()
    } else {
        format!("--login-server={login} --accept-dns=false")
    }
}

/// A port of `TailscaleNodeService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.tailscale_node_path;
    let name = node_name(input);
    let args = extra_args(input);
    format!(
        "services:\n  tailscale:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    \
         restart: unless-stopped\n    \
         # The HOST's network stack, so the interface it creates belongs\n    \
         # to this machine rather than to a container nobody routes to.\n    \
         # With this, the host's own curl is\n    \
         # already routed into the mesh.\n    \
         network_mode: host\n    cap_add:\n      - NET_ADMIN\n      - NET_RAW\n    \
         devices:\n      - /dev/net/tun:/dev/net/tun\n    volumes:\n      \
         # The node's identity. Losing it means re-joining as a new\n      \
         # node and leaving a dead one behind in the server's list.\n      \
         - {path}/state:/var/lib/tailscale\n    environment:\n      \
         TS_STATE_DIR: /var/lib/tailscale\n      TS_HOSTNAME: {name}\n      \
         # Read from .env, which is 0600 and written once.\n      \
         TS_AUTHKEY: ${{TS_AUTHKEY}}\n      \
         # --accept-dns=false: see the type comment. The server's own\n      \
         # resolver must not depend on a container being up.\n      \
         TS_EXTRA_ARGS: {args}",
    )
}

#[cfg(test)]
pub fn env_template() -> String {
    "TS_AUTHKEY=".to_string()
}

pub fn parse_status(text: &str) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let state = value.get("BackendState")?.as_str()?.to_string();
    let address = value
        .get("Self")
        .and_then(|me| me.get("TailscaleIPs"))
        .and_then(|ips| ips.as_array())
        .and_then(|ips| ips.iter().find_map(|ip| ip.as_str()))
        .unwrap_or_default()
        .to_string();
    Some((state, address))
}

/// The last login failure the client logged, if any
pub fn last_login_error(log: &str) -> Option<String> {
    log.lines()
        .rev()
        .find(|line| line.contains("Received error:") || line.contains("backend error:"))
        .map(|line| {
            let text = line.split_once("error:").map(|(_, rest)| rest).unwrap_or(line);
            text.trim().chars().take(160).collect()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/mesh/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn scenario(name: &str) -> Input {
        let mut input = Input::default();
        match name {
            "default-public-en" | "default-public-ru" => {
                input.domain = "example.com".to_string();
                input.tailscale_login_server = "https://mesh.example.com".to_string();
            }
            "custom-public-en" => {
                input.domain = "example.com".to_string();
                input.headscale_path = "/srv/mesh".to_string();
                input.headscale_hostname = "control.example.com".to_string();
                input.headscale_base_domain = "mesh.internal".to_string();
                input.tailscale_node_path = "/srv/node".to_string();
                input.tailscale_node_name = "vault-host".to_string();
                input.tailscale_login_server = "https://control.example.com".to_string();
            }
            "subdomain-public-en" => {
                input.domain = "b5.example.net".to_string();
                input.additional_domains = vec!["b6.example.net".to_string()];
                input.tailscale_login_server = "https://mesh.b5.example.net".to_string();
            }
            "tailscale-public-en" => {
                input.domain = "example.com".to_string();
                input.tailscale_node_name = "server".to_string();
            }
            other => panic!("unknown scenario {other}"),
        }
        input
    }

    const SCENARIOS: &[&str] = &["default-public-en", "default-public-ru", "custom-public-en",
                                 "subdomain-public-en", "tailscale-public-en"];

    #[test]
    fn fixture_parity_compose() {
        for name in SCENARIOS {
            let input = scenario(name);
            assert_eq!(
                compose_contents(&input),
                fixture(&format!("node-{name}__docker-compose.yml")),
                "{name}"
            );
        }
    }

    #[test]
    fn fixture_parity_env_template() {
        for name in SCENARIOS {
            assert_eq!(env_template(), fixture(&format!("node-{name}__env.template")), "{name}");
        }
    }

    #[test]
    fn fixture_parity_node_name() {
        for name in SCENARIOS {
            assert_eq!(node_name(&scenario(name)), fixture(&format!("node-{name}__node-name.txt")), "{name}");
        }
    }

    #[test]
    fn fixture_parity_compose_directory() {
        for name in SCENARIOS {
            assert_eq!(
                scenario(name).tailscale_node_path,
                fixture(&format!("node-{name}__compose-directory.txt")),
                "{name}"
            );
        }
    }

    fn base(domain: &str) -> Input {
        let mut input = Input::default();
        input.domain = domain.to_string();
        input
    }

    #[test]
    fn the_clients_last_login_error_is_quoted_rather_than_classified() {
        let log = "2026/08/15 12:22:48 control: RegisterReq: got response\n\
                   2026/08/15 12:22:48 Received error: invalid key: API key kJFWdPYQX421CNTRL not valid\n";
        let why = last_login_error(log).expect("the failure must be found");
        assert!(why.contains("invalid key"), "{why}");
        assert!(why.contains("not valid"), "{why}");
        assert!(last_login_error("nothing interesting here\n").is_none());
    }

    #[test]
    fn the_clients_state_and_address_are_read_back() {
        let joined = r#"{"BackendState":"Running","Self":{"TailscaleIPs":["100.81.1.61","fd7a::1"]}}"#;
        assert_eq!(parse_status(joined), Some(("Running".to_string(), "100.81.1.61".to_string())));
        let out = r#"{"BackendState":"NeedsLogin","Self":{}}"#;
        assert_eq!(parse_status(out), Some(("NeedsLogin".to_string(), String::new())));
        assert_eq!(parse_status("not json"), None);
    }

    #[test]
    fn the_node_is_named_after_the_first_label_of_the_domain() {
        assert_eq!(node_name(&base("b5.example.net")), "b5");
        assert_eq!(node_name(&base("example.com")), "example");
    }

    #[test]
    fn an_explicit_name_wins() {
        let mut input = base("example.com");
        input.tailscale_node_name = "vault-host".to_string();
        assert_eq!(node_name(&input), "vault-host");
    }

    #[test]
    fn the_flag_is_present_only_when_this_deployment_runs_the_control_server() {
        let mut input = base("example.com");
        assert_eq!(extra_args(&input), "--accept-dns=false", "joining Tailscale passes no login server");
        assert!(!compose_contents(&input).contains("--login-server"));

        input.tailscale_login_server = "https://control.example.com".to_string();
        assert_eq!(extra_args(&input), "--login-server=https://control.example.com --accept-dns=false");
        assert!(compose_contents(&input).contains("--login-server=https://control.example.com"));
    }

    #[test]
    fn the_node_never_accepts_dns_from_the_mesh() {
        assert!(compose_contents(&base("example.com")).contains("--accept-dns=false"));
    }
}
