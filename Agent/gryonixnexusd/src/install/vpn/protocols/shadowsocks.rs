//! Shadowsocks (shadowsocks-rust) — one TCP+UDP port, one config file, one server-minted key

use crate::install::context::Input;

/// `ShadowsocksService.composeProject` — the `-p` every compose verb needs.
pub const COMPOSE_PROJECT: &str = "shadowsocks";

pub const CONTAINER: &str = "shadowsocks";

pub const IMAGE: &str = "ghcr.io/shadowsocks/ssserver-rust:v1.24.0";

/// Where the image reads its config INSIDE the container.
const CONTAINER_CONFIG_PATH: &str = "/etc/shadowsocks-rust/config.json";

/// `ShadowsocksService.method`
pub const METHOD: &str = "2022-blake3-aes-256-gcm";

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.shadowsocks_path
}

pub fn config_path(input: &Input) -> String {
    format!("{}/config.json", dir(input))
}

/// A port of `ShadowsocksService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.shadowsocks_port;
    format!(
        "services:
  ssserver:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    # Explicit binary name: the image's entrypoint does not prepend
    # `ssserver` for a bare `-c …`, so `exec \"$@\"` chokes on the
    # leading option (\"exec: illegal option -c\"). Run as root (0:0):
    # config.json is chmod 600 root-owned (setup and the panel both
    # keep it 600), so a non-root process could not read it.
    command: ssserver -c {CONTAINER_CONFIG_PATH}
    user: \"0:0\"
    volumes:
      - {path}/config.json:{CONTAINER_CONFIG_PATH}:ro
    ports:
      - \"{port}:{port}/tcp\"
      - \"{port}:{port}/udp\""
    )
}

/// A port of the `EOF_SS_CONFIG` heredoc — the server's whole configuration
pub fn config_json(input: &Input, password: &str) -> String {
    let port = input.shadowsocks_port;
    format!(
        "{{
    \"server\": \"0.0.0.0\",
    \"server_port\": {port},
    \"password\": \"{password}\",
    \"method\": \"{METHOD}\",
    \"mode\": \"tcp_and_udp\",
    \"timeout\": 300
}}
"
    )
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, heredoc_body, scenario_input};

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("ss-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("ss-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        assert_eq!(
            config_json(&input, "${SS_PASSWORD}"),
            heredoc_body(
                &fixture(&format!("ss-{scenario}__setup-steps.txt")),
                "EOF_SS_CONFIG"
            ),
            "{scenario}: config.json"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity("default-public-en");
    }

    /// Every path and every port moved at once.
    #[test]
    fn custompaths_public_en() {
        assert_parity("custompaths-public-en");
    }

    #[test]
    fn customhost_public_en() {
        assert_parity("customhost-public-en");
    }

    /// Russian
    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru), "compose is language-independent");
        assert_eq!(
            config_json(&en, "K"),
            config_json(&ru, "K"),
            "config.json is language-independent"
        );
    }
}
