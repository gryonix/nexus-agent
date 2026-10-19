//! OpenVPN — the classic UDP VPN, and the only protocol here whose image is BUILT on the server

use crate::install::context::Input;

/// `OpenVPNService.composeProject`.
pub const COMPOSE_PROJECT: &str = "openvpn";

/// `OpenVPNService.containerName`, pinned for the dashboard's restart literal.
pub const CONTAINER: &str = "openvpn";

pub const IMAGE: &str = "gryonix-openvpn:local";

pub const CLIENT_NAME: &str = "gryonixnexus";

const SUBNET: &str = "10.11.0.0";

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.openvpn_path
}

pub fn data_dir(input: &Input) -> String {
    format!("{}/data", dir(input))
}

/// The image build context.
pub fn build_dir(input: &Input) -> String {
    format!("{}/build", dir(input))
}

pub fn ca_path(input: &Input) -> String {
    format!("{}/pki/ca.crt", data_dir(input))
}

/// The ready-to-import client profile the report prints inline.
pub fn client_profile_path(input: &Input) -> String {
    format!("{}/{CLIENT_NAME}.ovpn", dir(input))
}

/// A port of `OpenVPNService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.openvpn_port;
    format!(
        "services:
  openvpn:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    volumes:
      - {path}/data:/etc/openvpn
    ports:
      - \"{port}:1194/udp\""
    )
}

pub fn build_files() -> [(&'static str, &'static str); 4] {
    [
        ("Dockerfile", DOCKERFILE),
        ("gryonix-ovpn-run", RUN_SCRIPT),
        ("ovpn_getclient", GET_CLIENT),
        ("ovpn_revokeclient", REVOKE_CLIENT),
    ]
}

const DOCKERFILE: &str = "FROM alpine:3.22
RUN apk add --no-cache openvpn easy-rsa iptables openssl
ENV OPENVPN=/etc/openvpn \\
    EASYRSA=/usr/share/easy-rsa \\
    EASYRSA_PKI=/etc/openvpn/pki \\
    EASYRSA_ALGO=ec \\
    EASYRSA_CURVE=prime256v1 \\
    EASYRSA_CRL_DAYS=3650 \\
    EASYRSA_BATCH=1
RUN ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa
COPY ovpn_getclient ovpn_revokeclient gryonix-ovpn-run /usr/local/bin/
RUN chmod +x /usr/local/bin/ovpn_getclient /usr/local/bin/ovpn_revokeclient /usr/local/bin/gryonix-ovpn-run
CMD [\"gryonix-ovpn-run\"]
";

const RUN_SCRIPT: &str = "#!/bin/sh
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
iptables -t nat -C POSTROUTING -s 10.11.0.0/24 -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -A POSTROUTING -s 10.11.0.0/24 -j MASQUERADE
exec openvpn --config /etc/openvpn/server.conf
";

/// kylemanna-compatible: prints a self-contained profile to stdout
const GET_CLIENT: &str = "#!/bin/sh
set -eu
CN=\"$1\"
PKI=/etc/openvpn/pki
. /etc/openvpn/gryonix-env
cat <<PROFILE
client
dev tun
proto udp
remote $OVPN_HOST $OVPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3
<ca>
$(cat \"$PKI/ca.crt\")
</ca>
<cert>
$(openssl x509 -in \"$PKI/issued/$CN.crt\")
</cert>
<key>
$(cat \"$PKI/private/$CN.key\")
</key>
<tls-crypt>
$(cat /etc/openvpn/tc.key)
</tls-crypt>
PROFILE
";

/// kylemanna-compatible: revoke plus a fresh CRL
const REVOKE_CLIENT: &str = "#!/bin/sh
set -eu
CN=\"$1\"
PKI=/etc/openvpn/pki
easyrsa revoke \"$CN\"
easyrsa gen-crl
cp -f \"$PKI/crl.pem\" /etc/openvpn/crl.pem
chmod 644 /etc/openvpn/crl.pem
if [ \"${2:-}\" = \"remove\" ]; then
  rm -f \"$PKI/issued/$CN.crt\" \"$PKI/private/$CN.key\" \"$PKI/reqs/$CN.req\"
fi
";

pub fn hostname(input: &Input) -> String {
    super::super::panel::hostname(input)
}

/// `data/gryonix-env` — the two values `ovpn_getclient` sources
pub fn gryonix_env(input: &Input) -> String {
    format!("OVPN_HOST={}\nOVPN_PORT={}\n", hostname(input), input.openvpn_port)
}

/// A port of the `EOF_OVPN_SERVER` heredoc
pub fn server_conf(input: &Input) -> String {
    let host = hostname(input);
    format!(
        "# Managed by gryonixNexus — OpenVPN server (container-internal port 1194).
server {SUBNET} 255.255.255.0
topology subnet
port 1194
proto udp
dev tun
ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/{host}.crt
key /etc/openvpn/pki/private/{host}.key
dh none
ecdh-curve prime256v1
tls-crypt /etc/openvpn/tc.key
crl-verify /etc/openvpn/crl.pem
keepalive 10 60
persist-key
persist-tun
user nobody
group nobody
push \"redirect-gateway def1\"
push \"block-ipv6\"
push \"dhcp-option DNS 1.1.1.1\"
push \"dhcp-option DNS 1.0.0.1\"
explicit-exit-notify 1
verb 3
"
    )
}

pub fn pki_script(input: &Input) -> String {
    let host = hostname(input);
    format!(
        "
    set -eu
    easyrsa init-pki
    easyrsa build-ca nopass
    easyrsa --san=DNS:{host} build-server-full {host} nopass
    easyrsa build-client-full {CLIENT_NAME} nopass
    easyrsa gen-crl
    cp -f /etc/openvpn/pki/crl.pem /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
    openvpn --genkey secret /etc/openvpn/tc.key
  "
    )
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, heredoc_body, scenario_input};

    fn pki_script_from_fixture(steps: &str) -> String {
        let mut lines = steps.lines();
        loop {
            let line = lines.next().expect("the steps must run the PKI one-shot");
            if line.contains("sh -c \"") {
                break;
            }
        }
        let mut body = String::from("\n");
        for line in lines {
            if let Some(prefix) = line.strip_suffix('"') {
                if prefix.trim().is_empty() {
                    body.push_str(prefix);
                    return body;
                }
            }
            body.push_str(line);
            body.push('\n');
        }
        panic!("the sh -c body is never closed");
    }

    fn env_from_fixture(steps: &str) -> String {
        let line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("printf 'OVPN_HOST="))
            .expect("the steps must write gryonix-env");
        let (format, args) = line
            .trim_start()
            .trim_start_matches("printf '")
            .split_once("' ")
            .expect("a quoted format followed by arguments");
        let values: Vec<String> = args
            .split_once('>')
            .map(|(args, _redirect)| args)
            .unwrap_or(args)
            .split_whitespace()
            .map(|token| token.trim_matches('\'').to_string())
            .collect();
        let mut out = String::new();
        let mut values = values.into_iter();
        let mut rest = format;
        while let Some(at) = rest.find("%s") {
            out.push_str(&rest[..at]);
            out.push_str(&values.next().expect("one value per %s"));
            rest = &rest[at + 2..];
        }
        out.push_str(rest);
        out.replace("\\n", "\n")
    }

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        let steps = fixture(&format!("ovpn-{scenario}__setup-steps.txt"));
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("ovpn-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("ovpn-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        for (name, delimiter) in [
            ("Dockerfile", "EOF_OVPN_DOCKERFILE"),
            ("gryonix-ovpn-run", "EOF_OVPN_RUN"),
            ("ovpn_getclient", "EOF_OVPN_GETCLIENT"),
            ("ovpn_revokeclient", "EOF_OVPN_REVOKE"),
        ] {
            let ours = build_files()
                .into_iter()
                .find(|(candidate, _)| *candidate == name)
                .unwrap_or_else(|| panic!("{name} must be one of the build files"))
                .1;
            assert_eq!(ours, heredoc_body(&steps, delimiter), "{scenario}: build/{name}");
        }
        assert_eq!(
            server_conf(&input),
            heredoc_body(&steps, "EOF_OVPN_SERVER"),
            "{scenario}: data/server.conf"
        );
        assert_eq!(gryonix_env(&input), env_from_fixture(&steps), "{scenario}: data/gryonix-env");
        assert_eq!(pki_script(&input), pki_script_from_fixture(&steps), "{scenario}: the PKI one-shot");
    }

    #[test]
    fn default_public_en() {
        assert_parity("default-public-en");
    }

    #[test]
    fn custompaths_public_en() {
        assert_parity("custompaths-public-en");
    }

    #[test]
    fn customhost_public_en() {
        assert_parity("customhost-public-en");
        let input = scenario_input("customhost-public-en");
        assert!(server_conf(&input).contains("issued/tunnel.example.com.crt"));
        assert!(pki_script(&input).contains("--san=DNS:tunnel.example.com"));
        assert!(gryonix_env(&input).starts_with("OVPN_HOST=tunnel.example.com\n"));
    }

    #[test]
    fn the_build_context_is_the_same_in_every_scenario() {
        for scenario in [
            "default-public-en",
            "custompaths-public-en",
            "customhost-public-en",
            "customsni-public-en",
            "default-public-ru",
        ] {
            let steps = fixture(&format!("ovpn-{scenario}__setup-steps.txt"));
            assert_eq!(DOCKERFILE, heredoc_body(&steps, "EOF_OVPN_DOCKERFILE"), "{scenario}");
            assert_eq!(RUN_SCRIPT, heredoc_body(&steps, "EOF_OVPN_RUN"), "{scenario}");
            assert_eq!(GET_CLIENT, heredoc_body(&steps, "EOF_OVPN_GETCLIENT"), "{scenario}");
            assert_eq!(REVOKE_CLIENT, heredoc_body(&steps, "EOF_OVPN_REVOKE"), "{scenario}");
        }
    }

    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru));
        assert_eq!(server_conf(&en), server_conf(&ru));
        assert_eq!(pki_script(&en), pki_script(&ru));
    }
}
