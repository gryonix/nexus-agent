pub mod amnezia;
pub mod openvpn;
pub mod shadowsocks;
pub mod xray;

#[cfg(test)]
pub mod tests_support {
    use crate::language::Language;
    use crate::install::context::Input;

    /// One dumped artifact, by file name.
    pub fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/install/vpn/protocols/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    /// The body of a heredoc inside a dumped `setupSteps` text
    pub fn heredoc_body(steps: &str, delimiter: &str) -> String {
        let open_quoted = format!("<<'{delimiter}'");
        let open_plain = format!("<<{delimiter}");
        let mut lines = steps.lines();
        loop {
            let line = lines
                .next()
                .unwrap_or_else(|| panic!("no heredoc opening for {delimiter} in these steps"));
            if line.contains(&open_quoted) || line.trim_end().ends_with(&open_plain) {
                break;
            }
        }
        let mut body = String::new();
        for line in lines {
            if line.trim_end() == delimiter {
                return body;
            }
            body.push_str(line);
            body.push('\n');
        }
        panic!("heredoc {delimiter} is never terminated in these steps");
    }

    /// The `Input` matching one dumped scenario's `ServiceContext`
    pub fn scenario_input(scenario: &str) -> Input {
        let mut input = Input {
            domain: "example.com".to_string(),
            ..Input::default()
        };
        match scenario {
            "default-public-en" => {}
            "custompaths-public-en" => {
                input.amnezia_wg_path = "/srv/awg".to_string();
                input.amnezia_wg_port = 51922;
                input.shadowsocks_path = "/srv/ss".to_string();
                input.shadowsocks_port = 9388;
                input.xray_reality_path = "/srv/xray".to_string();
                input.xray_reality_port = 9443;
                input.openvpn_path = "/srv/ovpn".to_string();
                input.openvpn_port = 1195;
                input.admin_username = "operator".to_string();
            }
            "customhost-public-en" => {
                input.additional_domains = vec!["example.org".to_string()];
                input.vpn_hostname = "tunnel.example.com".to_string();
            }
            "customsni-public-en" => {
                input.xray_reality_sni = "www.cloudflare.com".to_string();
            }
            "default-public-ru" => {
                input.language = Language::Ru;
            }
            other => panic!("unknown fixture scenario {other}"),
        }
        input
    }
}
