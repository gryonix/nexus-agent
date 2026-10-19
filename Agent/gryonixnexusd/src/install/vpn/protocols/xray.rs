//! XRay VLESS + XTLS-Vision + REALITY — one TCP port, one config file, three server-minted secrets

use crate::install::context::Input;

/// `XrayRealityService.composeProject`.
pub const COMPOSE_PROJECT: &str = "xray";

pub const CONTAINER: &str = "xray";

pub const IMAGE: &str = "ghcr.io/xtls/xray-core:26.7.11";

pub const CONTAINER_CONFIG_DIR: &str = "/usr/local/etc/xray";

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.xray_reality_path
}

/// Where the single config file lives on the HOST
pub fn config_path(input: &Input) -> String {
    format!("{}/config/config.json", dir(input))
}

/// The persisted client link
pub fn link_path(input: &Input) -> String {
    format!("{}/link.txt", dir(input))
}

/// The endpoint hostname clients dial — the panel's own hostname rule
pub fn hostname(input: &Input) -> String {
    super::super::panel::hostname(input)
}

/// A port of `XrayRealityService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.xray_reality_port;
    format!(
        "services:
  xray:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    # Run as root (0:0): config.json is chmod 600 root-owned (setup
    # and the panel both keep it 600, since it holds the REALITY
    # private key), and the image runs as a non-root user that would
    # otherwise get \"permission denied\" reading it.
    user: \"0:0\"
    volumes:
      - {path}/config:{CONTAINER_CONFIG_DIR}:ro
    ports:
      - \"{port}:{port}/tcp\""
    )
}

/// A port of the `EOF_XRAY_CONFIG` heredoc
pub fn config_json(input: &Input, uuid: &str, private_key: &str, short_id: &str) -> String {
    let port = input.xray_reality_port;
    let sni = &input.xray_reality_sni;
    format!(
        "{{
    \"log\": {{ \"loglevel\": \"warning\" }},
    \"inbounds\": [
        {{
            \"listen\": \"0.0.0.0\",
            \"port\": {port},
            \"protocol\": \"vless\",
            \"settings\": {{
                \"clients\": [ {{ \"id\": \"{uuid}\", \"flow\": \"xtls-rprx-vision\" }} ],
                \"decryption\": \"none\"
            }},
            \"streamSettings\": {{
                \"network\": \"tcp\",
                \"security\": \"reality\",
                \"realitySettings\": {{
                    \"dest\": \"{sni}:443\",
                    \"serverNames\": [ \"{sni}\" ],
                    \"privateKey\": \"{private_key}\",
                    \"shortIds\": [ \"{short_id}\" ]
                }}
            }},
            \"sniffing\": {{ \"enabled\": true, \"destOverride\": [ \"http\", \"tls\", \"quic\" ], \"routeOnly\": true }}
        }}
    ],
    \"outbounds\": [ {{ \"protocol\": \"freedom\", \"tag\": \"direct\" }} ]
}}
"
    )
}

pub fn config_with_site(config: &str, site: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(config).ok()?;
    let reality = value
        .get_mut("inbounds")?
        .as_array_mut()?
        .iter_mut()
        .find(|inbound| inbound["protocol"] == "vless")?
        .get_mut("streamSettings")?
        .get_mut("realitySettings")?;
    let dest = format!("{site}:443");
    let mut names = vec![site.to_string()];
    for earlier in reality["serverNames"].as_array().into_iter().flatten().filter_map(|name| name.as_str()) {
        if names.len() < MAX_SERVER_NAMES && !names.iter().any(|name| name == earlier) {
            names.push(earlier.to_string());
        }
    }
    if reality["dest"] == dest.as_str() && reality["serverNames"] == serde_json::json!(names) {
        return None;
    }
    reality["dest"] = serde_json::json!(dest);
    reality["serverNames"] = serde_json::json!(names);
    serde_json::to_string_pretty(&value).ok().map(|text| text + "\n")
}

const MAX_SERVER_NAMES: usize = 4;

/// Freedom lets devices reach this server's resolver relay
pub fn config_allowing_vpn_dns(config: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(config).ok()?;
    let freedom = value
        .get_mut("outbounds")?
        .as_array_mut()?
        .iter_mut()
        .find(|outbound| outbound["protocol"] == "freedom")?
        .as_object_mut()?;
    let rule = serde_json::json!({
        "action": "allow",
        "ip": [format!("{}/32", crate::vpn_dns::ADDRESS)],
        "port": "53",
    });
    let settings = freedom.entry("settings").or_insert_with(|| serde_json::json!({})).as_object_mut()?;
    let rules = settings.entry("finalRules").or_insert_with(|| serde_json::json!([])).as_array_mut()?;
    if rules.contains(&rule) {
        return None;
    }
    rules.insert(0, rule);
    serde_json::to_string_pretty(&value).ok().map(|text| text + "\n")
}

/// The client link with its `sni` replaced
pub fn link_with_site(link: &str, site: &str) -> String {
    let Some((head, rest)) = link.split_once("sni=") else { return link.to_string() };
    let tail = rest.find(['&', '#']).map_or("", |end| &rest[end..]);
    format!("{head}sni={site}{tail}")
}

/// Reality settings with a new key and short id
pub fn config_with_key(config: &str, private_key: &str, short_id: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(config).ok()?;
    let reality = value
        .get_mut("inbounds")?
        .as_array_mut()?
        .iter_mut()
        .find(|inbound| inbound["protocol"] == "vless")?
        .get_mut("streamSettings")?
        .get_mut("realitySettings")?;
    reality["privateKey"] = serde_json::json!(private_key);
    reality["shortIds"] = serde_json::json!([short_id]);
    serde_json::to_string_pretty(&value).ok().map(|text| text + "\n")
}

/// The link with a new public key and short id
pub fn link_with_key(link: &str, public_key: &str, short_id: &str) -> String {
    link_with_param(&link_with_param(link, "pbk", public_key), "sid", short_id)
}

fn link_with_param(link: &str, name: &str, value: &str) -> String {
    let marker = format!("&{name}=");
    let Some((head, rest)) = link.split_once(&marker) else { return link.to_string() };
    let tail = rest.find(['&', '#']).map_or("", |end| &rest[end..]);
    format!("{head}{marker}{value}{tail}")
}

pub fn client_link(input: &Input, uuid: &str, public_key: &str, short_id: &str) -> String {
    format!(
        "vless://{uuid}@{host}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp#gryonixNexus\n",
        host = hostname(input),
        port = input.xray_reality_port,
        sni = input.xray_reality_sni,
    )
}

pub fn parse_keys(output: &str) -> Option<(String, String)> {
    fn first<'a>(output: &'a str, prefixes: &[&str]) -> Option<&'a str> {
        output.lines().find_map(|line| {
            prefixes.iter().find_map(|prefix| {
                line.strip_prefix(prefix).map(|rest| rest.trim_start_matches([' ', '\t']))
            })
        })
    }

    let public_line = output.lines().find_map(|line| {
        let rest = line.strip_prefix("Password")?;
        let (head, tail) = rest.split_once(':')?;
        if head.contains(':') {
            return None;
        }
        Some(tail.trim_start_matches([' ', '\t']))
    });

    let private = first(output, &["PrivateKey:", "Private key:"])?;
    let public = public_line.or_else(|| first(output, &["Public key:"]))?;
    if private.is_empty() || public.is_empty() {
        return None;
    }
    Some((private.to_string(), public.to_string()))
}

#[cfg(test)]
mod site_tests {
    use super::*;

    #[test]
    fn the_camouflage_site_is_replaced_in_the_config_and_the_link() {
        let input = Input { xray_reality_sni: "www.apple.com".into(), ..Input::default() };
        let config = config_json(&input, "U", "P", "S");
        assert_eq!(config_with_site(&config, "www.apple.com"), None);
        let changed = config_with_site(&config, "www.microsoft.com").unwrap();
        assert!(changed.contains("\"dest\": \"www.microsoft.com:443\""));
        assert!(changed.contains("\"dest\": \"www.microsoft.com:443\"") && !changed.contains("\"dest\": \"www.apple.com"));
        assert!(changed.contains("\"www.apple.com\""), "devices on the earlier site keep working");
        assert_eq!(config_with_site(&changed, "www.microsoft.com"), None);
        assert!(changed.contains("\"privateKey\": \"P\"") && changed.contains("\"id\": \"U\""));
        let link = client_link(&input, "U", "K", "S");
        let moved = link_with_site(&link, "www.microsoft.com");
        assert!(moved.contains("&sni=www.microsoft.com&fp=chrome&pbk=K"));
        assert!(!moved.contains("apple"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three shapes the pinned tag's family has printed
    #[test]
    fn a_new_key_replaces_the_pair_and_keeps_the_devices() {
        let input = Input::default();
        let config = config_json(&input, "U", "OLDPRIV", "aaaa1111");
        let rotated = config_with_key(&config, "NEWPRIV", "bbbb2222").unwrap();
        let value: serde_json::Value = serde_json::from_str(&rotated).unwrap();
        let reality = &value["inbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(reality["privateKey"], "NEWPRIV");
        assert_eq!(reality["shortIds"], serde_json::json!(["bbbb2222"]));
        assert_eq!(value["inbounds"][0]["settings"]["clients"][0]["id"], "U", "devices keep their ids");
        let link = client_link(&input, "U", "OLDPUB", "aaaa1111");
        let moved = link_with_key(&link, "NEWPUB", "bbbb2222");
        assert!(moved.contains("&pbk=NEWPUB&sid=bbbb2222&type=tcp#gryonixNexus"), "{moved}");
        assert!(!moved.contains("OLDPUB") && moved.starts_with("vless://U@"));
    }

    #[test]
    fn freedom_lets_devices_reach_the_resolver_relay_once() {
        let config = config_json(&Input::default(), "U", "P", "S");
        let allowed = config_allowing_vpn_dns(&config).expect("the rule is added");
        let value: serde_json::Value = serde_json::from_str(&allowed).unwrap();
        let rule = &value["outbounds"][0]["settings"]["finalRules"][0];
        assert_eq!(rule["action"], "allow");
        assert_eq!(rule["ip"][0], "10.53.0.53/32");
        assert_eq!(rule["port"], "53");
        assert_eq!(value["inbounds"][0]["settings"]["clients"][0]["id"], "U", "clients kept");
        assert_eq!(config_allowing_vpn_dns(&allowed), None, "added once");
    }

    #[test]
    fn every_documented_x25519_shape_parses() {
        let cases = [
            ("PrivateKey: aPriv\nPassword (PublicKey): aPub\n", "aPriv", "aPub"),
            ("PrivateKey: bPriv\nPassword: bPub\n", "bPriv", "bPub"),
            ("Private key: cPriv\nPublic key: cPub\n", "cPriv", "cPub"),
        ];
        for (output, private, public) in cases {
            assert_eq!(
                parse_keys(output),
                Some((private.to_string(), public.to_string())),
                "shape {output:?}"
            );
        }
    }

    #[test]
    fn a_missing_half_is_no_answer() {
        assert_eq!(parse_keys("PrivateKey: only\n"), None);
        assert_eq!(parse_keys("Password: only\n"), None);
        assert_eq!(parse_keys(""), None);
        assert_eq!(parse_keys("PrivateKey:\nPassword: p\n"), None);
    }

    /// `head -n1`: the first match wins, not the last.
    #[test]
    fn the_first_matching_line_wins() {
        let output = "PrivateKey: first\nPrivateKey: second\nPassword: pub\n";
        assert_eq!(parse_keys(output).unwrap().0, "first");
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, heredoc_body, scenario_input};

    fn link_from_fixture(steps: &str, uuid: &str, public_key: &str, short_id: &str) -> String {
        let format_line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("printf 'vless://"))
            .expect("the steps must build the link with printf");
        let args_line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("\"$XRAY_UUID\""))
            .expect("the printf arguments must follow on the next line");

        let format = format_line
            .trim_start()
            .trim_start_matches("printf '")
            .trim_end()
            .trim_end_matches('\\')
            .trim_end()
            .trim_end_matches('\'');
        let args: Vec<String> = args_line
            .trim_start()
            .split_once('>')
            .map(|(args, _redirect)| args)
            .unwrap_or(args_line)
            .split_whitespace()
            .map(|token| token.trim_matches('"').to_string())
            .collect();
        assert_eq!(args.len(), 6, "the link takes six arguments: {args:?}");

        let mut out = String::new();
        let mut values = [uuid, &args[1], &args[2], &args[3], public_key, short_id].into_iter();
        let mut rest = format;
        while let Some(at) = rest.find("%s") {
            out.push_str(&rest[..at]);
            out.push_str(values.next().expect("one value per %s"));
            rest = &rest[at + 2..];
        }
        out.push_str(rest);
        out.replace("\\n", "\n")
    }

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        let steps = fixture(&format!("xray-{scenario}__setup-steps.txt"));
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("xray-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("xray-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        assert_eq!(
            hostname(&input),
            fixture(&format!("xray-{scenario}__hostname.txt")),
            "{scenario}: hostname"
        );
        assert_eq!(
            config_json(&input, "${XRAY_UUID}", "${XRAY_PRIV}", "${XRAY_SID}"),
            heredoc_body(&steps, "EOF_XRAY_CONFIG"),
            "{scenario}: config.json"
        );
        assert_eq!(
            client_link(&input, "U", "P", "S"),
            link_from_fixture(&steps, "U", "P", "S"),
            "{scenario}: link.txt"
        );
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
        assert!(client_link(&input, "U", "P", "S").contains("tunnel.example.com"));
        assert!(!config_json(&input, "U", "P", "S").contains("tunnel.example.com"));
    }

    #[test]
    fn customsni_public_en() {
        assert_parity("customsni-public-en");
        let input = scenario_input("customsni-public-en");
        assert_eq!(config_json(&input, "U", "P", "S").matches("www.cloudflare.com").count(), 2);
        assert!(client_link(&input, "U", "P", "S").contains("sni=www.cloudflare.com"));
    }

    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru));
        assert_eq!(config_json(&en, "U", "P", "S"), config_json(&ru, "U", "P", "S"));
        assert_eq!(client_link(&en, "U", "P", "S"), client_link(&ru, "U", "P", "S"));
    }
}
