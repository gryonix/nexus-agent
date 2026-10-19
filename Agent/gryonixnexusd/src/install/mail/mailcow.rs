//! Mailcow's install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/MailcowService.swift`

use super::{FirewallPort, Proto};
use crate::install::caddy::{self, WebIngress};
use crate::install::context::Input;

pub const SERVICE_ID: &str = "mailcow";

pub const COMPOSE_PROJECT: &str = "mailcowdockerized";
pub const REPO_URL: &str = "https://github.com/mailcow/mailcow-dockerized";
pub const BRANCH: &str = "master";
/// Local bind for mailcow's web UI
pub const WEB_UI_PORT: u16 = 8080;
pub const WEB_UI_HTTPS_PORT: u16 = 18443;
pub const CERT_SYNC_CONTAINERS: [&str; 3] = ["postfix-mailcow", "dovecot-mailcow", "nginx-mailcow"];
pub const CERT_SYNC_SCRIPT_PATH: &str = "/opt/gryonixnexus-mailcow-cert-sync.sh";
pub const CERT_SYNC_UNIT: &str = "gryonixnexus-mailcow-cert-sync";
/// `MailcowService.dkimDumpScriptPath`
pub const DKIM_DUMP_SCRIPT_PATH: &str = "/opt/gryonixnexus-dkim.sh";
pub const ADMIN_PASSWORD_FILE: &str = ".gryonixnexus-admin-password";
pub const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";
pub const DKIM_DUMP_DONE_MARKER: &str = "GRYONIXNEXUS_DKIM_DONE";

pub fn hostname(input: &Input) -> String {
    format!("mail.{}", input.domain)
}

#[allow(dead_code)]
pub fn dns_hostnames(_input: &Input) -> Vec<String> {
    Vec::new()
}

pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![
        FirewallPort { port: 25, proto: Proto::Tcp, comment: "SMTP".to_string() },
        FirewallPort { port: 465, proto: Proto::Tcp, comment: "SMTPS".to_string() },
        FirewallPort { port: 587, proto: Proto::Tcp, comment: "Submission".to_string() },
        FirewallPort { port: 143, proto: Proto::Tcp, comment: "IMAP".to_string() },
        FirewallPort { port: 993, proto: Proto::Tcp, comment: "IMAPS".to_string() },
        FirewallPort { port: 4190, proto: Proto::Tcp, comment: "Sieve".to_string() },
    ]
}

pub fn web_ingress(input: &Input) -> WebIngress {
    let public_paths = SYNC_PATHS.iter().map(|path| path.to_string()).collect();
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_HTTPS_PORT, admin_guard: true, upstream_https: true, public_paths }
}

/// Calendar, contacts and ActiveSync paths, open outside the VPN
pub const SYNC_PATHS: &[&str] = &[
    "/SOGo/dav",
    "/SOGo/dav/*",
    "/.well-known/caldav",
    "/.well-known/carddav",
    "/principals",
    "/principals/*",
    "/Microsoft-Server-ActiveSync",
    "/Microsoft-Server-ActiveSync/*",
];

/// The Caddy site NAMES this ingress publishes — see `adguard::caddy_site_names`/`mail::dockermailserver::caddy_site_names`
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site_with_public_paths(
        SERVICE_ID,
        &joined,
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        false,
        false,
        &ingress.public_paths,
        false,
    )
}

/// Autodiscover and autoconfig names for every mail domain
pub fn autoconfig_site_names(domains: &[String]) -> Vec<String> {
    domains.iter().flat_map(|d| ["autodiscover", "autoconfig"].map(|label| format!("{label}.{d}"))).collect()
}

/// The autoconfig site, or none when no name is ready
pub fn autoconfig_site(names: &[String]) -> Option<String> {
    (!names.is_empty()).then(|| caddy::autoconfig_site(SERVICE_ID, names, WEB_UI_HTTPS_PORT))
}

pub fn mail_domains(input: &Input) -> Vec<String> {
    let mut domains = vec![input.domain.clone()];
    domains.extend(input.additional_domains.iter().cloned());
    domains
}

pub fn generate_config_env(input: &Input) -> Vec<(&'static str, String)> {
    vec![
        ("COMPOSE_VERSION", "native".to_string()),
        ("MAILCOW_HOSTNAME", hostname(input)),
        ("MAILCOW_TZ", "UTC".to_string()),
        ("MAILCOW_BRANCH", BRANCH.to_string()),
    ]
}

pub const GENERATE_CONFIG_STDIN: &str = "y\ny\ny\n";

pub fn mailcow_conf_path(input: &Input) -> String {
    format!("{}/mailcow.conf", input.mailcow_path)
}

fn replace_conf_line(conf: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let had_trailing_newline = conf.ends_with('\n');
    let mut out: Vec<String> =
        conf.lines().map(|line| if line.starts_with(&prefix) { format!("{key}={value}") } else { line.to_string() }).collect();
    if out.is_empty() {
        out.push(format!("{key}={value}"));
    }
    let mut joined = out.join("\n");
    if had_trailing_newline {
        joined.push('\n');
    }
    joined
}

pub fn patch_conf_for_caddy(conf: &str) -> String {
    let mut out = conf.to_string();
    out = replace_conf_line(&out, "HTTP_BIND", "127.0.0.1");
    out = replace_conf_line(&out, "HTTP_PORT", &WEB_UI_PORT.to_string());
    out = replace_conf_line(&out, "HTTPS_BIND", "127.0.0.1");
    out = replace_conf_line(&out, "HTTPS_PORT", &WEB_UI_HTTPS_PORT.to_string());
    out = replace_conf_line(&out, "SKIP_LETS_ENCRYPT", "y");
    out
}

pub fn patch_conf_compose_version(conf: &str) -> String {
    if conf.lines().any(|line| line.starts_with("DOCKER_COMPOSE_VERSION=")) {
        replace_conf_line(conf, "DOCKER_COMPOSE_VERSION", "native")
    } else {
        let mut out = conf.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("DOCKER_COMPOSE_VERSION=native\n");
        out
    }
}

pub fn ipv4_network_prefix(conf: &str) -> Option<String> {
    conf.lines()
        .filter_map(|line| line.strip_prefix("IPV4_NETWORK="))
        .last()
        .map(|value| value.chars().filter(|c| !c.is_whitespace()).collect::<String>())
        .filter(|value| !value.is_empty())
}

pub const DEFAULT_NETWORK_PREFIX: &str = "172.22.1";

pub fn api_key_present(conf: &str) -> bool {
    conf.lines().any(|line| line.starts_with("API_KEY="))
}

pub fn read_conf_value(conf: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    conf.lines().filter_map(|line| line.strip_prefix(prefix.as_str())).last().map(str::to_string)
}

pub fn api_conf_append(api_key: &str, network_prefix: &str) -> String {
    format!("API_KEY={api_key}\nAPI_ALLOW_FROM={network_prefix}.1,127.0.0.1\n")
}

pub fn api_base() -> String {
    format!("https://127.0.0.1:{WEB_UI_HTTPS_PORT}/api/v1")
}

pub fn add_domain_body(domain: &str) -> String {
    format!(
        "{{\"domain\":\"{domain}\",\"description\":\"Managed by gryonixNexus\",\"aliases\":\"400\",\"defquota\":\"3072\",\"maxquota\":\"10240\",\"quota\":\"10240\",\"mailboxes\":\"50\",\"active\":\"1\",\"restart_sogo\":\"10\"}}"
    )
}

/// The JSON body `POST add/dkim` takes
pub fn add_dkim_body(domain: &str) -> String {
    format!("{{\"domains\":\"{domain}\",\"dkim_selector\":\"dkim\",\"key_size\":2048}}")
}

/// The JSON body `POST edit/admin` takes — `setupSteps`'s inline literal
pub fn edit_admin_body(password: &str) -> String {
    format!("{{\"items\":[\"admin\"],\"attr\":{{\"password\":\"{password}\",\"password2\":\"{password}\"}}}}")
}

/// Curl config holding the API key and any body
pub fn curl_config(api_key: &str, body: Option<&str>) -> String {
    let mut text = format!("header = {}\n", config_quote(&format!("X-API-Key: {api_key}")));
    if let Some(body) = body {
        text.push_str(&format!("data = {}\n", config_quote(body)));
    }
    text
}

fn config_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r");
    format!("\"{escaped}\"")
}

pub fn cert_sync_script(input: &Input) -> String {
    let host = hostname(input);
    let path = &input.mailcow_path;
    let containers = CERT_SYNC_CONTAINERS.join(" ");
    format!(
        r#"#!/bin/bash
set -eu
DOMAIN="{host}"
MAILCOW="{path}"
DEST="$MAILCOW/data/assets/ssl"
CADDY_DATA="/var/lib/caddy/.local/share/caddy/certificates"
SRC_CRT="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.crt" 2>/dev/null | head -n1)"
SRC_KEY="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.key" 2>/dev/null | head -n1)"
if [ -z "$SRC_CRT" ] || [ -z "$SRC_KEY" ]; then exit 0; fi
if cmp -s "$SRC_CRT" "$DEST/cert.pem" && cmp -s "$SRC_KEY" "$DEST/key.pem"; then exit 0; fi
cp "$SRC_CRT" "$DEST/cert.pem"
cp "$SRC_KEY" "$DEST/key.pem"
cd "$MAILCOW"
docker compose restart {containers} >/dev/null 2>&1 || true
"#
    )
}

/// The `EOF_MC_CERTSVC` heredoc body.
pub fn cert_sync_service_unit() -> String {
    format!(
        "[Unit]\nDescription=Sync Caddy TLS certificate into Mailcow (SMTP/IMAPS)\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={CERT_SYNC_SCRIPT_PATH}\n"
    )
}

pub fn cert_sync_timer_unit() -> String {
    "[Unit]\nDescription=Periodic Caddy to Mailcow TLS certificate sync\n[Timer]\nOnActiveSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
        .to_string()
}

/// The DKIM dump: creates missing keys, prints every domain's record
pub fn dkim_dump_script(input: &Input) -> String {
    let path = &input.mailcow_path;
    format!(
        r#"#!/bin/bash
set -euo pipefail
CONF="{path}/mailcow.conf"
[ -r "$CONF" ] || {{ echo "{DKIM_DUMP_DONE_MARKER}"; exit 0; }}
MC_KEY="$(grep '^API_KEY=' "$CONF" | tail -n1 | cut -d= -f2-)"
API="https://127.0.0.1:{WEB_UI_HTTPS_PORT}/api/v1"
mc() {{ curl -fsSk --max-time 20 -K - "$@" <<< "header = \"X-API-Key: $MC_KEY\""; }}
DOMAINS="$({{ mc "$API/get/domain/all" 2>/dev/null | jq -r '.[].domain_name // empty' 2>/dev/null || true; mc "$API/get/alias-domain/all" 2>/dev/null | jq -r '.[].alias_domain // empty' 2>/dev/null || true; }} | sort -u)"
dkim_of() {{ mc "$API/get/dkim/$1" 2>/dev/null | jq -r "select(type == \"object\") | .$2 // empty" 2>/dev/null || true; }}
for D in $DOMAINS; do
  if [ -z "$(dkim_of "$D" dkim_txt)" ]; then
    mc -X POST -H "Content-Type: application/json" -d "{{\"domains\":\"$D\",\"dkim_selector\":\"dkim\",\"key_size\":2048}}" "$API/add/dkim" >/dev/null 2>&1 || true
  fi
  TXT="$(dkim_of "$D" dkim_txt)"
  SEL="$(dkim_of "$D" dkim_selector)"
  if [ -n "$TXT" ]; then echo "{DKIM_MARKER} ${{SEL:-dkim}}._domainkey.$D $TXT"; fi
done
echo "{DKIM_DUMP_DONE_MARKER}"
"#
    )
}

/// Rewrites an older DKIM wrapper, keeping its mailcow folder
pub fn refresh_dkim_dump_script() -> std::io::Result<bool> {
    let path = std::path::Path::new(DKIM_DUMP_SCRIPT_PATH);
    let Ok(old) = std::fs::read_to_string(path) else { return Ok(false) };
    let Some(folder) = wrapper_folder(&old) else { return Ok(false) };
    let fresh = dkim_dump_script(&Input { mailcow_path: folder, ..Input::default() });
    if fresh == old {
        return Ok(false);
    }
    std::fs::write(path, fresh)?;
    Ok(true)
}

/// The mailcow folder a written wrapper points at
fn wrapper_folder(script: &str) -> Option<String> {
    script.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("CONF=\"")?;
        rest.strip_suffix("/mailcow.conf\"").map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_wrapper_is_rebuilt_for_its_own_folder() {
        let input = Input { mailcow_path: "/srv/mail cow".to_string(), ..Input::default() };
        let script = dkim_dump_script(&input);
        assert_eq!(wrapper_folder(&script).as_deref(), Some("/srv/mail cow"));
        assert!(script.contains("/add/dkim"));
        assert!(script.contains("get/alias-domain/all"));
        assert_eq!(wrapper_folder("#!/bin/bash\necho hi\n"), None);
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_is_always_mail_dot_domain() {
        assert_eq!(hostname(&base("example.com")), "mail.example.com");
    }

    #[test]
    fn dns_hostnames_is_empty() {
        assert!(dns_hostnames(&base("example.com")).is_empty());
    }

    #[test]
    fn firewall_ports_match_swift_order_and_comments() {
        let ports = firewall_ports();
        let rendered: Vec<String> = ports.iter().map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment)).collect();
        assert_eq!(
            rendered,
            vec![
                "25/tcp SMTP".to_string(),
                "465/tcp SMTPS".to_string(),
                "587/tcp Submission".to_string(),
                "143/tcp IMAP".to_string(),
                "993/tcp IMAPS".to_string(),
                "4190/tcp Sieve".to_string(),
            ]
        );
    }

    #[test]
    fn web_ingress_proxies_https_with_admin_guard_on() {
        let ingress = web_ingress(&base("example.com"));
        assert!(ingress.admin_guard);
        assert!(ingress.upstream_https);
        assert_eq!(ingress.upstream_port, WEB_UI_HTTPS_PORT);
        assert_eq!(ingress.hostname, "mail.example.com");
    }

    #[test]
    fn caddy_site_mirrors_the_hostname_onto_additional_domains() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert!(caddy_site(&input).starts_with("mail.example.com, mail.example.org {"));
    }

    #[test]
    fn caddy_site_exercises_the_https_upstream_branch() {
        let site = caddy_site(&base("example.com"));
        assert!(site.contains("reverse_proxy https://127.0.0.1:18443"));
        assert!(site.contains("tls_insecure_skip_verify"));
    }

    #[test]
    fn mail_domains_are_the_primary_then_the_additional_ones_in_order() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(mail_domains(&input), vec!["example.com", "example.org", "example.net"]);
    }

    #[test]
    fn generate_config_env_carries_the_native_compose_flavour_and_the_hostname() {
        let env = generate_config_env(&base("example.com"));
        assert!(env.contains(&("COMPOSE_VERSION", "native".to_string())));
        assert!(env.contains(&("MAILCOW_HOSTNAME", "mail.example.com".to_string())));
        assert!(env.contains(&("MAILCOW_BRANCH", "master".to_string())));
    }

    #[test]
    fn replace_conf_line_only_touches_the_matching_key() {
        let conf = "FOO=1\nHTTP_BIND=0.0.0.0\nBAR=2\n";
        let patched = replace_conf_line(conf, "HTTP_BIND", "127.0.0.1");
        assert_eq!(patched, "FOO=1\nHTTP_BIND=127.0.0.1\nBAR=2\n");
    }

    #[test]
    fn replace_conf_line_is_a_no_op_when_the_key_is_absent() {
        let conf = "FOO=1\n";
        assert_eq!(replace_conf_line(conf, "HTTP_BIND", "127.0.0.1"), conf);
    }

    #[test]
    fn patch_conf_for_caddy_sets_all_five_keys() {
        let conf = "HTTP_BIND=0.0.0.0\nHTTP_PORT=80\nHTTPS_BIND=0.0.0.0\nHTTPS_PORT=443\nSKIP_LETS_ENCRYPT=n\n";
        let patched = patch_conf_for_caddy(conf);
        assert!(patched.contains("HTTP_BIND=127.0.0.1\n"));
        assert!(patched.contains("HTTP_PORT=8080\n"));
        assert!(patched.contains("HTTPS_BIND=127.0.0.1\n"));
        assert!(patched.contains("HTTPS_PORT=18443\n"));
        assert!(patched.contains("SKIP_LETS_ENCRYPT=y\n"));
    }

    #[test]
    fn patch_conf_compose_version_replaces_when_present() {
        let conf = "FOO=1\nDOCKER_COMPOSE_VERSION=\nBAR=2\n";
        assert_eq!(patch_conf_compose_version(conf), "FOO=1\nDOCKER_COMPOSE_VERSION=native\nBAR=2\n");
    }

    #[test]
    fn patch_conf_compose_version_replaces_even_when_the_value_is_empty() {
        let conf = "DOCKER_COMPOSE_VERSION=\n";
        assert_eq!(patch_conf_compose_version(conf), "DOCKER_COMPOSE_VERSION=native\n");
    }

    #[test]
    fn patch_conf_compose_version_appends_when_missing() {
        let conf = "FOO=1\n";
        assert_eq!(patch_conf_compose_version(conf), "FOO=1\nDOCKER_COMPOSE_VERSION=native\n");
    }

    #[test]
    fn ipv4_network_prefix_reads_whatever_the_generator_actually_picked() {
        assert_eq!(ipv4_network_prefix("IPV4_NETWORK=172.23.5\n"), Some("172.23.5".to_string()));
        assert_eq!(ipv4_network_prefix("FOO=1\n"), None);
    }

    #[test]
    fn ipv4_network_prefix_takes_the_last_matching_line() {
        assert_eq!(ipv4_network_prefix("IPV4_NETWORK=172.22.1\nIPV4_NETWORK=172.23.5\n"), Some("172.23.5".to_string()));
    }

    #[test]
    fn api_key_present_checks_the_conf_not_a_guess() {
        assert!(!api_key_present("FOO=1\n"));
        assert!(api_key_present("FOO=1\nAPI_KEY=abc123\n"));
    }

    #[test]
    fn api_conf_append_is_the_two_line_printf() {
        assert_eq!(api_conf_append("deadbeef", "172.22.1"), "API_KEY=deadbeef\nAPI_ALLOW_FROM=172.22.1.1,127.0.0.1\n");
    }

    #[test]
    fn add_domain_and_dkim_bodies_carry_the_domain_and_the_pinned_selector() {
        assert!(add_domain_body("example.com").contains("\"domain\":\"example.com\""));
        let dkim = add_dkim_body("example.com");
        assert!(dkim.contains("\"domains\":\"example.com\""));
        assert!(dkim.contains("\"dkim_selector\":\"dkim\""));
    }

    #[test]
    fn a_custom_install_path_reaches_the_scripts_too() {
        let mut input = base("example.com");
        input.mailcow_path = "/srv/mailcow".to_string();
        assert!(cert_sync_script(&input).contains("MAILCOW=\"/srv/mailcow\""));
        assert!(dkim_dump_script(&input).contains("CONF=\"/srv/mailcow/mailcow.conf\""));
        assert_eq!(mailcow_conf_path(&input), "/srv/mailcow/mailcow.conf");
    }

    #[test]
    fn cert_sync_script_does_not_chmod_the_copied_certificate() {
        assert!(!cert_sync_script(&base("example.com")).contains("chmod"));
    }

    #[test]
    fn the_dkim_dump_script_keeps_curl_dash_f_unlike_the_provisioning_loop() {
        assert!(dkim_dump_script(&base("example.com")).contains("curl -fsSk"));
    }

    #[test]
    fn the_dkim_dump_script_keeps_the_key_off_the_command_line() {
        let text = dkim_dump_script(&base("example.com"));
        assert!(text.contains("-K - \"$@\" <<< \"header = "));
        assert!(!text.contains("-H \"X-API-Key"));
    }

    #[test]
    fn the_curl_config_quotes_what_would_end_a_value() {
        assert_eq!(curl_config("k-1", None), "header = \"X-API-Key: k-1\"\n");
        let config = curl_config("a\"b\\c", Some("{\"x\":1}"));
        assert!(config.contains("header = \"X-API-Key: a\\\"b\\\\c\"\n"));
        assert!(config.ends_with("data = \"{\\\"x\\\":1}\"\n"));
    }

    #[test]
    fn the_cert_sync_units_point_at_the_script_this_module_writes() {
        assert!(cert_sync_service_unit().contains(&format!("ExecStart={CERT_SYNC_SCRIPT_PATH}")));
        assert!(cert_sync_timer_unit().contains("WantedBy=timers.target"));
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

    fn firewall_ports_text(ports: &[FirewallPort]) -> String {
        ports.iter().map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment)).collect::<Vec<_>>().join("\n")
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(
            firewall_ports_text(&firewall_ports()),
            fixture(&format!("{scenario}__firewall-ports.txt")),
            "{scenario}: firewall-ports.txt"
        );
        assert_eq!(caddy_site(input), fixture(&format!("{scenario}__caddy-site.txt")), "{scenario}: caddy-site.txt");
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
    }

    #[test]
    fn default_en() {
        assert_parity(&base("example.com"), "mail-mailcow-default-en");
    }

    #[test]
    fn mirrored_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mail-mailcow-mirrored-en");
    }

    #[test]
    fn custom_en() {
        let mut input = base("example.com");
        input.mailcow_path = "/srv/mailcow".to_string();
        assert_parity(&input, "mail-mailcow-custom-en");
    }

    fn heredoc_body(dump: &str, marker: &str) -> String {
        let open = format!("<<'{marker}'\n");
        let start = dump
            .find(&open)
            .unwrap_or_else(|| panic!("the dumped setupSteps carries no {marker} heredoc"))
            + open.len();
        let rest = &dump[start..];
        let close = format!("\n{marker}\n");
        let end = rest
            .find(&close)
            .unwrap_or_else(|| panic!("the {marker} heredoc is never closed in the dumped setupSteps"));
        format!("{}\n", &rest[..end])
    }

    fn assert_written_files_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-mailcow-{scenario}__setup-steps.txt"));
        assert_eq!(cert_sync_script(input), heredoc_body(&dump, "EOF_MC_CERTSYNC"), "{scenario}: cert-sync script");
        assert_eq!(
            cert_sync_service_unit(),
            heredoc_body(&dump, "EOF_MC_CERTSVC"),
            "{scenario}: cert-sync service unit"
        );
        assert_eq!(
            cert_sync_timer_unit(),
            heredoc_body(&dump, "EOF_MC_CERTTIMER"),
            "{scenario}: cert-sync timer unit"
        );
        assert_eq!(dkim_dump_script(input), heredoc_body(&dump, "EOF_GD_DKIM"), "{scenario}: DKIM dump wrapper");
    }

    fn assert_imperative_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-mailcow-{scenario}__setup-steps.txt"));

        assert!(dump.contains(&format!("MAILCOW_HOSTNAME={}", hostname(input))), "{scenario}: MAILCOW_HOSTNAME env");
        assert!(dump.contains("MAILCOW_BRANCH=master"), "{scenario}: MAILCOW_BRANCH env");

        let before = "HTTP_BIND=0.0.0.0\nHTTP_PORT=80\nHTTPS_BIND=0.0.0.0\nHTTPS_PORT=443\nSKIP_LETS_ENCRYPT=n\n";
        let patched = patch_conf_for_caddy(before);
        for (key, value) in [
            ("HTTP_BIND", "127.0.0.1".to_string()),
            ("HTTP_PORT", WEB_UI_PORT.to_string()),
            ("HTTPS_BIND", "127.0.0.1".to_string()),
            ("HTTPS_PORT", WEB_UI_HTTPS_PORT.to_string()),
            ("SKIP_LETS_ENCRYPT", "y".to_string()),
        ] {
            assert!(
                dump.contains(&format!("sed -i 's/^{key}=.*/{key}={value}/' mailcow.conf")),
                "{scenario}: the dump's own sed line for {key}"
            );
            assert!(
                patched.contains(&format!("{key}={value}\n")),
                "{scenario}: patch_conf_for_caddy did not actually set {key}={value}"
            );
        }

        assert!(dump.contains("DOCKER_COMPOSE_VERSION=native"), "{scenario}: the DOCKER_COMPOSE_VERSION fix-up");
        assert!(
            patch_conf_compose_version("FOO=1\n").contains("DOCKER_COMPOSE_VERSION=native\n"),
            "{scenario}: patch_conf_compose_version did not actually append the fix-up"
        );

        assert!(
            dump.contains(r#"{\"domain\":\"$MC_DOMAIN\",\"description\":\"Managed by gryonixNexus\""#),
            "{scenario}: add/domain field structure"
        );
        assert!(add_domain_body("example.com").contains("\"description\":\"Managed by gryonixNexus\""), "{scenario}: add_domain_body field structure");
        assert!(
            dump.contains(r#"{\"domains\":\"$MC_DOMAIN\",\"dkim_selector\":\"dkim\",\"key_size\":2048}"#),
            "{scenario}: add/dkim field structure"
        );
        assert!(add_dkim_body("example.com").contains("\"dkim_selector\":\"dkim\""), "{scenario}: add_dkim_body field structure");
        for domain in mail_domains(input) {
            assert!(dump.contains(domain.as_str()), "{scenario}: {domain} missing from the domain here-document list");
        }
    }

    #[test]
    fn default_en_imperative() {
        let input = base("example.com");
        assert_written_files_parity(&input, "default-en");
        assert_imperative_parity(&input, "default-en");
    }

    #[test]
    fn mirrored_en_imperative() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_written_files_parity(&input, "mirrored-en");
        assert_imperative_parity(&input, "mirrored-en");
    }

    #[test]
    fn edit_admin_body_names_the_admin_and_repeats_the_password() {
        assert_eq!(
            edit_admin_body("abc123"),
            r#"{"items":["admin"],"attr":{"password":"abc123","password2":"abc123"}}"#
        );
    }

    #[test]
    fn custom_en_imperative() {
        let mut input = base("example.com");
        input.mailcow_path = "/srv/mailcow".to_string();
        assert_written_files_parity(&input, "custom-en");
        assert_imperative_parity(&input, "custom-en");
    }
}
