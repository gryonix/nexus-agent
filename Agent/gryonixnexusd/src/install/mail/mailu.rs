//! Mailu's install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/MailuService.swift`

use super::FirewallPort;
use crate::install::caddy::{self, WebIngress};
use crate::install::context::Input;

pub const SERVICE_ID: &str = "mailu";

pub const IMAGE_TAG: &str = "2024.06";
/// Session store and rspamd's backend
pub const CACHE_IMAGE: &str = "redis:8-alpine";
pub const COMPOSE_PROJECT: &str = "mailu";
/// Loopback port Caddy proxies to
pub const WEB_UI_PORT: u16 = 8085;
pub const FRONT_SERVICE: &str = "front";
pub const ADMIN_SERVICE: &str = "admin";
pub const ADMIN_RUN_AS_USER: &str = "mailu";
/// `MailuService.certSyncScriptPath`/`.certSyncUnit`
pub const CERT_SYNC_SCRIPT_PATH: &str = "/opt/gryonixnexus-mailu-cert-sync.sh";
pub const CERT_SYNC_UNIT: &str = "gryonixnexus-mailu-cert-sync";
/// `MailuService.dkimDumpScriptPath`
pub const DKIM_DUMP_SCRIPT_PATH: &str = "/opt/gryonixnexus-mailu-dkim.sh";
pub const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";
pub const DKIM_DUMP_DONE_MARKER: &str = "GRYONIXNEXUS_DKIM_DONE";
pub const CONFIG_EXPORT_PROBE_ARGS: &[&str] = &["flask", "mailu", "config-export", "-j"];
pub const CONFIG_IMPORT_ARGS: &[&str] = &["flask", "mailu", "config-import", "-q", "-u"];

fn component_image(component: &str) -> String {
    format!("ghcr.io/mailu/{component}:{IMAGE_TAG}")
}

/// A port of the private `host(in:last:)` helper shared by `resolverAddress`/`gatewayAddress`
fn host_in_subnet(subnet: &str, last: &str) -> String {
    let base = subnet.split('/').next().unwrap_or(subnet);
    let mut octets: Vec<&str> = base.split('.').collect();
    if octets.len() != 4 {
        return base.to_string();
    }
    octets[3] = last;
    octets.join(".")
}

/// A port of `MailuService.resolverAddress(subnet:)`
fn resolver_address(subnet: &str) -> String {
    host_in_subnet(subnet, "254")
}

/// A port of `MailuService.gatewayAddress(subnet:)`
fn gateway_address(subnet: &str) -> String {
    host_in_subnet(subnet, "1")
}

pub fn hostname(input: &Input) -> String {
    format!("mail.{}", input.domain)
}

/// A port of `MailuService.composeFile(_:).composeContents`
pub fn compose_contents(input: &Input) -> String {
    let path = &input.mailu_path;
    let resolver_addr = resolver_address(&input.mailu_subnet);
    let mut lines = core_services(path, &resolver_addr);
    lines.extend(mail_services(path, &resolver_addr));
    lines.extend(network_lines(&input.mailu_subnet));
    lines.join("\n")
}

/// The cache, the front and the resolver
fn core_services(path: &str, resolver_addr: &str) -> Vec<String> {
    vec![
        "services:".to_string(),
        "  redis:".to_string(),
        format!("    image: {CACHE_IMAGE}"),
        "    restart: unless-stopped".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/redis:/data"),
        "  front:".to_string(),
        format!("    image: {}", component_image("nginx")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    logging:".to_string(),
        "      driver: json-file".to_string(),
        "    ports:".to_string(),
        "      # The web UI stays on loopback behind Caddy; the mail ports".to_string(),
        "      # are the only public binds, and they are not proxyable —".to_string(),
        "      # SMTP and IMAP are not HTTP.".to_string(),
        "      #".to_string(),
        "      # 143 and 587 are deliberately absent, not forgotten: the".to_string(),
        "      # front's dovecot proxy gates those two listeners behind".to_string(),
        "      # PORT_143/PORT_587 and binds them to port 0 when unset,".to_string(),
        "      # which is the case here — unlike 465/993/4190, which it".to_string(),
        "      # always enables. Publishing a dead port would still open".to_string(),
        "      # the public interface, because docker publishes through".to_string(),
        "      # its own DNAT, past the firewall.".to_string(),
        format!("      - \"127.0.0.1:{WEB_UI_PORT}:80\""),
        "      - \"25:25\"".to_string(),
        "      - \"465:465\"".to_string(),
        "      - \"993:993\"".to_string(),
        "      - \"4190:4190\"".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/certs:/certs"),
        format!("      - {path}/overrides/nginx:/overrides:ro"),
        "  resolver:".to_string(),
        format!("    image: {}", component_image("unbound")),
        "    env_file: .env".to_string(),
        "    restart: unless-stopped".to_string(),
        "    networks:".to_string(),
        "      default:".to_string(),
        format!("        ipv4_address: {resolver_addr}"),
    ]
}

/// Admin, IMAP, SMTP, antispam and webmail
fn mail_services(path: &str, resolver_addr: &str) -> Vec<String> {
    vec![
        "  admin:".to_string(),
        format!("    image: {}", component_image("admin")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/data:/data"),
        format!("      - {path}/dkim:/dkim"),
        "    depends_on:".to_string(),
        "      - redis".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  imap:".to_string(),
        format!("    image: {}", component_image("dovecot")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/mail:/mail"),
        format!("      - {path}/overrides:/overrides:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  smtp:".to_string(),
        format!("    image: {}", component_image("postfix")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/mailqueue:/queue"),
        format!("      - {path}/overrides:/overrides:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  antispam:".to_string(),
        format!("    image: {}", component_image("rspamd")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/filter:/var/lib/rspamd"),
        format!("      - {path}/overrides/rspamd:/etc/rspamd/override.d:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
        "      - redis".to_string(),
        "      - resolver".to_string(),
        "    dns:".to_string(),
        format!("      - {resolver_addr}"),
        "  webmail:".to_string(),
        format!("    image: {}", component_image("webmail")),
        "    restart: unless-stopped".to_string(),
        "    env_file: .env".to_string(),
        "    volumes:".to_string(),
        format!("      - {path}/webmail:/data"),
        format!("      - {path}/overrides/roundcube:/overrides:ro"),
        "    depends_on:".to_string(),
        "      - front".to_string(),
    ]
}

fn network_lines(subnet: &str) -> Vec<String> {
    vec![
        String::new(),
        "networks:".to_string(),
        "  default:".to_string(),
        "    driver: bridge".to_string(),
        "    ipam:".to_string(),
        "      config:".to_string(),
        "        # Fixed on purpose: SUBNET below has to name the range".to_string(),
        "        # docker really used, and letting docker choose it would".to_string(),
        "        # make the two disagree the first time the pool shifts.".to_string(),
        format!("        - subnet: {subnet}"),
    ]
}

/// A port of `MailuService.envTemplate(_:)`
pub fn env_template(input: &Input) -> String {
    let domain = &input.domain;
    let subnet = &input.mailu_subnet;
    let hostnames: String = std::iter::once(domain.clone())
        .chain(input.additional_domains.iter().cloned())
        .map(|d| format!("mail.{d}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut lines = identity_env(input, &hostnames);
    lines.extend(proxy_env(&gateway_address(subnet)));
    lines.extend(feature_env(&hostname(input)));
    lines.join("\n")
}

/// Domain, secrets, subnet and the first administrator
fn identity_env(input: &Input, hostnames: &str) -> Vec<String> {
    let domain = &input.domain;
    let admin = &input.admin_username;
    let subnet = &input.mailu_subnet;
    vec![
        "# Managed by gryonixNexus. Generated on the server; secrets are the".to_string(),
        "# __RANDOM__ markers, replaced once and then left alone on re-runs.".to_string(),
        "SECRET_KEY=__RANDOM__".to_string(),
        format!("DOMAIN={domain}"),
        format!("HOSTNAMES={hostnames}"),
        "POSTMASTER=postmaster".to_string(),
        "# See the type comment: Caddy owns 80/443 and the ACME account, so Mailu".to_string(),
        "# serves plain HTTP for the proxy and uses the synced certificate for".to_string(),
        "# SMTP/IMAP only.".to_string(),
        "TLS_FLAVOR=mail".to_string(),
        format!("SUBNET={subnet}"),
        "# The first administrator is created by the stack itself. `ifmissing`".to_string(),
        "# rather than `update`: a re-run of setup must not reset a password the".to_string(),
        "# owner has since changed.".to_string(),
        format!("INITIAL_ADMIN_ACCOUNT={admin}"),
        format!("INITIAL_ADMIN_DOMAIN={domain}"),
        "INITIAL_ADMIN_PW=__RANDOM__".to_string(),
        "INITIAL_ADMIN_MODE=ifmissing".to_string(),
    ]
}

/// What Mailu trusts behind the proxy
fn proxy_env(gateway_addr: &str) -> Vec<String> {
    vec![
        "# Behind a proxy Mailu would otherwise log and rate-limit Caddy's".to_string(),
        "# address instead of the client's.".to_string(),
        "#".to_string(),
        "# The trusted address is the BRIDGE GATEWAY, not 127.0.0.1: Caddy".to_string(),
        "# connects to a published port on the host, and the container sees that".to_string(),
        "# connection arriving from the docker network's gateway. This is the".to_string(),
        "# same trap as mailcow's API_ALLOW_FROM — a loopback".to_string(),
        "# value here does not fail loudly, it silently makes every client look".to_string(),
        "# like the proxy, which means the per-IP rate limit bans everyone at".to_string(),
        "# once the first time one client gets a password wrong.".to_string(),
        "REAL_IP_HEADER=X-Forwarded-For".to_string(),
        format!("REAL_IP_FROM={gateway_addr}"),
        "WEBROOT_REDIRECT=/webmail".to_string(),
    ]
}

/// The admin interface, webmail and filtering switches
fn feature_env(host: &str) -> Vec<String> {
    vec![
        "# ADMIN gates the admin interface ITSELF, WEB_ADMIN only says where it".to_string(),
        "# would live. Without this the nginx template renders no location for".to_string(),
        "# it at all: /admin falls through to WEBROOT_REDIRECT and lands on the".to_string(),
        "# webmail, which reads as \"the admin UI is broken\". The setup report points at /admin.".to_string(),
        "ADMIN=true".to_string(),
        "WEB_ADMIN=/admin".to_string(),
        "WEB_WEBMAIL=/webmail".to_string(),
        "WEBMAIL=roundcube".to_string(),
        "WEBDAV=none".to_string(),
        "# Off deliberately: ClamAV alone wants about a gigabyte of RAM, which is".to_string(),
        "# most of a small server's headroom. Rspamd still filters spam.".to_string(),
        "ANTIVIRUS=none".to_string(),
        "MESSAGE_SIZE_LIMIT=50000000".to_string(),
        "RECIPIENT_DELIMITER=+".to_string(),
        "DMARC_RUA=postmaster".to_string(),
        "DMARC_RUF=postmaster".to_string(),
        format!("COMPOSE_PROJECT_NAME={COMPOSE_PROJECT}"),
        format!("MAILU_HOSTNAME={host}"),
    ]
}

/// A port of `MailuService.dnsHostnames(_:)`: always empty
#[allow(dead_code)]
pub fn dns_hostnames(_input: &Input) -> Vec<String> {
    Vec::new()
}

/// A port of `MailuService.firewallPorts(_:)`
pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![
        FirewallPort::tcp(25, "SMTP"),
        FirewallPort::tcp(465, "SMTPS (implicit TLS)"),
        FirewallPort::tcp(993, "IMAPS (implicit TLS)"),
        FirewallPort::tcp(4190, "Sieve"),
    ]
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see `adguard::caddy_site_names`/`mail::dockermailserver::caddy_site_names`/ `mail::mailcow::caddy_site_names`
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

pub fn mail_domains(input: &Input) -> Vec<String> {
    let mut domains = vec![input.domain.clone()];
    domains.extend(input.additional_domains.iter().cloned());
    domains
}

pub fn directories_0755(input: &Input) -> Vec<String> {
    let path = &input.mailu_path;
    let mut dirs = vec![path.clone()];
    for name in ["mail", "mailqueue", "filter", "webmail", "redis"] {
        dirs.push(format!("{path}/{name}"));
    }
    for name in ["overrides", "overrides/nginx", "overrides/rspamd", "overrides/roundcube"] {
        dirs.push(format!("{path}/{name}"));
    }
    dirs
}

pub fn directories_0700(input: &Input) -> Vec<String> {
    let path = &input.mailu_path;
    ["certs", "dkim", "data"].iter().map(|name| format!("{path}/{name}")).collect()
}

pub fn domain_import_yaml(input: &Input) -> String {
    let entries: Vec<String> =
        mail_domains(input).iter().map(|d| format!("  - name: {d}\n    dkim_key: -generate-")).collect();
    format!("domain:\n{}\n", entries.join("\n"))
}

pub fn cert_sync_script(input: &Input) -> String {
    let host = hostname(input);
    let path = &input.mailu_path;
    format!(
        r#"#!/bin/bash
set -eu
DOMAIN="{host}"
MAILU="{path}"
DEST="$MAILU/certs"
CADDY_DATA="/var/lib/caddy/.local/share/caddy/certificates"
SRC_CRT="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.crt" 2>/dev/null | head -n1)"
SRC_KEY="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.key" 2>/dev/null | head -n1)"
# No certificate yet (ACME still pending) is not an error: the timer
# comes back every hour and the mail ports keep serving the old one.
if [ -z "$SRC_CRT" ] || [ -z "$SRC_KEY" ]; then exit 0; fi
if cmp -s "$SRC_CRT" "$DEST/cert.pem" && cmp -s "$SRC_KEY" "$DEST/key.pem"; then exit 0; fi
cp "$SRC_CRT" "$DEST/cert.pem"
cp "$SRC_KEY" "$DEST/key.pem"
chmod 600 "$DEST/cert.pem" "$DEST/key.pem"
cd "$MAILU"
# Only the services that terminate TLS themselves; restarting the whole
# project would drop deliveries in flight for nothing.
docker compose -p {COMPOSE_PROJECT} restart {FRONT_SERVICE} >/dev/null 2>&1 || true
"#
    )
}

pub fn cert_sync_service_unit() -> String {
    format!(
        "[Unit]\nDescription=Sync Caddy TLS certificate into Mailu (SMTP/IMAPS)\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={CERT_SYNC_SCRIPT_PATH}\n"
    )
}

pub fn cert_sync_timer_unit() -> String {
    "[Unit]\nDescription=Periodic Caddy to Mailu TLS certificate sync\n[Timer]\nOnActiveSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
        .to_string()
}

pub fn dkim_dump_script(input: &Input) -> String {
    let path = &input.mailu_path;
    format!(
        r#"#!/bin/bash
set -euo pipefail
cd {path} 2>/dev/null || {{ echo "{DKIM_DUMP_DONE_MARKER}"; exit 0; }}
# --dns asks Mailu for the records it would publish; the private key is
# NOT in that projection, which is why this dump can be whitelisted.
OUT="$(timeout 60 docker compose -p {COMPOSE_PROJECT} exec -T -u {ADMIN_RUN_AS_USER} {ADMIN_SERVICE} \
       flask mailu config-export -d -j domain 2>/dev/null || true)"
printf '%s' "$OUT" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for domain in data.get("domain", []):
    record = domain.get("dns_dkim")
    if not record:
        continue
    # dns_dkim is a full zone line: "<name> 600 IN TXT \"v=DKIM1…\"".
    # The app wants the name and the value, so keep those two.
    name, _, rest = record.partition(" ")
    value = rest[rest.find("\"") :].strip() if "\"" in rest else rest.strip()
    print("{DKIM_MARKER} " + name.rstrip(".") + " " + value)
' 2>/dev/null || true
echo "{DKIM_DUMP_DONE_MARKER}"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_is_always_mail_subdomain() {
        assert_eq!(hostname(&base("example.com")), "mail.example.com");
    }

    #[test]
    fn dns_hostnames_is_always_empty() {
        assert!(dns_hostnames(&base("example.com")).is_empty());
    }

    #[test]
    fn firewall_ports_are_the_four_the_engine_answers_on() {
        let ports = firewall_ports();
        assert_eq!(ports.len(), 4);
        assert_eq!(ports[0].port, 25);
        assert_eq!(ports[3].port, 4190);
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
        assert!(caddy_site(&input).starts_with("mail.example.com, mail.example.org {"));
    }

    #[test]
    fn resolver_and_gateway_addresses_take_the_last_octet_of_the_subnet() {
        assert_eq!(resolver_address("172.29.0.0/24"), "172.29.0.254");
        assert_eq!(gateway_address("172.29.0.0/24"), "172.29.0.1");
    }

    #[test]
    fn mail_domains_are_the_primary_then_the_additional_ones_in_order() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(mail_domains(&input), vec!["example.com", "example.org", "example.net"]);
    }

    #[test]
    fn the_0700_directories_are_not_in_the_0755_list() {
        let input = base("example.com");
        let dirs_0755 = directories_0755(&input);
        for dir in directories_0700(&input) {
            assert!(!dirs_0755.contains(&dir), "{dir} must not be 0755");
        }
        assert_eq!(directories_0700(&input), vec!["/opt/mailu/certs", "/opt/mailu/dkim", "/opt/mailu/data"]);
    }

    #[test]
    fn domain_import_yaml_has_one_generate_block_per_domain() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert_eq!(
            domain_import_yaml(&input),
            "domain:\n  - name: example.com\n    dkim_key: -generate-\n  - name: example.org\n    dkim_key: -generate-\n"
        );
    }

    #[test]
    fn a_custom_install_path_reaches_the_scripts_too() {
        let mut input = base("example.com");
        input.mailu_path = "/srv/mailu".to_string();
        assert!(cert_sync_script(&input).contains("MAILU=\"/srv/mailu\""));
        assert!(dkim_dump_script(&input).contains("cd /srv/mailu 2>/dev/null"));
    }

    #[test]
    fn the_cert_sync_units_point_at_the_script_this_module_writes() {
        assert!(cert_sync_service_unit().contains(&format!("ExecStart={CERT_SYNC_SCRIPT_PATH}")));
        assert!(cert_sync_timer_unit().contains("WantedBy=timers.target"));
    }

    #[test]
    fn cert_sync_restarts_only_the_front_service() {
        let script = cert_sync_script(&base("example.com"));
        assert!(script.contains(&format!("restart {FRONT_SERVICE} >")));
        assert!(!script.contains("restart admin"));
    }

    #[test]
    fn the_dkim_dump_script_uses_the_dns_projection_and_the_shared_marker() {
        let script = dkim_dump_script(&base("example.com"));
        assert!(script.contains("config-export -d -j domain"));
        assert!(script.contains(&format!("print(\"{DKIM_MARKER} \"")));
        assert!(script.contains(&format!("echo \"{DKIM_DUMP_DONE_MARKER}\"")));
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
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            env_template(input),
            fixture(&format!("{scenario}__env.template")),
            "{scenario}: env.template"
        );
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

    /// Domain `example.com`, every field at its Swift default.
    #[test]
    fn default_en() {
        assert_parity(&base("example.com"), "mail-mailu-default-en");
    }

    #[test]
    fn mirrored_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mail-mailu-mirrored-en");
    }

    #[test]
    fn custom_en() {
        let mut input = base("example.com");
        input.mailu_path = "/srv/mailu".to_string();
        input.mailu_subnet = "172.30.0.0/24".to_string();
        assert_parity(&input, "mail-mailu-custom-en");
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
        let dump = fixture(&format!("mail-mailu-{scenario}__setup-steps.txt"));
        assert_eq!(cert_sync_script(input), heredoc_body(&dump, "EOF_MU_CERTSYNC"), "{scenario}: cert-sync script");
        assert_eq!(
            cert_sync_service_unit(),
            heredoc_body(&dump, "EOF_MU_CERTSVC"),
            "{scenario}: cert-sync service unit"
        );
        assert_eq!(cert_sync_timer_unit(), heredoc_body(&dump, "EOF_MU_CERTTIMER"), "{scenario}: cert-sync timer unit");
        assert_eq!(dkim_dump_script(input), heredoc_body(&dump, "EOF_GD_MU_DKIM"), "{scenario}: DKIM dump wrapper");
    }

    fn assert_imperative_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-mailu-{scenario}__setup-steps.txt"));

        assert!(
            dump.contains(&format!("install -d -m 755 {}\n", input.mailu_path)),
            "{scenario}: the bare mailu_path 0755 line"
        );
        assert!(
            dump.contains(&format!("install -d -m 700 {}\n", directories_0700(input).join(" "))),
            "{scenario}: the 0700 directory line"
        );
        let dirs_0755 = directories_0755(input);
        let mail_group = dirs_0755[1..6].join(" ");
        let overrides_group = dirs_0755[6..10].join(" ");
        assert!(dump.contains(&format!("install -d -m 755 {mail_group}\n")), "{scenario}: the mail-data 0755 line");
        assert!(
            dump.contains(&format!("install -d -m 755 {overrides_group}\n")),
            "{scenario}: the overrides 0755 line"
        );

        for domain in mail_domains(input) {
            assert!(dump.contains(&format!("- name: {domain}")), "{scenario}: no domain-import entry for {domain}");
        }
        assert!(dump.contains("flask mailu config-export -j"), "{scenario}: the readiness probe");
        assert!(dump.contains("flask mailu config-import -q -u"), "{scenario}: the merge-mode import call");
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
    fn custom_en_imperative() {
        let mut input = base("example.com");
        input.mailu_path = "/srv/mailu".to_string();
        input.mailu_subnet = "172.30.0.0/24".to_string();
        assert_written_files_parity(&input, "custom-en");
        assert_imperative_parity(&input, "custom-en");
    }
}
