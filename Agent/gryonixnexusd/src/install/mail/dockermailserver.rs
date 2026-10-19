//! docker-mailserver's install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/DockerMailserverService.swift`

use super::FirewallPort;
use crate::install::caddy::{self, WebIngress};
use crate::install::context::Input;

pub const SERVICE_ID: &str = "docker-mailserver";

pub const IMAGE: &str = "ghcr.io/docker-mailserver/docker-mailserver:15.1.0";
/// Roundcube supplies the webmail this engine has none of
pub const WEBMAIL_IMAGE: &str = "roundcube/roundcubemail:1.6.17-apache";
pub const COMPOSE_PROJECT: &str = "dockermailserver";
pub const CONTAINER: &str = "mailserver";
pub const WEBMAIL_CONTAINER: &str = "mailserver-webmail";
/// Loopback port Caddy proxies the webmail to
pub const WEB_UI_PORT: u16 = 8086;

/// `DockerMailserverService.certSyncScriptPath` / `.certSyncUnit`
pub const CERT_SYNC_SCRIPT_PATH: &str = "/opt/gryonixnexus-dms-cert-sync.sh";
pub const CERT_SYNC_UNIT: &str = "gryonixnexus-dms-cert-sync";
/// `DockerMailserverService.dkimDumpScriptPath`
pub const DKIM_DUMP_SCRIPT_PATH: &str = "/opt/gryonixnexus-dms-dkim.sh";
/// The mailbox wrapper's path
#[allow(dead_code)]
pub const MAILBOX_SCRIPT_PATH: &str = "/opt/gryonixnexus-dms-mailbox.sh";
pub const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";
pub const DKIM_DUMP_DONE_MARKER: &str = "GRYONIXNEXUS_DKIM_DONE";
pub const DKIM_SELECTOR: &str = "dkim";
pub const DKIM_KEY_SIZE: u32 = 2048;

pub fn hostname(input: &Input) -> String {
    format!("mail.{}", input.domain)
}

pub fn mail_domains(input: &Input) -> Vec<String> {
    let mut domains = vec![input.domain.clone()];
    domains.extend(input.additional_domains.iter().cloned());
    domains
}

pub fn admin_mailbox(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

pub fn directories_0755(input: &Input) -> Vec<String> {
    let path = &input.docker_mailserver_path;
    let mut dirs = vec![path.clone()];
    for name in ["mail-data", "mail-state", "mail-logs", "config", "webmail", "webmail-db"] {
        dirs.push(format!("{path}/{name}"));
    }
    dirs
}

pub fn certs_dir(input: &Input) -> String {
    format!("{}/certs", input.docker_mailserver_path)
}

pub fn cert_pem_path(input: &Input) -> String {
    format!("{}/cert.pem", certs_dir(input))
}

pub fn key_pem_path(input: &Input) -> String {
    format!("{}/key.pem", certs_dir(input))
}

pub fn placeholder_cert_args(input: &Input) -> Vec<String> {
    let host = hostname(input);
    vec![
        "req".to_string(),
        "-x509".to_string(),
        "-newkey".to_string(),
        "rsa:2048".to_string(),
        "-nodes".to_string(),
        "-days".to_string(),
        "3650".to_string(),
        "-subj".to_string(),
        format!("/CN={host}"),
        "-addext".to_string(),
        format!("subjectAltName=DNS:{host}"),
        "-keyout".to_string(),
        key_pem_path(input),
        "-out".to_string(),
        cert_pem_path(input),
    ]
}

pub const READINESS_PROBE_ARGS: &[&str] = &["setup", "help"];

pub const LIST_MAILBOXES_ARGS: &[&str] = &["setup", "email", "list"];

pub fn add_mailbox_args(address: &str) -> Vec<String> {
    vec!["setup".to_string(), "email".to_string(), "add".to_string(), address.to_string()]
}

pub fn dkim_config_args(domain: &str) -> Vec<String> {
    vec![
        "setup".to_string(),
        "config".to_string(),
        "dkim".to_string(),
        "keysize".to_string(),
        DKIM_KEY_SIZE.to_string(),
        "selector".to_string(),
        DKIM_SELECTOR.to_string(),
        "domain".to_string(),
        domain.to_string(),
    ]
}

/// A byte-exact port of `DockerMailserverService.composeFile(_:).composeContents`
pub fn compose_contents(input: &Input) -> String {
    let path = &input.docker_mailserver_path;
    let hostname = hostname(input);
    format!(
        "services:\n  mailserver:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    hostname: {hostname}\n    restart: unless-stopped\n    env_file: .env\n    # Every client port, including the STARTTLS pair. This engine\n    # serves them all, so opening them is honest here.\n    ports:\n      - \"25:25\"\n      - \"143:143\"\n      - \"465:465\"\n      - \"587:587\"\n      - \"993:993\"\n      - \"4190:4190\"\n    volumes:\n      - {path}/mail-data:/var/mail\n      - {path}/mail-state:/var/mail-state\n      - {path}/mail-logs:/var/log/mail\n      - {path}/config:/tmp/docker-mailserver\n      - {path}/certs:/etc/gryonixnexus-certs:ro\n      - /etc/localtime:/etc/localtime:ro\n    # The container answers to its own certificate name INSIDE the\n    # compose network. Roundcube verifies the peer name (PHP does\n    # by default and Roundcube leaves imap_conn_options unset), so\n    # connecting to `mailserver` failed against a certificate\n    # issued for {hostname}. Aliasing here fixes\n    # the name instead of switching verification off.\n    networks:\n      default:\n        aliases:\n          - {hostname}\n    # Postfix and Dovecot change kernel-visible limits and need to\n    # drop privileges themselves; this is the capability set\n    # upstream documents for a non-privileged run.\n    cap_add:\n      - NET_ADMIN\n    stop_grace_period: 1m\n  webmail:\n    image: {WEBMAIL_IMAGE}\n    container_name: {WEBMAIL_CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - mailserver\n    environment:\n      # The mail container's alias, not its service name: this\n      # name is what the certificate is issued for, and the\n      # connection is verified. It still resolves inside the\n      # compose network, so the traffic never leaves the host and\n      # never touches the published ports.\n      ROUNDCUBEMAIL_DEFAULT_HOST: ssl://{hostname}\n      ROUNDCUBEMAIL_DEFAULT_PORT: \"993\"\n      ROUNDCUBEMAIL_SMTP_SERVER: tls://{hostname}\n      ROUNDCUBEMAIL_SMTP_PORT: \"587\"\n      ROUNDCUBEMAIL_PLUGINS: archive,zipdownload,managesieve\n      ROUNDCUBEMAIL_UPLOAD_MAX_FILESIZE: 25M\n    volumes:\n      - {path}/webmail:/var/roundcube/config\n      # /var/roundcube/db is where the image puts its sqlite file\n      # (ROUNDCUBEMAIL_DB_DIR); mounted anywhere else the database\n      # stays in the container layer and every recreate throws\n      # away the users' settings, contacts and address book.\n      - {path}/webmail-db:/var/roundcube/db\n    ports:\n      # Loopback only: Caddy terminates TLS in front of it, which\n      # also puts it under the lockdown guard like every other UI.\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    )
}

/// A byte-exact port of `DockerMailserverService.envTemplate(_:)`
pub fn env_template(input: &Input) -> String {
    let hostname = hostname(input);
    format!(
        "# Managed by gryonixNexus. Generated on the server; the __RANDOM__ marker\n# is replaced once and then left alone on re-runs.\nOVERRIDE_HOSTNAME={hostname}\nPOSTMASTER_ADDRESS=postmaster@{domain}\n# The certificate is handed in by the sync timer below — Caddy owns the\n# ACME account on this host, and only one process can.\nSSL_TYPE=manual\nSSL_CERT_PATH=/etc/gryonixnexus-certs/cert.pem\nSSL_KEY_PATH=/etc/gryonixnexus-certs/key.pem\n# Rspamd is the modern filter and it also signs DKIM; Amavis, ClamAV and\n# SpamAssassin are the legacy chain and together they are most of the\n# memory this engine was chosen to avoid. ClamAV alone wants about a\n# gigabyte, which is most of a small server's headroom.\nENABLE_RSPAMD=1\nENABLE_OPENDKIM=0\nENABLE_AMAVIS=0\nENABLE_CLAMAV=0\nENABLE_SPAMASSASSIN=0\n# Sieve on 4190, the same port the other engines publish.\nENABLE_MANAGESIEVE=1\n# No fail2ban: it needs NET_ADMIN plus host firewall access, and the\n# deployment already has nftables in front of this container.\nENABLE_FAIL2BAN=0\n# Mailboxes live in a file the wrapper edits — no LDAP, no OIDC.\nACCOUNT_PROVISIONER=FILE\n# Only the webmail container may relay without authenticating, and it\n# reaches Postfix over the compose network.\nPERMIT_DOCKER=connected-networks\nPOSTFIX_MESSAGE_SIZE_LIMIT=50000000\nFIRST_MAILBOX_PASSWORD=__RANDOM__",
        domain = input.domain
    )
}

pub const FIRST_MAILBOX_PASSWORD_KEY: &str = "FIRST_MAILBOX_PASSWORD";

pub fn cert_sync_script(input: &Input) -> String {
    let host = hostname(input);
    let path = &input.docker_mailserver_path;
    format!(
        r#"#!/bin/bash
set -eu
DOMAIN="{host}"
DMS="{path}"
DEST="$DMS/certs"
CADDY_DATA="/var/lib/caddy/.local/share/caddy/certificates"
SRC_CRT="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.crt" 2>/dev/null | head -n1)"
SRC_KEY="$(find "$CADDY_DATA" -type f -name "${{DOMAIN}}.key" 2>/dev/null | head -n1)"
# No certificate yet (ACME still pending) is not an error: the timer
# comes back every hour and the mail ports keep serving what they have.
if [ -z "$SRC_CRT" ] || [ -z "$SRC_KEY" ]; then exit 0; fi
if cmp -s "$SRC_CRT" "$DEST/cert.pem" && cmp -s "$SRC_KEY" "$DEST/key.pem"; then exit 0; fi
cp "$SRC_CRT" "$DEST/cert.pem"
cp "$SRC_KEY" "$DEST/key.pem"
chmod 644 "$DEST/cert.pem"
chmod 600 "$DEST/key.pem"
cd "$DMS"
# Postfix and Dovecot read the certificate at start; the container has
# no reload hook for a file that changed under it.
docker compose -p {COMPOSE_PROJECT} restart {CONTAINER} >/dev/null 2>&1 || true
"#
    )
}

pub fn cert_sync_service_unit() -> String {
    format!(
        "[Unit]\nDescription=Sync Caddy TLS certificate into Docker Mailserver (SMTP/IMAPS)\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={CERT_SYNC_SCRIPT_PATH}\n"
    )
}

/// The `EOF_DMS_CERTTIMER` heredoc body
pub fn cert_sync_timer_unit() -> String {
    "[Unit]\nDescription=Periodic Caddy to Docker Mailserver TLS certificate sync\n[Timer]\nOnActiveSec=5min\nOnUnitActiveSec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
        .to_string()
}

pub fn dkim_dump_script(input: &Input) -> String {
    let path = &input.docker_mailserver_path;
    format!(
        r#"#!/bin/bash
set -euo pipefail
# `setup config dkim` is what actually MINTS the key (see the install
# step that calls it), and it always writes BIND-format keys under
# opendkim/keys/<domain>/dkim.txt — REGARDLESS of ENABLE_RSPAMD vs
# ENABLE_OPENDKIM. Rspamd's dkim_signing module reads its signing key
# from that same path by the image's own default config; "opendkim"
# here names where the key lives, not which engine signs with it.
#
# An earlier version of this wrapper globbed
# `rspamd/dkim/*-dkim-*.public.dns.txt`, a path rspamd never writes on
# this image: the real
# key sat at opendkim/keys/<domain>/dkim.txt the whole time, and the
# glob matched nothing, so every report said "not ready yet" forever.
#
# dkim.txt is a BIND zone-file record, not a bare value:
#   dkim._domainkey IN TXT ( "v=DKIM1; h=sha256; k=rsa; "
#     "p=MIIB..." "dYRV...AB" )  ; ----- DKIM key dkim for <domain>
# The quoted segments concatenate directly (no separator) into the
# single value to publish — the first segment's own trailing space
# is what keeps "k=rsa;" and "p=..." apart, so no extra space is added
# here.
for F in {path}/config/opendkim/keys/*/dkim.txt; do
  [ -f "$F" ] || continue
  D="$(basename "$(dirname "$F")")"
  V="$(grep -o '"[^"]*"' "$F" | tr -d '"\n' | head -c 2000)"
  [ -n "$V" ] || continue
  # Bare, no quotes around $V — mailcow and Mailu both print the value
  # unquoted (see their own dkimMarker lines), and DKIMRecordParser /
  # DKIMExport downstream both expect the bare "v=DKIM1;...;p=..."
  # string, adding their own quoting where a format needs it (the BIND
  # zone export, the DNS provider's own form). A quoted value here
  # would ship the literal `"` characters into every artifact and
  # clipboard copy built from it.
  echo "{DKIM_MARKER} {DKIM_SELECTOR}._domainkey.$D $V"
done
echo "{DKIM_DUMP_DONE_MARKER}"
"#
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(_input: &Input) -> Vec<String> {
    Vec::new()
}

pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![
        FirewallPort::tcp(25, "SMTP"),
        FirewallPort::tcp(465, "SMTPS"),
        FirewallPort::tcp(587, "Submission"),
        FirewallPort::tcp(143, "IMAP"),
        FirewallPort::tcp(993, "IMAPS"),
        FirewallPort::tcp(4190, "Sieve"),
    ]
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see `adguard::caddy_site_names`
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

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_has_no_override_unlike_adguard() {
        assert_eq!(hostname(&base("example.com")), "mail.example.com");
    }

    #[test]
    fn dns_hostnames_is_always_empty() {
        assert!(dns_hostnames(&base("example.com")).is_empty());
    }

    #[test]
    fn firewall_ports_match_swift_order_and_wording() {
        let ports = firewall_ports();
        let rendered: Vec<String> =
            ports.iter().map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment)).collect();
        assert_eq!(
            rendered,
            vec![
                "25/tcp SMTP",
                "465/tcp SMTPS",
                "587/tcp Submission",
                "143/tcp IMAP",
                "993/tcp IMAPS",
                "4190/tcp Sieve",
            ]
        );
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
        assert_eq!(
            caddy_site_names(&input),
            vec!["mail.example.com".to_string(), "mail.example.org".to_string()]
        );
        assert!(caddy_site(&input).starts_with("mail.example.com, mail.example.org {"));
    }

    #[test]
    fn a_name_outside_the_primary_domain_is_never_mirrored() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert!(input.mirrored_hostnames("mail.other.net").is_empty());
    }

    #[test]
    fn mail_domains_are_the_primary_then_the_additional_ones_in_order() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(mail_domains(&input), vec!["example.com", "example.org", "example.net"]);
    }

    #[test]
    fn the_first_mailbox_follows_the_shared_admin_name() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_eq!(admin_mailbox(&input), "operator@example.com");
    }

    #[test]
    fn the_certificate_directory_is_not_in_the_0755_list() {
        let input = base("example.com");
        assert!(!directories_0755(&input).contains(&certs_dir(&input)));
        assert_eq!(certs_dir(&input), "/opt/docker-mailserver/certs");
    }

    #[test]
    fn the_dkim_argv_pins_the_selector_and_the_key_size() {
        assert_eq!(
            dkim_config_args("example.com"),
            vec!["setup", "config", "dkim", "keysize", "2048", "selector", "dkim", "domain", "example.com"]
        );
    }

    #[test]
    fn the_readiness_probe_is_not_the_list_subcommand() {
        assert_eq!(READINESS_PROBE_ARGS, &["setup", "help"]);
        assert_ne!(READINESS_PROBE_ARGS, LIST_MAILBOXES_ARGS);
    }

    #[test]
    fn the_add_mailbox_argv_carries_no_password() {
        let args = add_mailbox_args("admin@example.com");
        assert_eq!(args, vec!["setup", "email", "add", "admin@example.com"]);
        assert!(!args.iter().any(|a| a.contains("s3cret")));
    }

    #[test]
    fn the_placeholder_certificate_names_the_mail_hostname_in_both_places() {
        let args = placeholder_cert_args(&base("example.com"));
        assert!(args.contains(&"/CN=mail.example.com".to_string()));
        assert!(args.contains(&"subjectAltName=DNS:mail.example.com".to_string()));
        assert!(args.contains(&"/opt/docker-mailserver/certs/key.pem".to_string()));
        assert!(args.contains(&"/opt/docker-mailserver/certs/cert.pem".to_string()));
    }

    #[test]
    fn the_dkim_dump_script_globs_the_path_the_key_is_actually_written_to() {
        let script = dkim_dump_script(&base("example.com"));
        assert!(script.contains("for F in /opt/docker-mailserver/config/opendkim/keys/*/dkim.txt; do"));
        assert!(!script.contains("rspamd/dkim/*-dkim-*.public.dns.txt; do"));
        assert!(script.contains("echo \"GRYONIXNEXUS_DKIM dkim._domainkey.$D $V\""));
    }

    #[test]
    fn a_custom_install_path_reaches_the_scripts_too() {
        let mut input = base("example.com");
        input.docker_mailserver_path = "/srv/dms".to_string();
        assert!(cert_sync_script(&input).contains("DMS=\"/srv/dms\""));
        assert!(dkim_dump_script(&input).contains("for F in /srv/dms/config/opendkim/keys/*/dkim.txt; do"));
        assert_eq!(certs_dir(&input), "/srv/dms/certs");
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

    fn firewall_ports_text() -> String {
        firewall_ports()
            .iter()
            .map(|p| format!("{}/{} {}", p.port, p.proto.as_str(), p.comment))
            .collect::<Vec<_>>()
            .join("\n")
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

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("mail-dms-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            env_template(input),
            fixture(&format!("mail-dms-{scenario}__env.template")),
            "{scenario}: env.template"
        );
        assert_eq!(hostname(input), fixture(&format!("mail-dms-{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("mail-dms-{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(
            firewall_ports_text(),
            fixture(&format!("mail-dms-{scenario}__firewall-ports.txt")),
            "{scenario}: firewall-ports.txt"
        );
        assert_eq!(
            caddy_site(input),
            fixture(&format!("mail-dms-{scenario}__caddy-site.txt")),
            "{scenario}: caddy-site.txt"
        );
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("mail-dms-{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
    }

    fn assert_written_files_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-dms-{scenario}__setup-steps.txt"));
        assert_eq!(
            cert_sync_script(input),
            heredoc_body(&dump, "EOF_DMS_CERTSYNC"),
            "{scenario}: cert-sync script"
        );
        assert_eq!(
            cert_sync_service_unit(),
            heredoc_body(&dump, "EOF_DMS_CERTSVC"),
            "{scenario}: cert-sync service unit"
        );
        assert_eq!(
            cert_sync_timer_unit(),
            heredoc_body(&dump, "EOF_DMS_CERTTIMER"),
            "{scenario}: cert-sync timer unit"
        );
        assert_eq!(dkim_dump_script(input), heredoc_body(&dump, "EOF_DMS_DKIM"), "{scenario}: DKIM dump wrapper");
    }

    fn assert_imperative_parity(input: &Input, scenario: &str) {
        let dump = fixture(&format!("mail-dms-{scenario}__setup-steps.txt"));

        let dirs_line = dump
            .lines()
            .find(|line| line.starts_with("install -d -m 755 "))
            .unwrap_or_else(|| panic!("{scenario}: no 0755 install line in the dump"));
        let dumped: Vec<&str> =
            dirs_line.strip_prefix("install -d -m 755 ").expect("checked by find above").split(' ').collect();
        assert_eq!(directories_0755(input), dumped, "{scenario}: the 0755 directory list");
        assert!(
            dump.contains(&format!("install -d -m 700 {}\n", certs_dir(input))),
            "{scenario}: the certificate directory must be 0700"
        );

        for expected in ["-newkey rsa:2048", "-days 3650", "-nodes"] {
            assert!(dump.contains(expected), "{scenario}: the dump is missing `{expected}`");
        }
        let args = placeholder_cert_args(input);
        let value_of = |flag: &str| -> String {
            let at = args.iter().position(|a| a == flag).unwrap_or_else(|| panic!("{scenario}: no {flag} in the argv"));
            args[at + 1].clone()
        };
        assert!(
            dump.contains(&format!("-subj \"{}\"", value_of("-subj"))),
            "{scenario}: the certificate subject must match the dump"
        );
        assert!(
            dump.contains(&format!("-addext \"{}\"", value_of("-addext"))),
            "{scenario}: the certificate SAN must match the dump"
        );
        assert!(
            dump.contains(&format!("-keyout {}", value_of("-keyout"))),
            "{scenario}: the key path must match the dump"
        );
        assert!(
            dump.contains(&format!("-out {}", value_of("-out"))),
            "{scenario}: the certificate path must match the dump"
        );
        assert!(dump.contains(&format!("chmod 644 {}", cert_pem_path(input))), "{scenario}: cert.pem is 0644");
        assert!(dump.contains(&format!("chmod 600 {}", key_pem_path(input))), "{scenario}: key.pem is 0600");

        assert!(dump.contains(&format!("dms_exec {}", READINESS_PROBE_ARGS.join(" "))), "{scenario}: the probe");
        for domain in mail_domains(input) {
            assert!(
                dump.contains(&format!("dms_exec {}", dkim_config_args(&domain).join(" "))),
                "{scenario}: no DKIM command for {domain}"
            );
        }
        // The first mailbox's address, as the bash version spells it.
        assert!(
            dump.contains(&format!("dms_mailbox add \"{}\"", admin_mailbox(input))),
            "{scenario}: the first mailbox address"
        );
    }

    #[test]
    fn default_en() {
        let input = base("example.com");
        assert_parity(&input, "default-en");
        assert_written_files_parity(&input, "default-en");
        assert_imperative_parity(&input, "default-en");
    }

    #[test]
    fn mirrored_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "mirrored-en");
        assert_written_files_parity(&input, "mirrored-en");
        assert_imperative_parity(&input, "mirrored-en");
    }

    #[test]
    fn custom_en() {
        let mut input = base("example.com");
        input.docker_mailserver_path = "/srv/dms".to_string();
        assert_parity(&input, "custom-en");
        assert_written_files_parity(&input, "custom-en");
        assert_imperative_parity(&input, "custom-en");
    }

    #[test]
    fn adminuser_en() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_written_files_parity(&input, "adminuser-en");
        assert_imperative_parity(&input, "adminuser-en");
    }
}
