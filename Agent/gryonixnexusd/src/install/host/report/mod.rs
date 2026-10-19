//! `install-report.txt` — the one place an install's generated credentials are written down

use crate::install::context::Input;
use crate::install::host::{backup_ctl, HostInput, HostRole, CATALOG_ORDER};
use crate::install::mail::mailcow;
use crate::language::Language;

pub mod l10n;

/// Where the report lands, mirroring `SetupMarkers.reportFilePath`
pub const REPORT_PATH: &str = "/var/lib/gryonixnexus/install-report.txt";

/// The machine-readable DKIM twin, mirrored by `ServerControl`'s `DKIMRecordParser`
const DKIM_MARKER: &str = "GRYONIXNEXUS_DKIM";

/// The two engine-specific DKIM dumpers
const DMS_DKIM_WRAPPER: &str = "/opt/gryonixnexus-dms-dkim.sh";
const MAILU_DKIM_WRAPPER: &str = "/opt/gryonixnexus-mailu-dkim.sh";

const MAILCOW_HTTPS_PORT: u16 = 18443;

const VPN_PANEL_PATH: &str = "/opt/gryonix-vpn-panel";

/// `OpenVPNService.clientName` — the single profile the install mints.
const OPENVPN_CLIENT: &str = "gryonixnexus";

const SHADOWSOCKS_METHOD: &str = "2022-blake3-aes-256-gcm";

const VAULTWARDEN_ENV: &str = "/opt/vaultwarden/.env";

/// The units whose state the report prints, per host role
const SERVICES_HOST_UNITS: &[&str] = &["nftables", "docker", "caddy"];
const RELAY_UNITS: &[&str] = &["nftables", "wg-quick@wg0"];

// MARK: - Facts

pub trait Facts {
    fn systemctl_is_active(&self, unit: &str) -> String;

    /// A file's contents, `None` when it cannot be read
    fn read_file(&self, path: &str) -> Option<String>;

    fn dkim_wrapper(&self, path: &str) -> String;

    /// mailcow's `/api/v1/get/dkim/<domain>`, already reduced to `.dkim_txt`
    fn mailcow_dkim(&self, api_key: &str, domain: &str, https_port: u16) -> String;

    fn wg_show(&self, interface: &str) -> String;
}

// MARK: - Topology

#[derive(Debug, Clone, PartialEq)]
pub enum Topology {
    /// Scenario A, scenario B's home half, and local-only.
    ServicesHost {
        /// The address the PTR record must resolve to
        ptr_ip: Option<String>,
        /// The name the PTR should answer with (`ptrHostname`).
        ptr_hostname: String,
        tunnel_endpoint: Option<String>,
    },
    /// Scenario B's relay half.
    Relay {
        wg_port: u16,
        forwarded_ports: Vec<u16>,
        /// The home half's tunnel address, the DNAT target.
        home_wg_address: String,
        ptr_hostname: String,
    },
}

// MARK: - Rendering

/// The host's report
pub fn render(input: &HostInput, topology: &Topology, facts: &dyn Facts) -> String {
    match (input.role, topology) {
        (HostRole::VpsRelay, Topology::Relay { .. }) => render_relay(input, topology, facts),
        (HostRole::SingleHost | HostRole::HomeBackend, Topology::ServicesHost { .. }) => {
            render_services_host(input, topology, facts)
        }
        (role, topology) => unreachable!(
            "report topology does not match the host role: {role:?} with {topology:?}"
        ),
    }
}

fn render_services_host(input: &HostInput, topology: &Topology, facts: &dyn Facts) -> String {
    let Topology::ServicesHost {
        ptr_ip,
        ptr_hostname,
        tunnel_endpoint,
    } = topology
    else {
        unreachable!("render_services_host is only reached through render")
    };
    let l = input.language;
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!("==> {}\n", l10n::report_title(l)));
    out.push_str(&format!("{}{}\n", l10n::domain_label(l), input.install.domain));

    if let Some(endpoint) = tunnel_endpoint {
        out.push_str(&format!("{}\n", tunnel_report_line(input, endpoint)));
    }
    if let Some(engine) = mail_engine(input) {
        let _ = engine;
        out.push_str(&format!(
            "{}mail.{}\n",
            l10n::mail_host_label(l),
            input.install.domain
        ));
    }
    if let Some(ip) = ptr_ip {
        out.push_str(&format!("{}\n", l10n::ptr_reminder(l, ip, ptr_hostname)));
    }
    if backup_ctl::needs_stored_passphrase(input) {
        let secret = facts
            .read_file(backup_ctl::PASSPHRASE_PATH)
            .unwrap_or_default();
        out.push_str(&format!("{}{}\n", l10n::backup_passphrase_label(l), secret));
    }

    out.push('\n');
    out.push_str(&format!("{}\n", l10n::service_status_header(l)));
    out.push_str(&unit_status_block(SERVICES_HOST_UNITS, facts));
    out.push('\n');

    if !input.install.local_only {
        out.push_str(&format!("{}\n", l10n::caddy_dns_reminder(l)));
    }

    let credentials = service_lines(input, facts);
    if !credentials.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}\n", l10n::service_credentials_header(l)));
        out.push_str(&credentials);
    }
    out
}

fn render_relay(input: &HostInput, topology: &Topology, facts: &dyn Facts) -> String {
    let Topology::Relay {
        wg_port,
        forwarded_ports,
        home_wg_address,
        ptr_hostname,
    } = topology
    else {
        unreachable!("render_relay is only reached through render")
    };
    let l = input.language;
    let ports = forwarded_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!("==> {}\n", l10n::report_title(l)));
    out.push_str(&format!(
        "{}\n",
        l10n::vps_report_wire_guard(l, i64::from(*wg_port))
    ));
    out.push_str(&format!(
        "{}\n",
        l10n::vps_report_firewall(l, &ports, home_wg_address)
    ));
    out.push_str(&format!("{}\n", l10n::vps_report_forwarding(l)));
    out.push('\n');
    out.push_str(&format!("{}\n", l10n::service_status_header(l)));
    out.push_str(&unit_status_block(RELAY_UNITS, facts));
    out.push('\n');
    out.push_str(&format!("{}\n", l10n::vps_handshake_note(l)));
    let wg = facts.wg_show("wg0");
    out.push_str(&wg);
    out.push('\n');
    out.push_str(&format!("{}\n", l10n::next_steps_header(l)));
    out.push_str(&format!("  {}\n", l10n::vps_next_step_home(l)));
    out.push_str(&format!(
        "  {}\n",
        l10n::vps_next_step_ptr(l, ptr_hostname)
    ));
    out
}

fn unit_status_block(units: &[&str], facts: &dyn Facts) -> String {
    let mut out = String::new();
    for unit in units {
        let status = facts.systemctl_is_active(unit);
        out.push_str(&format!("  {unit:<14} {status}\n"));
    }
    out
}

fn tunnel_report_line(input: &HostInput, endpoint: &str) -> String {
    let l = input.language;
    format!(
        "{}wg0 -> {endpoint} {}",
        l10n::pad_label(&l10n::tunnel_report_line_label(l)),
        l10n::tunnel_report_line_note(l)
    )
}

// MARK: - Which services report, and in what order

/// The mail engine on this host, if any
fn mail_engine(input: &HostInput) -> Option<&str> {
    ["mailcow", "mailu", "docker-mailserver"]
        .into_iter()
        .find(|id| input.services.iter().any(|s| s == id))
}

fn reporting_services(input: &HostInput) -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| input.services.iter().any(|s| s == id))
        .collect();
    let panel = "vpn-panel";
    let has_protocol = ids.iter().any(|id| VPN_PROTOCOLS.contains(id));
    if has_protocol && !ids.contains(&panel) {
        let at = CATALOG_ORDER.iter().position(|id| *id == panel).unwrap();
        let before = ids
            .iter()
            .position(|id| CATALOG_ORDER.iter().position(|c| c == id).unwrap() > at)
            .unwrap_or(ids.len());
        ids.insert(before, panel);
    }
    if let Some(engine) = mail_engine(input) {
        ids.retain(|id| *id != engine);
        let engine: &'static str = CATALOG_ORDER.iter().find(|id| **id == engine).unwrap();
        ids.insert(0, engine);
    }
    ids
}

/// `ServiceID.vpnProtocols` — the panel is implied by any of these.
const VPN_PROTOCOLS: &[&str] = &[
    "wireguard-vpn",
    "amnezia-wg",
    "shadowsocks",
    "xray-reality",
    "openvpn",
];

fn service_lines(input: &HostInput, facts: &dyn Facts) -> String {
    let mut out = String::new();
    for id in reporting_services(input) {
        out.push_str(&service_block(id, input, facts));
    }
    out
}

/// One service's credential block
fn service_block(id: &str, input: &HostInput, facts: &dyn Facts) -> String {
    let l = input.language;
    let among = input.install_among_neighbours();
    let i = &among;
    let mut out = String::new();
    let handled = service_block_1(id, i, l, facts, &mut out)
        || service_block_2(id, i, l, facts, &mut out)
        || service_block_3(id, i, l, facts, &mut out)
        || service_block_4(id, i, l, facts, &mut out)
        || service_block_5(id, i, l, facts, &mut out)
        || service_block_6(id, i, l, facts, &mut out)
        || service_block_7(id, i, l, facts, &mut out)
        || service_block_8(id, i, l, facts, &mut out)
        || service_block_9(id, input, i, l, &mut out)
        || service_block_10(id, input, i, l, facts, &mut out)
        || service_block_11(id, i, l, facts, &mut out)
        || service_block_12(id, input, i, l, facts, &mut out)
        || service_block_13(id, i, l, facts, &mut out)
        || service_block_14(id, i, l, facts, &mut out);
    if !handled {
        unreachable!("report block asked for an id outside CATALOG_ORDER: {id}")
    }
    out
}

fn service_block_1(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "mailcow" => {
            let path = &i.mailcow_path;
            out.push_str(&format!(
                "Mailcow:      https://mail.{}  ({}: {path})\n",
                i.domain,
                l10n::directory_label(l)
            ));
            out.push_str(&format!("  {}: admin\n", l10n::administrator_label(l)));
            // `$(cat file)`: the shell strips the trailing newline.
            let admin_password = facts
                .read_file(&format!("{path}/{}", mailcow::ADMIN_PASSWORD_FILE))
                .unwrap_or_default()
                .trim_end_matches('\n')
                .to_string();
            if admin_password.is_empty() {
                out.push_str(&format!("  {}: moohoo\n", l10n::password_label(l)));
                out.push_str(&format!("  {}\n", l10n::mailcow_default_password_note(l)));
            } else {
                out.push_str(&format!("  {}: {admin_password}\n", l10n::password_label(l)));
            }
            out.push_str(&format!("  {}\n", l10n::mailcow_auto_cert_note(l)));
            let key = conf_value_last(facts, &format!("{path}/mailcow.conf"), "API_KEY");
            for domain in std::iter::once(&i.domain).chain(i.additional_domains.iter()) {
                let record = format!("dkim._domainkey.{domain}");
                let value = facts.mailcow_dkim(&key, domain, MAILCOW_HTTPS_PORT);
                if value.is_empty() {
                    out.push_str(&format!("  {}\n", l10n::mailcow_dkim_not_ready(l)));
                } else {
                    out.push_str(&format!("  {}\n", l10n::mailcow_dkim_header(l, &record)));
                    out.push_str(&format!("  {value}\n"));
                    out.push_str(&format!("{DKIM_MARKER} {record} {value}\n"));
                }
            }
            true
        }
        _ => false,
    }
}

fn service_block_2(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "mailu" => {
            let path = &i.mailu_path;
            let host = format!("mail.{}", i.domain);
            out.push_str(&format!("Mailu:        https://{host}/admin\n"));
            out.push_str(&format!(
                "  {}:     https://{host}/webmail\n",
                l10n::webmail_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}@{}\n",
                l10n::administrator_label(l),
                i.admin_username,
                i.domain
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{path}/.env"), "INITIAL_ADMIN_PW")
            ));
            out.push_str(&format!("  {}\n", l10n::mailu_client_ports_note(l)));
            out.push_str(&format!("  {}:\n", l10n::dkim_records_label(l)));
            out.push_str(&dkim_wrapper_lines(
                facts,
                MAILU_DKIM_WRAPPER,
                &l10n::mailu_dkim_pending_note(l),
            ));
            true
        }
        "docker-mailserver" => {
            let path = &i.docker_mailserver_path;
            let host = format!("mail.{}", i.domain);
            out.push_str("Docker Mailserver:\n");
            out.push_str(&format!(
                "  {}:     https://{host}\n",
                l10n::webmail_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}@{}\n",
                l10n::first_mailbox_label(l),
                i.admin_username,
                i.domain
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{path}/.env"), "FIRST_MAILBOX_PASSWORD")
            ));
            out.push_str(&format!("  {}\n", l10n::dms_mailboxes_note(l)));
            out.push_str(&format!("  {}:\n", l10n::dkim_records_label(l)));
            out.push_str(&dkim_wrapper_lines(
                facts,
                DMS_DKIM_WRAPPER,
                &l10n::dms_dkim_pending_note(l),
            ));
            true
        }
        _ => false,
    }
}

fn service_block_3(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "vaultwarden" => {
            let host = crate::install::vaultwarden::hostname(i);
            out.push_str(&format!("Vaultwarden:  https://{host}\n"));
            out.push_str(&format!(
                "  {}: https://{host}/admin\n",
                l10n::admin_panel_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::vaultwarden_admin_token_label(l),
                env_value(facts, VAULTWARDEN_ENV, "ADMIN_TOKEN")
            ));
            out.push_str(&format!("  {}\n", l10n::vaultwarden_register_note(l)));
            out.push_str(&format!(
                "  {}\n",
                if i.vaultwarden_allow_signups {
                    l10n::vaultwarden_signups_open(l)
                } else {
                    l10n::vaultwarden_signups_closed(l)
                }
            ));
            true
        }
        "psono" => {
            out.push_str(&format!("Psono:        https://{}\n", crate::install::psono::hostname(i)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                crate::install::psono::admin_login(i)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{}/.env", i.psono_path), "PSONO_ADMIN_PASSWORD")
            ));
            true
        }
        _ => false,
    }
}

fn service_block_4(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "passbolt" => {
            out.push_str(&format!("Passbolt:     https://{}\n", crate::install::passbolt::hostname(i)));
            let url_file = format!("{}/.registration-url", i.passbolt_path);
            match facts.read_file(&url_file) {
                Some(text) if !text.is_empty() => {
                    out.push_str(&format!("  {}\n", l10n::passbolt_setup_url_label(l)));
                    out.push_str(&format!("  {}\n", strip_trailing_newlines(&text)));
                }
                _ => out.push_str(&format!(
                    "  {}\n",
                    l10n::passbolt_already_configured_note(l)
                )),
            }
            true
        }
        "nextcloud" => {
            out.push_str(&format!("Nextcloud:    https://{}\n", crate::install::nextcloud::hostname(i)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                i.admin_username
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.nextcloud_path),
                    "NEXTCLOUD_ADMIN_PASSWORD"
                )
            ));
            true
        }
        "seafile" => {
            out.push_str(&format!("Seafile:      https://{}\n", crate::install::seafile::hostname(i)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                seafile_admin_login(i)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.seafile_path),
                    "SEAFILE_ADMIN_PASSWORD"
                )
            ));
            true
        }
        "immich" => {
            out.push_str(&format!("Immich:       https://{}\n", crate::install::immich::hostname(i)));
            out.push_str(&format!("  {}\n", l10n::immich_admin_warning(l)));
            true
        }
        _ => false,
    }
}

fn service_block_5(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "photoprism" => {
            let path = &i.photoprism_path;
            out.push_str(&format!("PhotoPrism:   https://{}\n", crate::install::photoprism::hostname(i)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                i.admin_username
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{path}/.env"), "PHOTOPRISM_ADMIN_PASSWORD")
            ));
            out.push_str(&format!(
                "  {}: {path}/originals\n",
                l10n::photoprism_originals_label(l)
            ));
            true
        }
        "gitlab" => {
            let host = crate::install::gitlab::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("GitLab:       https://{host}\n"));
            out.push_str(&format!("  {}: root\n", l10n::administrator_label(l)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.gitlab_path),
                    "GITLAB_ROOT_PASSWORD"
                )
            ));
            out.push_str(&format!("  {}\n", l10n::gitlab_registration_closed_note(l)));
            out.push_str(&format!("  {}\n", l10n::gitlab_first_start_note(l)));
            out.push_str(&format!(
                "  {}\n",
                if i.gitlab_ssh_port == 0 {
                    l10n::gitlab_ssh_disabled_note(l)
                } else {
                    l10n::gitlab_ssh_note(l, host, i64::from(i.gitlab_ssh_port))
                }
            ));
            true
        }
        _ => false,
    }
}

fn service_block_6(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "forgejo" => {
            let host = crate::install::forgejo::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("Forgejo:      https://{host}\n"));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                crate::install::forgejo::admin_username(i)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.forgejo_path),
                    "FORGEJO_ADMIN_PASSWORD"
                )
            ));
            out.push_str(&format!("  {}\n", l10n::forgejo_registration_closed_note(l)));
            out.push_str(&format!(
                "  {}\n",
                if i.forgejo_ssh_port == 0 {
                    l10n::forgejo_ssh_disabled_note(l)
                } else {
                    l10n::forgejo_ssh_note(l, host, i64::from(i.forgejo_ssh_port))
                }
            ));
            true
        }
        "minecraft-java" => {
            let address = if i.minecraft_java_port == 25565 {
                format!("play.{}", i.domain)
            } else {
                format!("play.{}:{}", i.domain, i.minecraft_java_port)
            };
            out.push_str(&format!("Minecraft (Java):  {address}\n"));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::minecraft_flavour_label(l),
                i.minecraft_java_flavour
            ));
            if !i.minecraft_java_accepts_eula {
                out.push_str(&format!("  {}\n", l10n::minecraft_eula_not_accepted(l)));
            }
            if i.minecraft_java_version.trim().is_empty() {
                out.push_str(&format!("  {}\n", l10n::minecraft_version_follows_latest(l)));
            }
            if i.minecraft_java_whitelist.trim().is_empty() {
                out.push_str(&format!("  {}\n", l10n::minecraft_no_whitelist(l)));
            }
            true
        }
        _ => false,
    }
}

fn service_block_7(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "minecraft-bedrock" => {
            out.push_str(&format!(
                "Minecraft (Bedrock): play.{}:{}\n",
                i.domain, i.minecraft_bedrock_port
            ));
            out.push_str(&format!("  {}\n", l10n::minecraft_bedrock_on_arm(l)));
            if !i.minecraft_bedrock_accepts_eula {
                out.push_str(&format!("  {}\n", l10n::minecraft_eula_not_accepted(l)));
            }
            true
        }
        "crafty-controller" => {
            out.push_str(&format!(
                "Crafty Controller: https://{}\n",
                crate::install::crafty::hostname(i)
            ));
            out.push_str(&format!(
                "  {}: {}/config/default-creds.txt\n",
                l10n::crafty_first_login(l),
                i.crafty_path
            ));
            true
        }
        "jellyfin" => {
            out.push_str(&format!("Jellyfin:     https://{}\n", crate::install::jellyfin::hostname(i)));
            out.push_str(&format!("  {}\n", l10n::jellyfin_admin_warning(l)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::jellyfin_library_label(l),
                i.jellyfin_media_path
            ));
            true
        }
        "mosquitto" => {
            out.push_str(&format!(
                "Mosquitto:    {}:{}\n",
                l10n::mosquitto_network_address(l),
                crate::install::mosquitto::BROKER_PORT
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::mosquitto_accounts_label(l),
                crate::install::mosquitto::USERS.join(", ")
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{}/.env", i.mosquitto_path), "MQTT_PASSWORD")
            ));
            true
        }
        "zigbee2mqtt" => {
            out.push_str(&format!(
                "Zigbee2MQTT:  https://{}\n",
                crate::install::zigbee2mqtt::hostname(i)
            ));
            out.push_str(&format!("  {}\n", l10n::zigbee2mqtt_pairing_hint(l)));
            true
        }
        _ => false,
    }
}

fn service_block_8(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "home-assistant" => {
            out.push_str(&format!(
                "Home Assistant: https://{}\n",
                crate::install::home_assistant::hostname(i)
            ));
            out.push_str(&format!("  {}\n", l10n::home_assistant_owner_warning(l)));
            out.push_str(&format!("  {}\n", l10n::home_assistant_app_hint(l)));
            true
        }
        "ollama" => {
            out.push_str(&format!(
                "Ollama:       127.0.0.1:{}\n",
                crate::install::ollama::API_PORT
            ));
            out.push_str(&format!("  {}\n", l10n::ollama_no_models_note(l)));
            out.push_str(&format!(
                "  docker exec -it {} ollama pull llama3.2\n",
                crate::install::ollama::CONTAINER
            ));
            out.push_str(&format!("  {}\n", l10n::ollama_model_size_note(l)));
            if i.ollama_uses_gpu {
                let override_path = crate::install::ollama::gpu_override_path(i);
                if facts.read_file(&override_path).is_some() {
                    out.push_str(&format!("  {}\n", l10n::ollama_gpu_enabled_note(l)));
                } else {
                    out.push_str(&format!("  {}\n", l10n::ollama_gpu_missing_note(l)));
                }
            }
            true
        }
        "litellm" => {
            out.push_str(&format!(
                "LiteLLM:      https://{}\n",
                crate::install::litellm::hostname(i)
            ));
            let key = facts
                .read_file(crate::install::litellm::GATEWAY_KEY_PATH)
                .map(|text| text.trim_end_matches('\n').to_string())
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!("  {}: {key}\n", l10n::lite_llm_master_key_label(l)));
            out.push_str(&format!("  {}\n", l10n::lite_llm_keys_note(l)));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::lite_llm_keys_file_label(l),
                crate::install::llm_keys::KEYS_ENV_PATH
            ));
            true
        }
        _ => false,
    }
}

fn service_block_9(id: &str, input: &HostInput, i: &Input, l: Language, out: &mut String) -> bool {
    match id {
        "anythingllm" => {
            out.push_str(&format!(
                "AnythingLLM:  https://{}\n",
                crate::install::anythingllm::hostname(i)
            ));
            out.push_str(&format!("  {}\n", l10n::anythingllm_admin_warning(l)));
            if crate::install::anythingllm::model_source(&input.services).is_none() {
                out.push_str(&format!("  {}\n", l10n::anythingllm_no_model_note(l)));
            }
            out.push_str(&format!("  {}\n", l10n::anythingllm_settings_note(l)));
            true
        }
        "qdrant" => {
            out.push_str(&format!(
                "Qdrant:       127.0.0.1:{}\n",
                crate::install::qdrant::API_PORT
            ));
            out.push_str(&format!("  {}\n", l10n::qdrant_loopback_note(l)));
            true
        }
        "searxng" => {
            out.push_str(&format!(
                "SearXNG:      127.0.0.1:{}\n",
                crate::install::searxng::WEB_UI_PORT
            ));
            out.push_str(&format!("  {}\n", l10n::searxng_loopback_note(l)));
            true
        }
        _ => false,
    }
}

fn service_block_10(id: &str, input: &HostInput, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "openclaw" => {
            out.push_str(&format!(
                "OpenClaw:     https://{}\n",
                crate::install::openclaw::hostname(i)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::openclaw_token_note(l),
                env_value(facts, &format!("{}/.env", i.openclaw_path), "OPENCLAW_GATEWAY_TOKEN")
            ));
            out.push_str(&format!("  {}\n", l10n::openclaw_pairing_note(l)));
            match crate::install::openclaw::model_endpoint(&input.services) {
                Some(endpoint) => out.push_str(&format!(
                    "  {}: {endpoint}\n",
                    l10n::openclaw_model_note(l)
                )),
                None => out.push_str(&format!("  {}\n", l10n::openclaw_no_model_note(l))),
            }
            true
        }
        "n8n" => {
            out.push_str(&format!("n8n:          https://{}\n", crate::install::n8n::hostname(i)));
            out.push_str(&format!("  {}\n", l10n::n8n_owner_warning(l)));
            out.push_str(&format!("  {}\n", l10n::n8n_webhooks_public_note(l)));
            true
        }
        "open-webui" => {
            out.push_str(&format!(
                "Open WebUI:   https://{}\n",
                crate::install::open_webui::hostname(i)
            ));
            out.push_str(&format!("  {}\n", l10n::open_web_ui_admin_warning(l)));
            if crate::install::open_webui::engine_url(&input.services).is_none() {
                out.push_str(&format!("  {}\n", l10n::open_web_ui_no_engine_note(l)));
            }
            true
        }
        "cloudflared" => {
            out.push_str("Cloudflare Tunnel:\n");
            out.push_str(&format!(
                "  {}: {}/.env\n",
                l10n::cloudflared_token_note(l),
                i.cloudflared_path
            ));
            out.push_str(&format!("  {}: https://127.0.0.1:443\n", l10n::cloudflared_routes_note(l)));
            out.push_str(&format!("  {}\n", l10n::cloudflared_no_ports_note(l)));
            true
        }
        _ => false,
    }
}

fn service_block_11(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "headscale" => {
            let host = crate::install::headscale::hostname(i);
            let base = crate::install::headscale::base_domain(i);
            out.push_str(&format!("Headscale: https://{host}\n"));
            out.push_str(&format!("  {}\n", l10n::headscale_no_web_ui_note(l)));
            out.push_str(&format!("  {}:\n", l10n::headscale_create_user_note(l)));
            out.push_str(&format!(
                "    sudo docker exec {} headscale users create <name>\n",
                crate::install::headscale::CONTAINER
            ));
            out.push_str(&format!(
                "    sudo docker exec {} headscale preauthkeys create --user <id> --reusable --expiration 24h\n",
                crate::install::headscale::CONTAINER
            ));
            out.push_str(&format!("  {}:\n", l10n::headscale_join_note(l)));
            out.push_str(&format!("    tailscale up --login-server https://{host} --authkey <key>\n"));
            out.push_str(&format!("  {}: <device>.{base}\n", l10n::headscale_magic_dns_note(l)));
            true
        }
        "tailscale-node" => {
            let name = crate::install::tailscale::node_name(i);
            let base = crate::install::headscale::base_domain(i);
            out.push_str(&format!("{}: {name}.{base}\n", l10n::mesh_node_title(l)));
            out.push_str(&format!("  {}\n", l10n::mesh_node_explain_note(l)));
            true
        }
        "adguard-home" => {
            let host = crate::install::adguard::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("AdGuard Home: https://{host}\n"));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                i.admin_username
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(
                    facts,
                    &format!("{}/.env", i.adguard_path),
                    "ADGUARD_ADMIN_PASSWORD"
                )
            ));
            out.push_str(&format!(
                "  {}: https://{host}/dns-query\n",
                l10n::adguard_do_h_note(l)
            ));
            out.push_str(&format!("  {}\n", l10n::adguard_plain_dns_note(l)));
            true
        }
        _ => false,
    }
}

fn service_block_12(id: &str, input: &HostInput, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "pihole" => {
            let host = crate::install::pihole::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("Pi-hole: https://{host}/admin\n"));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{}/.env", i.pihole_path), "PIHOLE_ADMIN_PASSWORD")
            ));
            out.push_str(&format!(
                "  {}\n",
                if i.pihole_serves_network {
                    l10n::pihole_serves_network_note(l)
                } else {
                    l10n::pihole_loopback_note(l)
                }
            ));
            true
        }
        "authelia" => {
            let host = crate::install::authelia::hostname(i);
            out.push_str(&format!("Authelia: https://{host}\n"));
            out.push_str(&format!("  {}: {}\n", l10n::administrator_label(l), i.admin_username));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{}/.env", i.authelia_path), "AUTHELIA_ADMIN_PASSWORD")
            ));
            let names = crate::install::authelia::protected_hostnames(i, &input.services);
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::authelia_protects_note(l),
                if names.is_empty() { "—".to_string() } else { names.join(", ") }
            ));
            true
        }
        _ => false,
    }
}

fn service_block_13(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "homepage" => {
            let host = crate::install::homepage::hostname(i);
            out.push_str(&format!("Homepage: https://{host}\n"));
            out.push_str(&format!(
                "  {}: {}/config/services.yaml\n",
                l10n::homepage_generated_note(l),
                i.homepage_path
            ));
            out.push_str(&format!(
                "  {}: {}/config/bookmarks.yaml\n",
                l10n::homepage_own_edits_note(l),
                i.homepage_path
            ));
            true
        }
        "wireguard-vpn" => true,
        "amnezia-wg" => {
            out.push_str(&format!(
                "AmneziaWG: {}:{} (UDP)\n",
                crate::install::vpn::panel::hostname(i), i.amnezia_wg_port
            ));
            out.push_str(&format!(
                "  {}\n",
                l10n::amnezia_admin_via_wire_guard_note(l)
            ));
            true
        }
        "shadowsocks" => {
            let endpoint = format!("{}:{}", crate::install::vpn::panel::hostname(i), i.shadowsocks_port);
            out.push_str(&format!("Shadowsocks: {endpoint} (TCP+UDP)\n"));
            let password = shadowsocks_password(facts, &i.shadowsocks_path);
            out.push_str(&format!("  {}:\n", l10n::shadowsocks_link_label(l)));
            out.push_str(&format!(
                "  ss://{SHADOWSOCKS_METHOD}:{}@{endpoint}#gryonixNexus\n",
                percent_encode_userinfo(&password)
            ));
            out.push_str(&format!("  {}\n", l10n::shadowsocks_clients_note(l)));
            out.push_str(&format!("  {}\n", l10n::admin_via_wire_guard_note(l)));
            true
        }
        "xray-reality" => {
            out.push_str(&format!(
                "VLESS/Reality: {}:{} (TCP)\n",
                crate::install::vpn::panel::hostname(i), i.xray_reality_port
            ));
            out.push_str(&format!("  {}:\n", l10n::xray_link_label(l)));
            let link = facts
                .read_file(&format!("{}/link.txt", i.xray_reality_path))
                .unwrap_or_default();
            out.push_str(&format!("  {}\n", strip_trailing_newlines(&link)));
            out.push_str(&format!("  {}\n", l10n::xray_clients_note(l)));
            out.push_str(&format!("  {}\n", l10n::admin_via_wire_guard_note(l)));
            true
        }
        _ => false,
    }
}

fn service_block_14(id: &str, i: &Input, l: Language, facts: &dyn Facts, out: &mut String) -> bool {
    match id {
        "openvpn" => {
            let path = &i.openvpn_path;
            out.push_str(&format!(
                "OpenVPN: {}:{} (UDP)\n",
                crate::install::vpn::panel::hostname(i), i.openvpn_port
            ));
            out.push_str(&format!("  {}:\n", l10n::open_vpn_config_label(l)));
            out.push_str(&format!("  ----- BEGIN {OPENVPN_CLIENT}.ovpn -----\n"));
            if let Some(profile) = facts.read_file(&format!("{path}/{OPENVPN_CLIENT}.ovpn")) {
                out.push_str(&profile);
            }
            out.push_str(&format!("  ----- END {OPENVPN_CLIENT}.ovpn -----\n"));
            out.push_str(&format!("  {}\n", l10n::open_vpn_clients_note(l)));
            out.push_str(&format!("  {}\n", l10n::admin_via_wire_guard_note(l)));
            true
        }
        "vpn-panel" => {
            let host = crate::install::vpn::panel::hostname(i);
            let host = host.as_str();
            out.push_str(&format!("VPN Panel: https://{host}\n"));
            out.push_str(&format!(
                "  {}: https://{host}\n",
                l10n::admin_panel_label(l)
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::administrator_label(l),
                env_value(facts, &format!("{VPN_PANEL_PATH}/.env"), "ADMIN_USER")
            ));
            out.push_str(&format!(
                "  {}: {}\n",
                l10n::password_generated_on_server_label(l),
                env_value(facts, &format!("{VPN_PANEL_PATH}/.env"), "ADMIN_PASSWORD")
            ));
            out.push_str(&format!("  {}\n", l10n::vpn_clients_note(l)));
            true
        }
        _ => false,
    }
}

// MARK: - Reading what the shell read

fn env_value(facts: &dyn Facts, path: &str, key: &str) -> String {
    let text = facts.read_file(path).unwrap_or_default();
    let prefix = format!("{key}=");
    text.lines()
        .find(|line| line.starts_with(&prefix))
        .map(|line| line[prefix.len()..].to_string())
        .unwrap_or_default()
}

fn conf_value_last(facts: &dyn Facts, path: &str, key: &str) -> String {
    let text = facts.read_file(path).unwrap_or_default();
    let prefix = format!("{key}=");
    text.lines()
        .filter(|line| line.starts_with(&prefix))
        .next_back()
        .map(|line| line[prefix.len()..].to_string())
        .unwrap_or_default()
}

fn dkim_wrapper_lines(facts: &dyn Facts, wrapper: &str, pending_note: &str) -> String {
    let stdout = facts.dkim_wrapper(wrapper);
    let marker = format!("{DKIM_MARKER} ");
    let mut lines = String::new();
    for line in stdout.lines().filter(|l| l.starts_with(&marker)) {
        let mut parts = line.splitn(3, ' ');
        let (_, name, value) = (parts.next(), parts.next(), parts.next());
        if let (Some(name), Some(value)) = (name, value) {
            lines.push_str(&format!("    {name} TXT {value}\n"));
        }
    }
    if lines.is_empty() {
        format!("    {pending_note}\n")
    } else {
        lines
    }
}

fn shadowsocks_password(facts: &dyn Facts, path: &str) -> String {
    let text = facts
        .read_file(&format!("{path}/config.json"))
        .unwrap_or_default();
    let mut found = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.split_once("\"password\"") {
            let after = rest.1.trim_start();
            let Some(after) = after.strip_prefix(':') else {
                continue;
            };
            let after = after.trim_start();
            if let Some(after) = after.strip_prefix('"') {
                if let Some(end) = after.find('"') {
                    found.push(after[..end].to_string());
                }
            }
        }
    }
    found.into_iter().next().unwrap_or_default()
}

fn percent_encode_userinfo(password: &str) -> String {
    password
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

fn seafile_admin_login(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

fn strip_trailing_newlines(text: &str) -> &str {
    text.trim_end_matches('\n')
}

#[cfg(test)]
mod tests;
