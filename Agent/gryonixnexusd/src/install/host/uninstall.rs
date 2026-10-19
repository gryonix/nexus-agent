//! Port of `UninstallSections` — `/opt/gryonixnexus-uninstall.sh`

use crate::install::context::Input;
use crate::install::host::access::service_sudoers_lines;
use crate::install::host::{HostInput, HostRole};

// MARK: - Parameters `HostInput` does not carry

#[derive(Debug, Clone, PartialEq)]
pub struct DashboardAccess {
    /// `DashboardAccessInput.createUser`
    pub create_user: bool,
    pub app_public_key: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackupPaths {
    pub root: String,
    pub mailcow: String,
    pub vaultwarden: String,
}

impl Default for BackupPaths {
    fn default() -> Self {
        Self {
            root: "/opt/backups".to_string(),
            mailcow: "/opt/backups/mailcow".to_string(),
            vaultwarden: "/opt/backups/vaultwarden".to_string(),
        }
    }
}

impl BackupPaths {
    pub fn for_id(&self, id: &str) -> String {
        format!("{}/{id}", self.root)
    }
}

// MARK: - Catalog order

use super::CATALOG_ORDER;

const VPN_PROTOCOLS: &[&str] =
    &["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"];

const VPN_PANEL: &str = "vpn-panel";

fn is_vpn_member(id: &str) -> bool {
    VPN_PROTOCOLS.contains(&id) || id == VPN_PANEL
}

// MARK: - Per-service UninstallSpec

/// A port of `ServiceCatalog.UninstallSpec`.
struct Spec {
    compose_project: Option<&'static str>,
    config_directory: Option<String>,
    data_paths: Vec<String>,
    backup_dirs: Vec<String>,
    pre_steps: Vec<String>,
    post_steps: Vec<String>,
}

impl Spec {
    fn empty() -> Self {
        Self {
            compose_project: None,
            config_directory: None,
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }
    }

    fn default_for(compose_project: &'static str, config_directory: impl Into<String>) -> Self {
        Self { compose_project: Some(compose_project), config_directory: Some(config_directory.into()), ..Self::empty() }
    }
}

fn spec_for(id: &str, input: &Input, backups: &BackupPaths) -> Spec {
    spec_for_1(id, input, backups)
        .or_else(|| spec_for_2(id, input, backups))
        .or_else(|| spec_for_3(id, input, backups))
        .or_else(|| spec_for_4(id, input, backups))
        .or_else(|| spec_for_5(id, input, backups))
        .or_else(|| spec_for_6(id, input, backups))
        .or_else(|| spec_for_7(id, input, backups))
        .unwrap_or_else(|| unreachable!("spec_for called with an id outside CATALOG_ORDER: {id}"))
}

fn spec_for_1(id: &str, input: &Input, backups: &BackupPaths) -> Option<Spec> {
    use crate::install::mail::{mailcow, mailu};
    match id {
        "mailcow" => Some(Spec {
            compose_project: Some(mailcow::COMPOSE_PROJECT),
            config_directory: Some(input.mailcow_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: vec![backups.mailcow.clone()],
            pre_steps: Vec::new(),
            post_steps: vec![
                format!("systemctl disable --now {unit}.timer >/dev/null 2>&1 || true", unit = mailcow::CERT_SYNC_UNIT),
                format!(
                    "rm -f /etc/systemd/system/{unit}.service /etc/systemd/system/{unit}.timer {script}",
                    unit = mailcow::CERT_SYNC_UNIT,
                    script = mailcow::CERT_SYNC_SCRIPT_PATH
                ),
                "systemctl daemon-reload || true".to_string(),
                format!(
                    "rm -f '{path}/bot-backup.sh' '{path}'/bot-backup.sh.bak.* || true",
                    path = input.mailcow_path
                ),
                format!("rm -f {}", mailcow::DKIM_DUMP_SCRIPT_PATH),
            ],
        }),
        "mailu" => Some(Spec {
            compose_project: Some(mailu::COMPOSE_PROJECT),
            config_directory: None,
            data_paths: vec![input.mailu_path.clone()],
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: vec![
                format!("systemctl disable --now {unit}.timer >/dev/null 2>&1 || true", unit = mailu::CERT_SYNC_UNIT),
                format!(
                    "rm -f /etc/systemd/system/{unit}.service /etc/systemd/system/{unit}.timer '{cert}' '{dkim}'",
                    unit = mailu::CERT_SYNC_UNIT,
                    cert = mailu::CERT_SYNC_SCRIPT_PATH,
                    dkim = mailu::DKIM_DUMP_SCRIPT_PATH
                ),
                format!(
                    "rm -f '{cert}'.bak.* '{dkim}'.bak.*",
                    cert = mailu::CERT_SYNC_SCRIPT_PATH,
                    dkim = mailu::DKIM_DUMP_SCRIPT_PATH
                ),
                "systemctl daemon-reload || true".to_string(),
            ],
        }),
        _ => None,
    }
}

fn spec_for_2(id: &str, input: &Input, backups: &BackupPaths) -> Option<Spec> {
    use crate::install::mail::dockermailserver as dms;
    match id {
        "docker-mailserver" => Some(Spec {
            compose_project: Some(dms::COMPOSE_PROJECT),
            config_directory: None,
            data_paths: vec![input.docker_mailserver_path.clone()],
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: vec![
                format!("systemctl disable --now {unit}.timer >/dev/null 2>&1 || true", unit = dms::CERT_SYNC_UNIT),
                format!(
                    "rm -f /etc/systemd/system/{unit}.service /etc/systemd/system/{unit}.timer '{cert}' '{mailbox}' '{dkim}'",
                    unit = dms::CERT_SYNC_UNIT,
                    cert = dms::CERT_SYNC_SCRIPT_PATH,
                    mailbox = dms::MAILBOX_SCRIPT_PATH,
                    dkim = dms::DKIM_DUMP_SCRIPT_PATH
                ),
                format!(
                    "rm -f '{cert}'.bak.* '{mailbox}'.bak.* '{dkim}'.bak.*",
                    cert = dms::CERT_SYNC_SCRIPT_PATH,
                    mailbox = dms::MAILBOX_SCRIPT_PATH,
                    dkim = dms::DKIM_DUMP_SCRIPT_PATH
                ),
                "systemctl daemon-reload || true".to_string(),
            ],
        }),
        "vaultwarden" => Some(Spec {
            compose_project: Some(crate::install::vaultwarden::COMPOSE_PROJECT),
            config_directory: Some(crate::install::vaultwarden::COMPOSE_DIRECTORY.to_string()),
            data_paths: vec![
                input.vaultwarden_data_path.clone(),
                format!("{}.pre-restore-*", input.vaultwarden_data_path),
            ],
            backup_dirs: vec![backups.vaultwarden.clone()],
            pre_steps: Vec::new(),
            post_steps: vec!["rm -f /opt/vaultwarden-update.sh /opt/vaultwarden-update.sh.bak.* || true".to_string()],
        }),
        "psono" => Some(Spec {
            compose_project: Some(crate::install::psono::COMPOSE_PROJECT),
            config_directory: Some(input.psono_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.psono_path)],
            backup_dirs: vec![backups.for_id("psono")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "passbolt" => Some(Spec {
            compose_project: Some(crate::install::passbolt::COMPOSE_PROJECT),
            config_directory: Some(input.passbolt_path.clone()),
            // A port of `PassboltService.secretsPath(_:)`: `<passboltPath>/secrets`.
            data_paths: vec![format!("{}/secrets.pre-restore-*", input.passbolt_path)],
            backup_dirs: vec![backups.for_id("passbolt")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "nextcloud" => Some(Spec {
            compose_project: Some(crate::install::nextcloud::COMPOSE_PROJECT),
            config_directory: Some(input.nextcloud_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.nextcloud_path)],
            backup_dirs: vec![backups.for_id("nextcloud")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        _ => None,
    }
}

fn spec_for_3(id: &str, input: &Input, backups: &BackupPaths) -> Option<Spec> {
    match id {
        "seafile" => Some(Spec {
            compose_project: Some(crate::install::seafile::COMPOSE_PROJECT),
            config_directory: Some(input.seafile_path.clone()),
            // A port of `SeafileService.dataPath(_:)`: `<seafilePath>/data`.
            data_paths: vec![format!("{}/data.pre-restore-*", input.seafile_path)],
            backup_dirs: vec![backups.for_id("seafile")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "immich" => Some(Spec {
            compose_project: Some(crate::install::immich::COMPOSE_PROJECT),
            config_directory: Some(input.immich_path.clone()),
            data_paths: vec![format!("{}/library.pre-restore-*", input.immich_path)],
            backup_dirs: vec![backups.for_id("immich")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "photoprism" => Some(Spec {
            compose_project: Some(crate::install::photoprism::COMPOSE_PROJECT),
            config_directory: Some(input.photoprism_path.clone()),
            data_paths: vec![format!("{}/originals.pre-restore-*", input.photoprism_path)],
            backup_dirs: vec![backups.for_id("photoprism")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "gitlab" => Some(Spec::default_for(crate::install::gitlab::COMPOSE_PROJECT, input.gitlab_path.clone())),
        "forgejo" => Some(Spec {
            compose_project: Some(crate::install::forgejo::COMPOSE_PROJECT),
            config_directory: Some(input.forgejo_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.forgejo_path)],
            backup_dirs: vec![backups.for_id("forgejo")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "jellyfin" => Some(Spec {
            compose_project: Some(crate::install::jellyfin::COMPOSE_PROJECT),
            config_directory: Some(input.jellyfin_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.jellyfin_path)],
            backup_dirs: vec![backups.for_id("jellyfin")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "mosquitto" => Some(Spec {
            compose_project: Some(crate::install::mosquitto::COMPOSE_PROJECT),
            config_directory: Some(input.mosquitto_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.mosquitto_path)],
            backup_dirs: vec![backups.for_id("mosquitto")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "zigbee2mqtt" => Some(Spec {
            compose_project: Some(crate::install::zigbee2mqtt::COMPOSE_PROJECT),
            config_directory: Some(input.zigbee2mqtt_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.zigbee2mqtt_path)],
            backup_dirs: vec![backups.for_id("zigbee2mqtt")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        _ => None,
    }
}

fn spec_for_4(id: &str, input: &Input, backups: &BackupPaths) -> Option<Spec> {
    match id {
        "home-assistant" => Some(Spec {
            compose_project: Some(crate::install::home_assistant::COMPOSE_PROJECT),
            config_directory: Some(input.home_assistant_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.home_assistant_path)],
            backup_dirs: vec![backups.for_id("home-assistant")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "minecraft-java" => Some(Spec {
            compose_project: Some(crate::install::minecraft::JAVA_COMPOSE_PROJECT),
            config_directory: Some(input.minecraft_java_path.clone()),
            data_paths: vec![format!("{}/data", input.minecraft_java_path)],
            backup_dirs: vec![backups.for_id("minecraft-java")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "minecraft-bedrock" => Some(Spec {
            compose_project: Some(crate::install::minecraft::BEDROCK_COMPOSE_PROJECT),
            config_directory: Some(input.minecraft_bedrock_path.clone()),
            data_paths: vec![format!("{}/data", input.minecraft_bedrock_path)],
            backup_dirs: vec![backups.for_id("minecraft-bedrock")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "crafty-controller" => Some(Spec {
            compose_project: Some(crate::install::crafty::COMPOSE_PROJECT),
            config_directory: Some(input.crafty_path.clone()),
            data_paths: vec![
                format!("{}/config", input.crafty_path),
                format!("{}/servers", input.crafty_path),
            ],
            backup_dirs: vec![backups.for_id("crafty-controller")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "open-webui" => Some(Spec {
            compose_project: Some(crate::install::open_webui::COMPOSE_PROJECT),
            config_directory: Some(input.open_webui_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.open_webui_path)],
            backup_dirs: vec![backups.for_id("open-webui")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "ollama" => Some(Spec {
            compose_project: Some(crate::install::ollama::COMPOSE_PROJECT),
            config_directory: Some(input.ollama_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        _ => None,
    }
}

fn spec_for_5(id: &str, input: &Input, backups: &BackupPaths) -> Option<Spec> {
    match id {
        "litellm" => Some(Spec {
            compose_project: Some(crate::install::litellm::COMPOSE_PROJECT),
            config_directory: Some(input.litellm_path.clone()),
            data_paths: vec![
                crate::install::llm_keys::KEYS_ENV_PATH.to_string(),
                crate::install::litellm::GATEWAY_KEY_PATH.to_string(),
            ],
            backup_dirs: vec![backups.for_id("litellm")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "anythingllm" => Some(Spec {
            compose_project: Some(crate::install::anythingllm::COMPOSE_PROJECT),
            config_directory: Some(input.anythingllm_path.clone()),
            data_paths: vec![format!("{}.pre-restore-*", input.anythingllm_path)],
            backup_dirs: vec![backups.for_id("anythingllm")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "qdrant" => Some(Spec {
            compose_project: Some(crate::install::qdrant::COMPOSE_PROJECT),
            config_directory: Some(input.qdrant_path.clone()),
            data_paths: vec![
                crate::install::qdrant::API_KEY_PATH.to_string(),
                format!("{}/storage.pre-restore-*", input.qdrant_path),
            ],
            backup_dirs: vec![backups.for_id("qdrant")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "searxng" => Some(Spec {
            compose_project: Some(crate::install::searxng::COMPOSE_PROJECT),
            config_directory: Some(input.searxng_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "openclaw" => Some(Spec {
            compose_project: Some(crate::install::openclaw::COMPOSE_PROJECT),
            config_directory: Some(input.openclaw_path.clone()),
            data_paths: vec![format!("{}/state.pre-restore-*", input.openclaw_path)],
            backup_dirs: vec![backups.for_id("openclaw")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        _ => None,
    }
}

fn spec_for_6(id: &str, input: &Input, backups: &BackupPaths) -> Option<Spec> {
    match id {
        "n8n" => Some(Spec {
            compose_project: Some(crate::install::n8n::COMPOSE_PROJECT),
            config_directory: Some(input.n8n_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.n8n_path)],
            backup_dirs: vec![backups.for_id("n8n")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "adguard-home" => Some(Spec {
            compose_project: Some(crate::install::adguard::COMPOSE_PROJECT),
            config_directory: Some(input.adguard_path.clone()),
            data_paths: vec![format!("{}/conf.pre-restore-*", input.adguard_path)],
            backup_dirs: vec![backups.for_id("adguard-home")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "pihole" => Some(Spec {
            compose_project: Some(crate::install::pihole::COMPOSE_PROJECT),
            config_directory: Some(input.pihole_path.clone()),
            data_paths: vec![format!("{}/etc-pihole.pre-restore-*", input.pihole_path)],
            backup_dirs: vec![backups.for_id("pihole")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "authelia" => Some(Spec {
            compose_project: Some(crate::install::authelia::COMPOSE_PROJECT),
            config_directory: Some(input.authelia_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.authelia_path)],
            backup_dirs: vec![backups.for_id("authelia")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "homepage" => Some(Spec {
            compose_project: Some(crate::install::homepage::COMPOSE_PROJECT),
            config_directory: Some(input.homepage_path.clone()),
            data_paths: vec![format!("{}/config.pre-restore-*", input.homepage_path)],
            backup_dirs: vec![backups.for_id("homepage")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "headscale" => Some(Spec {
            compose_project: Some(crate::install::headscale::COMPOSE_PROJECT),
            config_directory: Some(input.headscale_path.clone()),
            data_paths: vec![format!("{}/data.pre-restore-*", input.headscale_path)],
            backup_dirs: vec![backups.for_id("headscale")],
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        _ => None,
    }
}

fn spec_for_7(id: &str, input: &Input, backups: &BackupPaths) -> Option<Spec> {
    match id {
        "tailscale-node" => Some(Spec {
            compose_project: Some(crate::install::tailscale::COMPOSE_PROJECT),
            config_directory: Some(input.tailscale_node_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "cloudflared" => Some(Spec {
            compose_project: Some(crate::install::cloudflared::COMPOSE_PROJECT),
            config_directory: Some(input.cloudflared_path.clone()),
            data_paths: Vec::new(),
            backup_dirs: Vec::new(),
            pre_steps: Vec::new(),
            post_steps: Vec::new(),
        }),
        "wireguard-vpn" => Some(Spec::empty()),
        "amnezia-wg" => Some(Spec::default_for("awgvpn", input.amnezia_wg_path.clone())),
        "shadowsocks" => Some(Spec::default_for("shadowsocks", input.shadowsocks_path.clone())),
        "xray-reality" => Some(Spec::default_for("xray", input.xray_reality_path.clone())),
        "openvpn" => Some(Spec::default_for("openvpn", input.openvpn_path.clone())),
        "vpn-panel" => Some({
            let path = crate::install::vpn::panel::PATH;
            Spec {
                compose_project: Some(crate::install::vpn::panel::COMPOSE_PROJECT),
                config_directory: Some(path.to_string()),
                data_paths: vec![format!("{path}/data.pre-restore-*")],
                backup_dirs: vec![backups.for_id("vpn-panel")],
                pre_steps: vec!["ip link delete wgpanel 2>/dev/null || true".to_string()],
                post_steps: vec![
                    format!("rm -f {}", crate::install::vpn::panel::LOCKDOWN_SCRIPT_PATH),
                    format!(": > {} 2>/dev/null || true", crate::install::caddy::ADMIN_GUARD_PATH),
                    "systemctl reload caddy 2>/dev/null || true".to_string(),
                ],
            }
        }),
        _ => None,
    }
}

pub(crate) fn hostname_for(id: &str, input: &Input) -> Option<String> {
    use crate::install::mail::{dockermailserver as dms, mailcow, mailu};
    match id {
        "mailcow" => Some(mailcow::hostname(input)),
        "mailu" => Some(mailu::hostname(input)),
        "docker-mailserver" => Some(dms::hostname(input)),
        "vaultwarden" => Some(crate::install::vaultwarden::hostname(input)),
        "psono" => Some(crate::install::psono::hostname(input)),
        "passbolt" => Some(crate::install::passbolt::hostname(input)),
        "nextcloud" => Some(crate::install::nextcloud::hostname(input)),
        "seafile" => Some(crate::install::seafile::hostname(input)),
        "immich" => Some(crate::install::immich::hostname(input)),
        "photoprism" => Some(crate::install::photoprism::hostname(input)),
        "gitlab" => Some(crate::install::gitlab::hostname(input)),
        "forgejo" => Some(crate::install::forgejo::hostname(input)),
        "jellyfin" => Some(crate::install::jellyfin::hostname(input)),
        "home-assistant" => Some(crate::install::home_assistant::hostname(input)),
        "zigbee2mqtt" => Some(crate::install::zigbee2mqtt::hostname(input)),
        "crafty-controller" => Some(crate::install::crafty::hostname(input)),
        "open-webui" => Some(crate::install::open_webui::hostname(input)),
        "litellm" => Some(crate::install::litellm::hostname(input)),
        "n8n" => Some(crate::install::n8n::hostname(input)),
        "anythingllm" => Some(crate::install::anythingllm::hostname(input)),
        // Publishes nothing — see its module note.
        "qdrant" => None,
        // Nor this: the callers are the containers beside it.
        "searxng" => None,
        "openclaw" => Some(crate::install::openclaw::hostname(input)),
        "ollama" => None,
        "adguard-home" => Some(crate::install::adguard::hostname(input)),
        "pihole" => Some(crate::install::pihole::hostname(input)),
        "homepage" => Some(crate::install::homepage::hostname(input)),
        "authelia" => Some(crate::install::authelia::hostname(input)),
        "headscale" => Some(crate::install::headscale::hostname(input)),
        "cloudflared" => None,
        "vpn-panel" => Some(crate::install::vpn::panel::hostname(input)),
        "wireguard-vpn" | "amnezia-wg" | "shadowsocks" | "xray-reality" | "openvpn" => None,
        _ => None,
    }
}

fn site_headers(id: &str, input: &Input) -> Vec<String> {
    let Some(hostname) = hostname_for(id, input) else { return Vec::new() };
    let mut names = vec![hostname.clone()];
    names.extend(input.mirrored_hostnames(&hostname));
    vec![names.join(", ")]
}

fn quoted_path(path: &str) -> String {
    path.split('*')
        .map(|part| if part.is_empty() { String::new() } else { format!("'{part}'") })
        .collect::<Vec<_>>()
        .join("*")
}

/// A port of `UninstallSections.purgeBlock(_:indent:)`.
fn purge_block(spec: &Spec, indent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut data_targets: Vec<String> = spec.config_directory.clone().into_iter().collect();
    data_targets.extend(spec.data_paths.iter().cloned());
    if !data_targets.is_empty() {
        lines.push(format!("{indent}if [ \"$PURGE_DATA\" -eq 1 ]; then"));
        for target in &data_targets {
            lines.push(format!("{indent}  rm -rf {}", quoted_path(target)));
        }
        lines.push(format!("{indent}fi"));
    }
    if !spec.backup_dirs.is_empty() {
        lines.push(format!("{indent}if [ \"$PURGE_BACKUPS\" -eq 1 ]; then"));
        for target in &spec.backup_dirs {
            lines.push(format!("{indent}  rm -rf {}", quoted_path(target)));
        }
        lines.push(format!("{indent}fi"));
    }
    lines
}

fn sudoers_owners(
    ids: &[&'static str],
    input: &Input,
    backups: &BackupPaths,
    user: &str,
) -> std::collections::HashMap<String, std::collections::HashSet<&'static str>> {
    let mut owners: std::collections::HashMap<String, std::collections::HashSet<&'static str>> =
        std::collections::HashMap::new();
    for id in ids {
        for line in service_sudoers_lines(id, input, backups, user) {
            owners.entry(line).or_default().insert(id);
        }
    }
    owners
}

fn removable_sudoers_lines(
    unit: &[&'static str],
    input: &Input,
    backups: &BackupPaths,
    user: &str,
    owners: &std::collections::HashMap<String, std::collections::HashSet<&'static str>>,
) -> Vec<String> {
    let unit_ids: std::collections::HashSet<&'static str> = unit.iter().copied().collect();
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for id in unit {
        for line in service_sudoers_lines(id, input, backups, user) {
            if !seen.insert(line.clone()) {
                continue;
            }
            let Some(owning) = owners.get(&line) else { continue };
            if owning.iter().any(|owner| !unit_ids.contains(owner)) {
                continue;
            }
            result.push(line);
        }
    }
    result
}

fn sudoers_removal_call(lines: &[String]) -> Vec<String> {
    if lines.is_empty() {
        return Vec::new();
    }
    let quoted: Vec<String> = lines.iter().map(|line| format!("'{line}'")).collect();
    vec!["  remove_sudoers_lines \\".to_string(), format!("    {}", quoted.join(" \\\n    "))]
}

/// A port of `UninstallSections.uninstallFunction(name:spec:siteHeaders:sudoersLines:)`.
fn uninstall_function(name: &str, spec: &Spec, headers: &[String], sudoers_lines: &[String]) -> String {
    let mut lines = vec![format!("uninstall_{name}() {{")];
    for step in &spec.pre_steps {
        lines.push(format!("  {step}"));
    }
    if let Some(project) = spec.compose_project {
        lines.push(format!("  compose_down '{project}'"));
    }
    for header in headers {
        lines.push(format!("  remove_caddy_site '{header}'"));
    }
    for step in &spec.post_steps {
        lines.push(format!("  {step}"));
    }
    lines.extend(purge_block(spec, "  "));
    lines.extend(sudoers_removal_call(sudoers_lines));
    lines.push("}".to_string());
    lines.join("\n")
}

fn function_name(id: &str) -> String {
    id.replace('-', "_")
}

const AGENT_UNIT: &str = "gryonixnexusd.service";
const AGENT_BINARY_PATH: &str = "/usr/local/bin/gryonixnexusd";
const AGENT_SOCKET_PATH: &str = "/run/gryonixnexusd.sock";
const AGENT_STATE_DIRECTORY: &str = "/var/lib/gryonixnexus/agent";
const AGENT_MDNS_UNIT: &str = "gryonixnexus-mdns.service";
const AGENT_MDNS_SCRIPT: &str = "/usr/local/lib/gryonixnexus/mdns-aliases.sh";
const AGENT_HOME_NETWORK_SNIPPET: &str = "/etc/caddy/gryonixnexus-home-network.caddy";
const PREDECESSOR_UNIT: &str = "gryonixnexus.service";
const PREDECESSOR_BINARY_PATH: &str = "/usr/local/bin/gryonixd";
const PREDECESSOR_SOCKET_PATH: &str = "/run/gryonixd.sock";

/// A port of `UninstallSections.agentRemoval(indent:)`.
fn agent_removal(indent: &str) -> Vec<String> {
    fn unit_removal(indent: &str, unit: &str, binary: &str, socket: &str) -> Vec<String> {
        vec![
            format!("{indent}if [ -f /etc/systemd/system/{unit} ]; then"),
            format!("{indent}  systemctl disable --now '{unit}' >/dev/null 2>&1 || true"),
            format!("{indent}  rm -f '/etc/systemd/system/{unit}'"),
            format!("{indent}  systemctl daemon-reload || true"),
            format!("{indent}fi"),
            format!("{indent}rm -f '{binary}' '{socket}'"),
        ]
    }
    let mut lines = vec![
        format!("{indent}# Control-plane agent: installed by its own bootstrap, outside this"),
        format!("{indent}# setup, and therefore invisible to everything else here. Stopped"),
        format!("{indent}# before the state directory below is removed — the unit's"),
        format!("{indent}# StateDirectory= re-creates it on every start."),
    ];
    lines.extend(unit_removal(indent, AGENT_UNIT, AGENT_BINARY_PATH, AGENT_SOCKET_PATH));
    lines.push(format!("{indent}rm -rf '{AGENT_STATE_DIRECTORY}'"));
    lines.push(format!("{indent}# The agent's mDNS names and home-network doors."));
    lines.push(format!("{indent}systemctl disable --now '{AGENT_MDNS_UNIT}' >/dev/null 2>&1 || true"));
    lines.push(format!(
        "{indent}rm -f '/etc/systemd/system/{AGENT_MDNS_UNIT}' '{AGENT_MDNS_SCRIPT}' '{AGENT_HOME_NETWORK_SNIPPET}'"
    ));
    lines.push(format!("{indent}# The agent's system updater and its start and shutdown units."));
    lines.push(format!("{indent}systemctl disable --now 'gryonixnexus-update-at-start.service' >/dev/null 2>&1 || true"));
    lines.push(format!("{indent}rm -f '/etc/gryonixnexus/update-at-start.conf'"));
    lines.push(format!("{indent}systemctl disable --now 'gryonixnexus-update-at-stop.service' >/dev/null 2>&1 || true"));
    lines.push(format!("{indent}systemctl disable --now 'gryonixnexus-system-scheduled.timer' >/dev/null 2>&1 || true"));
    lines.push(format!("{indent}rm -f '/opt/gryonixnexus-system-ctl.sh' '/etc/systemd/system/gryonixnexus-update-at-start.service' '/etc/systemd/system/gryonixnexus-update-at-stop.service' '/var/log/gryonixnexus-system-update.log'"));
    lines.push(format!("{indent}rm -f '/etc/systemd/system/gryonixnexus-system-scheduled.timer' '/etc/systemd/system/gryonixnexus-system-scheduled.service' '/etc/gryonixnexus/system-schedule.conf'"));
    lines.push(format!("{indent}# The daemon before the rename (gryonixd). install-agent.sh removes"));
    lines.push(format!("{indent}# it, but a host that never re-ran the bootstrap still has it, and"));
    lines.push(format!("{indent}# its unit is Restart=always too."));
    lines.extend(unit_removal(indent, PREDECESSOR_UNIT, PREDECESSOR_BINARY_PATH, PREDECESSOR_SOCKET_PATH));
    lines
}

const SHARED_BACKUP_COPY_GLOBS: &[&str] = &[
    "/etc/nftables.conf.bak.*",
    "/etc/wireguard/wg0.conf.bak.*",
    "/etc/systemd/system/gryonixnexus-*.service.bak.*",
];

fn home_backup_copy_globs() -> Vec<&'static str> {
    let mut globs = SHARED_BACKUP_COPY_GLOBS.to_vec();
    globs.extend([
        "/opt/gryonixnexus-*.bak.*",
        "/opt/vaultwarden-update.sh.bak.*",
        "/etc/caddy/Caddyfile.bak.*",
        "/etc/systemd/system/gryonixnexus-*.timer.bak.*",
        "/etc/sysctl.d/99-gryonixnexus-rpfilter.conf.bak.*",
    ]);
    globs
}

fn vps_backup_copy_globs() -> Vec<&'static str> {
    let mut globs = SHARED_BACKUP_COPY_GLOBS.to_vec();
    globs.extend(["/opt/gryonixnexus-*.bak.*", "/etc/sysctl.d/99-gryonixnexus-forwarding.conf.bak.*"]);
    globs
}

/// A port of `UninstallSections.backupCopyRemoval(indent:globs:)`.
fn backup_copy_removal(indent: &str, globs: &[&str]) -> String {
    format!(
        "{indent}# Backup copies the setup makes before overwriting a managed file.\n{indent}rm -f {} || true",
        globs.join(" ")
    )
}

/// A port of `UninstallSections.appKeyRemoval(_:)`
fn app_key_removal(ssh_user: Option<&str>, access: Option<&DashboardAccess>) -> String {
    let (Some(user), Some(access)) = (ssh_user, access) else { return "  :".to_string() };
    if !access.create_user {
        return "  :".to_string();
    }
    [
        format!("  APP_KEY='{}'", access.app_public_key),
        format!("  USER_HOME=\"$(getent passwd '{user}' | cut -d: -f6 || true)\""),
        "  if [ -n \"$USER_HOME\" ] && [ -f \"$USER_HOME/.ssh/authorized_keys\" ]; then".to_string(),
        "    grep -vxF \"$APP_KEY\" \"$USER_HOME/.ssh/authorized_keys\" > \"$USER_HOME/.ssh/authorized_keys.gryonixnexus\" || true".to_string(),
        "    mv \"$USER_HOME/.ssh/authorized_keys.gryonixnexus\" \"$USER_HOME/.ssh/authorized_keys\"".to_string(),
        "    chmod 600 \"$USER_HOME/.ssh/authorized_keys\"".to_string(),
        "    # Root wrote the replacement, and sshd reads authorized_keys as".to_string(),
        "    # the account: leaving it root-owned makes the file unreadable to".to_string(),
        "    # sshd and kills every OTHER key the account has. Same reason the".to_string(),
        "    # revoke step chowns; see revokeInstallKey.".to_string(),
        format!("    chown '{user}' \"$USER_HOME/.ssh/authorized_keys\""),
        "  fi".to_string(),
    ]
    .join("\n")
}

const CONTAINER_CONTROL_SCRIPT_PATH: &str = "/opt/gryonixnexus-container-ctl.sh";
const RESTORE_SCRIPT_PATH: &str = "/opt/gryonixnexus-restore.sh";
pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-uninstall.sh";
const DONE_MARKER: &str = "GRYONIXNEXUS_UNINSTALL_DONE";
const VPN_TARGET: &str = "vpn";
const ALL_TARGET: &str = "--all";
const PURGE_DATA_FLAG: &str = "--purge-data";
const PURGE_BACKUPS_FLAG: &str = "--purge-backups";

const WIREGUARD_INTERFACE: &str = "wg0";

/// A port of `DashboardAccessSections.passwordAuthCloseUninstallLines(indent:)`
fn password_auth_close_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# SSH password login comes back BEFORE the app key is stripped below,"),
        format!("{indent}# so this machine is never left with neither way in."),
        format!("{indent}rm -f {}", crate::install::ssh_password::DROP_IN_PATH),
        format!("{indent}systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true"),
    ]
}

fn relay_route_sync_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Policy routing that sends relayed replies back through the"),
        format!("{indent}# tunnel — armed by install(), re-synced by its own timer."),
        format!("{indent}systemctl disable --now 'gryonixnexus-relay-route-sync.timer' 'gryonixnexus-relay-route-sync.service' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-relay-route-sync.timer /etc/systemd/system/gryonixnexus-relay-route-sync.service"),
        format!("{indent}systemctl daemon-reload || true"),
        format!("{indent}rm -f '/opt/gryonixnexus-relay-route-sync.sh'"),
        format!("{indent}ip rule del fwmark '0x1' table '100' 2>/dev/null || true"),
        format!("{indent}ip route flush table '100' 2>/dev/null || true"),
    ]
}

fn update_control_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Scheduled updates: the timer is armed by set-schedule, not by"),
        format!("{indent}# setup, so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now 'gryonixnexus-autoupdate.timer' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-autoupdate.timer /etc/systemd/system/gryonixnexus-autoupdate.service"),
        format!("{indent}rm -f '/etc/gryonixnexus/autoupdate.conf' '/var/lib/gryonixnexus/autoupdate-status.txt'"),
        format!("{indent}rm -f '/opt/gryonixnexus-update-ctl.sh'"),
    ]
}

/// A port of `UninstallSections.dynamicDNSUninstallLines(indent:)`
fn dynamic_dns_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Dynamic DNS: the timer is armed by the panel long after setup,"),
        format!("{indent}# so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now 'gryonixnexus-ddns.timer' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-ddns.timer /etc/systemd/system/gryonixnexus-ddns.service"),
        format!("{indent}rm -f '/etc/gryonixnexus/ddns.conf' '/var/lib/gryonixnexus/ddns-status.txt'"),
        format!("{indent}rm -f '/opt/gryonixnexus-ddns.sh'"),
    ]
}

/// A port of `BackupControlSections.uninstallLines(indent:)` — see the note on `update_control_uninstall_lines`
fn backup_control_uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Scheduled backups: the timer is armed by set-schedule, not by"),
        format!("{indent}# setup, so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now 'gryonixnexus-autobackup.timer' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/gryonixnexus-autobackup.timer /etc/systemd/system/gryonixnexus-autobackup.service"),
        format!("{indent}# The destination, its key and its last result — the key is a real"),
        format!("{indent}# secret and the config names somebody else's machine."),
        format!("{indent}rm -f '/etc/gryonixnexus/autobackup-dest.conf' '/etc/gryonixnexus/autobackup-dest.key' '/etc/gryonixnexus/autobackup-dest.key.pub' '/etc/gryonixnexus/autobackup-dest.status' '/etc/gryonixnexus/autobackup-dest.known_hosts'"),
        format!("{indent}rm -f '/opt/gryonixnexus-backup-ctl.sh'"),
        format!("{indent}rm -rf '/etc/gryonixnexus'"),
    ]
}

// MARK: - Assembly

fn selected_app_services(input: &HostInput) -> Vec<&'static str> {
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| !is_vpn_member(id) && !is_mesh_member(id) && input.services.iter().any(|s| s == id))
        .collect()
}

const MESH_TARGET: &str = "headscale";
const MESH_NODE: &str = "tailscale-node";

fn is_mesh_member(id: &str) -> bool {
    id == MESH_TARGET || id == MESH_NODE
}

fn selected_mesh_services(input: &HostInput) -> Vec<&'static str> {
    let has_server = input.services.iter().any(|s| s == MESH_TARGET);
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            is_mesh_member(id) && (present || (*id == MESH_NODE && has_server))
        })
        .collect()
}

fn selected_vpn_services(input: &HostInput) -> Vec<&'static str> {
    let has_protocol = VPN_PROTOCOLS.iter().any(|p| input.services.iter().any(|s| s == p));
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            (is_vpn_member(id)) && (present || (*id == VPN_PANEL && has_protocol))
        })
        .collect()
}

/// A port of `UninstallSections.servicesHostWrapper(_:context:includeWireGuard:)`
pub fn services_host_wrapper(
    input: &HostInput,
    backups: &BackupPaths,
    access: Option<&DashboardAccess>,
    include_wire_guard: bool,
) -> String {
    let among = input.install_among_neighbours();
    let settings = &among;
    let app_services = selected_app_services(input);
    let vpn_services = selected_vpn_services(input);
    let mesh_services = selected_mesh_services(input);

    let all_ids: Vec<&'static str> =
        app_services.iter().copied().chain(mesh_services.iter().copied()).chain(vpn_services.iter().copied()).collect();
    let sudoers_owners_by_line = input
        .ssh_user
        .as_deref()
        .map(|user| sudoers_owners(&all_ids, settings, backups, user))
        .unwrap_or_default();

    let mut functions: Vec<String> = Vec::new();
    let mut case_arms: Vec<String> = Vec::new();
    let mut all_calls: Vec<String> = Vec::new();

    for id in &app_services {
        let name = function_name(id);
        let spec = spec_for(id, settings, backups);
        let headers = site_headers(id, settings);
        let sudoers_lines = input
            .ssh_user
            .as_deref()
            .map(|user| removable_sudoers_lines(&[id], settings, backups, user, &sudoers_owners_by_line))
            .unwrap_or_default();
        functions.push(uninstall_function(&name, &spec, &headers, &sudoers_lines));
        case_arms.push(format!("  {id}) uninstall_{name} ;;"));
        all_calls.push(format!("  uninstall_{name}"));
    }

    if !mesh_services.is_empty() {
        let mut mesh_lines = vec!["uninstall_headscale() {".to_string()];
        let mut seen_projects: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for id in &mesh_services {
            let spec = spec_for(id, settings, backups);
            for step in &spec.pre_steps {
                mesh_lines.push(format!("  {step}"));
            }
            if let Some(project) = spec.compose_project {
                if seen_projects.insert(project) {
                    mesh_lines.push(format!("  compose_down '{project}'"));
                }
            }
            for header in site_headers(id, settings) {
                mesh_lines.push(format!("  remove_caddy_site '{header}'"));
            }
            for step in &spec.post_steps {
                mesh_lines.push(format!("  {step}"));
            }
        }
        for id in &mesh_services {
            let spec = spec_for(id, settings, backups);
            mesh_lines.extend(purge_block(&spec, "  "));
        }
        if let Some(user) = input.ssh_user.as_deref() {
            mesh_lines.extend(sudoers_removal_call(&removable_sudoers_lines(
                &mesh_services,
                settings,
                backups,
                user,
                &sudoers_owners_by_line,
            )));
        }
        mesh_lines.push("}".to_string());
        functions.push(mesh_lines.join("\n"));
        if input.services.iter().any(|s| s == MESH_TARGET) {
            case_arms.push(format!("  {MESH_TARGET}) uninstall_headscale ;;"));
        }
        case_arms.push(format!("  {MESH_NODE}) uninstall_headscale ;;"));
        all_calls.push("  uninstall_headscale".to_string());
    }

    if !vpn_services.is_empty() {
        let mut vpn_lines = vec!["uninstall_vpn() {".to_string()];
        let mut seen_projects: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for id in &vpn_services {
            let spec = spec_for(id, settings, backups);
            for step in &spec.pre_steps {
                vpn_lines.push(format!("  {step}"));
            }
            if let Some(project) = spec.compose_project {
                if seen_projects.insert(project) {
                    vpn_lines.push(format!("  compose_down '{project}'"));
                }
            }
            for header in site_headers(id, settings) {
                vpn_lines.push(format!("  remove_caddy_site '{header}'"));
            }
            for step in &spec.post_steps {
                vpn_lines.push(format!("  {step}"));
            }
        }
        for id in &vpn_services {
            let spec = spec_for(id, settings, backups);
            vpn_lines.extend(purge_block(&spec, "  "));
        }
        if let Some(user) = input.ssh_user.as_deref() {
            vpn_lines.extend(sudoers_removal_call(&removable_sudoers_lines(
                &vpn_services,
                settings,
                backups,
                user,
                &sudoers_owners_by_line,
            )));
        }
        vpn_lines.push("}".to_string());
        functions.push(vpn_lines.join("\n"));
        case_arms.push(format!("  {VPN_TARGET}) uninstall_vpn ;;"));
        all_calls.push("  uninstall_vpn".to_string());
    }

    let tunnel_cleanup = if include_wire_guard {
        let mut lines = vec![
            format!("  systemctl disable --now wg-quick@{WIREGUARD_INTERFACE} >/dev/null 2>&1 || true"),
            format!("  rm -f '/etc/wireguard/{WIREGUARD_INTERFACE}.conf'"),
            "  rm -f /etc/ssh/sshd_config.d/60-gryonixnexus-tunnel.conf".to_string(),
            "  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true".to_string(),
        ];
        lines.extend(relay_route_sync_uninstall_lines("  "));
        lines.push("  rm -f /etc/sysctl.d/99-gryonixnexus-rpfilter.conf".to_string());
        lines.join("\n")
    } else {
        String::new()
    };

    let home_globs = home_backup_copy_globs();

    format!(
        "#!/bin/bash\n\
         # Managed by gryonixNexus — remove services or the whole gryonixNexus install.\n\
         # Usage: gryonixnexus-uninstall.sh <service|{VPN_TARGET}|{ALL_TARGET}> [{PURGE_DATA_FLAG}] [{PURGE_BACKUPS_FLAG}]\n\
         # Default keeps data and backups on disk; the flags delete them (independently).\n\
         set -euo pipefail\n\
         \n\
         TARGET=\"${{1:-}}\"\n\
         PURGE_DATA=0\n\
         PURGE_BACKUPS=0\n\
         shift || true\n\
         for arg in \"$@\"; do\n\
         \x20 case \"$arg\" in\n\
         \x20   {PURGE_DATA_FLAG}) PURGE_DATA=1 ;;\n\
         \x20   {PURGE_BACKUPS_FLAG}) PURGE_BACKUPS=1 ;;\n\
         \x20 esac\n\
         done\n\
         \n\
         compose_down() {{\n\
         \x20 if [ \"$PURGE_DATA\" -eq 1 ]; then\n\
         \x20   # --rmi all also reclaims the images, but only the ones THIS\n\
         \x20   # project's services use — the scoped replacement for the\n\
         \x20   # `docker system prune -af` that used to run once at the end and\n\
         \x20   # took every unused image and stopped container on the host with\n\
         \x20   # it, ours or not. Images still referenced elsewhere are skipped\n\
         \x20   # by docker itself.\n\
         \x20   docker compose -p \"$1\" down --remove-orphans --volumes --rmi all >/dev/null 2>&1 || true\n\
         \x20 else\n\
         \x20   docker compose -p \"$1\" down --remove-orphans >/dev/null 2>&1 || true\n\
         \x20 fi\n\
         }}\n\
         \n\
         # Removes one site block from the Caddyfile. The header is the exact\n\
         # first line of the block as writeCaddyfile emits it (top-level `{cb}` on\n\
         # its own line closes it) — wrapper and Caddyfile are regenerated\n\
         # together on every setup run, so the format cannot drift between them.\n\
         remove_caddy_site() {{\n\
         \x20 local f=/etc/caddy/Caddyfile\n\
         \x20 [ -f \"$f\" ] || return 0\n\
         \x20 awk -v start=\"$1 {{\" '\n\
         \x20   $0 == start {{skip=1; next}}\n\
         \x20   skip && $0 == \"{cb}\" {{skip=0; next}}\n\
         \x20   !skip {{print}}\n\
         \x20 ' \"$f\" > \"$f.gryonixnexus\" && mv \"$f.gryonixnexus\" \"$f\"\n\
         \x20 systemctl reload caddy 2>/dev/null || true\n\
         }}\n\
         \n\
         # Drops exactly the sudoers lines named — baked in by the generator\n\
         # from the SAME sudoersLines a service was whitelisted with, never\n\
         # rediscovered here. Staged and validated with visudo, the same way\n\
         # the whitelist is written: a set of lines that fails to parse (should\n\
         # never happen — they are asked in the format already on disk) leaves\n\
         # the whitelist untouched rather than risk one sudo cannot read.\n\
         remove_sudoers_lines() {{\n\
         \x20 local f=/etc/sudoers.d/gryonixnexus-control\n\
         \x20 [ -f \"$f\" ] || return 0\n\
         \x20 local tmp=\"$f.gryonixnexus\"\n\
         \x20 printf '%s\\n' \"$@\" | grep -vFxf - \"$f\" > \"$tmp\" || true\n\
         \x20 if [ -s \"$tmp\" ] && visudo -cf \"$tmp\" >/dev/null 2>&1; then\n\
         \x20   mv \"$tmp\" \"$f\"\n\
         \x20 else\n\
         \x20   rm -f \"$tmp\"\n\
         \x20 fi\n\
         }}\n\
         \n\
         {functions}\n\
         \n\
         uninstall_all() {{\n\
         {all_calls}\n\
         {update_lines}\n\
         {backup_lines}\n\
         {ddns_lines}\n\
         {agent_lines}\n\
         \x20 # Host metrics collector + its history\n\
         \x20 systemctl disable --now gryonixnexus-metrics >/dev/null 2>&1 || true\n\
         \x20 rm -f /etc/systemd/system/gryonixnexus-metrics.service /opt/gryonixnexus-metrics-collector.sh\n\
         \x20 systemctl daemon-reload || true\n\
         \x20 rm -rf /var/lib/gryonixnexus\n\
         \x20 # Caddy: only the sites this app wrote are removed\n\
         \x20 rest=\"$(mktemp)\"\n\
         \x20 {{ [ -f /etc/caddy/Caddyfile ] && awk '\n\
         \x20   BEGIN{{d=0;b=\"\";own=0}}\n\
         \x20   d==0&&b==\"\"&&index($0,\"{{\")==0{{print;next}}\n\
         \x20   {{b=b $0 \"\\n\"; if(index($0,\"# gryonixnexus:\"))own=1; t=$0; o=gsub(/[{{]/,\"\",t); t=$0; c=gsub(/[}}]/,\"\",t); d+=o-c;\n\
         \x20    if(d<=0){{ if(!own) printf \"%s\",b; b=\"\"; own=0; d=0}}}}\n\
         \x20   END{{printf \"%s\",b}}' /etc/caddy/Caddyfile > \"$rest\"; }} || : > \"$rest\"\n\
         \x20 if grep -Eq '^[^#[:space:]{{}}].*[{{][[:space:]]*$' \"$rest\"; then\n\
         \x20   cat \"$rest\" > /etc/caddy/Caddyfile\n\
         \x20   {{ caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 && systemctl reload caddy >/dev/null 2>&1; }} || true\n\
         \x20 else\n\
         \x20   systemctl disable --now caddy >/dev/null 2>&1 || true\n\
         \x20   rm -f /etc/caddy/Caddyfile\n\
         \x20 fi\n\
         \x20 rm -f \"$rest\" '{admin_guard}'\n\
         {tunnel_cleanup}\n\
         \x20 # No host-wide `docker system prune` here: image reclamation is done\n\
         \x20 # per compose project by compose_down --rmi all, which cannot\n\
         \x20 # reach Docker state this deployment did not create.\n\
         \x20 # Dashboard wrappers, then our own whitelist last — after this line\n\
         \x20 # the app's sudo access is gone, which is the point.\n\
         \x20 rm -f '{container_ctl}' '{restore}'\n\
         \x20 # The agent bootstrap wrapper and whatever sources it unpacked. A\n\
         \x20 # root-owned script the erase leaves behind is the DDNS lesson: the\n\
         \x20 # erased machine still carrying something only root can remove.\n\
         \x20 rm -f '{agent_bootstrap}'\n\
         \x20 rm -rf '{agent_unpack}'\n\
         {backup_copy}\n\
         {password_auth}\n\
         {app_key}\n\
         \x20 rm -f /etc/sudoers.d/gryonixnexus-control\n\
         \x20 rm -f '{SCRIPT_PATH}'\n\
         }}\n\
         \n\
         case \"$TARGET\" in\n\
         {case_arms}\n\
         \x20 {ALL_TARGET}) uninstall_all ;;\n\
         \x20 *) echo \"unsupported target: ${{TARGET}}\" >&2; exit 2 ;;\n\
         esac\n\
         echo '{DONE_MARKER}'",
        cb = "}",
        functions = functions.join("\n\n"),
        all_calls = all_calls.join("\n"),
        update_lines = update_control_uninstall_lines("  ").join("\n"),
        backup_lines = backup_control_uninstall_lines("  ").join("\n"),
        ddns_lines = dynamic_dns_uninstall_lines("  ").join("\n"),
        agent_lines = agent_removal("  ").join("\n"),
        admin_guard = crate::install::caddy::ADMIN_GUARD_PATH,
        tunnel_cleanup = tunnel_cleanup,
        container_ctl = CONTAINER_CONTROL_SCRIPT_PATH,
        agent_bootstrap = crate::install::host::access::AGENT_BOOTSTRAP_SCRIPT_PATH,
        agent_unpack = crate::install::host::agent_bootstrap::UNPACK_ROOT,
        restore = RESTORE_SCRIPT_PATH,
        backup_copy = backup_copy_removal("  ", &home_globs),
        password_auth = password_auth_close_uninstall_lines("  ").join("\n"),
        app_key = app_key_removal(input.ssh_user.as_deref(), access),
        case_arms = case_arms.join("\n"),
    )
}

/// A port of `UninstallSections.vpsWrapper(_:language:)` — scenario B's relay half
pub fn vps_wrapper(input: &HostInput, access: Option<&DashboardAccess>) -> String {
    let globs = vps_backup_copy_globs();
    format!(
        "#!/bin/bash\n\
         # Managed by gryonixNexus — remove the gryonixNexus install from this relay.\n\
         # Usage: gryonixnexus-uninstall.sh {ALL_TARGET}\n\
         set -euo pipefail\n\
         \n\
         TARGET=\"${{1:-}}\"\n\
         if [ \"$TARGET\" != \"{ALL_TARGET}\" ]; then\n\
         \x20 echo \"unsupported target: ${{TARGET}}\" >&2; exit 2\n\
         fi\n\
         \n\
         systemctl disable --now wg-quick@{WIREGUARD_INTERFACE} >/dev/null 2>&1 || true\n\
         rm -f '/etc/wireguard/{WIREGUARD_INTERFACE}.conf'\n\
         rm -f /etc/sysctl.d/99-gryonixnexus-forwarding.conf\n\
         {agent_lines}\n\
         systemctl disable --now gryonixnexus-metrics >/dev/null 2>&1 || true\n\
         rm -f /etc/systemd/system/gryonixnexus-metrics.service /opt/gryonixnexus-metrics-collector.sh\n\
         systemctl daemon-reload || true\n\
         rm -rf /var/lib/gryonixnexus\n\
         {update_lines}\n\
         {backup_lines}\n\
         {ddns_lines}\n\
         {backup_copy}\n\
         {password_auth}\n\
         {app_key}\n\
         rm -f /etc/sudoers.d/gryonixnexus-control\n\
         rm -f '{SCRIPT_PATH}'\n\
         echo '{DONE_MARKER}'",
        agent_lines = agent_removal("").join("\n"),
        update_lines = update_control_uninstall_lines("").join("\n"),
        backup_lines = backup_control_uninstall_lines("").join("\n"),
        ddns_lines = dynamic_dns_uninstall_lines("").join("\n"),
        backup_copy = backup_copy_removal("", &globs),
        password_auth = password_auth_close_uninstall_lines("").join("\n"),
        app_key = app_key_removal(input.ssh_user.as_deref(), access),
    )
}

/// An older wrapper made to reclaim tagged images on purge
pub fn refresh_image_reclaim() -> std::io::Result<bool> {
    let path = std::path::Path::new(SCRIPT_PATH);
    let Ok(old) = std::fs::read_to_string(path) else { return Ok(false) };
    if !old.contains("--rmi local") {
        return Ok(false);
    }
    std::fs::write(path, old.replace("--rmi local", "--rmi all"))?;
    Ok(true)
}

pub fn render(input: &HostInput, backups: &BackupPaths, access: Option<&DashboardAccess>) -> String {
    match input.role {
        HostRole::SingleHost => services_host_wrapper(input, backups, access, false),
        HostRole::HomeBackend => services_host_wrapper(input, backups, access, true),
        HostRole::VpsRelay => vps_wrapper(input, access),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;
    use crate::install::context::Input;

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/install/host/uninstall/{name}.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn base_input() -> Input {
        Input {
            domain: "example.com".to_string(),
            wireguard_vpn_port: 51821,
            xray_reality_port: 8443,
            ..Input::default()
        }
    }

    fn host(services: &[&str]) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    fn access() -> DashboardAccess {
        DashboardAccess {
            create_user: true,
            app_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake gryonixnexus-app".to_string(),
        }
    }

    fn multidomain_input() -> Input {
        Input {
            domain: "example.com".to_string(),
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            wireguard_vpn_port: 51821,
            xray_reality_port: 8443,
            ..Input::default()
        }
    }

    #[test]
    fn fixture_parity() {
        let cases: &[(&str, &[&str])] = &[
            ("A-bare-access-en", &[]),
            ("A-mailcow-access-en", &["mailcow"]),
            ("A-nomail-access-en", &["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"]),
            (
                "A-mailcow-wg-access-en",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn"],
            ),
            (
                "A-mailcow-awg-access-en",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "amnezia-wg"],
            ),
            ("A-nomail-ss-access-en", &["vaultwarden", "shadowsocks"]),
            ("A-mailcow-xray-access-en", &["mailcow", "vaultwarden", "xray-reality"]),
            ("A-nomail-ovpn-access-en", &["vaultwarden", "openvpn"]),
            ("A-mailu-access-en", &["mailu"]),
            ("A-dms-access-en", &["docker-mailserver"]),
            (
                "A-dms-full-access-en",
                &["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn"],
            ),
            (
                "A-mailu-full-access-en",
                &["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn"],
            ),
            ("A-jellyfin-access-en", &["jellyfin"]),
            (
                "A-jellyfin-full-access-en",
                &["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn"],
            ),
            ("A-adguard-access-en", &["adguard-home"]),
            (
                "A-adguard-full-access-en",
                &["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn"],
            ),
            ("A-photoprism-access-en", &["photoprism"]),
            ("A-photoprism-immich-access-en", &["photoprism", "immich", "vaultwarden"]),
            ("A-seafile-access-en", &["seafile"]),
            ("A-seafile-nextcloud-access-en", &["seafile", "nextcloud", "vaultwarden"]),
            ("A-psono-access-en", &["psono"]),
            ("A-psono-vaultwarden-access-en", &["psono", "vaultwarden"]),
            ("A-passbolt-access-en", &["passbolt"]),
            ("A-passwords-shelf-access-en", &["passbolt", "psono", "vaultwarden"]),
        ];

        for (fixture_name, services) in cases {
            let input = host(services);
            let backups = BackupPaths::default();
            let acc = access();
            let actual = services_host_wrapper(&input, &backups, Some(&acc), false);
            let expected = fixture(fixture_name);
            assert_eq!(actual, expected.trim_end_matches('\n'), "{fixture_name}");
        }
    }

    #[test]
    fn every_managed_path_the_crate_names_is_removed_by_some_wrapper() {
        let everything: Vec<String> = CATALOG_ORDER.iter().map(|id| id.to_string()).collect();
        let acc = access();
        let backups = BackupPaths::default();
        let mut wrappers = String::new();
        for role in [HostRole::SingleHost, HostRole::HomeBackend, HostRole::VpsRelay] {
            let input = HostInput {
                services: everything.clone(),
                install: base_input(),
                language: Language::En,
                ssh_user: Some("admin".to_string()),
                role,
            };
            wrappers.push_str(&render(&input, &backups, Some(&acc)));
            wrappers.push('\n');
            wrappers.push_str(&vps_wrapper(&input, Some(&acc)));
            wrappers.push('\n');
        }

        let mut unremoved = Vec::new();
        for path in managed_paths_named_in_code() {
            if !wrappers.contains(&path) {
                unremoved.push(path);
            }
        }
        assert!(
            unremoved.is_empty(),
            "these root-owned paths are written by this crate and removed by neither wrapper — \
             an erased host would keep them:\n  {}",
            unremoved.join("\n  ")
        );
    }

    /// Managed paths named anywhere in the crate's CODE, comments excluded.
    fn managed_paths_named_in_code() -> std::collections::BTreeSet<String> {
        fn sources(dir: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("a source directory reads").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    sources(&path, into);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    into.push(path);
                }
            }
        }

        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&root, &mut files);

        let mut found = std::collections::BTreeSet::new();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a source file reads");
            for line in text.lines() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                for prefix in [
                    "/opt/gryonixnexus-",
                    "/etc/systemd/system/gryonixnexus-",
                    "/etc/ssh/sshd_config.d/",
                ] {
                    let mut rest = line;
                    while let Some(at) = rest.find(prefix) {
                        let tail = &rest[at..];
                        let end = tail
                            .find(|c: char| !(c.is_ascii_alphanumeric() || "/-_.".contains(c)))
                            .unwrap_or(tail.len());
                        let path = &tail[..end];
                        if path.ends_with(".sh")
                            || path.ends_with(".service")
                            || path.ends_with(".timer")
                            || path.ends_with(".conf")
                        {
                            found.insert(path.to_string());
                        }
                        rest = &tail[end.max(1)..];
                    }
                }
            }
        }
        found
    }

    #[test]
    fn fixture_parity_multidomain() {
        let input = HostInput {
            services: ["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "amnezia-wg"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            install: multidomain_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        };
        let backups = BackupPaths::default();
        let acc = access();
        let actual = services_host_wrapper(&input, &backups, Some(&acc), false);
        let expected = fixture("A-multidomain");
        assert_eq!(actual, expected.trim_end_matches('\n'));
    }

    #[test]
    fn render_dispatches_single_host_to_the_services_wrapper() {
        let input = host(&["adguard-home"]);
        let backups = BackupPaths::default();
        let acc = access();
        assert_eq!(
            render(&input, &backups, Some(&acc)),
            services_host_wrapper(&input, &backups, Some(&acc), false)
        );
    }

    #[test]
    fn every_installable_service_can_also_be_removed() {
        let ids = crate::install::execute::implemented_service_ids();
        let mut on_host: Vec<&str> = Vec::new();
        for id in &ids {
            if *id == "vpn" {
                on_host.extend(VPN_PROTOCOLS.iter().copied());
                on_host.push(VPN_PANEL);
            } else {
                on_host.push(id);
            }
        }
        let input = host(&on_host);
        let script = services_host_wrapper(&input, &BackupPaths::default(), None, false);
        for id in ids {
            assert!(
                script.contains(&format!("{id}) uninstall_")),
                "the uninstall wrapper has no arm for `{id}` — installing it would leave a service \
                 the agent cannot remove"
            );
        }
    }

    #[test]
    fn no_dashboard_access_collapses_the_app_key_block_to_a_no_op() {
        let input = HostInput { ssh_user: None, ..host(&["adguard-home"]) };
        let backups = BackupPaths::default();
        let script = services_host_wrapper(&input, &backups, None, false);
        assert!(script.contains("\n  :\n"), "expected a bare no-op line inside uninstall_all:\n{script}");
        assert!(!script.contains("APP_KEY="));
        assert!(script.contains("adguard-home) uninstall_adguard_home ;;"));
    }

    #[test]
    fn existing_user_mode_also_collapses_to_a_no_op() {
        let input = host(&["adguard-home"]);
        let backups = BackupPaths::default();
        let acc = DashboardAccess { create_user: false, app_public_key: "irrelevant".to_string() };
        let script = services_host_wrapper(&input, &backups, Some(&acc), false);
        assert!(script.contains("\n  :\n"));
        assert!(!script.contains("APP_KEY="));
    }

    #[test]
    fn quoted_path_keeps_the_glob_star_unquoted() {
        assert_eq!(quoted_path("/opt/adguardhome/conf.pre-restore-*"), "'/opt/adguardhome/conf.pre-restore-'*");
        assert_eq!(quoted_path("/opt/adguardhome"), "'/opt/adguardhome'");
    }

    #[test]
    fn every_case_arm_uses_the_hyphenated_catalog_id_not_the_function_name() {
        let input = host(&["adguard-home", "docker-mailserver"]);
        let backups = BackupPaths::default();
        let acc = access();
        let script = services_host_wrapper(&input, &backups, Some(&acc), false);
        assert!(script.contains("  adguard-home) uninstall_adguard_home ;;"));
        assert!(script.contains("  docker-mailserver) uninstall_docker_mailserver ;;"));
        assert!(!script.contains("  adguard_home)"));
    }

    #[test]
    fn vps_wrapper_has_no_home_only_provisioning() {
        let input = HostInput {
            services: Vec::new(),
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::VpsRelay,
        };
        let acc = access();
        let script = vps_wrapper(&input, Some(&acc));
        assert!(script.contains("Usage: gryonixnexus-uninstall.sh --all"));
        assert!(script.contains("if [ \"$TARGET\" != \"--all\" ]; then"));
        assert!(script.contains("wg-quick@wg0"));
        assert!(script.contains("/etc/sysctl.d/99-gryonixnexus-forwarding.conf"));
        assert!(script.contains(AGENT_UNIT));
        assert!(script.ends_with("echo 'GRYONIXNEXUS_UNINSTALL_DONE'"));
        assert!(!script.contains("/etc/caddy/Caddyfile"));
        assert!(!script.contains(CONTAINER_CONTROL_SCRIPT_PATH));
        assert!(!script.contains("compose_down"));
    }

    #[test]
    fn removing_the_control_server_takes_its_node_with_it() {
        let input = HostInput {
            services: vec!["headscale".to_string(), "tailscale-node".to_string()],
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        };
        let script = services_host_wrapper(&input, &BackupPaths::default(), None, false);

        assert!(script.contains("uninstall_headscale() {"), "{script}");
        assert!(script.contains("compose_down 'headscale'"), "{script}");
        assert!(script.contains("compose_down 'tailscale'"), "{script}");
        assert!(script.contains("  headscale) uninstall_headscale ;;"), "{script}");
        assert!(script.contains("  tailscale-node) uninstall_headscale ;;"), "{script}");
    }

    #[test]
    fn render_dispatches_vps_relay_to_the_vps_wrapper() {
        let input = HostInput {
            services: Vec::new(),
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::VpsRelay,
        };
        let acc = access();
        assert_eq!(render(&input, &BackupPaths::default(), Some(&acc)), vps_wrapper(&input, Some(&acc)));
    }
}
