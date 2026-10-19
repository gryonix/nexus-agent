//! The HOST half of install — everything the setup script provisions that is not one service's compose project

use crate::language::Language;
use crate::install::context::Input;

/// What every file in this module renders from
#[derive(Debug, Clone, PartialEq)]
pub struct HostInput {
    pub services: Vec<String>,
    pub install: Input,
    /// The language the wrapper's own human-readable messages are written in.
    pub language: Language,
    /// The control user the sudoers whitelist is written for
    pub ssh_user: Option<String>,
    pub role: HostRole,
}

impl HostInput {
    pub fn install_among_neighbours(&self) -> Input {
        Input { installed_services: self.services.clone(), ..self.install.clone() }
    }
}

/// Which half of the deployment this host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRole {
    /// Scenario A, and the services host of a local-only deployment.
    SingleHost,
    VpsRelay,
    /// Scenario B's private half — carries the services.
    HomeBackend,
}

/// `ServiceRegistry.all`'s order, as the raw `ServiceID` values
pub const CATALOG_ORDER: &[&str] = &[
    "mailcow",
    "mailu",
    "docker-mailserver",
    "vaultwarden",
    "psono",
    "passbolt",
    "nextcloud",
    "seafile",
    "immich",
    "photoprism",
    "forgejo",
    "gitlab",
    "jellyfin",
    "minecraft-java",
    "minecraft-bedrock",
    "crafty-controller",
    "adguard-home",
    // Mirrors `ServiceRegistry`: AdGuard leads the DNS shelf, Pi-hole follows.
    "pihole",
    "headscale",
    "tailscale-node",
    "cloudflared",
    "homepage",
    "authelia",
    "wireguard-vpn",
    "amnezia-wg",
    "shadowsocks",
    "xray-reality",
    "openvpn",
    "vpn-panel",
    "open-webui",
    "ollama",
    "anythingllm",
    "litellm",
    "qdrant",
    "searxng",
    "openclaw",
    "n8n",
    "home-assistant",
    "mosquitto",
    "zigbee2mqtt",
];

/// The VPN's catalog ids — the panel plus the five protocols
pub const VPN_IDS: &[&str] = &[
    "wireguard-vpn",
    "amnezia-wg",
    "shadowsocks",
    "xray-reality",
    "openvpn",
    "vpn-panel",
];

/// Does this host carry any VPN piece?
pub fn has_vpn(services: &[String]) -> bool {
    services.iter().any(|id| VPN_IDS.contains(&id.as_str()))
}

pub mod agent_bootstrap;
pub mod lock;

pub mod access;

/// `/opt/gryonixnexus-backup-ctl.sh` — `BackupControlSections`.
pub mod backup_ctl;

/// The inputs behind the backup wrapper
pub mod backup_ctl_store;

/// `/opt/gryonixnexus-update-ctl.sh` — `UpdateControlSections`.
pub mod update_ctl;

/// `/opt/gryonixnexus-uninstall.sh` — `UninstallSections`.
pub mod uninstall;

/// `/opt/gryonixnexus-restore.sh` — `DashboardAccessSections.restoreWrapper`.
pub mod restore;

/// `/opt/gryonixnexus-admin-lockdown.sh` — the VPN-only admin guard control.
pub mod lockdown;

/// `/opt/gryonixnexus-metrics-collector.sh` and its unit — the CSV bucket daemon `ServerMetricsStore` reads
pub mod metrics;

pub mod report;

pub mod ddns;

pub mod provision;
