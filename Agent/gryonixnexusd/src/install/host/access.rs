//! Port of `DashboardAccessSections`: the sudoers whitelist and container control script

use crate::install::context::Input;
use crate::install::host::uninstall::BackupPaths;
use crate::install::host::{HostInput, HostRole};

use super::CATALOG_ORDER;

pub const CONTAINER_CONTROL_SCRIPT_PATH: &str = "/opt/gryonixnexus-container-ctl.sh";
const UNINSTALL_SCRIPT_PATH: &str = "/opt/gryonixnexus-uninstall.sh";
pub const AGENT_BOOTSTRAP_SCRIPT_PATH: &str = "/opt/gryonixnexus-agent-bootstrap.sh";
pub const AGENT_BRIDGE_SUDOERS_TARGET: &str = "/usr/local/bin/gryonixnexusd bridge";
pub const AGENT_PAIR_CODE_SUDOERS_TARGET: &str = "/usr/local/bin/gryonixnexusd pair-code";
const BACKUP_CTL_SCRIPT_PATH: &str = "/opt/gryonixnexus-backup-ctl.sh";
const UPDATE_CTL_SCRIPT_PATH: &str = "/opt/gryonixnexus-update-ctl.sh";
const RESTORE_SCRIPT_PATH: &str = "/opt/gryonixnexus-restore.sh";
const WIREGUARD_INTERFACE: &str = "wg0";

const VPN_PROTOCOLS: &[&str] =
    &["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"];
const VPN_PANEL: &str = "vpn-panel";

const NO_BACKUP_IDS: &[&str] = VPN_PROTOCOLS;

const UPDATE_CTL_EXCLUDED_IDS: &[&str] = &["mailcow", "gitlab", "wireguard-vpn", "openvpn", "vpn-panel"];

fn selected_services_in_order(input: &HostInput) -> Vec<&'static str> {
    let has_protocol = VPN_PROTOCOLS.iter().any(|p| input.services.iter().any(|s| s == p));
    CATALOG_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            present || (*id == VPN_PANEL && has_protocol)
        })
        .collect()
}

// MARK: - Per-service sudoers targets

fn compose_power(project: &str) -> Vec<String> {
    vec![
        format!("/usr/bin/docker compose -p {project} ps"),
        format!("/usr/bin/docker compose -p {project} restart"),
        format!("/usr/bin/docker compose -p {project} start"),
        format!("/usr/bin/docker compose -p {project} stop"),
    ]
}

fn container_power(name: &str) -> Vec<String> {
    vec![
        "/usr/bin/docker ps -a".to_string(),
        format!("/usr/bin/docker restart {name}"),
        format!("/usr/bin/docker start {name}"),
        format!("/usr/bin/docker stop {name}"),
    ]
}

fn compose_logs(project: &str) -> String {
    format!("/usr/bin/docker compose -p {project} logs --tail 500 --timestamps")
}

fn container_logs(name: &str) -> String {
    format!("/usr/bin/docker logs --tail 500 --timestamps {name}")
}

fn compose_generic(project: &str, path: &str) -> Vec<String> {
    let _ = path;
    let mut lines = compose_power(project);
    lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
    lines.push(RESTORE_SCRIPT_PATH.to_string());
    lines.push(compose_logs(project));
    lines
}

/// The container-based mirror of [`compose_generic`] — jellyfin and adguard-home
fn container_generic(name: &str, path: &str) -> Vec<String> {
    let _ = path;
    let mut lines = container_power(name);
    lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
    lines.push(RESTORE_SCRIPT_PATH.to_string());
    lines.push(container_logs(name));
    lines
}

fn container_power_only(name: &str, path: &str) -> Vec<String> {
    let _ = path;
    let mut lines = container_power(name);
    lines.push(container_logs(name));
    lines
}

fn service_sudoers_targets(id: &str, input: &Input, backups: &BackupPaths, user: &str) -> Vec<String> {
    service_sudoers_targets_1(id, input, backups, user)
        .or_else(|| service_sudoers_targets_2(id, input))
        .or_else(|| service_sudoers_targets_3(id))
        .unwrap_or_else(|| unreachable!("service_sudoers_targets called with an id outside CATALOG_ORDER: {id}"))
}

fn service_sudoers_targets_1(id: &str, input: &Input, backups: &BackupPaths, user: &str) -> Option<Vec<String>> {
    match id {
        "mailcow" => Some({
            let mut lines = compose_power("mailcowdockerized");
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(compose_logs("mailcowdockerized"));
            lines.push("/opt/gryonixnexus-dkim.sh".to_string());
            lines
        }),
        "mailu" => Some({
            let mut lines = compose_power("mailu");
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(compose_logs("mailu"));
            lines.push("/opt/gryonixnexus-mailu-dkim.sh".to_string());
            lines
        }),
        "docker-mailserver" => Some({
            let mut lines = compose_power("dockermailserver");
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(compose_logs("dockermailserver"));
            lines.push("/opt/gryonixnexus-dms-mailbox.sh".to_string());
            lines.push("/opt/gryonixnexus-dms-dkim.sh".to_string());
            lines
        }),
        "vaultwarden" => Some({
            let mut lines = container_power(&input.vaultwarden_container);
            let staging =
                format!("{}/{}-backup.tar.gz", backups.vaultwarden, input.vaultwarden_container);
            let relative = input.vaultwarden_data_path.trim_start_matches('/');
            lines.push(format!("/bin/tar czf {staging} -C / {relative}"));
            lines.push(format!("/bin/chown {user} {staging}"));
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(container_logs(&input.vaultwarden_container));
            lines
        }),
        "psono" => Some(compose_generic("psono", &input.psono_path)),
        "passbolt" => Some(compose_generic("passbolt", &input.passbolt_path)),
        "nextcloud" => Some(compose_generic("nextcloud", &input.nextcloud_path)),
        "seafile" => Some(compose_generic("seafile", &input.seafile_path)),
        "immich" => Some(compose_generic("immich", &input.immich_path)),
        "photoprism" => Some(compose_generic("photoprism", &input.photoprism_path)),
        "gitlab" => Some(compose_generic("gitlab", &input.gitlab_path)),
        "forgejo" => Some(compose_generic("forgejo", &input.forgejo_path)),
        "jellyfin" => Some(container_generic("jellyfin", &input.jellyfin_path)),
        "home-assistant" => Some(container_generic(
            crate::install::home_assistant::CONTAINER,
            &input.home_assistant_path,
        )),
        "mosquitto" => Some(container_generic(
            crate::install::mosquitto::CONTAINER,
            &input.mosquitto_path,
        )),
        _ => None,
    }
}

fn service_sudoers_targets_2(id: &str, input: &Input) -> Option<Vec<String>> {
    match id {
        "zigbee2mqtt" => Some(container_generic(
            crate::install::zigbee2mqtt::CONTAINER,
            &input.zigbee2mqtt_path,
        )),
        "minecraft-java" => Some(container_generic("minecraft-java", &input.minecraft_java_path)),
        "minecraft-bedrock" => Some(container_generic("minecraft-bedrock", &input.minecraft_bedrock_path)),
        "crafty-controller" => Some(container_generic("crafty", &input.crafty_path)),
        "open-webui" => Some(container_generic("open-webui", &input.open_webui_path)),
        "litellm" => Some(container_generic("litellm", &input.litellm_path)),
        "n8n" => Some(compose_generic("n8n", &input.n8n_path)),
        "anythingllm" => Some(container_generic("anythingllm", &input.anythingllm_path)),
        "qdrant" => Some(container_generic("qdrant", &input.qdrant_path)),
        "searxng" => Some(container_power_only("searxng", &input.searxng_path)),
        "openclaw" => Some(container_generic("openclaw", &input.openclaw_path)),
        "ollama" => Some(container_power_only("ollama", &input.ollama_path)),
        "adguard-home" => Some(container_generic("adguardhome", &input.adguard_path)),
        "pihole" => Some(container_generic("pihole", &input.pihole_path)),
        "homepage" => Some(container_generic("homepage", &input.homepage_path)),
        "authelia" => Some(container_generic("authelia", &input.authelia_path)),
        "headscale" => Some(container_generic("headscale", &input.headscale_path)),
        "cloudflared" => Some(container_power_only("cloudflared", &input.cloudflared_path)),
        "wireguard-vpn" => Some(vec![
            "/usr/bin/docker ps -a".to_string(),
            "/usr/bin/docker restart vpnpanel".to_string(),
            container_logs("vpnpanel"),
        ]),
        "amnezia-wg" => Some(container_power_only("awgvpn", &input.amnezia_wg_path)),
        "shadowsocks" => Some(container_power_only("shadowsocks", &input.shadowsocks_path)),
        "xray-reality" => Some(container_power_only("xray", &input.xray_reality_path)),
        "openvpn" => Some(container_power_only("openvpn", &input.openvpn_path)),
        "tailscale-node" => Some(container_power_only(
            crate::install::tailscale::CONTAINER,
            &input.tailscale_node_path,
        )),
        _ => None,
    }
}

fn service_sudoers_targets_3(id: &str) -> Option<Vec<String>> {
    match id {
        "vpn-panel" => Some({
            let mut lines = container_power("vpnpanel");
            lines.push(BACKUP_CTL_SCRIPT_PATH.to_string());
            lines.push(RESTORE_SCRIPT_PATH.to_string());
            lines.push(container_logs("vpnpanel"));
            lines.push("/opt/gryonixnexus-admin-lockdown.sh".to_string());
            lines
        }),
        _ => None,
    }
}

// MARK: - Assembly

fn sudoers_line(user: &str, target: &str) -> String {
    format!("{user} ALL=(ALL) NOPASSWD: {target}")
}

pub(crate) fn service_sudoers_lines(id: &str, input: &Input, backups: &BackupPaths, user: &str) -> Vec<String> {
    service_sudoers_targets(id, input, backups, user).iter().map(|target| sudoers_line(user, target)).collect()
}

/// A port of `DashboardAccessSections.servicesHostSudoersLines`
fn services_host_sudoers_lines(input: &HostInput, backups: &BackupPaths, user: &str, include_wire_guard: bool) -> Vec<String> {
    let selected = selected_services_in_order(input);

    let mut lines =
        vec![
            sudoers_line(user, "/usr/bin/systemctl restart sshd"),
            sudoers_line(user, "/usr/bin/systemctl reboot"),
            sudoers_line(user, "/usr/bin/systemctl poweroff"),
            sudoers_line(user, crate::system_ctl::SCRIPT_PATH),
        ];
    if include_wire_guard {
        lines.insert(0, sudoers_line(user, &format!("/usr/bin/systemctl restart wg-quick@{WIREGUARD_INTERFACE}")));
        lines.push(sudoers_line(user, "/usr/sbin/sysctl net.ipv4.ip_forward"));
        lines.push(sudoers_line(user, "/usr/bin/wg show"));
    }
    if !selected.is_empty() {
        lines.push(sudoers_line(user, "/usr/bin/docker ps"));
        lines.push(sudoers_line(user, CONTAINER_CONTROL_SCRIPT_PATH));
    }
    // Service removal / full cleanup — unconditional, matching Swift.
    lines.push(sudoers_line(user, UNINSTALL_SCRIPT_PATH));
    lines.push(sudoers_line(user, AGENT_BOOTSTRAP_SCRIPT_PATH));
    lines.push(sudoers_line(user, AGENT_BRIDGE_SUDOERS_TARGET));
    lines.push(sudoers_line(user, AGENT_PAIR_CODE_SUDOERS_TARGET));
    if selected.iter().any(|id| !NO_BACKUP_IDS.contains(id)) {
        lines.push(sudoers_line(user, BACKUP_CTL_SCRIPT_PATH));
    }
    if selected.iter().any(|id| !UPDATE_CTL_EXCLUDED_IDS.contains(id)) {
        lines.push(sudoers_line(user, UPDATE_CTL_SCRIPT_PATH));
    }
    for id in &selected {
        for target in service_sudoers_targets(id, &input.install, backups, user) {
            let line = sudoers_line(user, &target);
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    lines
}

/// A port of `DashboardAccessSections.vpsSudoersLines`
fn vps_sudoers_lines(user: &str) -> Vec<String> {
    vec![
        sudoers_line(user, &format!("/usr/bin/systemctl restart wg-quick@{WIREGUARD_INTERFACE}")),
        sudoers_line(user, "/usr/bin/systemctl restart sshd"),
        sudoers_line(user, "/usr/bin/systemctl reboot"),
        sudoers_line(user, "/usr/bin/systemctl poweroff"),
        sudoers_line(user, crate::system_ctl::SCRIPT_PATH),
        sudoers_line(user, "/sbin/sysctl net.ipv4.ip_forward"),
        sudoers_line(user, "/usr/bin/wg show"),
        sudoers_line(user, UNINSTALL_SCRIPT_PATH),
        // The app updates the relay's agent through this wrapper.
        sudoers_line(user, AGENT_BOOTSTRAP_SCRIPT_PATH),
        sudoers_line(user, AGENT_BRIDGE_SUDOERS_TARGET),
        sudoers_line(user, AGENT_PAIR_CODE_SUDOERS_TARGET),
    ]
}

fn sudoers_body(lines: &[String]) -> String {
    let mut body = String::from(
        "# Managed by gryonixNexus — Server Dashboard command whitelist.\n\
         # sudo matches these commands verbatim; do not add flags client-side.\n",
    );
    body.push_str(&lines.join("\n"));
    body
}

const CONTAINER_CTL_BODY: &str = r#"#!/bin/bash
# Managed by gryonixNexus — per-container control for the Server Dashboard.
# Usage: gryonixnexus-container-ctl.sh <start|stop|restart> <container>
# Whitelisted once in sudoers; validates its arguments before docker.
set -euo pipefail
ACTION="${1:-}"
NAME="${2:-}"
case "$ACTION" in
  start|stop|restart) ;;
  *) echo "unsupported action: ${ACTION}" >&2; exit 2 ;;
esac
case "$NAME" in
  [A-Za-z0-9]*) ;;
  *) echo "invalid container name: ${NAME}" >&2; exit 2 ;;
esac
case "$NAME" in
  *[!A-Za-z0-9_.-]*) echo "invalid container name: ${NAME}" >&2; exit 2 ;;
esac
exec docker "$ACTION" "$NAME""#;

pub fn container_control_script() -> &'static str {
    CONTAINER_CTL_BODY
}

#[derive(Debug, Clone, PartialEq)]
pub struct Access {
    pub sudoers_body: String,
    pub container_ctl_body: Option<String>,
}

pub fn render(input: &HostInput, backups: &BackupPaths) -> Option<Access> {
    let user = input.ssh_user.as_deref()?;
    let lines = match input.role {
        HostRole::VpsRelay => vps_sudoers_lines(user),
        HostRole::SingleHost => services_host_sudoers_lines(input, backups, user, false),
        HostRole::HomeBackend => services_host_sudoers_lines(input, backups, user, true),
    };
    let container_ctl_body = match input.role {
        HostRole::VpsRelay => None,
        HostRole::SingleHost | HostRole::HomeBackend => Some(CONTAINER_CTL_BODY.to_string()),
    };
    Some(Access { sudoers_body: sudoers_body(&lines), container_ctl_body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;

    fn fixture(dir: &str, name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/{dir}/{name}.txt", env!("CARGO_MANIFEST_DIR"));
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
            let access = render(&input, &backups).expect("ssh_user is Some in every case row");
            let expected = fixture("access_sudoers", fixture_name);
            assert_eq!(access.sudoers_body, expected.trim_end_matches('\n'), "{fixture_name}");
        }
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
        let access = render(&input, &backups).unwrap();
        let expected = fixture("access_sudoers", "A-multidomain");
        assert_eq!(access.sudoers_body, expected.trim_end_matches('\n'));
    }

    #[test]
    fn container_ctl_fixture_parity() {
        let expected = fixture("access_container_ctl", "A-adguard-access-en");
        assert_eq!(container_control_script(), expected.trim_end_matches('\n'));
    }

    #[test]
    fn no_ssh_user_renders_nothing() {
        let input = HostInput { ssh_user: None, ..host(&["adguard-home"]) };
        let backups = BackupPaths::default();
        assert!(render(&input, &backups).is_none());
    }

    #[test]
    fn render_dispatches_vps_relay_to_the_fixed_line_set() {
        let input = HostInput {
            services: vec!["mailcow".to_string(), "vaultwarden".to_string()],
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::VpsRelay,
        };
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        let expected = fixture("access_sudoers", "B-relay-access-en");
        assert_eq!(access.sudoers_body, expected.trim_end_matches('\n'));
        assert!(access.container_ctl_body.is_none());
        assert!(access.sudoers_body.contains(AGENT_BRIDGE_SUDOERS_TARGET));
        // The app updates the relay's agent through the bootstrap wrapper.
        assert!(access.sudoers_body.contains(AGENT_BOOTSTRAP_SCRIPT_PATH));
        assert!(!access.sudoers_body.contains("mailcowdockerized"));
        assert!(!access.sudoers_body.contains(CONTAINER_CONTROL_SCRIPT_PATH));
        assert!(access.sudoers_body.contains("/sbin/sysctl net.ipv4.ip_forward"));
        assert!(!access.sudoers_body.contains("/usr/sbin/sysctl"));
    }

    #[test]
    fn home_backend_adds_the_tunnel_lines() {
        let input = HostInput {
            services: vec!["adguard-home".to_string()],
            install: base_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::HomeBackend,
        };
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        let lines: Vec<&str> = access.sudoers_body.lines().collect();
        assert_eq!(lines[2], "admin ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart wg-quick@wg0");
        assert!(access.sudoers_body.contains("/usr/sbin/sysctl net.ipv4.ip_forward"));
        assert!(access.sudoers_body.contains("/usr/bin/wg show"));
    }

    #[test]
    fn identical_privileged_commands_across_two_services_collapse_to_one_line() {
        let input = host(&["wireguard-vpn"]);
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        let restart_count =
            access.sudoers_body.matches("admin ALL=(ALL) NOPASSWD: /usr/bin/docker restart vpnpanel").count();
        assert_eq!(restart_count, 1, "{}", access.sudoers_body);
        assert!(access.sudoers_body.contains("/usr/bin/docker start vpnpanel"));
        assert!(access.sudoers_body.contains("/usr/bin/docker stop vpnpanel"));
    }

    #[test]
    fn vaultwarden_backup_does_not_repeat_its_own_stop_start_lines() {
        let input = host(&["vaultwarden"]);
        let backups = BackupPaths::default();
        let access = render(&input, &backups).unwrap();
        assert_eq!(access.sudoers_body.matches("docker stop vaultwarden").count(), 1);
        assert_eq!(access.sudoers_body.matches("docker start vaultwarden").count(), 1);
        assert!(access.sudoers_body.contains("/bin/tar czf /opt/backups/vaultwarden/vaultwarden-backup.tar.gz -C / opt/vaultwarden/data"));
        assert!(access.sudoers_body.contains("/bin/chown admin /opt/backups/vaultwarden/vaultwarden-backup.tar.gz"));
    }

    #[test]
    fn container_ctl_validates_its_arguments_for_real() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-access-argtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script_path = dir.join("gryonixnexus-container-ctl.sh");
        std::fs::write(&script_path, container_control_script()).unwrap();

        let bin_dir = dir.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let stub_docker = bin_dir.join("docker");
        std::fs::write(&stub_docker, "#!/bin/sh\necho \"STUB_DOCKER_ARGS:$*\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub_docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let real_path = std::env::var("PATH").unwrap_or_default();
        let run = |args: &[&str]| -> (i32, String, String) {
            let output = std::process::Command::new("bash")
                .arg(&script_path)
                .args(args)
                .env("PATH", format!("{}:{real_path}", bin_dir.display()))
                .output()
                .expect("bash must be on PATH for this test");
            (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout).to_string(),
                String::from_utf8_lossy(&output.stderr).to_string(),
            )
        };

        let (code, stdout, _) = run(&["start", "nextcloud-app1"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:start nextcloud-app1");

        let (code, stdout, _) = run(&["restart", "adguardhome"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:restart adguardhome");

        let (code, stdout, _) = run(&["stop", "vaultwarden"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:stop vaultwarden");

        // Unsupported action: rejected before docker is ever reached.
        let (code, stdout, stderr) = run(&["frobnicate", "vaultwarden"]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(stderr.contains("unsupported action: frobnicate"));

        let (code, _, stderr) = run(&["start", "-rf"]);
        assert_eq!(code, 2);
        assert!(stderr.contains("invalid container name: -rf"));

        let (code, _, stderr) = run(&["start", "abc;rm"]);
        assert_eq!(code, 2);
        assert!(stderr.contains("invalid container name: abc;rm"));

        let (code, stdout, _) = run(&["start", "a.b_c-1"]);
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), "STUB_DOCKER_ARGS:start a.b_c-1");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
