//! What an install leaves behind for every LATER operation to stand on

use super::{access, backup_ctl, lockdown, metrics, report, restore, uninstall, update_ctl};
use super::{HostInput, HostRole};

/// One file the install must leave on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct HostFile {
    pub path: String,
    pub contents: String,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportTopology(pub report::Topology);

/// The relay carries metrics, uninstall and the agent bootstrap only
fn relay_files(input: &HostInput, backups: &uninstall::BackupPaths, access: Option<&uninstall::DashboardAccess>) -> Vec<HostFile> {
    let mut files = vec![
        HostFile {
            path: metrics::COLLECTOR_PATH.to_string(),
            contents: metrics::collector_script(),
            mode: Some(0o755),
        },
        HostFile {
            path: metrics::UNIT_PATH.to_string(),
            contents: metrics::unit(),
            mode: None,
        },
        HostFile {
            path: uninstall::SCRIPT_PATH.to_string(),
            contents: uninstall::render(input, backups, access),
            mode: Some(0o750),
        },
    ];
    files.extend(agent_bootstrap_file(input));
    return files;
}

fn wrapper_files(input: &HostInput, backups: &uninstall::BackupPaths, access: Option<&uninstall::DashboardAccess>) -> Vec<HostFile> {
    vec![
        HostFile {
            path: backup_ctl::SCRIPT_PATH.to_string(),
            contents: backup_ctl::script(input),
            mode: Some(0o750),
        },
        HostFile {
            path: format!("/etc/systemd/system/{}", backup_ctl::SERVICE_NAME),
            contents: backup_ctl::unit(),
            mode: None,
        },
        HostFile {
            path: update_ctl::SCRIPT_PATH.to_string(),
            contents: update_ctl::wrapper(input),
            mode: Some(0o750),
        },
        HostFile {
            path: format!("/etc/systemd/system/{}", update_ctl::SERVICE_NAME),
            contents: update_ctl::autoupdate_unit(),
            mode: None,
        },
        HostFile {
            path: uninstall::SCRIPT_PATH.to_string(),
            contents: uninstall::render(input, backups, access),
            mode: Some(0o750),
        },
        HostFile {
            path: restore::SCRIPT_PATH.to_string(),
            contents: restore::render(input, backups),
            mode: Some(0o750),
        },
        HostFile {
            path: metrics::COLLECTOR_PATH.to_string(),
            contents: metrics::collector_script(),
            mode: Some(0o755),
        },
        HostFile {
            path: metrics::UNIT_PATH.to_string(),
            contents: metrics::unit(),
            mode: None,
        },
    ]
}

pub fn files(
    input: &HostInput,
    backups: &uninstall::BackupPaths,
    access: Option<&uninstall::DashboardAccess>,
) -> Vec<HostFile> {
    // The relay: metrics, uninstall and the agent bootstrap only.
    if input.role == HostRole::VpsRelay {
        return relay_files(input, backups, access);
    }
    let mut files = wrapper_files(input, backups, access);

    files.push(HostFile {
        path: lockdown::SCRIPT_PATH.to_string(),
        contents: lockdown::render(),
        mode: Some(0o750),
    });

    files.extend(agent_bootstrap_file(input));

    if let Some(access) = access::render(input, backups) {
        if let Some(body) = access.container_ctl_body {
            files.push(HostFile {
                path: access::CONTAINER_CONTROL_SCRIPT_PATH.to_string(),
                contents: body,
                mode: Some(0o750),
            });
        }
    }
    files
}

fn agent_bootstrap_file(input: &HostInput) -> Option<HostFile> {
    let user = input.ssh_user.as_deref()?;
    Some(HostFile {
        path: access::AGENT_BOOTSTRAP_SCRIPT_PATH.to_string(),
        contents: super::agent_bootstrap::script(user),
        mode: Some(0o700),
    })
}

/// One rendered body, as it must land ON DISK
pub fn as_written(contents: &str) -> String {
    let mut out = contents.trim_end_matches('\n').to_string();
    out.push('\n');
    out
}

pub fn sudoers(input: &HostInput, backups: &uninstall::BackupPaths) -> Option<String> {
    access::render(input, backups).map(|access| access.sudoers_body)
}

pub fn app_public_key(uninstall_wrapper: &str) -> Option<String> {
    let line = uninstall_wrapper.lines().map(str::trim).find(|line| line.starts_with("APP_KEY='"))?;
    let key = line.strip_prefix("APP_KEY='")?.strip_suffix('\'')?;
    if key.is_empty() || key.contains('\'') {
        return None;
    }
    Some(key.to_string())
}

pub fn control_user(sudoers_file: &str) -> Option<String> {
    for line in sudoers_file.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (user, rest) = line.split_once(char::is_whitespace)?;
        if !rest.trim_start().starts_with("ALL=") {
            return None;
        }
        if user.is_empty() || user.contains('/') {
            return None;
        }
        return Some(user.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;
    use crate::install::context::Input;

    fn files_of(input: &HostInput, backups: &uninstall::BackupPaths) -> Vec<HostFile> {
        files(input, backups, None)
    }

    fn host(services: &[&str], user: Option<&str>, role: HostRole) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: user.map(str::to_string),
            role,
        }
    }

    #[test]
    fn the_whole_host_half_renders_for_every_installable_service() {
        let mut ids: Vec<&str> = Vec::new();
        for id in crate::install::execute::implemented_service_ids() {
            if id == "vpn" {
                ids.extend(["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn", "vpn-panel"]);
            } else {
                ids.push(id);
            }
        }
        for id in &ids {
            let input = host(&[id], Some("server-user"), HostRole::SingleHost);
            let rendered = files(&input, &uninstall::BackupPaths::default(), None);
            assert!(!rendered.is_empty(), "`{id}` produced no host files at all");
        }
        let input = host(&ids, Some("server-user"), HostRole::SingleHost);
        assert!(!files(&input, &uninstall::BackupPaths::default(), None).is_empty());
    }

    #[test]
    fn the_whole_host_half_renders_for_every_id_a_host_can_carry() {
        for id in crate::install::host::CATALOG_ORDER {
            let input = host(&[id], Some("server-user"), HostRole::SingleHost);
            let rendered = files(&input, &uninstall::BackupPaths::default(), None);
            assert!(!rendered.is_empty(), "`{id}` produced no host files at all");
        }
        let input = host(crate::install::host::CATALOG_ORDER, Some("server-user"), HostRole::SingleHost);
        assert!(!files(&input, &uninstall::BackupPaths::default(), None).is_empty());
    }

    #[test]
    fn the_control_user_is_read_from_an_existing_whitelist() {
        let file = "# Managed by gryonixNexus — Server Dashboard command whitelist.\n\
                    # sudo matches these commands verbatim; do not add flags client-side.\n\
                    gryonixbot ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart sshd\n";
        assert_eq!(control_user(file).as_deref(), Some("gryonixbot"));
    }

    /// Anything that is not a whitelist is not an answer
    #[test]
    fn nothing_that_is_not_a_rule_yields_a_user() {
        assert_eq!(control_user(""), None);
        assert_eq!(control_user("# only comments\n\n"), None);
        assert_eq!(control_user("Defaults env_keep += \"FOO\"\n"), None);
        assert_eq!(control_user("/usr/bin/something ALL=(ALL) NOPASSWD: x\n"), None);
    }

    #[test]
    fn a_host_with_no_control_user_gets_no_sudoers_and_no_container_wrapper() {
        let input = host(&["vaultwarden"], None, HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        assert_eq!(sudoers(&input, &backups), None);
        let paths: Vec<String> = files(&input, &backups, None).into_iter().map(|f| f.path).collect();
        assert!(!paths.contains(&access::CONTAINER_CONTROL_SCRIPT_PATH.to_string()), "{paths:?}");
        for expected in [
            backup_ctl::SCRIPT_PATH,
            update_ctl::SCRIPT_PATH,
            uninstall::SCRIPT_PATH,
            restore::SCRIPT_PATH,
            metrics::COLLECTOR_PATH,
            lockdown::SCRIPT_PATH,
        ] {
            assert!(paths.contains(&expected.to_string()), "{expected} missing from {paths:?}");
        }
    }

    #[test]
    fn a_host_with_a_control_user_gets_both() {
        let input = host(&["vaultwarden"], Some("gryonixbot"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        let body = sudoers(&input, &backups).expect("a control user means a whitelist");
        assert!(body.contains("gryonixbot ALL=(ALL) NOPASSWD:"), "{body}");
        let paths: Vec<String> = files(&input, &backups, None).into_iter().map(|f| f.path).collect();
        assert!(paths.contains(&access::CONTAINER_CONTROL_SCRIPT_PATH.to_string()));
    }

    #[test]
    fn what_is_written_is_what_is_read_back() {
        let input = host(&["vaultwarden", "vpn"], Some("gryonixbot"), HostRole::SingleHost);
        let body = sudoers(&input, &uninstall::BackupPaths::default()).unwrap();
        assert_eq!(control_user(&body).as_deref(), Some("gryonixbot"));
    }

    #[test]
    fn the_relay_gets_only_what_a_live_relay_has() {
        let input = host(&[], Some("gryonixbot"), HostRole::VpsRelay);
        let paths: Vec<String> = files_of(&input, &uninstall::BackupPaths::default())
            .into_iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(
            paths,
            vec![
                metrics::COLLECTOR_PATH.to_string(),
                metrics::UNIT_PATH.to_string(),
                uninstall::SCRIPT_PATH.to_string(),
                access::AGENT_BOOTSTRAP_SCRIPT_PATH.to_string(),
            ],
            "the relay's surface is exactly these four"
        );
        let body = sudoers(&input, &uninstall::BackupPaths::default()).unwrap();
        assert!(body.contains("wg-quick@wg0"), "{body}");
        assert!(!body.contains("docker"), "a relay runs no containers: {body}");
    }

    /// Every wrapper is a function of the SET
    #[test]
    fn adding_a_service_changes_the_wrappers_that_dispatch_on_it() {
        let backups = uninstall::BackupPaths::default();
        let before = files_of(&host(&["vaultwarden"], None, HostRole::SingleHost), &backups);
        let after = files_of(&host(&["vaultwarden", "nextcloud"], None, HostRole::SingleHost), &backups);
        for path in [backup_ctl::SCRIPT_PATH, update_ctl::SCRIPT_PATH, uninstall::SCRIPT_PATH] {
            let body = |set: &[HostFile]| {
                set.iter().find(|f| f.path == path).expect("wrapper must be written").contents.clone()
            };
            assert_ne!(body(&before), body(&after), "{path} must know about the new service");
            assert!(body(&after).contains("nextcloud"), "{path} must name the new service");
        }
    }

    #[test]
    fn the_aggregate_vpn_id_is_not_one_of_these() {
        let backups = uninstall::BackupPaths::default();
        let aggregate = files_of(&host(&["vpn"], None, HostRole::SingleHost), &backups);
        let expanded = files_of(&host(&["wireguard-vpn", "vpn-panel"], None, HostRole::SingleHost), &backups);
        let body = |set: &[HostFile], path: &str| {
            set.iter().find(|f| f.path == path).unwrap().contents.clone()
        };
        assert_ne!(
            body(&aggregate, uninstall::SCRIPT_PATH),
            body(&expanded, uninstall::SCRIPT_PATH),
            "the aggregate id must not render the same wrapper as the real ids"
        );
        assert!(
            body(&expanded, uninstall::SCRIPT_PATH).contains("vpn)"),
            "the expanded ids produce the wrapper's own vpn target"
        );
    }

    #[test]
    fn every_file_lands_on_disk_newline_terminated() {
        let input = host(&["vaultwarden", "vpn-panel"], Some("bot"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        for file in files(&input, &backups, None) {
            let written = as_written(&file.contents);
            assert!(written.ends_with('\n'), "{}", file.path);
            assert!(!written.ends_with("\n\n"), "{} must not gain a blank line", file.path);
            assert_eq!(written.trim_end_matches('\n'), file.contents.trim_end_matches('\n'));
        }
        let body = sudoers(&input, &backups).unwrap();
        assert!(as_written(&body).ends_with("gryonixnexus-admin-lockdown.sh\n"), "{body}");
    }

    #[test]
    fn every_wrapper_recognises_the_vpn_from_the_catalog_ids() {
        let input = host(&["vaultwarden", "wireguard-vpn", "vpn-panel"], Some("bot"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        let body = |files: &[HostFile], path: &str| {
            files.iter().find(|f| f.path == path).expect("written").contents.clone()
        };
        let files = files(&input, &backups, None);

        let backup = body(&files, backup_ctl::SCRIPT_PATH);
        assert!(backup.contains("vpn-panel)"), "the backup wrapper needs a vpn-panel arm");
        assert!(
            backup.lines().any(|l| l.starts_with("SERVICES=") && l.contains("vpn-panel")),
            "the panel must be in the backup service list"
        );
        assert!(body(&files, uninstall::SCRIPT_PATH).contains("vpn)"), "uninstall needs a vpn target");
        assert!(
            sudoers(&input, &backups).unwrap().contains("vpnpanel"),
            "the whitelist must authorise controlling the panel's container"
        );
    }

    #[test]
    fn the_app_key_is_recovered_from_the_wrapper_already_on_disk() {
        let existing = "  APP_KEY='ssh-ed25519 AAAAC3Nz key-comment'\n  USER_HOME=\"x\"\n";
        assert_eq!(
            app_public_key(existing).as_deref(),
            Some("ssh-ed25519 AAAAC3Nz key-comment")
        );
        assert_eq!(app_public_key("  :\n"), None);
        assert_eq!(app_public_key("  APP_KEY=''\n"), None);

        // Carried through to the rendered wrapper.
        let input = host(&["vaultwarden"], Some("server-user"), HostRole::SingleHost);
        let backups = uninstall::BackupPaths::default();
        let access = uninstall::DashboardAccess {
            create_user: true,
            app_public_key: "ssh-ed25519 KEY app".to_string(),
        };
        let with = files(&input, &backups, Some(&access));
        let body = |set: &[HostFile]| {
            set.iter().find(|f| f.path == uninstall::SCRIPT_PATH).unwrap().contents.clone()
        };
        assert!(body(&with).contains("APP_KEY='ssh-ed25519 KEY app'"), "{}", body(&with));
        assert!(!body(&files_of(&input, &backups)).contains("APP_KEY="), "no key, no block");
        assert_eq!(app_public_key(&body(&with)).as_deref(), Some("ssh-ed25519 KEY app"));
    }

    #[test]
    fn the_modes_are_the_generators() {
        let files = files_of(&host(&["vaultwarden"], Some("bot"), HostRole::SingleHost), &uninstall::BackupPaths::default());
        let mode = |path: &str| files.iter().find(|f| f.path == path).unwrap().mode;
        assert_eq!(mode(backup_ctl::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(update_ctl::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(uninstall::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(restore::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(access::CONTAINER_CONTROL_SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(lockdown::SCRIPT_PATH), Some(0o750));
        assert_eq!(mode(metrics::COLLECTOR_PATH), Some(0o755));
        assert_eq!(mode(metrics::UNIT_PATH), None);
    }
}
