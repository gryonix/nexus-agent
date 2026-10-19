//! The inputs behind the backup wrapper, kept so a newer agent renders it anew

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::backup_ctl;
use super::{HostInput, HostRole};
use crate::install::context::Input;

/// Paths only; the install's secrets never land here
pub const INPUT_PATH: &str = "/etc/gryonixnexus/backup-ctl-input.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredInput {
    pub services: Vec<String>,
    pub ssh_user: Option<String>,
    pub paths: BTreeMap<String, String>,
}

macro_rules! stored_fields {
    ($($field:ident),* $(,)?) => {
        impl StoredInput {
            pub fn from_host(input: &HostInput) -> Self {
                let mut paths = BTreeMap::new();
                $(paths.insert(stringify!($field).to_string(), input.install.$field.clone());)*
                Self { services: input.services.clone(), ssh_user: input.ssh_user.clone(), paths }
            }

            /// Language and role do not shape the wrapper
            pub fn to_host(&self) -> HostInput {
                let mut install = Input::default();
                $(if let Some(value) = self.paths.get(stringify!($field)) {
                    install.$field = value.clone();
                })*
                HostInput {
                    services: self.services.clone(),
                    language: install.language,
                    install,
                    ssh_user: self.ssh_user.clone(),
                    role: HostRole::SingleHost,
                }
            }
        }
    };
}

stored_fields!(
    adguard_path, anythingllm_path, authelia_path, crafty_path, docker_mailserver_path, forgejo_path,
    gitlab_path, headscale_path, home_assistant_path, homepage_path, immich_path, jellyfin_path,
    litellm_path, mailcow_path, mailu_path, minecraft_bedrock_path, minecraft_java_path, mosquitto_path,
    n8n_path, nextcloud_path, open_webui_path, openclaw_path, passbolt_path, photoprism_path,
    pihole_path, psono_path, qdrant_path, seafile_path, vaultwarden_container, vaultwarden_data_path,
    zigbee2mqtt_path,
);

/// Written next to the wrapper on every install and repair
pub fn store(input: &HostInput) -> std::io::Result<()> {
    store_at(Path::new(INPUT_PATH), input)
}

fn store_at(path: &Path, input: &HostInput) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(&StoredInput::from_host(input)).map_err(std::io::Error::other)?;
    crate::util::write_file_atomic(path, &body, 0o600)
}

/// The wrapper this agent writes from the stored inputs
pub fn rendered(stored: &Path) -> Option<String> {
    let text = std::fs::read_to_string(stored).ok()?;
    let input: StoredInput = serde_json::from_str(&text).ok()?;
    Some(super::provision::as_written(&backup_ctl::script(&input.to_host())))
}

/// A newer agent brings a newer wrapper without a repair
pub fn refresh_on_startup() {
    match refresh(Path::new(INPUT_PATH), Path::new(backup_ctl::SCRIPT_PATH)) {
        Ok(true) => tracing::info!("backup wrapper rewritten for this agent"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "backup wrapper not refreshed"),
    }
}

fn refresh(stored: &Path, script: &Path) -> std::io::Result<bool> {
    let Some(fresh) = rendered(stored) else { return Ok(false) };
    if !script.exists() || std::fs::read_to_string(script).ok().as_deref() == Some(fresh.as_str()) {
        return Ok(false);
    }
    crate::util::write_file_atomic(script, fresh.as_bytes(), 0o750)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gnx-backup-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn host(services: &[&str]) -> HostInput {
        let mut install = Input::default();
        install.nextcloud_path = "/srv/cloud".to_string();
        install.tailscale_auth_key = "tskey-secret".to_string();
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            language: install.language,
            install,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    #[test]
    fn the_stored_inputs_render_the_same_wrapper() {
        let input = host(&["nextcloud", "vaultwarden"]);
        let back = StoredInput::from_host(&input).to_host();
        assert_eq!(backup_ctl::script(&back), backup_ctl::script(&input));
    }

    #[test]
    fn no_secret_of_the_install_is_stored() {
        let body = serde_json::to_string(&StoredInput::from_host(&host(&["nextcloud"]))).unwrap();
        assert!(!body.contains("tskey-secret"));
        assert!(body.contains("/srv/cloud"));
    }

    #[test]
    fn an_old_wrapper_is_rewritten_and_a_current_one_left_alone() {
        let dir = scratch("old");
        let stored = dir.join("input.json");
        let script = dir.join("backup-ctl.sh");
        store_at(&stored, &host(&["nextcloud"])).unwrap();
        std::fs::write(&script, "#!/bin/bash\necho old\n").unwrap();

        assert!(refresh(&stored, &script).unwrap());
        assert_eq!(std::fs::read_to_string(&script).unwrap(), rendered(&stored).unwrap());
        assert!(!refresh(&stored, &script).unwrap(), "a current wrapper is not written again");
    }

    #[test]
    fn nothing_happens_without_stored_inputs_or_without_a_wrapper() {
        let dir = scratch("none");
        let stored = dir.join("input.json");
        let script = dir.join("backup-ctl.sh");
        std::fs::write(&script, "old").unwrap();
        assert!(!refresh(&stored, &script).unwrap());

        store_at(&stored, &host(&["nextcloud"])).unwrap();
        std::fs::remove_file(&script).unwrap();
        assert!(!refresh(&stored, &script).unwrap());
        assert!(!script.exists(), "a host without the wrapper does not get one");
    }
}
