//! App settings last applied per service, kept for every device.

use std::collections::{BTreeMap, HashMap};

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::install::{app_settings, doh};
use crate::pb;

const FILE: &str = "app-settings.txt";

/// Whether a setting key belongs to this service label
fn belongs(label: &str, key: &str) -> bool {
    let service = label.replace('-', "_");
    let owner = key.split('_').next().unwrap_or_default();
    !owner.is_empty() && service.starts_with(owner)
}

fn parse(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(key, _)| app_settings::is_known(key) && !app_settings::is_secret(key))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn render(values: &BTreeMap<String, String>) -> String {
    values.iter().map(|(key, value)| format!("{key}\t{value}\n")).collect()
}

fn read() -> BTreeMap<String, String> {
    parse(&std::fs::read_to_string(crate::util::state_dir().join(FILE)).unwrap_or_default())
}

/// The service's own settings laid over the stored ones
fn merged(mut stored: BTreeMap<String, String>, label: &str, applied: &BTreeMap<String, String>)
    -> BTreeMap<String, String> {
    for (key, value) in applied {
        let plain = !value.contains(['\n', '\t']);
        if belongs(label, key) && plain && !app_settings::is_secret(key) {
            stored.insert(key.clone(), value.clone());
        }
    }
    stored
}

/// Records the settings an install of `label` applied
pub fn remember(label: &str, applied: &BTreeMap<String, String>) {
    let values = merged(read(), label, applied);
    let dir = crate::util::state_dir();
    let written = std::fs::create_dir_all(&dir)
        .and_then(|()| crate::util::write_file_atomic(&dir.join(FILE), render(&values).as_bytes(), 0o644));
    if let Err(err) = written {
        tracing::warn!(?err, label, "could not store the applied app settings");
    }
}

/// DoH switches as the Caddyfile serves them now
fn live_doh(caddyfile: &str) -> HashMap<String, String> {
    ["adguard-home", "pihole"]
        .iter()
        .filter_map(|service| {
            let key = doh::setting_key(service)?;
            doh::address_in(caddyfile, service).map(|_| (key.to_string(), "true".to_string()))
        })
        .collect()
}

pub async fn get_app_settings(codec: Codec, _req: pb::GetAppSettingsRequest) -> Resp {
    let mut values: HashMap<String, String> = read().into_iter().collect();
    values.extend(live_doh(&crate::install::execute::current_caddyfile()));
    codec
        .encode(&pb::AppSettingValues { values })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn a_key_belongs_to_the_service_it_starts_with() {
        assert!(belongs("adguard-home", "adguard_doh"));
        assert!(belongs("open-webui", "open_webui_api_keys"));
        assert!(belongs("vaultwarden", "vaultwarden_smtp_host"));
        assert!(!belongs("nextcloud", "adguard_doh"));
        assert!(!belongs("pihole", "vaultwarden_smtp_host"));
    }

    #[test]
    fn only_the_installed_service_overwrites_its_keys() {
        let stored = map(&[("adguard_doh", "true"), ("nextcloud_upload_limit", "2G")]);
        let applied = map(&[("adguard_doh", "false"), ("nextcloud_upload_limit", "512M")]);
        let next = merged(stored, "nextcloud", &applied);
        assert_eq!(next["adguard_doh"], "true");
        assert_eq!(next["nextcloud_upload_limit"], "512M");
    }

    #[test]
    fn secrets_and_unknown_keys_are_never_kept() {
        let applied = map(&[("vaultwarden_smtp_password", "hunter2"), ("vaultwarden_smtp_host", "smtp.example.com")]);
        let next = merged(BTreeMap::new(), "vaultwarden", &applied);
        assert!(!next.contains_key("vaultwarden_smtp_password"));
        assert_eq!(next["vaultwarden_smtp_host"], "smtp.example.com");
        let read_back = parse("vaultwarden_smtp_password\tx\nmade_up_key\ty\nvaultwarden_smtp_host\th\n");
        assert_eq!(read_back, map(&[("vaultwarden_smtp_host", "h")]));
    }

    #[test]
    fn stored_text_reads_back() {
        let values = map(&[("adguard_query_log", "false"), ("nextcloud_upload_limit", "2G")]);
        assert_eq!(parse(&render(&values)), values);
    }
}
