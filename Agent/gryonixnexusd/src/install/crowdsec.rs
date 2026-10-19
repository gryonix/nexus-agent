//! Intrusion defence for the HOST: CrowdSec and its nftables bouncer

use std::path::{Path, PathBuf};

use super::execute::EventSink;
use super::packages::{have_binary, run_outside_sandbox, run_outside_sandbox_from_file};

const REPOSITORY_INSTALL_URL: &str = "https://install.crowdsec.net";

/// Where our acquisition drop-in lives
pub const ACQUISITION_PATH: &str = "/etc/crowdsec/acquis.d/gryonixnexus.yaml";

/// The bouncer's config
const BOUNCER_CONFIG_PATH: &str = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml";

const CREDENTIALS_PATH: &str = "/etc/crowdsec/local_api_credentials.yaml";

const LAPI_LISTEN_ADDR: &str = "127.0.0.1:8237";

pub(crate) const ENGINE_UNIT: &str = "crowdsec";
pub(crate) const BOUNCER_UNIT: &str = "crowdsec-firewall-bouncer";

/// The name the bouncer registers under with the local API
const BOUNCER_NAME: &str = "gryonixnexus-firewall-bouncer";

const UNREGISTERED_KEY: &str = "<API_KEY>";

/// What apt installs, and in two calls, engine first
pub(crate) const ENGINE_PACKAGE: &str = "crowdsec";
pub(crate) const BOUNCER_PACKAGE: &str = "crowdsec-firewall-bouncer-nftables";

/// The engine's own config, written by its post-installation script
const ENGINE_CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";

/// The acquisition CrowdSec parses our journals with
pub fn acquisition() -> String {
    "# Managed by gryonixNexus. Journald, not files: this fleet runs Debian with\n\
     # rsyslog inactive, so /var/log/auth.log does not exist and a file-based\n\
     # acquisition would parse nothing while reporting itself healthy.\n\
     source: journalctl\n\
     journalctl_filter:\n\
     \x20 - \"_SYSTEMD_UNIT=ssh.service\"\n\
     \x20 - \"_SYSTEMD_UNIT=sshd.service\"\n\
     labels:\n\
     \x20 type: syslog\n\
     ---\n\
     source: journalctl\n\
     journalctl_filter:\n\
     \x20 - \"_SYSTEMD_UNIT=caddy.service\"\n\
     labels:\n\
     \x20 type: caddy\n\
     ---\n\
     source: docker\n\
     container_name:\n\
     \x20 - vaultwarden\n\
     labels:\n\
     \x20 type: Dominic-Wagner/vaultwarden\n"
        .to_string()
}

const COLLECTIONS: &[&str] =
    &["crowdsecurity/sshd", "crowdsecurity/caddy", "crowdsecurity/linux", "Dominic-Wagner/vaultwarden"];

fn removal_marker() -> PathBuf {
    crate::util::state_dir().join("crowdsec-removed")
}

pub(crate) fn owner_removed() -> bool {
    removal_marker().exists()
}

pub(crate) fn remember_removal() {
    if let Err(err) = std::fs::write(removal_marker(), b"") {
        tracing::warn!("could not remember the CrowdSec removal: {err}");
    }
}

pub(crate) fn forget_removal() {
    let _ = std::fs::remove_file(removal_marker());
}

pub(crate) async fn ensure_present(enabled: bool, sink: &EventSink) {
    if !may_install(enabled, sink).await
        || !install_engine(sink).await
        || !configure_engine(sink).await
        || !start_engine(sink).await
        || !register_bouncer(sink).await
        || !start_bouncer(sink).await
    {
        return;
    }
    let _ = sink.step("intrusion defence is watching this host's journals").await;
}

async fn may_install(enabled: bool, sink: &EventSink) -> bool {
    if !enabled {
        let _ = sink
            .step("intrusion defence: off for this deployment (recommended, not required)")
            .await;
        return false;
    }
    if owner_removed() && !engine_configured() {
        let _ = sink.step("intrusion defence: removed by the owner, not installed again").await;
        return false;
    }
    if !have_binary("apt-get") || !have_binary("systemd-run") {
        let _ = sink
            .step("skipping intrusion defence: this build only installs packages on Debian/Ubuntu")
            .await;
        return false;
    }
    true
}

async fn install_engine(sink: &EventSink) -> bool {
    if engine_configured() {
        return true;
    }
    let _ = sink.step("installing CrowdSec, the host's intrusion defence").await;
    let script = format!(
        "set -e\n\
         export DEBIAN_FRONTEND=noninteractive\n\
         curl -fsSL {REPOSITORY_INSTALL_URL} | sh\n\
         dpkg --configure -a --force-confdef --force-confold || true\n\
         apt-get {APT_OPTIONS} install -y {ENGINE_PACKAGE}\n\
         apt-get {APT_OPTIONS} install -y {BOUNCER_PACKAGE}\n",
        APT_OPTIONS = super::packages::APT_OPTIONS,
    );
    if let Err(why) = run_outside_sandbox_from_file(&script, "installing CrowdSec", sink).await {
        let _ = sink.warn(&format!("intrusion defence is NOT installed: {why}")).await;
        return false;
    }
    if !engine_configured() {
        let _ = sink
            .warn("intrusion defence is NOT installed: CrowdSec did not finish configuring itself")
            .await;
        return false;
    }
    true
}

async fn configure_engine(sink: &EventSink) -> bool {
    if let Err(why) = write_acquisition() {
        let _ = sink.warn(&format!("could not write the CrowdSec acquisition: {why}")).await;
        return false;
    }
    if let Err(why) = pin_lapi_port() {
        let _ = sink
            .warn(&format!("could not move the CrowdSec local API off port 8080: {why}"))
            .await;
    }
    let installs: String =
        COLLECTIONS.iter().map(|name| format!("cscli collections install {name} --error || true\n")).collect();
    let _ = run_outside_sandbox(
        &format!("{installs}cscli hub update --error || true\n"),
        "installing the CrowdSec collections",
        sink,
    )
    .await;
    true
}

async fn start_engine(sink: &EventSink) -> bool {
    let started = run_outside_sandbox(
        &format!("systemctl enable --now {ENGINE_UNIT}\nsystemctl restart {ENGINE_UNIT}\n"),
        "starting CrowdSec",
        sink,
    )
    .await;
    if let Err(why) = started {
        let _ = sink.warn(&format!("CrowdSec is installed but not running: {why}")).await;
        return false;
    }
    true
}

async fn register_bouncer(sink: &EventSink) -> bool {
    match bouncer_registration_needed() {
        Ok(false) => return true,
        Err(why) => {
            let _ = sink.warn(&format!("could not read the CrowdSec bouncer's config: {why}")).await;
            return false;
        }
        Ok(true) => {}
    }
    let _ = sink.step("registering the CrowdSec bouncer with the host's local API").await;
    let config = bouncer_config_path();
    let script = format!(
        "set -e\n\
         cscli bouncers delete {BOUNCER_NAME} >/dev/null 2>&1 || true\n\
         KEY=$(cscli bouncers add {BOUNCER_NAME} -o raw)\n\
         [ -n \"$KEY\" ]\n\
         sed -i \"s|^api_key:.*|api_key: $KEY|\" {config}\n"
    );
    if let Err(why) = run_outside_sandbox_from_file(&script, "registering the CrowdSec bouncer", sink).await {
        let _ = sink.warn(&format!("the CrowdSec bouncer has no API key: {why}")).await;
        return false;
    }
    true
}

async fn start_bouncer(sink: &EventSink) -> bool {
    match bouncer_targets_its_own_table() {
        Ok(false) => {
            let _ = sink
                .warn(
                    "the CrowdSec bouncer is not aimed at its own nftables table — left stopped so \
                     it cannot write into the firewall this host manages",
                )
                .await;
            return false;
        }
        Err(why) => {
            let _ = sink.warn(&format!("could not read the CrowdSec bouncer's config: {why}")).await;
            return false;
        }
        Ok(true) => {}
    }
    let started = run_outside_sandbox(
        &format!("systemctl enable --now {BOUNCER_UNIT}\nsystemctl try-restart {BOUNCER_UNIT}\n"),
        "starting the CrowdSec firewall bouncer",
        sink,
    )
    .await;
    if let Err(why) = started {
        let _ = sink.warn(&format!("the CrowdSec bouncer is not running: {why}")).await;
        return false;
    }
    true
}

/// Is the engine INSTALLED, as opposed to merely unpacked?
pub(crate) fn engine_configured() -> bool {
    have_binary("cscli") && Path::new(&engine_config_path()).exists()
}

fn engine_config_path() -> String {
    std::env::var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG").unwrap_or_else(|_| ENGINE_CONFIG_PATH.to_string())
}

fn write_acquisition() -> std::io::Result<()> {
    let path = Path::new(ACQUISITION_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, acquisition())
}

fn credentials_path() -> String {
    std::env::var("GRYONIXNEXUSD_CROWDSEC_CREDENTIALS").unwrap_or_else(|_| CREDENTIALS_PATH.to_string())
}

fn pin_lapi_port() -> Result<(), String> {
    rewrite_scalar(&engine_config_path(), "listen_uri:", LAPI_LISTEN_ADDR)?;
    rewrite_scalar(&credentials_path(), "url:", &format!("http://{LAPI_LISTEN_ADDR}"))?;
    rewrite_scalar(&bouncer_config_path(), "api_url:", &format!("http://{LAPI_LISTEN_ADDR}/"))?;
    Ok(())
}

fn rewrite_scalar(path: &str, key: &str, value: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{path}: {err}"))?;
    let mut done = false;
    let mut changed = false;
    let rebuilt: Vec<String> = text
        .lines()
        .map(|line| {
            if done {
                return line.to_string();
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || !trimmed.starts_with(key) {
                return line.to_string();
            }
            done = true;
            let indent = &line[..line.len() - trimmed.len()];
            let replacement = format!("{indent}{key} {value}");
            if replacement != line {
                changed = true;
            }
            replacement
        })
        .collect();
    if !done {
        return Err(format!("{path}: no `{key}` line"));
    }
    if changed {
        let mut body = rebuilt.join("\n");
        if text.ends_with('\n') {
            body.push('\n');
        }
        std::fs::write(path, body).map_err(|err| format!("{path}: {err}"))?;
    }
    Ok(())
}

fn bouncer_targets_its_own_table() -> Result<bool, String> {
    let text = std::fs::read_to_string(bouncer_config_path()).map_err(|err| err.to_string())?;
    let names_our_table = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("table:"))
        .any(|line| {
            let value = line.trim_start_matches("table:").trim().trim_matches('"').trim_matches('\'');
            value == "crowdsec" || value == "crowdsec6"
        });
    Ok(names_our_table)
}

/// Overridable for tests, the same technique `systemd_run_bin` uses
fn bouncer_registration_needed() -> Result<bool, String> {
    let text = std::fs::read_to_string(bouncer_config_path()).map_err(|err| err.to_string())?;
    let key = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("api_key:"))
        .map(|line| line.trim_start_matches("api_key:").trim().trim_matches('"').trim_matches('\''))
        .unwrap_or("");
    Ok(key.is_empty() || key == UNREGISTERED_KEY)
}

fn bouncer_config_path() -> String {
    std::env::var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG")
        .unwrap_or_else(|_| BOUNCER_CONFIG_PATH.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_removal_by_the_owner_is_remembered_until_they_install_again() {
        let _env = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gnx-crowdsec-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &dir);
        assert!(!owner_removed());
        remember_removal();
        assert!(owner_removed());
        forget_removal();
        assert!(!owner_removed());
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_acquisition_reads_journals_and_never_a_log_file() {
        let text = acquisition();
        for line in text.lines().filter(|line| !line.trim_start().starts_with('#')) {
            assert!(!line.contains("filenames"), "a file acquisition parses nothing here: {line}");
            assert!(!line.contains("source: file"), "a file acquisition parses nothing here: {line}");
        }
        assert_eq!(text.matches("source: journalctl").count(), 2, "{text}");
    }

    #[test]
    fn sshd_is_matched_under_both_names_the_fleet_uses() {
        let text = acquisition();
        assert!(text.contains("_SYSTEMD_UNIT=ssh.service"), "{text}");
        assert!(text.contains("_SYSTEMD_UNIT=sshd.service"), "{text}");
    }

    #[test]
    fn every_source_carries_the_label_that_binds_it_to_a_parser() {
        let text = acquisition();
        assert_eq!(text.matches("labels:").count(), text.matches("source:").count(), "{text}");
        assert!(text.contains("type: syslog"), "{text}");
        assert!(text.contains("type: caddy"), "{text}");
        assert!(text.contains("type: Dominic-Wagner/vaultwarden"), "{text}");
    }

    #[test]
    fn the_two_sources_are_two_yaml_documents() {
        assert!(acquisition().contains("\n---\n"), "{}", acquisition());
    }

    #[test]
    fn a_collection_is_installed_for_every_source() {
        assert!(COLLECTIONS.contains(&"crowdsecurity/sshd"));
        assert!(COLLECTIONS.contains(&"crowdsecurity/caddy"));
        assert!(COLLECTIONS.contains(&"Dominic-Wagner/vaultwarden"));
    }

    static CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_bouncer_config(body: &str, check: impl FnOnce()) {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = std::env::temp_dir().join(format!("crowdsec-cfg-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bouncer.yaml");
        std::fs::write(&path, body).unwrap();
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG", &path);
        check();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_package_default_is_recognised_as_its_own_table() {
        with_bouncer_config(
            "mode: nftables\nnftables:\n  ipv4:\n    enabled: true\n    table: crowdsec\n    chain: crowdsec-chain\n",
            || assert_eq!(bouncer_targets_its_own_table(), Ok(true)),
        );
    }

    /// NEGATIVE CONTROL, and the one this module exists for
    #[test]
    fn a_bouncer_aimed_at_our_own_table_is_refused() {
        with_bouncer_config(
            "mode: nftables\nnftables:\n  ipv4:\n    enabled: true\n    table: filter\n",
            || assert_eq!(bouncer_targets_its_own_table(), Ok(false)),
        );
    }

    #[test]
    fn an_unreadable_config_is_an_error_and_not_a_false() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG", "/nonexistent/bouncer.yaml");
        let outcome = bouncer_targets_its_own_table();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG");
        assert!(outcome.is_err(), "{outcome:?}");
    }

    #[test]
    fn the_packages_placeholder_key_is_read_as_unregistered() {
        with_bouncer_config("api_url: http://127.0.0.1:8080/\napi_key: <API_KEY>\n", || {
            assert_eq!(bouncer_registration_needed(), Ok(true))
        });
    }

    #[test]
    fn an_empty_key_is_read_as_unregistered() {
        with_bouncer_config("api_key:\n", || assert_eq!(bouncer_registration_needed(), Ok(true)));
    }

    #[test]
    fn a_registered_bouncer_is_left_alone() {
        with_bouncer_config("api_key: 5d41402abc4b2a76b9719d911017c592\n", || {
            assert_eq!(bouncer_registration_needed(), Ok(false))
        });
    }

    #[test]
    fn a_quoted_table_name_is_the_same_table() {
        with_bouncer_config("nftables:\n  ipv4:\n    table: \"crowdsec\"\n", || {
            assert_eq!(bouncer_targets_its_own_table(), Ok(true))
        });
    }

    /// The bouncer must be the nftables build
    #[test]
    fn the_nftables_bouncer_is_the_one_installed() {
        assert!(BOUNCER_PACKAGE.ends_with("-nftables"), "{BOUNCER_PACKAGE}");
        assert!(!BOUNCER_PACKAGE.contains("iptables"), "{BOUNCER_PACKAGE}");
        assert_eq!(ENGINE_PACKAGE, "crowdsec");
    }

    #[test]
    fn an_unpacked_but_unconfigured_engine_does_not_count_as_installed() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", "/nonexistent/config.yaml");
        let answer = engine_configured();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG");
        assert!(!answer, "a missing config.yaml means the postinst never finished");
    }

    #[test]
    fn the_engine_is_installed_before_the_bouncer() {
        let source = include_str!("crowdsec.rs");
        let script = source.split("let script = format!(").nth(1).expect("the install script must be here");
        let engine = script.find("{ENGINE_PACKAGE}").expect("the engine must be installed");
        let bouncer = script.find("{BOUNCER_PACKAGE}").expect("the bouncer must be installed");
        assert!(engine < bouncer, "the bouncer cannot register itself before the engine exists");
    }

    #[test]
    fn the_install_script_is_staged_to_a_file() {
        let source = include_str!("crowdsec.rs");
        assert!(source.contains("run_outside_sandbox_from_file(&script"), "a multi-line ExecStart breaks the postinst");
    }

    #[test]
    fn pinning_the_lapi_port_rewrites_the_three_files_and_nothing_else() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = std::env::temp_dir().join(format!("crowdsec-lapi-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = dir.join("config.yaml");
        let creds = dir.join("local_api_credentials.yaml");
        let bouncer = dir.join("bouncer.yaml");
        std::fs::write(&engine, "api:\n  server:\n    listen_uri: 127.0.0.1:8080\n    profiles_path: /etc/crowdsec/profiles.yaml\n").unwrap();
        std::fs::write(&creds, "url: http://127.0.0.1:8080\nlogin: abc\npassword: def\n").unwrap();
        std::fs::write(&bouncer, "mode: nftables\napi_url: http://127.0.0.1:8080/\napi_key: KEY\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", &engine);
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_CREDENTIALS", &creds);
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG", &bouncer);

        assert_eq!(pin_lapi_port(), Ok(()));

        assert_eq!(
            std::fs::read_to_string(&engine).unwrap(),
            "api:\n  server:\n    listen_uri: 127.0.0.1:8237\n    profiles_path: /etc/crowdsec/profiles.yaml\n"
        );
        assert_eq!(
            std::fs::read_to_string(&creds).unwrap(),
            "url: http://127.0.0.1:8237\nlogin: abc\npassword: def\n"
        );
        assert_eq!(
            std::fs::read_to_string(&bouncer).unwrap(),
            "mode: nftables\napi_url: http://127.0.0.1:8237/\napi_key: KEY\n"
        );

        // Idempotent: a second run changes nothing and does not error.
        assert_eq!(pin_lapi_port(), Ok(()));
        assert!(std::fs::read_to_string(&engine).unwrap().contains("127.0.0.1:8237"));

        for var in ["GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", "GRYONIXNEXUSD_CROWDSEC_CREDENTIALS", "GRYONIXNEXUSD_CROWDSEC_BOUNCER_CONFIG"] {
            std::env::remove_var(var);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_lapi_port_is_not_mailcows() {
        assert_ne!(LAPI_LISTEN_ADDR, "127.0.0.1:8080");
        assert!(LAPI_LISTEN_ADDR.starts_with("127.0.0.1:"), "loopback only");
    }

    #[test]
    fn pinning_a_missing_file_is_an_error() {
        let _guard = CONFIG_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG", "/nonexistent/config.yaml");
        let outcome = pin_lapi_port();
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_ENGINE_CONFIG");
        assert!(outcome.is_err(), "{outcome:?}");
    }
}
