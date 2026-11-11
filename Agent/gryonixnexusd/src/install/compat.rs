//! What this machine cannot do for a service, found before anything is installed

use super::{odio, packaged, packages};
use crate::pb;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Limited,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub service: String,
    pub severity: Severity,
    pub code: &'static str,
    pub args: Vec<String>,
}

/// Hub parts left out on older systems
pub const LEFT_OUT_ON_OLDER_OS: &str = "myMPD, disc player, Snapcast, UPnP, Spotify";

/// The line the hub's packages target
const NEWEST_DEBIAN: &str = "Debian 13";

pub struct Facts {
    pub os_name: String,
    /// Whether libraries match Debian 13 or newer
    pub libraries_are_current: Option<bool>,
    pub has_sound_card: bool,
}

impl Facts {
    pub fn read() -> Self {
        let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        let mut facts = Self::from_os_release(&text);
        facts.has_sound_card = std::path::Path::new("/dev/snd").exists();
        facts
    }

    pub fn from_os_release(text: &str) -> Self {
        let value = |key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                .map(|raw| raw.trim().trim_matches('"').to_string())
        };
        let id = value("ID").unwrap_or_default();
        let major: Option<u32> =
            value("VERSION_ID").and_then(|version| version.split('.').next()?.parse().ok());
        let libraries_are_current = match (id.as_str(), major) {
            ("debian" | "raspbian", Some(major)) => Some(major >= 13),
            ("ubuntu", Some(major)) => Some(major >= 24),
            _ => None,
        };
        let os_name = value("PRETTY_NAME").filter(|name| !name.is_empty()).unwrap_or_else(|| "this system".to_string());
        Self { os_name, libraries_are_current, has_sound_card: true }
    }
}

fn finding(service: &str, severity: Severity, code: &'static str, args: &[&str]) -> Finding {
    Finding { service: service.to_string(), severity, code, args: args.iter().map(|arg| arg.to_string()).collect() }
}

/// Findings for one service on these facts
pub fn evaluate(service: &str, facts: &Facts, unavailable: &[String]) -> Vec<Finding> {
    let mut found = Vec::new();
    let older = facts.libraries_are_current == Some(false);
    for package in unavailable {
        found.push(finding(service, Severity::Blocked, "package_unavailable", &[package, &facts.os_name]));
    }
    if service == "mympd" && older {
        found.push(finding(service, Severity::Blocked, "needs_newer_os", &[&facts.os_name, NEWEST_DEBIAN]));
    }
    if service == odio::SERVICE_ID && older {
        found.push(finding(service, Severity::Limited, "reduced_on_older_os", &[&facts.os_name, LEFT_OUT_ON_OLDER_OS]));
    }
    if !facts.has_sound_card {
        let severity = if service == "shairport-sync" { Severity::Blocked } else { Severity::Limited };
        let plays_sound = service == "shairport-sync" || service == odio::SERVICE_ID || packaged::AUDIO_HUB_PLAYERS.contains(&service);
        if plays_sound {
            found.push(finding(service, severity, "no_sound_card", &[]));
        }
    }
    found
}

/// Packages apt cannot offer here
async fn unavailable_packages(service: &str) -> Vec<String> {
    let Some(spec) = packaged::find(service) else { return Vec::new() };
    if !packages::have_binary("apt-cache") {
        return Vec::new();
    }
    let output = tokio::process::Command::new("apt-cache").arg("policy").args(spec.packages).output().await;
    let Ok(output) = output else { return Vec::new() };
    without_candidate(spec.packages, &String::from_utf8_lossy(&output.stdout))
}

/// Packages without an apt candidate
fn without_candidate(asked: &[&str], policy: &str) -> Vec<String> {
    let mut candidates: std::collections::HashMap<&str, bool> = std::collections::HashMap::new();
    let mut current = "";
    for line in policy.lines() {
        if let Some(name) = line.strip_suffix(':').filter(|name| !name.starts_with(' ')) {
            current = name;
        } else if let Some(value) = line.trim_start().strip_prefix("Candidate:") {
            candidates.insert(current, !value.contains("(none)"));
        }
    }
    asked.iter().filter(|name| !candidates.get(*name).copied().unwrap_or(false)).map(|name| name.to_string()).collect()
}

/// `Install/CheckInstall`
pub async fn run_check(codec: crate::api::Codec, req: pb::CheckInstallRequest) -> crate::api::Resp {
    let mut findings = Vec::new();
    for service in req.services.iter().filter(|service| !service.is_empty()) {
        findings.extend(check(service).await.iter().map(Finding::to_pb));
    }
    codec.encode(&pb::CheckInstallResult { findings }).unwrap_or_else(|err| {
        crate::api::connect_error(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

pub async fn check(service: &str) -> Vec<Finding> {
    let facts = Facts::read();
    evaluate(service, &facts, &unavailable_packages(service).await)
}

impl Finding {
    /// The finding in English
    pub fn message(&self) -> String {
        let arg = |at: usize| self.args.get(at).map(String::as_str).unwrap_or("");
        let text = match self.code {
            "package_unavailable" => format!("the package {} is not available for {}", arg(0), arg(1)),
            "needs_newer_os" => format!("it needs {}, and this machine runs {}", arg(1), arg(0)),
            "reduced_on_older_os" => format!("on {} it installs without {}, which need newer system libraries", arg(0), arg(1)),
            "no_sound_card" => "this machine has no sound card (/dev/snd)".to_string(),
            other => other.to_string(),
        };
        format!("{}: {text}", self.service)
    }

    pub fn to_pb(&self) -> pb::InstallFinding {
        let severity = match self.severity {
            Severity::Limited => pb::install_finding::Severity::Limited,
            Severity::Blocked => pb::install_finding::Severity::Blocked,
        };
        pb::InstallFinding {
            service: self.service.clone(),
            severity: severity as i32,
            code: self.code.to_string(),
            args: self.args.clone(),
            message: self.message(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(os_release: &str) -> Facts {
        Facts::from_os_release(os_release)
    }

    const BOOKWORM: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n";
    const TRIXIE: &str = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n";

    #[test]
    fn the_hub_is_reduced_below_debian_13_and_whole_on_it() {
        let old = evaluate("odio", &facts(BOOKWORM), &[]);
        assert_eq!(old.len(), 1);
        assert_eq!((old[0].severity, old[0].code), (Severity::Limited, "reduced_on_older_os"));
        assert!(evaluate("odio", &facts(TRIXIE), &[]).is_empty());
    }

    #[test]
    fn mympd_is_blocked_below_debian_13() {
        let found = evaluate("mympd", &facts(BOOKWORM), &[]);
        assert_eq!((found[0].severity, found[0].code), (Severity::Blocked, "needs_newer_os"));
        assert!(evaluate("mympd", &facts(TRIXIE), &[]).is_empty());
    }

    #[test]
    fn a_package_the_system_lacks_blocks_its_service() {
        let found = evaluate("upmpdcli", &facts(BOOKWORM), &["upmpdcli".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].args, vec!["upmpdcli".to_string(), "Debian GNU/Linux 12 (bookworm)".to_string()]);
        assert!(found[0].message().contains("upmpdcli is not available for Debian GNU/Linux 12"));
    }

    #[test]
    fn an_unknown_system_is_not_accused() {
        let found = evaluate("odio", &facts("ID=arch\n"), &[]);
        assert!(found.is_empty());
        assert!(evaluate("mympd", &facts("ID=ubuntu\nVERSION_ID=\"22.04\"\n"), &[]).len() == 1);
        assert!(evaluate("mympd", &facts("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), &[]).is_empty());
    }

    #[test]
    fn a_missing_sound_card_blocks_the_speaker_and_only_warns_the_rest() {
        let mut quiet = facts(TRIXIE);
        quiet.has_sound_card = false;
        assert_eq!(evaluate("shairport-sync", &quiet, &[])[0].severity, Severity::Blocked);
        assert_eq!(evaluate("odio", &quiet, &[])[0].severity, Severity::Limited);
        assert!(evaluate("vaultwarden", &quiet, &[]).is_empty());
    }

    #[test]
    fn apt_policy_shows_which_packages_have_no_candidate() {
        let policy = "mpd:\n  Installed: (none)\n  Candidate: 0.23.12-1\n  Version table:\n     0.23.12-1 500\nupmpdcli:\n  Installed: (none)\n  Candidate: (none)\n  Version table:\n";
        assert_eq!(without_candidate(&["mpd", "upmpdcli", "ghost"], policy), vec!["upmpdcli".to_string(), "ghost".to_string()]);
    }
}
