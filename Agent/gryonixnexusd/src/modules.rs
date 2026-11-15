//! Add-on programs beside the core, put in place only while needed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::pb;

/// One module: its name and program
pub struct Module {
    pub name: &'static str,
    pub program: &'static str,
}

pub const AUDIO: Module = Module { name: "audio", program: "gryonixnexus-audio" };

pub const ALL: &[Module] = &[AUDIO];

const RUN_TIMEOUT: Duration = Duration::from_secs(20);

fn installer_root() -> PathBuf {
    std::env::var("GRYONIXNEXUSD_MODULES_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/usr/local/lib/gryonixnexus"))
}

/// The installer's copy; the agent only reads it
fn installed(module: &Module) -> PathBuf {
    installer_root().join("modules-cache").join(module.program)
}

/// The copy an agent update leaves ready
fn updated(module: &Module) -> PathBuf {
    crate::util::state_dir().join("modules-cache").join(module.program)
}

fn modified(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().filter(|meta| meta.is_file())?.modified().ok()
}

/// The newest ready copy of a module
pub fn cached(module: &Module) -> Option<PathBuf> {
    [updated(module), installed(module)].into_iter().filter(|path| path.is_file()).max_by_key(|path| modified(path))
}

/// Where an active module runs from
pub fn active(module: &Module) -> PathBuf {
    crate::util::state_dir().join("modules").join(module.program)
}

pub fn is_active(module: &Module) -> bool {
    active(module).is_file()
}

/// Copies a program into place under a temporary name first
fn place(source: &Path, to: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    }
    let staged = to.with_extension("new");
    std::fs::copy(source, &staged).map_err(|err| format!("could not write {}: {err}", staged.display()))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|err| err.to_string())?;
    std::fs::rename(&staged, to).map_err(|err| err.to_string())
}

/// Puts a module in place from its newest ready copy
pub fn activate(module: &Module) -> Result<(), String> {
    let Some(from) = cached(module) else {
        return Err(format!("the {} module is not on this server; update the agent first", module.name));
    };
    place(&from, &active(module)).map_err(|why| format!("the {} module could not be put in place: {why}", module.name))
}

/// Keeps a new copy ready; refreshes the active one
pub fn store(module: &Module, source: &Path) -> Result<(), String> {
    place(source, &updated(module))?;
    if is_active(module) {
        activate(module)?;
    }
    Ok(())
}

/// Whether a ready copy is newer than the active one
fn is_stale(module: &Module) -> bool {
    let newest = cached(module).and_then(|path| modified(&path));
    matches!((newest, modified(&active(module))), (Some(ready), Some(running)) if ready > running)
}

/// Takes an active module away; the installer's copy stays
pub fn deactivate(module: &Module) {
    let _ = std::fs::remove_file(active(module));
}

/// Runs a module verb, handing it input, returning its output
pub async fn run(module: &Module, verb: &str, input: &str) -> Result<String, String> {
    if !is_active(module) || is_stale(module) {
        activate(module)?;
    }
    let mut child = tokio::process::Command::new(active(module))
        .arg(verb)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("the {} module did not start: {err}", module.name))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes()).await;
    }
    let output = tokio::time::timeout(RUN_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("the {} module timed out", module.name))?
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Active modules, for the agent's own health
pub fn health() -> Vec<pb::AgentModule> {
    ALL.iter()
        .filter(|module| is_active(module))
        .map(|module| pb::AgentModule {
            name: module.name.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            size_bytes: std::fs::metadata(active(module)).map(|m| m.len()).unwrap_or_default(),
            running: false,
        })
        .collect()
}

/// Audio services whose presence keeps the audio module
pub const AUDIO_SERVICES: &[&str] =
    &["shairport-sync", "uxplay", "odio", "snapserver", "snapclient", "upmpdcli", "bluealsa", "raspotify", "mympd"];

/// Drops the audio module when no audio service is left
pub fn settle_audio(installed: &[String]) {
    if !installed.iter().any(|id| AUDIO_SERVICES.contains(&id.as_str())) {
        deactivate(&AUDIO);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_is_put_in_place_and_taken_away() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!("gnx-modules-{}", std::process::id()));
        std::env::set_var("GRYONIXNEXUSD_MODULES_DIR", dir.join("installer"));
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", dir.join("state"));
        assert!(activate(&AUDIO).is_err(), "no installer copy yet");
        std::fs::create_dir_all(dir.join("installer/modules-cache")).unwrap();
        std::fs::write(installed(&AUDIO), b"#!/bin/sh\n").unwrap();
        activate(&AUDIO).unwrap();
        assert!(active(&AUDIO).starts_with(dir.join("state")), "the agent writes only its own directory");
        assert_eq!(health().len(), 1);
        settle_audio(&["odio".to_string()]);
        assert!(is_active(&AUDIO));

        let fresh = dir.join("fresh");
        std::fs::write(&fresh, b"#!/bin/sh\n# newer\n").unwrap();
        store(&AUDIO, &fresh).unwrap();
        assert_eq!(cached(&AUDIO), Some(updated(&AUDIO)), "an update's copy wins over the installer's");
        assert_eq!(std::fs::read(active(&AUDIO)).unwrap(), std::fs::read(&fresh).unwrap());

        settle_audio(&["vaultwarden".to_string()]);
        assert!(!is_active(&AUDIO));
        assert!(cached(&AUDIO).is_some());
        let _ = std::fs::remove_dir_all(dir);
        std::env::remove_var("GRYONIXNEXUSD_MODULES_DIR");
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
    }
}
