//! Add-on programs beside the core, put in place only while needed.

use std::path::PathBuf;
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

fn root() -> PathBuf {
    std::env::var("GRYONIXNEXUSD_MODULES_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/usr/local/lib/gryonixnexus"))
}

/// Where the installer leaves each module ready
pub fn cached(module: &Module) -> PathBuf {
    root().join("modules-cache").join(module.program)
}

/// Where an active module runs from
pub fn active(module: &Module) -> PathBuf {
    root().join("modules").join(module.program)
}

pub fn is_active(module: &Module) -> bool {
    active(module).is_file()
}

/// Puts a module in place from the installer's copy
pub fn activate(module: &Module) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let from = cached(module);
    if !from.is_file() {
        return Err(format!("the {} module is not on this server; update the agent first", module.name));
    }
    let to = active(module);
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    }
    let staged = to.with_extension("new");
    std::fs::copy(&from, &staged).map_err(|err| format!("could not copy the {} module: {err}", module.name))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|err| err.to_string())?;
    std::fs::rename(&staged, &to).map_err(|err| err.to_string())
}

/// Keeps a new copy ready; refreshes the active one
pub fn store(module: &Module, source: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let cache = cached(module);
    if let Some(dir) = cache.parent() {
        std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    }
    let staged = cache.with_extension("new");
    std::fs::copy(source, &staged).map_err(|err| err.to_string())?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|err| err.to_string())?;
    std::fs::rename(&staged, &cache).map_err(|err| err.to_string())?;
    if is_active(module) {
        activate(module)?;
    }
    Ok(())
}

/// Takes an active module away; the installer's copy stays
pub fn deactivate(module: &Module) {
    let _ = std::fs::remove_file(active(module));
}

/// Runs a module verb, handing it input, returning its output
pub async fn run(module: &Module, verb: &str, input: &str) -> Result<String, String> {
    if !is_active(module) {
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
        let dir = std::env::temp_dir().join(format!("gnx-modules-{}", std::process::id()));
        std::env::set_var("GRYONIXNEXUSD_MODULES_DIR", &dir);
        assert!(activate(&AUDIO).is_err(), "no installer copy yet");
        std::fs::create_dir_all(dir.join("modules-cache")).unwrap();
        std::fs::write(cached(&AUDIO), b"#!/bin/sh\n").unwrap();
        activate(&AUDIO).unwrap();
        assert!(is_active(&AUDIO));
        assert_eq!(health().len(), 1);
        settle_audio(&["odio".to_string()]);
        assert!(is_active(&AUDIO));
        settle_audio(&["vaultwarden".to_string()]);
        assert!(!is_active(&AUDIO));
        assert!(cached(&AUDIO).is_file());
        let _ = std::fs::remove_dir_all(dir);
        std::env::remove_var("GRYONIXNEXUSD_MODULES_DIR");
    }
}
