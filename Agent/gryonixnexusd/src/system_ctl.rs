//! The server's own package updater, put on the host by the agent.

use std::os::unix::fs::PermissionsExt;

/// Where the updater lives; sudo grants name this path
pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-system-ctl.sh";

/// The updater, shipped inside the agent
pub const SCRIPT: &str = include_str!("../../bootstrap/system-ctl.sh");

fn script_path() -> String {
    std::env::var("GRYONIXNEXUSD_SYSTEM_CTL_PATH").unwrap_or_else(|_| SCRIPT_PATH.to_string())
}

/// Writes the updater when it is missing or differs
pub fn install_if_needed() -> Result<bool, String> {
    let path = script_path();
    if std::fs::read_to_string(&path).is_ok_and(|text| text == SCRIPT) {
        return Ok(false);
    }
    let staged = format!("{path}.new");
    std::fs::write(&staged, SCRIPT).map_err(|err| format!("could not write {staged}: {err}"))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("could not set the mode of {staged}: {err}"))?;
    std::fs::rename(&staged, &path).map_err(|err| format!("could not move {staged}: {err}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_updater_is_written_once_and_executable() {
        let dir = std::env::temp_dir().join(format!("system-ctl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("system-ctl.sh");
        std::env::set_var("GRYONIXNEXUSD_SYSTEM_CTL_PATH", &path);
        assert_eq!(install_if_needed(), Ok(true));
        assert_eq!(install_if_needed(), Ok(false), "an unchanged updater is left alone");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        assert!(std::fs::read_to_string(&path).unwrap().starts_with("#!/bin/bash"));
        std::env::remove_var("GRYONIXNEXUSD_SYSTEM_CTL_PATH");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_updater_names_its_own_path() {
        assert!(SCRIPT.contains(&format!("SELF={SCRIPT_PATH}")));
    }
}
