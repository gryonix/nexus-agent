//! A private file holding the admin token the agent minted for a service

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

pub fn path_of(file: &str) -> PathBuf {
    crate::util::state_dir().join(file)
}

pub fn text(owner: &str, token: &str) -> String {
    json!({ "owner": owner, "token": token }).to_string()
}

pub fn parse(content: &str) -> Option<(String, String)> {
    let value: Value = serde_json::from_str(content).ok()?;
    let owner = value.get("owner")?.as_str()?.to_string();
    let token = value.get("token")?.as_str()?.to_string();
    (!owner.is_empty() && !token.is_empty()).then_some((owner, token))
}

pub fn read(path: &Path) -> Option<(String, String)> {
    std::fs::read_to_string(path).ok().and_then(|content| parse(&content))
}

pub fn write(path: &Path, owner: &str, token: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let staged = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&staged);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&staged)?;
    file.write_all(text(owner, token).as_bytes())?;
    file.sync_all()?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&staged, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_round_trips_and_is_private() {
        let dir = std::env::temp_dir().join(format!("gnx-token-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("token.json");
        write(&path, "root", "glpat-abcdefghijklmnopqrst").unwrap();
        assert_eq!(read(&path), Some(("root".to_string(), "glpat-abcdefghijklmnopqrst".to_string())));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(parse("not json"), None);
        assert_eq!(parse("{\"owner\":\"\",\"token\":\"x\"}"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
