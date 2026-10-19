//! SSH keys of paired devices: added to and removed from the control users' authorized_keys.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;
use tokio::process::Command;

const SCRIPT: &str = include_str!("keys_ctl.sh");
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";
const RUN_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_TRANSFER_MINUTES: i64 = 15;
const MAX_TRANSFER_MINUTES: i64 = 60;

fn ctl_path() -> String {
    std::env::var("GRYONIXNEXUSD_KEYS_CTL").unwrap_or_else(|_| {
        let dir = std::env::var("GRYONIXNEXUSD_STATE_DIR").unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string());
        format!("{dir}/keys-ctl.sh")
    })
}

fn systemd_run() -> Option<String> {
    match std::env::var("GRYONIXNEXUSD_KEYS_SYSTEMD_RUN_BIN") {
        Ok(bin) if bin.is_empty() => None,
        Ok(bin) => Some(bin),
        Err(_) => Some("systemd-run".to_string()),
    }
}

pub fn ensure_wrapper() -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let path = ctl_path();
    if std::fs::read_to_string(&path).is_ok_and(|current| current == SCRIPT) {
        return Ok(false);
    }
    let staged = format!("{path}.new");
    std::fs::write(&staged, SCRIPT)?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&staged, &path)?;
    Ok(true)
}

pub fn split_key(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.split_whitespace();
    let (kind, blob) = (parts.next()?, parts.next()?);
    let blob_ok = blob.len() >= 40 && blob.len() <= 200 && blob.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c));
    (kind == "ssh-ed25519" && blob_ok).then_some((kind, blob))
}

/// The tag a device's key carries, from the key itself
pub fn tag_for_key(blob: &str) -> String {
    let digest = Sha256::digest(blob.as_bytes());
    format!("gnx-dev-{}", hex16(&digest))
}

pub fn transfer_tag(transfer_id: &str) -> String {
    format!("gnx-xfer-{transfer_id}")
}

fn hex16(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn valid_tag(tag: &str) -> bool {
    (6..=64).contains(&tag.len()) && tag.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

async fn run_ctl(args: &[&str]) -> Result<i32, String> {
    let mut command = match systemd_run() {
        Some(bin) => {
            let mut command = Command::new(bin);
            command.args(["--quiet", "--wait", "--collect", "--pipe", "--"]).arg(ctl_path());
            command
        }
        None => Command::new(ctl_path()),
    };
    command.args(args).stdin(std::process::Stdio::null()).kill_on_drop(true);
    let output = tokio::time::timeout(RUN_TIMEOUT, command.output())
        .await
        .map_err(|_| "the key helper timed out".to_string())?
        .map_err(|err| format!("the key helper did not start: {err}"))?;
    Ok(output.status.code().unwrap_or(-1))
}

pub async fn authorize(public_key: &str, tag: &str, expires_at: i64) -> Result<bool, String> {
    let (kind, blob) = split_key(public_key).ok_or("the SSH key is not an ed25519 public key")?;
    if !valid_tag(tag) {
        return Err("bad key tag".into());
    }
    let expiry = expires_at.to_string();
    let mut changed = false;
    for user in crate::ssh_watch::control_users() {
        match run_ctl(&["add", &user, tag, kind, blob, &expiry]).await? {
            0 => changed = true,
            3 => {}
            code => return Err(format!("the key helper failed for {user} ({code})")),
        }
    }
    Ok(changed)
}

pub async fn revoke(tag: &str) -> Result<bool, String> {
    if !valid_tag(tag) {
        return Err("bad key tag".into());
    }
    let mut removed = false;
    for user in crate::ssh_watch::control_users() {
        match run_ctl(&["remove", &user, tag]).await? {
            0 => removed = true,
            4 => {}
            code => return Err(format!("the key helper failed for {user} ({code})")),
        }
    }
    Ok(removed)
}

/// Drops transfer keys whose time is up
pub async fn prune() {
    for user in crate::ssh_watch::control_users() {
        let _ = run_ctl(&["prune", &user]).await;
    }
}

pub async fn on_pair(req: &crate::pb::PairRequest) -> bool {
    let Some((_, blob)) = split_key(&req.device_public_key) else { return false };
    let added = req.authorize_ssh_key && authorize(&req.device_public_key, &tag_for_key(blob), 0).await.unwrap_or(false);
    if !req.transfer_id.is_empty() && req.transfer_id.chars().all(|c| c.is_ascii_hexdigit()) {
        let _ = revoke(&transfer_tag(&req.transfer_id)).await;
    }
    added
}

/// Removes the key a device's pairing added
pub async fn on_revoke(public_key: &str) -> bool {
    let Some((_, blob)) = split_key(public_key) else { return false };
    revoke(&tag_for_key(blob)).await.unwrap_or(false)
}

/// Installs the helper and drops expired transfer keys every hour
pub fn spawn() {
    tokio::spawn(async {
        let _ = ensure_wrapper();
        loop {
            prune().await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

pub struct Transfer {
    pub id: String,
    pub seed: [u8; 32],
    pub expires_at_ms: i64,
}

fn random_bytes<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// `ssh-ed25519 <blob>` for a 32-byte seed
pub fn public_line(seed: &[u8; 32]) -> String {
    use base64::Engine;
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    let mut blob = Vec::new();
    for part in [b"ssh-ed25519".as_slice(), key.verifying_key().as_bytes().as_slice()] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    format!("ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(blob))
}

/// A one-time key, authorized for `minutes`, handed to one export
pub async fn mint_transfer(minutes: i32, now_secs: i64) -> Result<Transfer, String> {
    let minutes = if minutes <= 0 { DEFAULT_TRANSFER_MINUTES } else { (minutes as i64).min(MAX_TRANSFER_MINUTES) };
    let seed: [u8; 32] = random_bytes().map_err(|err| format!("no randomness: {err}"))?;
    let id = hex16(&random_bytes::<8>().map_err(|err| format!("no randomness: {err}"))?);
    let expires_at = now_secs + minutes * 60;
    let line = public_line(&seed);
    if !authorize(&line, &transfer_tag(&id), expires_at).await? {
        return Err("no control user could take the key".into());
    }
    Ok(Transfer { id, seed, expires_at_ms: expires_at * 1000 })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGGXGwG07/Xo7QRceaYftIbaIii+zfpZ5wulUpfayeon app";

    #[test]
    fn only_an_ed25519_public_key_is_taken() {
        assert!(split_key(KEY).is_some());
        assert!(split_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ app").is_none());
        assert!(split_key("ssh-ed25519 $(touch /x)").is_none());
        assert!(split_key("").is_none());
    }

    #[test]
    fn a_device_tag_comes_from_its_key_alone() {
        let (_, blob) = split_key(KEY).unwrap();
        assert_eq!(tag_for_key(blob), tag_for_key(blob));
        assert!(valid_tag(&tag_for_key(blob)));
        assert!(!valid_tag("bad tag; rm"));
    }

    #[test]
    fn a_seed_gives_a_well_formed_public_line() {
        let line = public_line(&[7u8; 32]);
        assert!(split_key(&line).is_some(), "{line}");
    }

    #[test]
    fn the_helper_adds_removes_and_prunes_only_tagged_lines() {
        let home = std::env::temp_dir().join(format!("gnx-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let file = home.join(".ssh/authorized_keys");
        std::fs::write(&file, "ssh-ed25519 AAAAORIGINAL install\n").unwrap();
        let script = std::env::temp_dir().join(format!("gnx-keys-ctl-{}.sh", std::process::id()));
        std::fs::write(&script, SCRIPT).unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("bash")
                .arg(&script)
                .args(args)
                .env("GNX_TEST_HOME", &home)
                .status()
                .unwrap()
                .code()
                .unwrap()
        };
        assert_eq!(run(&["add", "u", "gnx-dev-aaaaaa", "ssh-ed25519", "AAAANEWBLOB", "0"]), 0);
        assert_eq!(run(&["add", "u", "gnx-dev-aaaaaa", "ssh-ed25519", "AAAANEWBLOB", "0"]), 3);
        assert_eq!(run(&["add", "u", "gnx-xfer-1111", "ssh-ed25519", "AAAAGONEBLOB", "1"]), 0);
        run(&["prune", "u"]);
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("AAAAORIGINAL") && text.contains("AAAANEWBLOB") && !text.contains("AAAAGONEBLOB"), "{text}");
        assert_eq!(run(&["remove", "u", "gnx-dev-aaaaaa"]), 0);
        assert_eq!(run(&["remove", "u", "gnx-dev-aaaaaa"]), 4);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "ssh-ed25519 AAAAORIGINAL install\n");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_file(&script);
    }
}
