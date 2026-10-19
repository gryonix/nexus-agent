//! The two machines' ends of a service move: a one-use key on the old one, a directory and one `authorized_keys` line on the new one, and the cleanup

use std::path::{Path, PathBuf};
use std::process::Stdio;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::{backup, pb};

const STATE_DIR_ENV: &str = "GRYONIXNEXUSD_STATE_DIR";
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";
const INCOMING_ENV: &str = "GRYONIXNEXUSD_MOVE_INCOMING";
const INCOMING_FALLBACK: &str = "/var/lib/gryonixnexus/incoming";
const HOST_KEY_DIR_ENV: &str = "GRYONIXNEXUSD_MOVE_HOST_KEY_DIR";
const HOST_KEY_DIR_FALLBACK: &str = "/etc/ssh";
const KEYGEN_ENV: &str = "GRYONIXNEXUSD_MOVE_KEYGEN";
const SLACK_BYTES: i64 = 256 * 1024 * 1024;
pub const DATA_FILE: &str = "data.tar";

pub fn valid_transfer_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn safe_name(text: &str) -> bool {
    !text.is_empty() && text.len() <= 255 && text.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

pub fn safe_host(text: &str) -> bool {
    !text.is_empty() && text.len() <= 255 && text.chars().all(|c| c.is_ascii_alphanumeric() || ".:-_".contains(c))
}

fn refuse(message: &str) -> Resp {
    connect_error(StatusCode::BAD_REQUEST, "invalid_argument", message)
}

fn failed(message: &str) -> Resp {
    connect_error(StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition", message)
}

fn internal(message: &str) -> Resp {
    connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
}

pub fn transfer_dir(id: &str) -> PathBuf {
    let state = std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string());
    PathBuf::from(state).join("move").join(id)
}

pub fn incoming_dir(id: &str) -> PathBuf {
    let root = std::env::var(INCOMING_ENV).unwrap_or_else(|_| INCOMING_FALLBACK.to_string());
    PathBuf::from(root).join(id)
}

pub fn key_path(id: &str) -> PathBuf {
    transfer_dir(id).join("key")
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| internal(&err.to_string()))
}

fn make_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// One public key line, `type base64`, nothing else.
fn key_body(line: &str) -> Option<String> {
    let mut fields = line.split_whitespace();
    let (kind, body) = (fields.next()?, fields.next()?);
    let shaped = kind == "ssh-ed25519" && body.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c));
    shaped.then(|| format!("{kind} {body}"))
}

pub async fn prepare_send(codec: Codec, req: pb::PrepareMoveSendRequest) -> Resp {
    if !valid_transfer_id(&req.transfer_id) {
        return refuse("the transfer id must be 32 lowercase hex characters");
    }
    let dir = transfer_dir(&req.transfer_id);
    if let Err(err) = make_private_dir(&dir) {
        return internal(&format!("could not make {}: {err}", dir.display()));
    }
    let key = key_path(&req.transfer_id);
    if !key.exists() {
        if let Err(why) = generate_key(&key, &req.transfer_id).await {
            return internal(&why);
        }
    }
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap_or_default();
    match key_body(&public) {
        Some(public_key) => encode(codec, &pb::PrepareMoveSendResponse { public_key }),
        None => internal("the transfer key could not be read back"),
    }
}

async fn generate_key(key: &Path, id: &str) -> Result<(), String> {
    let bin = std::env::var(KEYGEN_ENV).unwrap_or_else(|_| "ssh-keygen".to_string());
    let comment = format!("gryonixnexus-move-{id}");
    let status = tokio::process::Command::new(bin)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", &comment, "-f"])
        .arg(key)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|err| format!("could not run ssh-keygen: {err}"))?;
    status.success().then_some(()).ok_or_else(|| "ssh-keygen could not make the transfer key".to_string())
}

struct Account {
    uid: u32,
    gid: u32,
}

fn lookup_account(name: &str) -> Option<Account> {
    let user = std::ffi::CString::new(name).ok()?;
    let entry = unsafe { libc::getpwnam(user.as_ptr()) };
    if entry.is_null() {
        return None;
    }
    // SAFETY: checked non-null above.
    Some(Account { uid: unsafe { (*entry).pw_uid }, gid: unsafe { (*entry).pw_gid } })
}

fn give_to(path: &Path, account: &Account) -> Result<(), String> {
    let text = std::ffi::CString::new(path.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: plain chown on a NUL-terminated path.
    let done = unsafe { libc::chown(text.as_ptr(), account.uid, account.gid) };
    (done == 0).then_some(()).ok_or_else(|| format!("could not hand {} to the login user", path.display()))
}

pub fn free_bytes(path: &Path) -> Option<i64> {
    let text = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs fills the struct for a NUL-terminated path.
    let done = unsafe { libc::statvfs(text.as_ptr(), &mut stats) };
    (done == 0).then(|| stats.f_bavail as i64 * stats.f_frsize as i64)
}

fn host_keys() -> String {
    let dir = std::env::var(HOST_KEY_DIR_ENV).unwrap_or_else(|_| HOST_KEY_DIR_FALLBACK.to_string());
    let mut lines = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return String::new() };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !(name.starts_with("ssh_host_") && name.ends_with("_key.pub")) {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
        let mut fields = text.split_whitespace();
        if let (Some(kind), Some(body)) = (fields.next(), fields.next()) {
            lines.push(format!("{kind} {body}"));
        }
    }
    lines.sort();
    lines.join("\n")
}

pub fn space_needed(expected_bytes: i64) -> i64 {
    expected_bytes.max(0).saturating_mul(2).saturating_add(SLACK_BYTES)
}

fn check_receive_request(req: &pb::PrepareMoveReceiveRequest) -> Result<(String, backup::Target, Account), Resp> {
    if !valid_transfer_id(&req.transfer_id) {
        return Err(refuse("the transfer id must be 32 lowercase hex characters"));
    }
    let target = backup::resolve(&req.service_id).map_err(|r| r.response())?;
    let account = safe_name(&req.control_user)
        .then(|| lookup_account(&req.control_user))
        .flatten()
        .ok_or_else(|| failed("the login user does not exist on this machine"))?;
    let key = key_body(&req.public_key).ok_or_else(|| refuse("the transfer key is not an ed25519 public key"))?;
    Ok((key, target, account))
}

pub async fn prepare_receive(codec: Codec, req: pb::PrepareMoveReceiveRequest) -> Resp {
    let (key, target, account) = match check_receive_request(&req) {
        Ok(checked) => checked,
        Err(response) => return response,
    };
    let hosts = host_keys();
    if hosts.is_empty() {
        return failed("this machine's SSH host keys could not be read");
    }
    let dir = incoming_dir(&req.transfer_id);
    if let Err(err) = make_private_dir(&dir).map_err(|e| e.to_string()).and_then(|()| give_to(&dir, &account)) {
        return internal(&err);
    }
    let free = [free_bytes(&dir), free_bytes(&target.directory).or_else(|| free_bytes(Path::new("/")))]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(0);
    if free < space_needed(req.expected_bytes) {
        let _ = std::fs::remove_dir_all(&dir);
        return failed("this machine does not have enough free space for the service's data");
    }
    let line = format!(
        "restrict,command=\"cat > {}/{DATA_FILE}\" {key} gryonixnexus-move-{}",
        dir.display(),
        req.transfer_id
    );
    encode(codec, &pb::PrepareMoveReceiveResponse { authorized_key_line: line, host_keys: hosts, free_bytes: free })
}

pub async fn discard(codec: Codec, req: pb::DiscardMoveTransferRequest) -> Resp {
    if !valid_transfer_id(&req.transfer_id) {
        return refuse("the transfer id must be 32 lowercase hex characters");
    }
    for dir in [transfer_dir(&req.transfer_id), incoming_dir(&req.transfer_id)] {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return internal(&format!("could not remove {}: {err}", dir.display())),
        }
    }
    encode(codec, &pb::DiscardMoveTransferResponse {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::STATE_DIR_ENV_LOCK;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn only_32_lowercase_hex_characters_name_a_transfer() {
        assert!(valid_transfer_id(ID));
        for bad in ["", "../x", &ID.to_uppercase(), &ID[..31], &format!("{ID}0"), "g123456789abcdef0123456789abcdef"] {
            assert!(!valid_transfer_id(bad), "{bad}");
        }
    }

    #[test]
    fn names_and_hosts_cannot_carry_shell_or_path_characters() {
        assert!(safe_name("server-user") && safe_host("10.0.0.5") && safe_host("fd00::5"));
        for bad in ["a b", "a/b", "a;b", "a\"b", "", "$(x)"] {
            assert!(!safe_name(bad) && !safe_host(bad), "{bad}");
        }
    }

    #[test]
    fn a_key_line_keeps_its_type_and_body_and_drops_the_comment() {
        assert_eq!(key_body("ssh-ed25519 AAAAC3Nza+/= comment here\n").as_deref(), Some("ssh-ed25519 AAAAC3Nza+/="));
        assert_eq!(key_body("ssh-rsa AAAA x"), None);
        assert_eq!(key_body("ssh-ed25519 AA\"AA"), None);
        assert_eq!(key_body(""), None);
    }

    #[test]
    fn the_space_a_move_needs_counts_the_archive_twice() {
        assert_eq!(space_needed(100), 200 + SLACK_BYTES);
        assert_eq!(space_needed(-5), SLACK_BYTES);
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gnx-move-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn stub_keygen(dir: &Path, works: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("keygen.sh");
        let body = if works {
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -f ] && f=\"$2\"; shift; done\necho k > \"$f\"\necho 'ssh-ed25519 AAAAtest gryonixnexus-move' > \"$f.pub\"\n"
        } else {
            "#!/bin/sh\nexit 1\n"
        };
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    async fn body_text(resp: Resp) -> String {
        use http_body_util::BodyExt;
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string()
    }

    #[tokio::test]
    async fn the_sending_machine_makes_one_key_and_gives_back_its_public_half() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("send");
        std::env::set_var(STATE_DIR_ENV, &dir);
        std::env::set_var(KEYGEN_ENV, stub_keygen(&dir, true));
        let resp = prepare_send(Codec::Json, pb::PrepareMoveSendRequest { transfer_id: ID.into() }).await;
        let text = body_text(resp).await;
        assert!(text.contains("ssh-ed25519 AAAAtest"), "{text}");
        assert!(!text.contains("gryonixnexus-move"), "the comment stays out of the answer");
        let again = prepare_send(Codec::Json, pb::PrepareMoveSendRequest { transfer_id: ID.into() }).await;
        assert!(body_text(again).await.contains("AAAAtest"));
        std::env::remove_var(STATE_DIR_ENV);
        std::env::remove_var(KEYGEN_ENV);
    }

    #[tokio::test]
    async fn a_failing_key_generator_and_a_bad_id_are_refused_by_name() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("sendbad");
        std::env::set_var(STATE_DIR_ENV, &dir);
        std::env::set_var(KEYGEN_ENV, stub_keygen(&dir, false));
        let bad = prepare_send(Codec::Json, pb::PrepareMoveSendRequest { transfer_id: "../..".into() }).await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let broken = prepare_send(Codec::Json, pb::PrepareMoveSendRequest { transfer_id: ID.into() }).await;
        assert_eq!(broken.status(), StatusCode::INTERNAL_SERVER_ERROR);
        std::env::remove_var(STATE_DIR_ENV);
        std::env::remove_var(KEYGEN_ENV);
    }

    #[tokio::test]
    async fn discarding_removes_the_key_and_the_directory_and_can_be_repeated() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("discard");
        std::env::set_var(STATE_DIR_ENV, dir.join("state"));
        std::env::set_var(INCOMING_ENV, dir.join("incoming"));
        std::fs::create_dir_all(transfer_dir(ID)).unwrap();
        std::fs::create_dir_all(incoming_dir(ID)).unwrap();
        std::fs::write(incoming_dir(ID).join(DATA_FILE), b"x").unwrap();
        for _ in 0..2 {
            let resp = discard(Codec::Json, pb::DiscardMoveTransferRequest { transfer_id: ID.into() }).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        assert!(!transfer_dir(ID).exists() && !incoming_dir(ID).exists());
        std::env::remove_var(STATE_DIR_ENV);
        std::env::remove_var(INCOMING_ENV);
    }

    #[test]
    fn host_keys_are_read_from_the_public_key_files_only() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("hostkeys");
        std::fs::write(dir.join("ssh_host_ed25519_key.pub"), "ssh-ed25519 AAAAhost root@box\n").unwrap();
        std::fs::write(dir.join("ssh_host_ed25519_key"), "PRIVATE").unwrap();
        std::fs::write(dir.join("sshd_config"), "Port 22").unwrap();
        std::env::set_var(HOST_KEY_DIR_ENV, &dir);
        assert_eq!(host_keys(), "ssh-ed25519 AAAAhost");
        std::env::remove_var(HOST_KEY_DIR_ENV);
    }
}
