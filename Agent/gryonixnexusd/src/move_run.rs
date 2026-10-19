//! The two long jobs of a service move: sending a backup archive to the
//! new machine, and checking and unpacking what arrived there.
//!
//! Both are journalled runs, so the app can close while they go on.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::move_transfer::{incoming_dir, key_path, safe_host, safe_name, transfer_dir, valid_transfer_id, DATA_FILE};
use crate::{backup, pb};

const TAR_ENV: &str = "GRYONIXNEXUSD_MOVE_TAR";
const SSH_ENV: &str = "GRYONIXNEXUSD_MOVE_SSH";
const RUN_TIMEOUT: Duration = Duration::from_secs(8 * 3600);
const CHUNK: usize = 256 * 1024;
const PROGRESS_EVERY: Duration = Duration::from_secs(10);
const STDERR_KEPT: usize = 4000;

struct SendPlan {
    service_id: String,
    transfer_id: String,
    directory: PathBuf,
    name: String,
    host: String,
    port: u16,
    user: String,
    known_hosts: String,
}

struct Sent {
    bytes: u64,
    sha256: String,
}

struct Sink {
    tx: Sender<Bytes>,
    codec: Codec,
    service_id: String,
    journal: Option<crate::jobs::Journal>,
}

impl Sink {
    fn new(tx: Sender<Bytes>, codec: Codec, service_id: &str) -> Self {
        let journal = crate::jobs::Journal::open(pb::JobKind::Move, service_id);
        Self { tx, codec, service_id: service_id.to_string(), journal }
    }

    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::MoveEvent {
        pb::MoveEvent {
            phase: phase as i32,
            service_id: self.service_id.clone(),
            job_id: crate::jobs::id_of(&self.journal),
            ..Default::default()
        }
    }

    async fn send(&self, event: pb::MoveEvent) {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let _ = self.tx.send(envelope(0x00, &self.codec.encode_payload(&event))).await;
    }

    async fn started(&self) {
        self.send(self.event(pb::ServiceOperationPhase::Started)).await;
    }

    async fn progress(&self, text: String) {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = "stdout".to_string();
        event.text = text;
        self.send(event).await;
    }

    async fn completed(&self, fill: impl FnOnce(&mut pb::MoveEvent)) {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        fill(&mut event);
        self.send(event).await;
    }

    async fn fail(&self, message: &str) {
        crate::jobs::finish(&self.journal, Some(message));
        let _ = self.tx.send(error_trailer("internal", message)).await;
    }
}

fn refuse(message: &str) -> Resp {
    connect_error(StatusCode::BAD_REQUEST, "invalid_argument", message)
}

fn precondition(message: &str) -> Resp {
    connect_error(StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition", message)
}

fn host_key_lines(text: &str) -> Option<Vec<String>> {
    let lines: Vec<String> = text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    let shaped = |line: &String| {
        let mut fields = line.split(' ');
        let (kind, body, rest) = (fields.next(), fields.next(), fields.next());
        kind.is_some_and(|k| k.starts_with("ssh-") || k.starts_with("ecdsa-"))
            && body.is_some_and(|b| !b.is_empty() && b.chars().all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)))
            && rest.is_none()
    };
    (!lines.is_empty() && lines.iter().all(shaped)).then_some(lines)
}

fn known_hosts(host: &str, port: u16, keys: &[String]) -> String {
    let name = if port == 22 { host.to_string() } else { format!("[{host}]:{port}") };
    keys.iter().map(|key| format!("{name} {key}\n")).collect()
}

fn check_send(req: &pb::SendMoveDataRequest) -> Result<SendPlan, Resp> {
    if !valid_transfer_id(&req.transfer_id) {
        return Err(refuse("the transfer id must be 32 lowercase hex characters"));
    }
    let target = backup::resolve(&req.service_id).map_err(|r| r.response())?;
    backup::validate_delete_path(&req.archive_path, &target.directory).map_err(|r| r.response())?;
    let name = req.archive_path.rsplit('/').next().unwrap_or_default().to_string();
    let port = u16::try_from(req.port).ok().filter(|p| *p != 0).unwrap_or(22);
    if !safe_host(&req.host) || !safe_name(&req.user) {
        return Err(refuse("the target machine's address or user has characters the agent will not pass to ssh"));
    }
    let keys = host_key_lines(&req.host_keys).ok_or_else(|| refuse("the target machine's host keys are missing or malformed"))?;
    if !key_path(&req.transfer_id).exists() {
        return Err(precondition("this transfer has no key; prepare it first"));
    }
    if std::fs::symlink_metadata(&req.archive_path).is_err() {
        return Err(precondition("the backup archive is not there any more"));
    }
    Ok(SendPlan {
        service_id: req.service_id.clone(),
        transfer_id: req.transfer_id.clone(),
        directory: target.directory,
        name,
        host: req.host.clone(),
        port,
        known_hosts: known_hosts(&req.host, port, &keys),
        user: req.user.clone(),
    })
}

pub async fn send_data(codec: Codec, req: pb::SendMoveDataRequest) -> Resp {
    let plan = match check_send(&req) {
        Ok(plan) => plan,
        Err(response) => return response,
    };
    let claim = match crate::jobs::OperationClaim::acquire("service", &plan.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let _claim = claim;
        let sink = Sink::new(tx, codec, &plan.service_id);
        sink.started().await;
        match pipe_archive(&plan, &sink).await {
            Ok(sent) => {
                let name = plan.name.clone();
                sink.completed(|e| (e.bytes, e.sha256, e.archive_name) = (sent.bytes as i64, sent.sha256, name)).await;
            }
            Err(why) => sink.fail(&why).await,
        }
    });
    stream_response(matches!(codec, Codec::Json), rx)
}

fn bin(env: &str, fallback: &str) -> String {
    std::env::var(env).unwrap_or_else(|_| fallback.to_string())
}

fn ssh_args(plan: &SendPlan, known: &Path) -> Vec<String> {
    let options = [
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "ConnectTimeout=20",
        "ServerAliveInterval=30",
        "LogLevel=ERROR",
    ];
    let mut args: Vec<String> = vec!["-T".into(), "-F".into(), "/dev/null".into()];
    for option in options {
        args.extend(["-o".to_string(), option.to_string()]);
    }
    args.extend(["-o".to_string(), format!("UserKnownHostsFile={}", known.display())]);
    args.extend(["-i".to_string(), key_path(&plan.transfer_id).display().to_string()]);
    args.extend(["-p".to_string(), plan.port.to_string(), format!("{}@{}", plan.user, plan.host)]);
    args.push("cat > /dev/null".to_string());
    args
}

fn drain(stream: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>) -> tokio::task::JoinHandle<String> {
    tokio::spawn(async move {
        let mut kept = Vec::new();
        if let Some(mut stream) = stream {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let room = STDERR_KEPT.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
        String::from_utf8_lossy(&kept).trim().to_string()
    })
}

async fn copy_hashed(
    from: &mut tokio::process::ChildStdout,
    to: &mut tokio::process::ChildStdin,
    sink: &Sink,
) -> Result<Sent, ()> {
    let (mut hasher, mut total) = (Sha256::new(), 0u64);
    let mut buf = vec![0u8; CHUNK];
    let mut last = tokio::time::Instant::now();
    loop {
        let n = from.read(&mut buf).await.map_err(|_| ())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
        to.write_all(&buf[..n]).await.map_err(|_| ())?;
        if last.elapsed() >= PROGRESS_EVERY {
            last = tokio::time::Instant::now();
            sink.progress(format!("sent {} MiB", total / (1024 * 1024))).await;
        }
    }
    to.shutdown().await.map_err(|_| ())?;
    Ok(Sent { bytes: total, sha256: format!("{:x}", hasher.finalize()) })
}

async fn pipe_archive(plan: &SendPlan, sink: &Sink) -> Result<Sent, String> {
    let known = transfer_dir(&plan.transfer_id).join("known_hosts");
    std::fs::write(&known, &plan.known_hosts).map_err(|e| format!("could not write the host key file: {e}"))?;
    let mut tar = tokio::process::Command::new(bin(TAR_ENV, "tar"))
        .arg("-C").arg(&plan.directory).args(["-cf", "-", "--"]).arg(&plan.name)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true)
        .spawn().map_err(|e| format!("could not run tar: {e}"))?;
    let mut ssh = tokio::process::Command::new(bin(SSH_ENV, "ssh"))
        .args(ssh_args(plan, &known))
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true)
        .spawn().map_err(|e| format!("could not run ssh: {e}"))?;
    sink.progress(format!("sending {} to {}", plan.name, plan.host)).await;
    let (tar_err, ssh_err) = (drain(tar.stderr.take()), drain(ssh.stderr.take()));
    let (mut out, mut input) = (tar.stdout.take().ok_or("tar has no output")?, ssh.stdin.take().ok_or("ssh has no input")?);
    let copied = tokio::time::timeout(RUN_TIMEOUT, copy_hashed(&mut out, &mut input, sink)).await;
    drop(input);
    let (tar_status, ssh_status) = (tar.wait().await, ssh.wait().await);
    let (tar_text, ssh_text) = (tar_err.await.unwrap_or_default(), ssh_err.await.unwrap_or_default());
    if matches!(ssh_status, Ok(s) if !s.success()) || ssh_status.is_err() || copied.is_err() {
        let why = if copied.is_err() { "the transfer timed out".to_string() } else { ssh_text };
        return Err(format!("the copy to {} failed: {}", plan.host, if why.is_empty() { "ssh stopped".into() } else { why }));
    }
    if matches!(tar_status, Ok(s) if !s.success()) {
        return Err(format!("reading the archive failed: {tar_text}"));
    }
    copied.ok().and_then(Result::ok).ok_or_else(|| format!("the copy to {} was cut short: {ssh_text}", plan.host))
}

struct AcceptPlan {
    service_id: String,
    transfer_id: String,
    directory: PathBuf,
    sha256: String,
    bytes: u64,
    name: String,
}

fn check_accept(req: &pb::AcceptMoveDataRequest) -> Result<AcceptPlan, Resp> {
    if !valid_transfer_id(&req.transfer_id) {
        return Err(refuse("the transfer id must be 32 lowercase hex characters"));
    }
    let target = backup::resolve(&req.service_id).map_err(|r| r.response())?;
    let hex = req.sha256.len() == 64 && req.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex || req.bytes < 0 {
        return Err(refuse("the checksum or the size of the transfer is malformed"));
    }
    if !safe_name(&req.archive_name) || req.archive_name.starts_with('.') || req.archive_name == "incoming" {
        return Err(refuse("the archive name is not a plain file name"));
    }
    Ok(AcceptPlan {
        service_id: req.service_id.clone(),
        transfer_id: req.transfer_id.clone(),
        directory: target.directory,
        sha256: req.sha256.clone(),
        bytes: req.bytes as u64,
        name: req.archive_name.clone(),
    })
}

pub async fn accept_data(codec: Codec, req: pb::AcceptMoveDataRequest) -> Resp {
    let plan = match check_accept(&req) {
        Ok(plan) => plan,
        Err(response) => return response,
    };
    let claim = match crate::jobs::OperationClaim::acquire("service", &plan.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let _claim = claim;
        let sink = Sink::new(tx, codec, &plan.service_id);
        sink.started().await;
        match verify_and_unpack(&plan, &sink).await {
            Ok(path) => sink.completed(|e| e.archive_path = path).await,
            Err(why) => sink.fail(&why).await,
        }
    });
    stream_response(matches!(codec, Codec::Json), rx)
}

async fn hash_file(path: &Path, sink: &Sink) -> Result<(u64, String), String> {
    let mut file = tokio::fs::File::open(path).await.map_err(|_| "nothing arrived on this machine".to_string())?;
    let (mut hasher, mut total) = (Sha256::new(), 0u64);
    let mut buf = vec![0u8; CHUNK];
    let mut last = tokio::time::Instant::now();
    loop {
        let n = file.read(&mut buf).await.map_err(|e| format!("could not read the received data: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
        if last.elapsed() >= PROGRESS_EVERY {
            last = tokio::time::Instant::now();
            sink.progress(format!("checked {} MiB", total / (1024 * 1024))).await;
        }
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

async fn verify_and_unpack(plan: &AcceptPlan, sink: &Sink) -> Result<String, String> {
    let received = incoming_dir(&plan.transfer_id).join(DATA_FILE);
    let meta = std::fs::symlink_metadata(&received).map_err(|_| "nothing arrived on this machine".to_string())?;
    if !meta.is_file() {
        return Err("what arrived is not a plain file".to_string());
    }
    sink.progress("checking what arrived".to_string()).await;
    let (bytes, sha) = hash_file(&received, sink).await?;
    if bytes != plan.bytes || sha != plan.sha256 {
        return Err(format!("what arrived ({bytes} bytes) is not what was sent ({} bytes)", plan.bytes));
    }
    let destination = plan.directory.join(&plan.name);
    if std::fs::symlink_metadata(&destination).is_ok() {
        return Err(format!("{} already exists in this machine's backups", plan.name));
    }
    std::fs::create_dir_all(&plan.directory).map_err(|e| format!("could not make the backup directory: {e}"))?;
    sink.progress("unpacking into the backup directory".to_string()).await;
    unpack(&received, &plan.directory, &plan.name).await?;
    let _ = std::fs::remove_file(&received);
    Ok(destination.to_string_lossy().to_string())
}

async fn unpack(tar_file: &Path, directory: &Path, name: &str) -> Result<(), String> {
    let output = tokio::process::Command::new(bin(TAR_ENV, "tar"))
        .arg("-xf").arg(tar_file).arg("-C").arg(directory).args(["--no-same-owner", "--"]).arg(name)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true)
        .output().await.map_err(|e| format!("could not run tar: {e}"))?;
    if !output.status.success() {
        return Err(format!("unpacking failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    if std::fs::symlink_metadata(directory.join(name)).is_err() {
        return Err("the received data did not hold the archive".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::STATE_DIR_ENV_LOCK;
    use std::os::unix::fs::PermissionsExt;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const KEYS: &str = "ssh-ed25519 AAAAhost";

    struct Rig {
        root: PathBuf,
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("gnx-run-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("backups/nextcloud")).unwrap();
            let wrapper = format!("#!/bin/bash\n  nextcloud) dir='{}/backups/nextcloud'; paths=('/x') ;;\n", root.display());
            std::fs::write(root.join("wrapper.sh"), wrapper).unwrap();
            std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", root.join("wrapper.sh"));
            std::env::set_var("GRYONIXNEXUSD_STATE_DIR", root.join("state"));
            std::env::set_var("GRYONIXNEXUSD_MOVE_INCOMING", root.join("incoming"));
            std::fs::create_dir_all(transfer_dir(ID)).unwrap();
            std::fs::write(key_path(ID), "key").unwrap();
            Self { root }
        }

        fn script(&self, name: &str, body: &str) -> PathBuf {
            let path = self.root.join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        fn archive(&self, name: &str, body: &[u8]) -> String {
            let path = self.root.join("backups/nextcloud").join(name);
            std::fs::write(&path, body).unwrap();
            path.to_string_lossy().to_string()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            for var in ["GRYONIXNEXUSD_BACKUP_WRAPPER", "GRYONIXNEXUSD_STATE_DIR", "GRYONIXNEXUSD_MOVE_INCOMING", SSH_ENV, TAR_ENV] {
                std::env::remove_var(var);
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn send_request(archive: String) -> pb::SendMoveDataRequest {
        pb::SendMoveDataRequest {
            transfer_id: ID.into(),
            service_id: "nextcloud".into(),
            archive_path: archive,
            host: "10.0.0.9".into(),
            port: 2222,
            user: "server-user".into(),
            host_keys: KEYS.into(),
        }
    }

    async fn events(resp: Resp) -> (Vec<pb::MoveEvent>, String) {
        use http_body_util::BodyExt;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let (mut found, mut at, mut trailer) = (Vec::new(), 0, String::new());
        while at + 5 <= bytes.len() {
            let len = u32::from_be_bytes(bytes[at + 1..at + 5].try_into().unwrap()) as usize;
            let payload = &bytes[at + 5..at + 5 + len];
            if bytes[at] & 0x02 != 0 {
                trailer = String::from_utf8_lossy(payload).to_string();
            } else {
                found.push(prost::Message::decode(payload).unwrap());
            }
            at += 5 + len;
        }
        (found, trailer)
    }

    #[tokio::test]
    async fn an_archive_is_piped_through_ssh_and_its_checksum_is_reported() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rig = Rig::new("send");
        let sink = rig.root.join("received.tar");
        let ssh = rig.script("ssh.sh", &format!("#!/bin/sh\necho \"$@\" > '{0}.args'\ncat > '{0}'\n", sink.display()));
        std::env::set_var(SSH_ENV, ssh);
        let archive = rig.archive("nextcloud-1.tar.gz", b"archive bytes");
        let (found, trailer) = events(send_data(Codec::Proto, send_request(archive)).await).await;
        assert!(trailer.is_empty() || !trailer.contains("error"), "{trailer}");
        let done = found.last().unwrap();
        assert_eq!(done.phase, pb::ServiceOperationPhase::Completed as i32);
        assert_eq!(done.archive_name, "nextcloud-1.tar.gz");
        let tar_bytes = std::fs::read(&sink).unwrap();
        assert_eq!(done.bytes as usize, tar_bytes.len());
        assert_eq!(done.sha256, format!("{:x}", Sha256::digest(&tar_bytes)));
        let args = std::fs::read_to_string(format!("{}.args", sink.display())).unwrap();
        assert!(args.contains("StrictHostKeyChecking=yes") && args.contains("server-user@10.0.0.9"), "{args}");
        let known = std::fs::read_to_string(transfer_dir(ID).join("known_hosts")).unwrap();
        assert_eq!(known, "[10.0.0.9]:2222 ssh-ed25519 AAAAhost\n");
    }

    #[tokio::test]
    async fn a_refused_connection_ends_the_run_with_ssh_s_own_words() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rig = Rig::new("refused");
        std::env::set_var(SSH_ENV, rig.script("ssh.sh", "#!/bin/sh\ncat > /dev/null\necho 'Permission denied (publickey).' >&2\nexit 255\n"));
        let archive = rig.archive("nextcloud-1.tar.gz", b"x");
        let (_, trailer) = events(send_data(Codec::Proto, send_request(archive)).await).await;
        assert!(trailer.contains("Permission denied (publickey)"), "{trailer}");
    }

    #[tokio::test]
    async fn requests_that_could_reach_outside_are_refused_before_anything_runs() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rig = Rig::new("guards");
        let good = rig.archive("a.tar", b"x");
        let mut cases = Vec::new();
        for (field, tweak) in [("path", 0), ("host", 1), ("keys", 2), ("id", 3), ("user", 4)] {
            let mut req = send_request(good.clone());
            match tweak {
                0 => req.archive_path = "/etc/shadow".into(),
                1 => req.host = "a b; reboot".into(),
                2 => req.host_keys = "ssh-ed25519 AA extra words".into(),
                3 => req.transfer_id = "nope".into(),
                _ => req.user = "x\" -o ProxyCommand=y".into(),
            }
            cases.push((field, send_data(Codec::Proto, req).await.status()));
        }
        for (field, status) in cases {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
        }
    }

    fn accept_request(bytes: u64, sha: &str) -> pb::AcceptMoveDataRequest {
        pb::AcceptMoveDataRequest {
            transfer_id: ID.into(),
            service_id: "nextcloud".into(),
            sha256: sha.into(),
            bytes: bytes as i64,
            archive_name: "nextcloud-1.tar.gz".into(),
        }
    }

    fn stage_incoming(rig: &Rig) -> (u64, String) {
        let data = rig.root.join("src");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("nextcloud-1.tar.gz"), b"payload").unwrap();
        let tar = incoming_dir(ID).join(DATA_FILE);
        std::fs::create_dir_all(incoming_dir(ID)).unwrap();
        let status = std::process::Command::new("tar").arg("-C").arg(&data).args(["-cf"]).arg(&tar).arg("nextcloud-1.tar.gz").status().unwrap();
        assert!(status.success());
        let bytes = std::fs::read(&tar).unwrap();
        (bytes.len() as u64, format!("{:x}", Sha256::digest(&bytes)))
    }

    #[tokio::test]
    async fn what_arrived_is_checked_and_unpacked_into_the_backup_directory() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rig = Rig::new("accept");
        let (bytes, sha) = stage_incoming(&rig);
        let (found, trailer) = events(accept_data(Codec::Proto, accept_request(bytes, &sha)).await).await;
        assert!(!trailer.contains("error"), "{trailer}");
        let path = found.last().unwrap().archive_path.clone();
        assert_eq!(path, rig.root.join("backups/nextcloud/nextcloud-1.tar.gz").to_string_lossy());
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        assert!(!incoming_dir(ID).join(DATA_FILE).exists(), "the tar goes once unpacked");
    }

    #[tokio::test]
    async fn damaged_data_is_refused_and_nothing_lands_in_the_backup_directory() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rig = Rig::new("damaged");
        let (bytes, sha) = stage_incoming(&rig);
        let wrong = "0".repeat(64);
        let (_, trailer) = events(accept_data(Codec::Proto, accept_request(bytes, &wrong)).await).await;
        assert!(trailer.contains("not what was sent"), "{trailer}");
        let (_, short) = events(accept_data(Codec::Proto, accept_request(bytes + 1, &sha)).await).await;
        assert!(short.contains("not what was sent"), "{short}");
        assert!(!rig.root.join("backups/nextcloud/nextcloud-1.tar.gz").exists());
    }

    #[tokio::test]
    async fn an_archive_that_already_exists_is_never_overwritten() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rig = Rig::new("exists");
        let (bytes, sha) = stage_incoming(&rig);
        rig.archive("nextcloud-1.tar.gz", b"mine");
        let (_, trailer) = events(accept_data(Codec::Proto, accept_request(bytes, &sha)).await).await;
        assert!(trailer.contains("already exists"), "{trailer}");
        assert_eq!(std::fs::read(rig.root.join("backups/nextcloud/nextcloud-1.tar.gz")).unwrap(), b"mine");
    }

    #[tokio::test]
    async fn nothing_arrived_is_said_plainly() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _rig = Rig::new("nothing");
        let (_, trailer) = events(accept_data(Codec::Proto, accept_request(1, &"a".repeat(64))).await).await;
        assert!(trailer.contains("nothing arrived"), "{trailer}");
    }

    #[test]
    fn host_keys_are_known_hosts_lines_in_the_shape_ssh_expects() {
        assert_eq!(known_hosts("h", 22, &["ssh-ed25519 AA".into()]), "h ssh-ed25519 AA\n");
        assert_eq!(known_hosts("h", 2200, &["ssh-ed25519 AA".into()]), "[h]:2200 ssh-ed25519 AA\n");
        assert!(host_key_lines("ssh-ed25519 AA\necdsa-sha2-nistp256 BB==").is_some());
        for bad in ["", "ssh-ed25519", "ssh-ed25519 AA comment", "rsa AA", "ssh-ed25519 A\"A"] {
            assert!(host_key_lines(bad).is_none(), "{bad}");
        }
    }
}
