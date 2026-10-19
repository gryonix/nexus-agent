//! Backups behind the API: what exists, what a run would cost, running one, deleting one

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::util::strip_ansi;
use crate::{discover, pb};

/// The wrapper every backup goes through
const WRAPPER_PATH: &str = "/opt/gryonixnexus-backup-ctl.sh";

/// Printed by a finished archive: `<marker> <bytes> <path>`
const BACKUP_DONE_MARKER: &str = "GRYONIXNEXUS_BACKUP_DONE";

/// Printed by `estimate`: `<marker> <data bytes> <free bytes>`.
const ESTIMATE_MARKER: &str = "GRYONIXNEXUS_BACKUP_ESTIMATE";

const STAGING_DIRECTORY: &str = "incoming";

/// The VPN protocols share one panel and one backup target
const VPN_WRAPPER_TARGET: &str = "vpn-panel";

/// What the wrapper says to a verb it lacks
const UNSUPPORTED_ACTION: &str = "unsupported action:";

const RUN_TIMEOUT_SECS: u64 = 4 * 3600;

const QUICK_TIMEOUT_SECS: u64 = 120;

const ECHO_LIMIT: usize = 96;

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    UnknownService(String),
    NoWrapper,
    /// The wrapper exists but has no arm for this service
    NotBackedUp(String),
    PathOutsideBackupDirectory(String),
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("unknown service '{}'", truncate(id)),
            ),
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no backup wrapper ({WRAPPER_PATH}) — re-run the setup script to install it"
                ),
            ),
            Rejection::NotBackedUp(id) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "the backup wrapper on this server has no entry for '{}'",
                    truncate(id)
                ),
            ),
            Rejection::PathOutsideBackupDirectory(path) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("'{}' is not inside this service's backup directory", truncate(path)),
            ),
        }
    }

    pub fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

fn wrapper_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_BACKUP_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

const CONFIG_PATH: &str = "/etc/gryonixnexus/autobackup.conf";

fn config_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_BACKUP_CONFIG").unwrap_or_else(|_| CONFIG_PATH.to_string()))
}

pub(crate) fn wrapper_home() -> PathBuf {
    let state = std::env::var("GRYONIXNEXUSD_STATE_DIR")
        .or_else(|_| std::env::var("STATE_DIRECTORY"))
        .unwrap_or_else(|_| AGENT_STATE_DIR.to_string());
    let home = PathBuf::from(state).join("wrapper-home");
    let _ = std::fs::create_dir_all(home.join(".gnupg"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(home.join(".gnupg"), std::fs::Permissions::from_mode(0o700));
    }
    home
}

/// Mirrors `main.rs`'s `STATE_DIR`
const AGENT_STATE_DIR: &str = "/var/lib/gryonixnexus/agent";

pub fn wrapper_target(service_id: &str) -> Option<&'static str> {
    if service_id == "vpn" {
        return Some(VPN_WRAPPER_TARGET);
    }
    discover::known_service_id(service_id)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub label: &'static str,
    pub directory: PathBuf,
}

/// Parse the wrapper's own service table
fn parse_directories(script: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for line in script.lines() {
        let line = line.trim();
        let Some((label, rest)) = line.split_once(')') else { continue };
        if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            continue;
        }
        let Some(after) = rest.split_once("dir='") else { continue };
        let Some((dir, _)) = after.1.split_once('\'') else { continue };
        if dir.starts_with('/') {
            found.push((label.to_string(), dir.to_string()));
        }
    }
    found
}

pub fn resolve(service_id: &str) -> Result<Target, Rejection> {
    let Some(label) = wrapper_target(service_id) else {
        return Err(Rejection::UnknownService(service_id.to_string()));
    };
    let script = std::fs::read_to_string(wrapper_path()).map_err(|_| Rejection::NoWrapper)?;
    parse_directories(&script)
        .into_iter()
        .find(|(candidate, _)| candidate == label)
        .map(|(_, dir)| Target {
            label,
            directory: PathBuf::from(dir),
        })
        .ok_or_else(|| Rejection::NotBackedUp(label.to_string()))
}

// ─────────────────────────── Listing ───────────────────────────

/// Read one backup directory
pub fn read_directory(dir: &Path) -> std::io::Result<Vec<pb::BackupArchive>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut archives = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == STAGING_DIRECTORY {
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        archives.push(pb::BackupArchive {
            name,
            path: entry.path().to_string_lossy().to_string(),
            size_bytes: meta.len() as i64,
            modified_at: modified,
            directory: meta.is_dir(),
            drive: String::new(),
        });
    }
    archives.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    Ok(archives)
}

fn listing(service_id: &str, target: &Target) -> Result<pb::BackupList, std::io::Error> {
    let mut archives = read_directory(&target.directory)?;
    archives.extend(crate::backup_drive::drive_archives(target.label));
    archives.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    Ok(pb::BackupList {
        service_id: service_id.to_string(),
        directory: target.directory.to_string_lossy().to_string(),
        archives,
    })
}

pub fn list_backups(codec: Codec, req: pb::ListBackupsRequest) -> Resp {
    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    match listing(&req.service_id, &target) {
        Ok(list) => encode(codec, &list),
        Err(err) => connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &format!("could not read {}: {err}", target.directory.display()),
        ),
    }
}

/// Every service the wrapper covers, listed in one pass
fn all_backups() -> Result<pb::AllBackups, Rejection> {
    let script = std::fs::read_to_string(wrapper_path()).map_err(|_| Rejection::NoWrapper)?;
    let directories = parse_directories(&script);
    let mut all = pb::AllBackups::default();
    for id in discover::all_service_ids() {
        let Some(label) = wrapper_target(id) else { continue };
        let Some((_, dir)) = directories.iter().find(|(candidate, _)| candidate == label) else { continue };
        let target = Target {
            label,
            directory: PathBuf::from(dir),
        };
        match listing(id, &target) {
            Ok(list) => all.lists.push(list),
            Err(_) => all.failed_service_ids.push(id.to_string()),
        }
    }
    Ok(all)
}

pub fn list_all_backups(codec: Codec) -> Resp {
    match all_backups() {
        Ok(all) => encode(codec, &all),
        Err(rejection) => rejection.response(),
    }
}

// ─────────────────────────── Estimate ───────────────────────────

/// `GRYONIXNEXUS_BACKUP_ESTIMATE <data bytes> <free bytes>` → the two numbers
fn parse_estimate(output: &str) -> Option<pb::BackupEstimate> {
    let line = output.lines().find(|line| line.trim_start().starts_with(ESTIMATE_MARKER))?;
    let mut fields = line.split_whitespace();
    fields.next()?; // the marker
    Some(pb::BackupEstimate {
        data_bytes: fields.next()?.parse().ok()?,
        free_bytes: fields.next()?.parse().ok()?,
    })
}

pub async fn estimate_backup(codec: Codec, req: pb::EstimateBackupRequest) -> Resp {
    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    let outcome = run_wrapper(&["estimate", target.label], None, QUICK_TIMEOUT_SECS).await;
    match outcome {
        Err(why) => wrapper_failed(&why),
        Ok(output) => match parse_estimate(&output.stdout) {
            Some(estimate) => encode(codec, &estimate),
            None => connect_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                "the backup wrapper on this server does not report estimates — re-run the setup script",
            ),
        },
    }
}

// ─────────────────────────── Delete ───────────────────────────

pub fn validate_delete_path(path: &str, dir: &Path) -> Result<(), Rejection> {
    let outside = || Rejection::PathOutsideBackupDirectory(path.to_string());
    if path.contains("..") {
        return Err(outside());
    }
    let prefix = format!("{}/", dir.to_string_lossy());
    let Some(rest) = path.strip_prefix(&prefix) else {
        return Err(outside());
    };
    if rest.is_empty() || rest.contains('/') || rest == STAGING_DIRECTORY {
        return Err(outside());
    }
    Ok(())
}

pub async fn delete_backup(codec: Codec, req: pb::DeleteBackupRequest) -> Resp {
    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    let on_drive = crate::backup_drive::drive_of(&req.path, target.label).is_some();
    if let (Err(rejection), false) = (validate_delete_path(&req.path, &target.directory), on_drive) {
        return rejection.response();
    }
    if let Err(why) = run_wrapper(&["delete", &req.path], None, QUICK_TIMEOUT_SECS).await {
        return wrapper_failed(&why);
    }
    match listing(&req.service_id, &target) {
        Ok(list) => encode(codec, &list),
        Err(err) => connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &format!("could not read {}: {err}", target.directory.display()),
        ),
    }
}

// ─────────────────────────── Schedule ───────────────────────────

pub(crate) fn read_backup_schedule() -> pb::BackupSchedulePolicy {
    let text = std::fs::read_to_string(config_path()).unwrap_or_default();
    let mut schedule = "off".to_string();
    let mut retention = 7i32;
    let mut services = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("SCHEDULE=") {
            let rest = rest.trim();
            if !rest.is_empty() {
                schedule = rest.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("RETENTION=") {
            if let Ok(value) = rest.trim().parse::<i32>() {
                if value >= 1 {
                    retention = value;
                }
            }
        } else if let Some(rest) = line.strip_prefix("SERVICES=") {
            let rest = rest.trim();
            let unquoted = rest.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')).unwrap_or(rest);
            services = unquoted.split_whitespace().map(str::to_string).collect();
        }
    }
    let destination = read_destination();
    pb::BackupSchedulePolicy {
        schedule,
        retention,
        services,
        destination: Some(destination.settings),
        destination_public_key: destination.public_key,
        last_shipment_at: destination.last_at,
        last_shipment_error: destination.last_error,
        last_shipment_ok: destination.last_ok,
        drives: wrapper_knows_drives().then(|| crate::backup_drive::read_drives(&config_dir())),
    }
}

struct StoredDestination {
    settings: pb::BackupDestination,
    public_key: String,
    last_at: i64,
    last_error: String,
    last_ok: bool,
}

fn destination_config_path() -> std::path::PathBuf {
    config_dir().join("autobackup-dest.conf")
}

fn config_dir() -> std::path::PathBuf {
    config_path()
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("/etc/gryonixnexus"))
}

fn shell_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim().strip_prefix(key)?.strip_prefix('=')?.trim();
    Some(
        rest.strip_prefix('\'')
            .and_then(|r| r.strip_suffix('\''))
            .unwrap_or(rest),
    )
}

fn read_destination() -> StoredDestination {
    let mut settings = pb::BackupDestination {
        kind: pb::BackupDestinationKind::None as i32,
        ..Default::default()
    };
    let text = std::fs::read_to_string(destination_config_path()).unwrap_or_default();
    for line in text.lines() {
        if let Some(value) = shell_value(line, "DEST_KIND") {
            settings.kind = match value {
                "ssh" => pb::BackupDestinationKind::Ssh as i32,
                "s3" => pb::BackupDestinationKind::S3 as i32,
                _ => pb::BackupDestinationKind::None as i32,
            };
        } else if let Some(value) = shell_value(line, "DEST_HOST") {
            settings.host = value.to_string();
        } else if let Some(value) = shell_value(line, "DEST_PORT") {
            settings.port = value.parse().unwrap_or(22);
        } else if let Some(value) = shell_value(line, "DEST_USER") {
            settings.user = value.to_string();
        } else if let Some(value) = shell_value(line, "DEST_PATH") {
            settings.path = value.to_string();
        } else if let Some(value) = shell_value(line, "DEST_BUCKET") {
            settings.bucket = value.to_string();
        } else if let Some(value) = shell_value(line, "DEST_KEEP") {
            settings.keep = value.parse().unwrap_or(0);
        }
    }

    let public_key = std::fs::read_to_string(config_dir().join("autobackup-dest.key.pub"))
        .unwrap_or_default()
        .trim()
        .to_string();

    let (mut last_at, mut last_error, mut last_ok) = (0i64, String::new(), false);
    let status = std::fs::read_to_string(config_dir().join("autobackup-dest.status")).unwrap_or_default();
    for line in status.lines() {
        if let Some(value) = shell_value(line, "AT") {
            last_at = value.parse().unwrap_or(0);
        } else if let Some(value) = shell_value(line, "OK") {
            last_ok = value == "1";
        } else if let Some(value) = shell_value(line, "ERROR") {
            last_error = value.to_string();
        }
    }
    StoredDestination { settings, public_key, last_at, last_error, last_ok }
}

pub async fn set_backup_destination(codec: Codec, req: pb::SetBackupDestinationRequest) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    let destination = req.destination.unwrap_or_default();
    let kind = match pb::BackupDestinationKind::try_from(destination.kind) {
        Ok(pb::BackupDestinationKind::Ssh) => "ssh",
        Ok(pb::BackupDestinationKind::S3) => "s3",
        _ => "none",
    };
    if kind != "none" && destination.host.trim().is_empty() && destination.bucket.trim().is_empty() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "a destination needs a host (ssh) or a bucket (s3)",
        );
    }
    let port = if destination.port == 0 { 22 } else { destination.port }.to_string();
    let keep = destination.keep.to_string();
    let args: Vec<&str> = vec![
        "set-destination",
        kind,
        destination.host.trim(),
        port.as_str(),
        destination.user.trim(),
        destination.path.trim(),
        destination.bucket.trim(),
        keep.as_str(),
    ];
    let secret = (!req.secret.is_empty()).then_some(req.secret.as_str());
    if let Err(detail) = run_wrapper(&args, secret, QUICK_TIMEOUT_SECS).await {
        return wrapper_failed(&detail);
    }
    encode(codec, &read_backup_schedule())
}

/// Send one small file and report what came back
pub async fn test_backup_destination(
    codec: Codec,
    _req: pb::TestBackupDestinationRequest,
) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    let output = match run_wrapper(&["test-destination"], None, 120).await {
        Ok(output) => output,
        Err(detail) => return wrapper_failed(&detail),
    };
    let (ok, detail) = parse_destination_test(&output.raw);
    encode(codec, &pb::BackupDestinationTest { ok, detail })
}

/// The wrapper's own verdict, out of everything it printed
fn parse_destination_test(stdout: &str) -> (bool, String) {
    let Some(line) = stdout
        .lines()
        .map(str::trim_end)
        .rev()
        .find(|line| line.starts_with(DEST_TEST_MARKER))
    else {
        let tail: Vec<&str> = stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && *line != "GRYONIXNEXUS_BACKUP_CTL_DONE")
            .collect();
        let said = tail.last().copied().unwrap_or("the wrapper printed nothing");
        return (false, said.chars().take(400).collect());
    };
    let rest = line[DEST_TEST_MARKER.len()..].trim_start();
    let (verdict, detail) = match rest.split_once(' ') {
        Some((verdict, detail)) => (verdict, detail.trim()),
        None => (rest, ""),
    };
    (verdict == "1", detail.to_string())
}

/// What `do_test_destination` prints
const DEST_TEST_MARKER: &str = "GRYONIXNEXUS_DEST_TEST";

pub async fn get_backup_schedule(codec: Codec, _req: pb::GetBackupScheduleRequest) -> Resp {
    encode(codec, &read_backup_schedule())
}

pub async fn set_backup_schedule(codec: Codec, req: pb::SetBackupScheduleRequest) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    if !req.passphrase.is_empty() {
        if let Err(why) = run_wrapper(&["set-passphrase"], Some(&req.passphrase), QUICK_TIMEOUT_SECS).await {
            return wrapper_failed(&why);
        }
    }
    let retention = req.retention.max(1).to_string();
    let mut args: Vec<&str> = vec!["set-schedule", req.schedule.as_str(), retention.as_str()];
    for service in &req.services {
        args.push(service.as_str());
    }
    if let Err(why) = run_wrapper(&args, None, QUICK_TIMEOUT_SECS).await {
        return wrapper_failed(&why);
    }
    encode(codec, &read_backup_schedule())
}

// ─────────────────────────── Run ───────────────────────────

fn encryption_flag(encryption: pb::BackupEncryption) -> Option<&'static str> {
    match encryption {
        pb::BackupEncryption::Unspecified => None,
        pb::BackupEncryption::Enabled => Some("--encrypt"),
        pb::BackupEncryption::Disabled => Some("--no-encrypt"),
    }
}

/// `GRYONIXNEXUS_BACKUP_DONE <bytes> <path>` → the archive that landed
fn parse_archive(output: &str) -> Option<pb::BackupArchive> {
    let line = output
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with(BACKUP_DONE_MARKER))?;
    let rest = line.trim_start().strip_prefix(BACKUP_DONE_MARKER)?.trim_start();
    let (size, path) = rest.split_once(' ')?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    Some(pb::BackupArchive {
        name: path.rsplit('/').next().unwrap_or(path).to_string(),
        path: path.to_string(),
        size_bytes: size.parse().unwrap_or(0),
        modified_at: now_millis(),
        directory: false,
        drive: crate::backup_drive::drive_name(path),
    })
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Run one backup, streaming the wrapper's output
pub async fn run_backup(codec: Codec, req: pb::RunBackupRequest) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("service", &req.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let target = match resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    let encryption = pb::BackupEncryption::try_from(req.encryption).unwrap_or(pb::BackupEncryption::Unspecified);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();
    let passphrase = req.passphrase.clone();

    tokio::spawn(async move {
        let _claim = claim;
        let sink = EventSink {
            tx,
            codec,
            service_id: service_id.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::Backup, &service_id),
        };
        let _ = sink.started(target.label).await;

        let mut args = vec!["backup", target.label];
        if let Some(flag) = encryption_flag(encryption) {
            args.push(flag);
        }
        let outcome = run_wrapper_streaming(&args, &passphrase, RUN_TIMEOUT_SECS, &sink).await;

        let mut failure = outcome.as_ref().err().cloned();
        let archive = outcome.ok().as_deref().and_then(parse_archive);
        let backups = match listing(&service_id, &target) {
            Ok(list) => Some(list),
            Err(err) => {
                failure.get_or_insert_with(|| format!("could not re-read the backup directory: {err}"));
                None
            }
        };
        let _ = sink.completed(archive, backups).await;
        if let Some(why) = failure {
            let _ = sink.fail(&why).await;
        }
    });

    stream_response(json, rx)
}

// ─────────────────────────── Wrapper plumbing ───────────────────────────

struct WrapperOutput {
    /// What a person should read: escapes gone, progress bars collapsed.
    stdout: String,
    raw: String,
}

/// Spawn the wrapper and collect its output
async fn run_wrapper(args: &[&str], passphrase: Option<&str>, timeout_secs: u64) -> Result<WrapperOutput, String> {
    let home = wrapper_home();
    let mut child = tokio::process::Command::new(wrapper_path())
        .args(args)
        .env("HOME", &home)
        .env("GNUPGHOME", home.join(".gnupg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the backup wrapper: {err}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        if let Some(passphrase) = passphrase {
            let _ = stdin.write_all(passphrase.as_bytes()).await;
        }
        let _ = stdin.shutdown().await;
        drop(stdin);
    }

    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| format!("the backup wrapper timed out after {timeout_secs}s"))?
        .map_err(|err| format!("the backup wrapper did not finish: {err}"))?;

    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
    let stdout = strip_ansi(&raw);
    if output.status.success() {
        return Ok(WrapperOutput { stdout, raw });
    }
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
    Err(describe_failure(output.status.code(), &stderr))
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = stderr.trim();
    let detail: String = detail.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the backup wrapper exited {code}"),
        (None, true) => "the backup wrapper was killed by a signal".to_string(),
    }
}

async fn feed_passphrase(child: &mut tokio::process::Child, passphrase: &str) {
    if let Some(mut stdin) = child.stdin.take() {
        if !passphrase.is_empty() {
            let _ = stdin.write_all(passphrase.as_bytes()).await;
        }
        let _ = stdin.shutdown().await;
        drop(stdin);
    }
}

async fn run_wrapper_streaming(
    args: &[&str],
    passphrase: &str,
    timeout_secs: u64,
    sink: &EventSink,
) -> Result<String, String> {
    let home = wrapper_home();
    let mut child = tokio::process::Command::new(wrapper_path())
        .args(args)
        .env("HOME", &home)
        .env("GNUPGHOME", home.join(".gnupg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the backup wrapper: {err}"))?;

    feed_passphrase(&mut child, passphrase).await;

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut stdout = String::new();
    let mut stderr = String::new();

    let outcome = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => {
                            let text = strip_ansi(&text);
                            stdout.push_str(&text);
                            stdout.push('\n');
                            let _ = sink.progress("stdout", text).await;
                        }
                        _ => out = None, // EOF or read error on this pipe
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => {
                            let text = strip_ansi(&text);
                            stderr.push_str(&text);
                            stderr.push('\n');
                            let _ = sink.progress("stderr", text).await;
                        }
                        _ => err = None,
                    }
                }
                else => break,
            }
        }
        child.wait().await
    })
    .await;

    match outcome {
        Err(_) => Err(format!("the backup timed out after {timeout_secs}s")),
        Ok(Err(io)) => Err(format!("the backup wrapper did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(stdout),
        Ok(Ok(status)) => Err(describe_failure(status.code(), &stderr)),
    }
}

/// Runs one quick wrapper verb, answering with the re-read policy
pub(crate) async fn run_quick(args: &[&str], codec: Codec) -> Resp {
    if !wrapper_path().exists() {
        return Rejection::NoWrapper.response();
    }
    if let Err(why) = run_wrapper(args, None, QUICK_TIMEOUT_SECS).await {
        return wrapper_failed(&why);
    }
    encode(codec, &read_backup_schedule())
}

fn wrapper_failed(detail: &str) -> Resp {
    if detail.contains(UNSUPPORTED_ACTION) {
        return connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "this server's backup tools are older than this request — run Repair server on it first",
        );
    }
    connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", detail)
}

/// Whether the installed wrapper has the USB drive verbs
fn wrapper_knows_drives() -> bool {
    std::fs::read_to_string(wrapper_path()).is_ok_and(|text| text.contains("set-drives)"))
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

/// Frames and pushes one run's events
struct EventSink {
    tx: Sender<Bytes>,
    codec: Codec,
    service_id: String,
    journal: Option<crate::jobs::Journal>,
}

impl EventSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::BackupEvent {
        pb::BackupEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            archive: None,
            backups: None,
            target: String::new(),
        }
    }

    async fn send(&self, event: pb::BackupEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, target: &str) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.target = target.to_string();
        self.send(event).await
    }

    async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, archive: Option<pb::BackupArchive>, backups: Option<pb::BackupList>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.archive = archive;
        event.backups = backups;
        self.send(event).await
    }

    async fn fail(&self, message: &str) -> Result<(), ()> {
        crate::jobs::finish(&self.journal, Some(message));
        self.tx
            .send(error_trailer("internal", message))
            .await
            .map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_destination_test, *};

    #[test]
    fn the_destination_verdict_is_read_as_printed() {
        let sandboxed = "GRYONIXNEXUS_DEST_TEST 1 Could not create directory /root/.ssh (Read-only file system).\nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        assert_eq!(
            parse_destination_test(sandboxed),
            (true, "Could not create directory /root/.ssh (Read-only file system).".to_string())
        );

        let plain = "GRYONIXNEXUS_DEST_TEST 1 \nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        assert_eq!(parse_destination_test(plain), (true, String::new()));

        let refused = "GRYONIXNEXUS_DEST_TEST 0 root@dest: Permission denied (publickey).\nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        assert_eq!(
            parse_destination_test(refused),
            (false, "root@dest: Permission denied (publickey).".to_string())
        );

        assert_eq!(
            parse_destination_test("GRYONIXNEXUS_BACKUP_CTL_DONE\n"),
            (false, "the wrapper printed nothing".to_string())
        );
        let with_cr = "GRYONIXNEXUS_DEST_TEST 1 Could not create directory /root/.ssh (Read-only file system).\r Failed to add the host to the list of known hosts (/root/.ssh/known_hosts).\r\nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        let (ok, detail) = parse_destination_test(with_cr);
        assert!(ok, "the verdict was 1 and must be read as such");
        assert!(detail.contains("Could not create directory"), "{detail}");

        assert_eq!(
            parse_destination_test("unsupported action: test-destination\n"),
            (false, "unsupported action: test-destination".to_string())
        );
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const WRAPPER: &str = r#"#!/bin/bash
        set -euo pipefail
        do_delete() {
          local path="${1:-}"
          case "$path" in
            *..*) echo "invalid path: ${path}" >&2; exit 2 ;;
          esac
          case "$path" in
            "/opt/backups/nextcloud"/*|"/opt/backups/vpn-panel"/*) ;;
            *) echo "path outside the backup directories: ${path}" >&2; exit 2 ;;
          esac
        }
        do_estimate() {
          local svc="${1:-}" dir="" total=0 free="" sz=""
          case "$svc" in
            nextcloud) dir='/opt/backups/nextcloud'; paths=('/opt/nextcloud/data' '/opt/nextcloud/db') ;;
            vpn-panel) dir='/opt/backups/vpn-panel'; paths=('/opt/vpn-panel/data') ;;
            docker-mailserver) dir='/srv/backups/docker-mailserver'; paths=('/opt/docker-mailserver') ;;
            *) echo "unsupported service: ${svc}" >&2; exit 2 ;;
          esac
        }
"#;

    #[test]
    fn the_wrappers_own_table_is_where_a_backup_directory_comes_from() {
        let found = parse_directories(WRAPPER);
        assert_eq!(
            found,
            vec![
                ("nextcloud".to_string(), "/opt/backups/nextcloud".to_string()),
                ("vpn-panel".to_string(), "/opt/backups/vpn-panel".to_string()),
                ("docker-mailserver".to_string(), "/srv/backups/docker-mailserver".to_string()),
            ]
        );
    }

    #[test]
    fn the_case_arms_that_are_not_service_labels_are_ignored() {
        for line in [
            "    *..*) echo bad ;;",
            "    *) echo \"unsupported\" ;;",
            "    *) dir='/opt/backups/fallback'; paths=() ;;",
            "  ;;",
        ] {
            assert!(parse_directories(line).is_empty(), "{line} must not parse as a service");
        }
        assert!(parse_directories("  nextcloud) dir='backups/nextcloud'; paths=() ;;").is_empty());
    }

    #[test]
    fn only_catalog_ids_resolve_to_a_wrapper_label() {
        // The gate: a client picks among the agent's own constants.
        assert_eq!(wrapper_target("nextcloud"), Some("nextcloud"));
        assert_eq!(wrapper_target("docker-mailserver"), Some("docker-mailserver"));
        assert_eq!(wrapper_target("jellyfin"), Some("jellyfin"));
        assert_eq!(wrapper_target("vpn"), Some("vpn-panel"));
        for hostile in ["nope", "nextcloud; rm -rf /", "../../etc/shadow", "", "--encrypt"] {
            assert_eq!(wrapper_target(hostile), None, "{hostile} must not resolve");
        }
    }

    #[test]
    fn the_label_that_reaches_argv_is_the_agents_own_string_not_the_requests() {
        let from_the_wire = String::from("nextcloud");
        let label = wrapper_target(&from_the_wire).expect("a catalog id resolves");
        assert_eq!(label, "nextcloud");
        assert!(
            !std::ptr::eq(label.as_ptr(), from_the_wire.as_ptr()),
            "the wrapper label must come from the agent's table, not from the request"
        );
    }

    #[test]
    fn a_host_with_no_wrapper_is_told_what_to_do_not_shown_an_empty_list() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", "/nonexistent/gryonixnexus-backup-ctl.sh");
        assert_eq!(resolve("nextcloud"), Err(Rejection::NoWrapper));
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
    }

    #[test]
    fn a_service_the_wrapper_has_no_arm_for_is_refused_before_anything_runs() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("backup-ctl.sh");
        std::fs::write(&script, WRAPPER).unwrap();
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &script);

        assert_eq!(
            resolve("nextcloud"),
            Ok(Target {
                label: "nextcloud",
                directory: PathBuf::from("/opt/backups/nextcloud")
            })
        );
        assert_eq!(resolve("immich"), Err(Rejection::NotBackedUp("immich".into())));

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_delete_path_must_be_inside_this_services_own_directory() {
        let dir = Path::new("/opt/backups/nextcloud");
        assert!(validate_delete_path("/opt/backups/nextcloud/nextcloud-20260806.tar.gz", dir).is_ok());
        assert!(validate_delete_path("/opt/backups/nextcloud/my  backup.tar.gz", dir).is_ok());
        for hostile in [
            "/opt/backups/vaultwarden/vault.tar.gz.gpg",
            "/opt/backups/nextcloud/../../../etc/shadow",
            "/etc/shadow",
            "/opt/backups/nextcloud",
            "/opt/backups/nextcloud/",
            "/opt/backups/nextcloud/incoming",
            "/opt/backups/nextcloudx/archive.tar.gz",
            "",
        ] {
            assert!(
                validate_delete_path(hostile, dir).is_err(),
                "{hostile} must be refused"
            );
        }
    }

    #[test]
    fn the_estimate_marker_is_read_as_two_byte_counts() {
        let output = "making room\nGRYONIXNEXUS_BACKUP_ESTIMATE 1073741824 223338299392\nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        assert_eq!(
            parse_estimate(output),
            Some(pb::BackupEstimate {
                data_bytes: 1_073_741_824,
                free_bytes: 223_338_299_392
            })
        );
        assert_eq!(parse_estimate("GRYONIXNEXUS_BACKUP_CTL_DONE\n"), None);
        assert_eq!(parse_estimate("GRYONIXNEXUS_BACKUP_ESTIMATE 12\n"), None);
    }

    #[test]
    fn the_archive_announcement_carries_size_and_path() {
        let output = "backing up\nGRYONIXNEXUS_BACKUP_DONE 4096 /opt/backups/nextcloud/nextcloud-2026.tar.gz.gpg\nGRYONIXNEXUS_BACKUP_CTL_DONE\n";
        let archive = parse_archive(output).unwrap();
        assert_eq!(archive.path, "/opt/backups/nextcloud/nextcloud-2026.tar.gz.gpg");
        assert_eq!(archive.name, "nextcloud-2026.tar.gz.gpg");
        assert_eq!(archive.size_bytes, 4096);
        assert_eq!(parse_archive("GRYONIXNEXUS_BACKUP_CTL_DONE\n"), None);
        // A path with spaces survives whole.
        let spaced = parse_archive("GRYONIXNEXUS_BACKUP_DONE 10 /opt/backups/nc/my backup.tar.gz").unwrap();
        assert_eq!(spaced.path, "/opt/backups/nc/my backup.tar.gz");
    }

    #[test]
    fn encryption_unspecified_passes_no_flag_at_all() {
        assert_eq!(encryption_flag(pb::BackupEncryption::Unspecified), None);
        assert_eq!(encryption_flag(pb::BackupEncryption::Enabled), Some("--encrypt"));
        assert_eq!(encryption_flag(pb::BackupEncryption::Disabled), Some("--no-encrypt"));
    }

    #[test]
    fn a_directory_that_does_not_exist_yet_is_an_empty_listing() {
        let missing = std::env::temp_dir().join("gryonixnexusd-backup-missing-dir");
        let _ = std::fs::remove_dir_all(&missing);
        assert!(read_directory(&missing).unwrap().is_empty());
    }

    #[test]
    fn listings_are_newest_first_and_skip_the_upload_staging_directory() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(STAGING_DIRECTORY)).unwrap();
        std::fs::create_dir_all(dir.join(".work-Ab3xQ1")).unwrap();
        std::fs::write(dir.join("old.tar.gz"), b"old").unwrap();
        std::fs::create_dir_all(dir.join("mailcow-2026-08-06")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(dir.join("new.tar.gz.gpg"), b"newer").unwrap();

        let archives = read_directory(&dir).unwrap();
        let names: Vec<_> = archives.iter().map(|a| a.name.as_str()).collect();
        assert!(!names.contains(&STAGING_DIRECTORY), "the upload staging dir is not a backup: {names:?}");
        assert!(
            !names.iter().any(|name| name.starts_with('.')),
            "the wrapper's in-flight work directory is not a backup: {names:?}"
        );
        assert_eq!(names.len(), 3);
        assert_eq!(names[0], "new.tar.gz.gpg", "newest first: {names:?}");
        let old = archives.iter().find(|a| a.name == "old.tar.gz").unwrap();
        assert_eq!(old.size_bytes, 3);
        assert!(!old.directory);
        assert!(archives.iter().find(|a| a.name == "mailcow-2026-08-06").unwrap().directory);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_covered_service_is_listed_in_one_reply() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("gryonixnexusd-backup-all-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (nextcloud, vault) = (root.join("nextcloud"), root.join("vaultwarden"));
        std::fs::create_dir_all(&nextcloud).unwrap();
        std::fs::write(nextcloud.join("a.tar.gz"), b"abc").unwrap();
        let wrapper = root.join("wrapper.sh");
        std::fs::write(
            &wrapper,
            format!(
                "nextcloud) dir='{}' ;;\nvaultwarden) dir='{}' ;;\n",
                nextcloud.display(),
                vault.display()
            ),
        )
        .unwrap();
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &wrapper);

        let all = all_backups().unwrap();
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");

        let ids: Vec<_> = all.lists.iter().map(|list| list.service_id.as_str()).collect();
        assert!(ids.contains(&"nextcloud") && ids.contains(&"vaultwarden"), "{ids:?}");
        let nextcloud_list = all.lists.iter().find(|l| l.service_id == "nextcloud").unwrap();
        assert_eq!(nextcloud_list.archives.len(), 1);
        assert_eq!(nextcloud_list.archives[0].size_bytes, 3);
        assert!(all.lists.iter().find(|l| l.service_id == "vaultwarden").unwrap().archives.is_empty());
        assert!(all.failed_service_ids.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_wrapper_means_no_listing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", "/nonexistent/gryonixnexus-wrapper");
        let result = all_backups();
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        assert!(matches!(result, Err(Rejection::NoWrapper)));
    }

    #[test]
    fn a_failing_wrapper_is_reported_in_its_own_words() {
        assert_eq!(describe_failure(Some(2), "no such backup: /x\n"), "no such backup: /x");
        assert_eq!(describe_failure(Some(2), "   "), "the backup wrapper exited 2");
        assert_eq!(describe_failure(None, ""), "the backup wrapper was killed by a signal");
        // Bounded: the message travels into logs and UI.
        let long = "x".repeat(900);
        assert_eq!(describe_failure(Some(1), &long).chars().count(), 400);
    }

    #[tokio::test]
    async fn the_passphrase_never_appears_in_the_wrappers_arguments() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-stdin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("wrapper.sh");
        std::fs::write(&script, "#!/bin/sh\necho \"ARGV: $*\"\necho \"STDIN: $(cat)\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &script);

        let out = run_wrapper(&["backup", "nextcloud", "--encrypt"], Some("s3cret-phrase"), 30)
            .await
            .unwrap();
        assert!(out.stdout.contains("ARGV: backup nextcloud --encrypt"), "{}", out.stdout);
        assert!(!out.stdout.contains("ARGV: backup nextcloud --encrypt s3cret"), "{}", out.stdout);
        assert!(out.stdout.contains("STDIN: s3cret-phrase"), "{}", out.stdout);

        let closed = tokio::time::timeout(
            Duration::from_secs(10),
            run_wrapper(&["backup", "nextcloud"], None, 30),
        )
        .await
        .expect("stdin must be closed, or the wrapper waits for EOF for ever")
        .unwrap();
        assert!(closed.stdout.contains("STDIN: \n") || closed.stdout.contains("STDIN: "), "{}", closed.stdout);

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_wrapper_is_handed_a_home_it_can_actually_write_to() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("wrapper.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nset -e\nmkdir -p \"$HOME/probe\"\n: > \"$HOME/probe/file\"\n\
             mkdir -p \"$GNUPGHOME\"\n: > \"$GNUPGHOME/random_seed\"\n\
             echo \"HOME: $HOME\"\necho \"GNUPGHOME: $GNUPGHOME\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &script);
        let state = dir.join("state");
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &state);

        let out = run_wrapper(&["backup", "nextcloud", "--encrypt"], Some("phrase"), 30)
            .await
            .expect("the wrapper must be able to write under the HOME it is given");
        let home = state.join("wrapper-home");
        assert!(out.stdout.contains(&format!("HOME: {}", home.display())), "{}", out.stdout);
        assert!(home.join("probe/file").exists(), "the child could not write under HOME");
        assert!(home.join(".gnupg/random_seed").exists(), "the child could not write under GNUPGHOME");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(home.join(".gnupg")).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "GNUPGHOME must not be readable by anyone else: {mode:o}");
        }

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── Schedule ───────────────────────────

    use prost::Message;

    fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let script = dir.join(name);
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    #[tokio::test]
    async fn get_backup_schedule_reads_off_disk_with_no_wrapper_call() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-sched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autobackup.conf");
        std::fs::write(&config, "SCHEDULE=every:1d@03:30\nRETENTION=14\nSERVICES='nextcloud vaultwarden'\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", &config);

        let resp = get_backup_schedule(Codec::Proto, pb::GetBackupScheduleRequest {}).await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::BackupSchedulePolicy::decode(body).unwrap();
        assert_eq!(policy.schedule, "every:1d@03:30");
        assert_eq!(policy.retention, 14);
        assert_eq!(policy.services, vec!["nextcloud", "vaultwarden"]);

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn get_backup_schedule_reads_off_as_the_default_for_a_missing_or_empty_config() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", "/nonexistent/autobackup.conf");
        let resp = get_backup_schedule(Codec::Proto, pb::GetBackupScheduleRequest {}).await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::BackupSchedulePolicy::decode(body).unwrap();
        assert_eq!(policy.schedule, "off");
        assert_eq!(policy.retention, 7);
        assert!(policy.services.is_empty());
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
    }

    #[tokio::test]
    async fn set_backup_schedule_answers_with_the_policy_re_read_from_disk_not_the_request() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-setsched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autobackup.conf");
        std::fs::write(&config, "SCHEDULE=every:1d@03:30\nRETENTION=14\nSERVICES='nextcloud'\n").unwrap();
        let wrapper = write_stub(&dir, "backup-ctl.sh", "#!/bin/sh\necho \"ARGV: $*\" > \"$(dirname \"$0\")/argv.txt\"\n");

        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &wrapper);
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", &config);

        let resp = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "every:1d@03:30".to_string(),
                retention: 14,
                services: vec!["nextcloud".to_string(), "gitlab".to_string()],
                passphrase: String::new(),
            },
        )
        .await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let policy = pb::BackupSchedulePolicy::decode(body).unwrap();
        assert_eq!(policy.services, vec!["nextcloud"], "gitlab must not appear: the answer is read, not echoed");

        let argv = std::fs::read_to_string(dir.join("argv.txt")).unwrap();
        assert_eq!(argv.trim(), "ARGV: set-schedule every:1d@03:30 14 nextcloud gitlab");

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_policy_offers_drives_only_when_the_wrapper_has_their_verbs() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-drives-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autobackup.conf");
        std::fs::write(&config, "SCHEDULE=off\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", &config);

        let old = write_stub(&dir, "old-ctl.sh", "#!/bin/sh\ncase \"$1\" in\n  set-schedule) ;;\nesac\n");
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &old);
        assert!(read_backup_schedule().drives.is_none(), "an older wrapper must not offer drives");

        let current = write_stub(&dir, "new-ctl.sh", "#!/bin/sh\ncase \"$1\" in\n  set-drives) ;;\nesac\n");
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &current);
        assert!(read_backup_schedule().drives.is_some(), "a wrapper with the verbs must offer drives");

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_verb_the_wrapper_lacks_asks_for_a_repair() {
        let resp = wrapper_failed("backup schedule unsupported action: set-drives");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let other = wrapper_failed("the backup wrapper exited 1");
        assert_eq!(other.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn set_backup_schedule_stores_a_passphrase_through_its_own_call_first() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-setpass-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("autobackup.conf");
        std::fs::write(&config, "SCHEDULE=off\n").unwrap();
        let wrapper = write_stub(
            &dir,
            "backup-ctl.sh",
            "#!/bin/sh\n\
             echo \"$1\" >> \"$(dirname \"$0\")/calls.txt\"\n\
             if [ \"$1\" = set-passphrase ]; then cat > \"$(dirname \"$0\")/passphrase.txt\"; fi\n",
        );
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &wrapper);
        std::env::set_var("GRYONIXNEXUSD_BACKUP_CONFIG", &config);

        let _ = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "every:1d@03:30".to_string(),
                retention: 7,
                services: vec!["vaultwarden".to_string()],
                passphrase: "correct horse battery staple".to_string(),
            },
        )
        .await;

        let calls = std::fs::read_to_string(dir.join("calls.txt")).unwrap();
        assert_eq!(calls.lines().collect::<Vec<_>>(), vec!["set-passphrase", "set-schedule"],
                  "set-passphrase must run, and run BEFORE set-schedule");
        let stored = std::fs::read_to_string(dir.join("passphrase.txt")).unwrap();
        assert_eq!(stored, "correct horse battery staple");

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_backup_schedule_surfaces_a_bad_grammar_refusal_in_the_wrappers_own_words() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-backup-badsched-{}", std::process::id()));
        let wrapper = write_stub(
            &dir,
            "backup-ctl.sh",
            "#!/bin/sh\necho 'unsupported schedule: bogus' >&2\nexit 2\n",
        );
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", &wrapper);

        let resp = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "bogus".to_string(),
                retention: 7,
                services: vec![],
                passphrase: String::new(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["message"].as_str().unwrap().contains("unsupported schedule"));

        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_backup_schedule_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_BACKUP_WRAPPER", "/nonexistent/gryonixnexus-backup-ctl.sh");
        let resp = set_backup_schedule(
            Codec::Proto,
            pb::SetBackupScheduleRequest {
                schedule: "off".to_string(),
                retention: 7,
                services: vec![],
                passphrase: String::new(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_BACKUP_WRAPPER");
    }
}
