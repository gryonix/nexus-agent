use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::pb;

const MANIFEST_URL_ENV: &str = "GRYONIXNEXUSD_AGENT_UPDATE_MANIFEST_URL";
const DEFAULT_MANIFEST_URL: &str = "https://raw.githubusercontent.com/gryonix/nexus-agent/main/latest.json";

const SIGNING_PUBLIC_KEY_HEX: &str = "22e7be06fa63ad3319c386b23dfefaf0efc1e1f96560582bad42eeadecbb0be5";
const SIGNING_PUBLIC_KEY_ENV: &str = "GRYONIXNEXUSD_AGENT_UPDATE_SIGNING_PUBLIC_KEY_HEX";

fn signing_key_hex() -> String {
    if cfg!(debug_assertions) {
        if let Ok(hex) = std::env::var(SIGNING_PUBLIC_KEY_ENV) {
            return hex;
        }
    }
    SIGNING_PUBLIC_KEY_HEX.to_string()
}

fn signing_public_key() -> VerifyingKey {
    let hex = signing_key_hex();
    let bytes: [u8; 32] = hex_decode_32(&hex).expect("the signing public key must be 32 valid hex bytes");
    VerifyingKey::from_bytes(&bytes).expect("the signing public key must be a valid Ed25519 point")
}

fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn signed_payload(manifest: &Manifest) -> Vec<u8> {
    format!("{}\n{}\n{}\n", manifest.version, manifest.tag, manifest.sha256).into_bytes()
}

fn verify_manifest_signature(manifest: &Manifest) -> Result<(), String> {
    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&manifest.signature)
        .map_err(|err| format!("manifest signature is not valid base64: {err}"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "manifest signature is not 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_bytes);
    signing_public_key()
        .verify(&signed_payload(manifest), &signature)
        .map_err(|_| "manifest signature does not verify".to_string())
}

const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// The status asks the feed again after this
const STATUS_FRESHNESS: Duration = Duration::from_secs(10 * 60);
/// Next look while an update waits for a quiet host
const BUSY_RETRY: Duration = Duration::from_secs(10 * 60);
const HTTP_TIMEOUT_SECS: u64 = 15;
const DOWNLOAD_TIMEOUT_SECS: u64 = 120;
const BUILD_TIMEOUT_SECS: u64 = 15 * 60;
const SMOKE_TEST_TIMEOUT_SECS: u64 = 10;

const STATE_DIR_ENV: &str = "GRYONIXNEXUSD_STATE_DIR";
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";

fn state_dir() -> PathBuf {
    PathBuf::from(std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string()))
}

fn apply_state_path() -> PathBuf {
    state_dir().join("agent-update-apply.json")
}

fn staging_dir() -> PathBuf {
    state_dir().join("agent-update-staging")
}

fn manifest_url() -> String {
    std::env::var(MANIFEST_URL_ENV).unwrap_or_else(|_| DEFAULT_MANIFEST_URL.to_string())
}

fn curl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN").unwrap_or_else(|_| "curl".to_string()))
}

fn tar_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_TAR_BIN").unwrap_or_else(|_| "tar".to_string()))
}

fn docker_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string()))
}

fn systemctl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string()))
}

fn bin_dest() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST").unwrap_or_else(|_| "/usr/local/bin/gryonixnexusd".to_string()))
}

fn rust_image() -> String {
    std::env::var("GRYONIXNEXUSD_AGENT_UPDATE_RUST_IMAGE").unwrap_or_else(|_| "rust:1-alpine".to_string())
}

// ────────────────────────────── checking ───────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub tag: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableUpdate {
    pub manifest: Manifest,
}

static LAST_CHECK: std::sync::Mutex<Option<AvailableUpdate>> = std::sync::Mutex::new(None);
static LAST_CHECK_AT: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// Claims the next feed check unless one ran recently
fn claim_check(fresh_for: Duration) -> bool {
    let mut at = LAST_CHECK_AT.lock().unwrap_or_else(|p| p.into_inner());
    if at.is_some_and(|at| at.elapsed() < fresh_for) {
        return false;
    }
    *at = Some(std::time::Instant::now());
    true
}

/// A fresh status for the app, without the six-hour wait
async fn refresh_if_stale() {
    if !claim_check(STATUS_FRESHNESS) {
        return;
    }
    match check(env!("CARGO_PKG_VERSION")).await {
        Ok(found) => *LAST_CHECK.lock().unwrap_or_else(|p| p.into_inner()) = found,
        Err(err) => tracing::debug!(%err, "agent update check did not complete"),
    }
}

/// The newer published version, if the last check found one
pub fn available_version() -> Option<String> {
    LAST_CHECK.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|u| u.manifest.version.clone())
}

/// Fetches the manifest and compares it against `installed`
pub async fn check(installed: &str) -> Result<Option<AvailableUpdate>, String> {
    let body = fetch_manifest().await?;
    let manifest: Manifest = serde_json::from_str(&body).map_err(|err| format!("malformed manifest: {err}"))?;
    verify_manifest_signature(&manifest).map_err(|err| format!("refusing an unsigned or forged manifest: {err}"))?;
    if is_newer(&manifest.version, installed) {
        Ok(Some(AvailableUpdate { manifest }))
    } else {
        Ok(None)
    }
}

async fn fetch_manifest() -> Result<String, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(HTTP_TIMEOUT_SECS + 5),
        tokio::process::Command::new(curl_bin())
            .args(["-sS", "-f", "--max-time", &HTTP_TIMEOUT_SECS.to_string(), &manifest_url()])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "curl timed out".to_string())?
    .map_err(|err| format!("could not run curl: {err}"))?;
    if !output.status.success() {
        return Err(format!("curl exited {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|err| format!("manifest was not UTF-8: {err}"))
}

fn is_newer(candidate: &str, installed: &str) -> bool {
    match (parse_version(candidate), parse_version(installed)) {
        (Some(candidate), Some(installed)) => candidate > installed,
        _ => false,
    }
}

fn parse_version(value: &str) -> Option<Vec<u64>> {
    let (numbers, suffix) = value.split_once(['-', '+']).unwrap_or((value, ""));
    let mut parts: Vec<u64> = numbers.split('.').map(|part| part.parse::<u64>().ok()).collect::<Option<_>>()?;
    parts.extend(suffix.parse::<u64>().ok());
    Some(parts)
}

pub fn spawn() {
    tokio::spawn(async move {
        loop {
            claim_check(Duration::ZERO);
            match check(env!("CARGO_PKG_VERSION")).await {
                Ok(found) => {
                    if let Some(update) = &found {
                        tracing::info!(
                            version = %update.manifest.version,
                            tag = %update.manifest.tag,
                            "a newer gryonixnexusd is published — confirm from the app to fetch it"
                        );
                    }
                    *LAST_CHECK.lock().unwrap_or_else(|p| p.into_inner()) = found.clone();
                    if let Some(update) = found {
                        apply_by_itself(&update).await;
                    }
                }
                Err(err) => tracing::debug!(%err, "agent update check did not complete"),
            }
            let waiting = available_version().is_some() && load_apply_state().auto() && anything_running();
            tokio::time::sleep(if waiting { BUSY_RETRY } else { CHECK_INTERVAL }).await;
        }
    });
}

// ──────────────────────────── apply state ────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct ApplyState {
    #[serde(default)]
    applying_version: Option<String>,
    #[serde(default)]
    apply_attempted: bool,
    #[serde(default)]
    last_apply_succeeded: bool,
    #[serde(default)]
    last_apply_reason: String,
    #[serde(default)]
    boot_attempts: u32,
    /// None means on: updates apply by themselves
    #[serde(default)]
    auto_update: Option<bool>,
    /// A version the agent failed to apply by itself
    #[serde(default)]
    auto_failed: Option<String>,
}

impl ApplyState {
    fn auto(&self) -> bool {
        self.auto_update.unwrap_or(true)
    }
}

const MAX_BOOT_ATTEMPTS: u32 = 3;

fn previous_binary() -> PathBuf {
    bin_dest().with_extension("previous")
}

fn load_apply_state() -> ApplyState {
    std::fs::read_to_string(apply_state_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_apply_state(state: &ApplyState) {
    let Ok(text) = serde_json::to_string(state) else { return };
    if let Err(err) = write_state_file(&apply_state_path(), &text) {
        tracing::warn!(%err, "could not persist the agent update state");
    }
}

fn write_state_file(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    file.write_all(text.as_bytes())
}

/// Called first thing in `main`, before anything that can fail
pub fn guard_startup() {
    let mut state = load_apply_state();
    let Some(expected) = state.applying_version.clone() else { return };
    if expected != env!("CARGO_PKG_VERSION") {
        return;
    }
    state.boot_attempts += 1;
    if state.boot_attempts <= MAX_BOOT_ATTEMPTS {
        save_apply_state(&state);
        return;
    }
    let restored = restore_previous(&previous_binary(), &bin_dest());
    state.applying_version = None;
    state.boot_attempts = 0;
    state.apply_attempted = true;
    state.last_apply_succeeded = false;
    state.last_apply_reason = match &restored {
        Ok(()) => format!("version {expected} did not start; the previous agent was put back"),
        Err(why) => format!("version {expected} did not start and the previous agent could not be put back: {why}"),
    };
    save_apply_state(&state);
    if restored.is_ok() {
        tracing::error!(version = %expected, "the new agent never started; the previous one was put back");
        std::process::exit(1);
    }
}

fn restore_previous(previous: &std::path::Path, current: &std::path::Path) -> Result<(), String> {
    if !previous.is_file() {
        return Err("no previous binary was kept".to_string());
    }
    std::fs::rename(previous, current).map_err(|err| err.to_string())
}

/// Called once at agent startup, before [`spawn`]
pub fn reconcile_on_startup() {
    let mut state = load_apply_state();
    let Some(expected) = state.applying_version.take() else { return };
    let running = env!("CARGO_PKG_VERSION");
    state.apply_attempted = true;
    state.boot_attempts = 0;
    if expected == running {
        state.last_apply_succeeded = true;
        state.last_apply_reason.clear();
        tracing::info!(version = %running, "agent update applied — running the new version");
    } else {
        state.last_apply_succeeded = false;
        state.last_apply_reason = format!("expected to come back as {expected}, started as {running} instead");
        tracing::warn!(expected = %expected, running = %running, "agent update did not take effect");
    }
    save_apply_state(&state);
}

// ────────────────────────────── RPCs ──────────────────────────────

pub async fn get_agent_update_status(codec: Codec, _req: pb::GetAgentUpdateStatusRequest) -> Resp {
    refresh_if_stale().await;
    let available = LAST_CHECK.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let state = load_apply_state();
    let status = pb::AgentUpdateStatus {
        installed_version: env!("CARGO_PKG_VERSION").to_string(),
        update_available: available.is_some(),
        available_version: available.as_ref().map(|u| u.manifest.version.clone()).unwrap_or_default(),
        available_tag: available.as_ref().map(|u| u.manifest.tag.clone()).unwrap_or_default(),
        apply_attempted: state.apply_attempted,
        last_apply_succeeded: state.last_apply_succeeded,
        last_apply_reason: state.last_apply_reason.clone(),
        auto_update: state.auto(),
    };
    codec
        .encode(&status)
        .unwrap_or_else(|err| connect_error(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn apply_agent_update(codec: Codec, _req: pb::ApplyAgentUpdateRequest) -> Resp {
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        run_apply(codec, tx).await;
    });
    stream_response(json, rx)
}

struct ApplySink {
    tx: Sender<Bytes>,
    codec: Codec,
    journal: Option<crate::jobs::Journal>,
}

impl ApplySink {
    fn job_id(&self) -> String {
        crate::jobs::id_of(&self.journal)
    }

    async fn emit(&self, phase: pb::JobPhase, text: &str, reason: &str) {
        let event = pb::AgentUpdateEvent {
            phase: phase as i32,
            text: text.to_string(),
            reason: reason.to_string(),
            job_id: self.job_id(),
        };
        let payload = self.codec.encode_payload(&event);
        let _ = self.tx.send(envelope(0x00, &payload)).await;
    }

    async fn started(&self) {
        crate::jobs::tee(&self.journal, pb::JobPhase::Started as i32, "agent", "checking for an update");
        self.emit(pb::JobPhase::Started, "checking for an update", "").await;
    }

    async fn progress(&self, text: &str) {
        crate::jobs::tee(&self.journal, pb::JobPhase::Progress as i32, "agent", text);
        self.emit(pb::JobPhase::Progress, text, "").await;
    }

    async fn failed(&self, reason: &str) {
        if let Some(journal) = &self.journal {
            journal.finish(Some(reason));
        }
        self.emit(pb::JobPhase::Failed, "", reason).await;
        let _ = self.tx.send(error_trailer("failed_precondition", reason)).await;
    }

    /// The LAST event the old process ever sends
    async fn restarting(&self) {
        if let Some(journal) = &self.journal {
            journal.append(pb::JobPhase::Completed, "agent", "installed — restarting");
            journal.finish(None);
        }
        self.emit(pb::JobPhase::Completed, "installed — restarting", "").await;
    }
}

/// `AgentUpdate/SetAgentAutoUpdate`
pub async fn set_agent_auto_update(codec: Codec, req: pb::SetAgentAutoUpdateRequest) -> Resp {
    save_apply_state(&ApplyState { auto_update: Some(req.enabled), ..load_apply_state() });
    get_agent_update_status(codec, pb::GetAgentUpdateStatusRequest {}).await
}

/// Whether the agent should apply this version by itself now
fn may_apply_by_itself(state: &ApplyState, version: &str, busy: bool) -> bool {
    state.auto() && !busy && state.applying_version.is_none() && state.auto_failed.as_deref() != Some(version)
}

fn anything_running() -> bool {
    crate::jobs::any_running() || crate::install::journal::any_running()
}

/// Applies a found update when switched on and nothing runs
async fn apply_by_itself(update: &AvailableUpdate) {
    let version = update.manifest.version.clone();
    if !may_apply_by_itself(&load_apply_state(), &version, anything_running()) {
        return;
    }
    tracing::info!(%version, "applying a published agent update by itself");
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    if !run_apply(Codec::Proto, tx).await {
        save_apply_state(&ApplyState { auto_failed: Some(version), ..load_apply_state() });
    }
}

/// True once the new binary is in and restarting
async fn run_apply(codec: Codec, tx: Sender<Bytes>) -> bool {
    let journal = crate::jobs::Journal::open(pb::JobKind::AgentUpdate, "gryonixnexusd");
    let sink = ApplySink { tx, codec, journal };
    sink.started().await;

    let Some((update, tarball)) = fetch_verified_release(&sink).await else { return false };
    let staging = staging_dir();
    let Some(built) = build_release(&sink, &update, &tarball, &staging).await else {
        let _ = std::fs::remove_dir_all(&staging);
        return false;
    };
    save_apply_state(&ApplyState { applying_version: Some(update.manifest.version.clone()), ..load_apply_state() });

    sink.progress("installing").await;
    if let Err(err) = swap_binary(&built) {
        sink.failed(&format!("could not install the new binary: {err}")).await;
        save_apply_state(&ApplyState { applying_version: None, ..load_apply_state() });
        let _ = std::fs::remove_dir_all(&staging);
        return false;
    }

    let _ = std::fs::remove_dir_all(&staging);
    sink.restarting().await;
    let _ = tokio::process::Command::new(systemctl_bin())
        .args(["restart", "gryonixnexusd"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    true
}

/// Checks for an update, downloads it and verifies its checksum
async fn fetch_verified_release(sink: &ApplySink) -> Option<(AvailableUpdate, Vec<u8>)> {
    let update = match check(env!("CARGO_PKG_VERSION")).await {
        Ok(Some(update)) => update,
        Ok(None) => {
            sink.failed("no update is currently available").await;
            return None;
        }
        Err(err) => {
            sink.failed(&format!("could not check for an update: {err}")).await;
            return None;
        }
    };
    sink.progress(&format!("downloading {}", update.manifest.tag)).await;
    let tarball = match download(&update.manifest.url).await {
        Ok(bytes) => bytes,
        Err(err) => {
            sink.failed(&format!("could not download the release: {err}")).await;
            return None;
        }
    };

    sink.progress("verifying the checksum").await;
    let actual = sha256_hex(&tarball);
    if actual != update.manifest.sha256 {
        sink.failed(&format!(
            "checksum mismatch: manifest names {}, downloaded file hashes to {actual} — refusing to build or run this",
            update.manifest.sha256
        ))
        .await;
        return None;
    }
    Some((update, tarball))
}

async fn build_release(
    sink: &ApplySink,
    update: &AvailableUpdate,
    tarball: &[u8],
    staging: &std::path::Path,
) -> Option<PathBuf> {
    let _ = std::fs::remove_dir_all(staging);
    if let Err(err) = std::fs::create_dir_all(staging) {
        sink.failed(&format!("could not create a staging directory: {err}")).await;
        return None;
    }

    sink.progress("unpacking").await;
    if let Err(err) = extract(tarball, staging).await {
        sink.failed(&err).await;
        return None;
    }

    let agent_dir = staging.join("Agent");
    let crate_dir = agent_dir.join("gryonixnexusd");
    if !crate_dir.join("Cargo.toml").is_file() {
        sink.failed("the downloaded release does not have the expected Agent/gryonixnexusd layout").await;
        return None;
    }

    sink.progress("building — this can take a few minutes").await;
    if let Err(err) = build_in_docker(&agent_dir).await {
        sink.failed(&err).await;
        return None;
    }

    let built = crate_dir.join("target").join("release").join("gryonixnexusd");
    if !built.is_file() {
        sink.failed("the build produced no binary").await;
        return None;
    }

    sink.progress("checking the new binary starts").await;
    if let Err(err) = smoke_test(&built, &update.manifest.version).await {
        sink.failed(&err).await;
        return None;
    }
    Some(built)
}

async fn download(url: &str) -> Result<Vec<u8>, String> {
    let output = tokio::time::timeout(
        Duration::from_secs(DOWNLOAD_TIMEOUT_SECS + 5),
        tokio::process::Command::new(curl_bin())
            .args(["-sS", "-f", "-L", "--max-time", &DOWNLOAD_TIMEOUT_SECS.to_string(), url])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "the download timed out".to_string())?
    .map_err(|err| format!("could not run curl: {err}"))?;
    if !output.status.success() {
        return Err(format!("curl exited {}", output.status));
    }
    Ok(output.stdout)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn extract(tarball: &[u8], into: &std::path::Path) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(tar_bin())
        .args(["-xzf", "-", "--strip-components=1", "-C"])
        .arg(into)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run tar: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(tarball).await;
    }
    let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .map_err(|_| "tar timed out".to_string())?
        .map_err(|err| format!("could not run tar: {err}"))?;
    if !output.status.success() {
        return Err(format!("tar exited {}: {}", output.status, bounded_tail(&output.stderr, 500)));
    }
    Ok(())
}

async fn build_in_docker(agent_dir: &std::path::Path) -> Result<(), String> {
    let mount = format!("{}:/src", agent_dir.display());
    let script = "if ! apk add --no-cache build-base protoc protobuf-dev >/tmp/apk.log 2>&1; then \
                   cat /tmp/apk.log >&2; exit 1; fi; cargo build --release --locked";
    let output = tokio::time::timeout(
        Duration::from_secs(BUILD_TIMEOUT_SECS),
        tokio::process::Command::new(docker_bin())
            .args(["run", "--rm", "-v", &mount, "-w", "/src/gryonixnexusd", &rust_image(), "sh", "-c", script])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "the build timed out".to_string())?
    .map_err(|err| format!("could not run docker: {err}"))?;
    if !output.status.success() {
        return Err(format!("the build failed:\n{}", bounded_tail(&output.stderr, 2000)));
    }
    Ok(())
}

fn bounded_tail(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        chars.into_iter().collect()
    } else {
        format!("…{}", chars[chars.len() - max_chars..].iter().collect::<String>())
    }
}

async fn smoke_test(binary: &std::path::Path, expected_version: &str) -> Result<(), String> {
    let output = tokio::time::timeout(
        Duration::from_secs(SMOKE_TEST_TIMEOUT_SECS),
        tokio::process::Command::new(binary).arg("version").stdin(Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| "the new binary did not answer 'version' in time".to_string())?
    .map_err(|err| format!("could not run the new binary: {err}"))?;
    if !output.status.success() {
        return Err(format!("the new binary exited {} answering 'version'", output.status));
    }
    let printed = String::from_utf8_lossy(&output.stdout);
    if !printed.contains(expected_version) {
        return Err(format!("the new binary reports '{}', expected {expected_version}", printed.trim()));
    }
    Ok(())
}

fn swap_binary(built: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let dest = bin_dest();
    let staged = dest.with_extension("new");
    let _ = std::fs::copy(&dest, previous_binary());
    std::fs::copy(built, &staged).map_err(|err| format!("could not stage the new binary next to the old one: {err}"))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(|err| {
        let _ = std::fs::remove_file(&staged);
        format!("could not set the new binary's mode: {err}")
    })?;
    std::fs::rename(&staged, &dest).map_err(|err| {
        let _ = std::fs::remove_file(&staged);
        format!("{err}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_applies_itself_only_when_on_quiet_and_not_failed_before() {
        let on = ApplyState::default();
        assert!(on.auto(), "on unless switched off");
        assert!(may_apply_by_itself(&on, "0.0.300", false));
        assert!(!may_apply_by_itself(&on, "0.0.300", true), "a running job waits");
        let off = ApplyState { auto_update: Some(false), ..ApplyState::default() };
        assert!(!may_apply_by_itself(&off, "0.0.300", false));
        let failed = ApplyState { auto_failed: Some("0.0.300".into()), ..ApplyState::default() };
        assert!(!may_apply_by_itself(&failed, "0.0.300", false));
        assert!(may_apply_by_itself(&failed, "0.0.301", false), "a newer version is tried");
        let applying = ApplyState { applying_version: Some("0.0.300".into()), ..ApplyState::default() };
        assert!(!may_apply_by_itself(&applying, "0.0.300", false));
    }
    use std::io::Write;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn sandbox(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-agent-update-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const TEST_PRIVATE_KEY_HEX: &str = "f10c702fd5a5263b92ccd3a5cd3463159ce7fc07f634cf2bde1afaeb07dacd58";
    const TEST_PUBLIC_KEY_HEX: &str = "48944c96c921bac5e29136ddb80f73254530c00b6cc712ca4a78e56e5bb70f18";

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&hex_decode_32(TEST_PRIVATE_KEY_HEX).unwrap())
    }

    fn signed_manifest_json(version: &str, tag: &str, url: &str, sha256: &str) -> String {
        use ed25519_dalek::Signer;
        let manifest = Manifest { version: version.into(), tag: tag.into(), url: url.into(), sha256: sha256.into(), signature: String::new() };
        let signature = test_signing_key().sign(&signed_payload(&manifest));
        use base64::Engine;
        let signature = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        format!(r#"{{"version":"{version}","tag":"{tag}","url":"{url}","sha256":"{sha256}","signature":"{signature}"}}"#)
    }

    // ─────────────────────────── version comparison ───────────────────────

    #[test]
    fn version_comparison_is_numeric_not_lexicographic() {
        assert!(is_newer("0.0.109", "0.0.108"));
        assert!(!is_newer("0.0.9", "0.0.10"));
        assert!(is_newer("0.0.10", "0.0.9"));
        assert!(is_newer("26.10.12-1", "26.10.12"));
        assert!(is_newer("26.10.12-2", "26.10.12-1"));
        assert!(!is_newer("26.10.12-9", "26.10.13"));
        assert!(!is_newer("0.0.108", "0.0.108"));
        assert!(!is_newer("0.0.107", "0.0.108"));
    }

    #[test]
    fn a_dated_version_beats_the_old_numbering() {
        assert!(is_newer("26.10.11", "0.0.237"));
        assert!(is_newer("26.11.1", "26.10.31"));
        assert!(!is_newer("0.0.237", "26.10.11"));
    }

    #[test]
    fn a_malformed_or_non_numeric_version_is_never_newer() {
        assert!(!is_newer("not-a-version", "0.0.108"));
        assert!(!is_newer("0.0.108", "not-a-version"));
        assert!(!is_newer("", ""));
    }

    // ────────────────────────────── check() ────────────────────────────────

    fn stub_curl(dir: &std::path::Path, body: &str, status: i32) -> PathBuf {
        let path = dir.join("curl");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "#!/bin/bash\ncat <<'BODY'\n{body}\nBODY\nexit {status}").unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn a_recent_check_is_not_repeated() {
        assert!(claim_check(Duration::ZERO));
        assert!(!claim_check(Duration::from_secs(3600)));
        assert!(claim_check(Duration::ZERO));
    }

    #[tokio::test]
    async fn a_newer_manifest_version_is_reported() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("newer");
        let body = signed_manifest_json("0.0.999", "v0.0.999", "https://example.com/x.tar.gz", "deadbeef");
        let curl = stub_curl(&dir, &body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        let update = result.unwrap().expect("a newer version must be reported");
        assert_eq!(update.manifest.version, "0.0.999");
        assert_eq!(update.manifest.tag, "v0.0.999");
    }

    #[tokio::test]
    async fn a_manifest_that_is_not_newer_reports_nothing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("current");
        let body = signed_manifest_json("0.0.108", "v0.0.108", "https://example.com/x.tar.gz", "deadbeef");
        let curl = stub_curl(&dir, &body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn a_manifest_with_a_tampered_field_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("tampered");
        let body = signed_manifest_json("0.0.999", "v0.0.999", "https://example.com/x.tar.gz", "deadbeef")
            .replace("deadbeef", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd");
        let curl = stub_curl(&dir, &body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        let err = result.expect_err("a tampered manifest must not be trusted");
        assert!(err.contains("signature"), "the failure must name the reason: {err}");
    }

    #[tokio::test]
    async fn a_manifest_with_an_invalid_signature_field_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("bad-sig-field");
        let body = r#"{"version":"0.0.999","tag":"v0.0.999","url":"https://example.com/x.tar.gz","sha256":"deadbeef","signature":"not-base64!!"}"#;
        let curl = stub_curl(&dir, body, 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        std::env::set_var(SIGNING_PUBLIC_KEY_ENV, TEST_PUBLIC_KEY_HEX);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        std::env::remove_var(SIGNING_PUBLIC_KEY_ENV);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_failed_fetch_is_an_error_not_a_silent_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("fetch-fail");
        let curl = stub_curl(&dir, "", 22); // curl's own exit code for -f on an HTTP error
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err(), "a curl failure must not read as 'nothing to report'");
    }

    #[tokio::test]
    async fn a_malformed_manifest_body_is_an_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("garbage");
        let curl = stub_curl(&dir, "not json at all", 0);
        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN", &curl);
        let result = check("0.0.108").await;
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_CURL_BIN");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err());
    }

    // ─────────────────────────────── digest ────────────────────────────────

    #[test]
    fn sha256_matches_a_known_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ─────────────────────────── apply-state reconciliation ───────────────

    fn with_state_dir<T>(name: &str, body: impl FnOnce() -> T) -> T {
        let dir = sandbox(name);
        std::env::set_var(STATE_DIR_ENV, &dir);
        let out = body();
        std::env::remove_var(STATE_DIR_ENV);
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn no_marker_means_reconcile_does_nothing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("no-marker", || {
            reconcile_on_startup();
            let state = load_apply_state();
            assert!(!state.apply_attempted);
        });
    }

    #[test]
    fn coming_back_as_the_expected_version_reads_as_success() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("success", || {
            save_apply_state(&ApplyState {
                applying_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                ..Default::default()
            });
            reconcile_on_startup();
            let state = load_apply_state();
            assert!(state.apply_attempted);
            assert!(state.last_apply_succeeded);
            assert!(state.last_apply_reason.is_empty());
            assert_eq!(state.applying_version, None, "the marker must be cleared once reconciled");
        });
    }

    #[test]
    fn coming_back_as_a_different_version_reads_as_failure() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("mismatch", || {
            save_apply_state(&ApplyState { applying_version: Some("99.99.99".to_string()), ..Default::default() });
            reconcile_on_startup();
            let state = load_apply_state();
            assert!(state.apply_attempted);
            assert!(!state.last_apply_succeeded);
            assert!(state.last_apply_reason.contains("99.99.99"));
            assert_eq!(state.applying_version, None);
        });
    }

    #[test]
    fn a_missing_state_file_reads_as_the_defaults() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        with_state_dir("missing", || {
            let state = load_apply_state();
            assert_eq!(state, ApplyState::default());
        });
    }

    // ──────────────────────────────── extract ──────────────────────────────

    fn make_tarball(dir: &std::path::Path) -> Vec<u8> {
        let root = dir.join("nexus-agent-v0.0.999");
        std::fs::create_dir_all(root.join("Agent").join("gryonixnexusd")).unwrap();
        std::fs::write(root.join("Agent").join("gryonixnexusd").join("Cargo.toml"), "[package]\n").unwrap();
        let archive = dir.join("out.tar.gz");
        let status = std::process::Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(dir)
            .arg("nexus-agent-v0.0.999")
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read(&archive).unwrap()
    }

    #[tokio::test]
    async fn extract_strips_the_codeload_wrapper_directory() {
        let src = sandbox("extract-src");
        let tarball = make_tarball(&src);
        let dest = sandbox("extract-dest");

        extract(&tarball, &dest).await.unwrap();

        assert!(dest.join("Agent").join("gryonixnexusd").join("Cargo.toml").is_file());
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    // ─────────────────────────────── smoke test ─────────────────────────────

    fn stub_binary(dir: &std::path::Path, prints: &str, status: i32) -> PathBuf {
        let path = dir.join("gryonixnexusd-stub");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "#!/bin/bash\necho '{prints}'\nexit {status}").unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn a_binary_that_prints_the_expected_version_passes() {
        let dir = sandbox("smoke-ok");
        let bin = stub_binary(&dir, "gryonixnexusd 0.0.999", 0);
        assert!(smoke_test(&bin, "0.0.999").await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_binary_that_prints_the_wrong_version_fails() {
        let dir = sandbox("smoke-wrong");
        let bin = stub_binary(&dir, "gryonixnexusd 0.0.1", 0);
        let err = smoke_test(&bin, "0.0.999").await.unwrap_err();
        assert!(err.contains("0.0.1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_binary_that_exits_nonzero_fails() {
        let dir = sandbox("smoke-crash");
        let bin = stub_binary(&dir, "boom", 1);
        assert!(smoke_test(&bin, "0.0.999").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────────── swap_binary ────────────────────────────

    #[test]
    fn swap_binary_replaces_the_destination_atomically() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = sandbox("swap");
        let built = dir.join("new-binary");
        std::fs::write(&built, b"new contents").unwrap();
        let dest = dir.join("installed");
        std::fs::write(&dest, b"old contents").unwrap();

        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST", &dest);
        let result = swap_binary(&built);
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST");

        assert!(result.is_ok());
        assert_eq!(std::fs::read(&dest).unwrap(), b"new contents");
        assert!(built.exists(), "the copy source is untouched — run_apply, not swap_binary, owns the staging tree's cleanup");
        assert!(!dest.with_extension("new").exists(), "the staged copy must be renamed away, not left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn swap_binary_survives_a_cross_filesystem_source() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let shm = std::path::PathBuf::from("/dev/shm");
        if !shm.is_dir() {
            return;
        }
        let built = shm.join(format!("gryonixnexusd-swap-test-{}", std::process::id()));
        std::fs::write(&built, b"new contents").unwrap();
        let dir = sandbox("swap-xdev");
        let dest = dir.join("installed");
        std::fs::write(&dest, b"old contents").unwrap();

        std::env::set_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST", &dest);
        let result = swap_binary(&built);
        std::env::remove_var("GRYONIXNEXUSD_AGENT_UPDATE_BIN_DEST");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"new contents");
        let _ = std::fs::remove_file(&built);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod signing_key_tests {
    use super::*;

    #[test]
    fn the_baked_in_key_is_a_valid_point() {
        assert!(hex_decode_32(SIGNING_PUBLIC_KEY_HEX).is_some());
        let bytes = hex_decode_32(SIGNING_PUBLIC_KEY_HEX).unwrap();
        assert!(VerifyingKey::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn the_previous_binary_is_put_back_over_the_current_one() {
        let dir = std::env::temp_dir().join(format!("agent-rollback-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (previous, current) = (dir.join("agent.previous"), dir.join("agent"));
        std::fs::write(&previous, b"old").unwrap();
        std::fs::write(&current, b"new").unwrap();
        restore_previous(&previous, &current).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"old");
        assert!(!previous.exists());
        assert!(restore_previous(&previous, &current).is_err(), "nothing left to put back");
    }
}
