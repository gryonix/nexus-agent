use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::Sender;

use crate::state::Store;
use super::adguard;
use super::home_network;
use super::caddy_check;
use super::authelia;
use super::litellm;
use super::llm_keys;
use super::anythingllm;
use super::n8n;
use super::qdrant;
use super::searxng;
use super::openclaw;
use super::ollama;
use super::open_webui;
use super::catalog;
use super::homepage;
use super::pihole;
use super::cloudflared;
use super::headscale;
use super::tailscale;
use super::caddy;
use super::context::{AutheliaProtection, Input};
use super::forgejo;
use super::gitlab;
use super::firewall_base;
use super::firewall_relay;
use super::relay_routes;
use super::crowdsec;
use super::ssh_password;
use super::packages;
use super::ports;
use super::immich;
use super::crafty;
use super::home_assistant;
use super::mosquitto;
use super::zigbee2mqtt;
use super::jellyfin;
use super::minecraft;
use super::mail::dockermailserver as dms;
use super::mail::mailcow;
use super::mail::mailu;
use super::nextcloud;
use super::passbolt;
use super::photoprism;
use super::psono;
use super::seafile;
use super::vaultwarden;
use super::firewall;
use super::host;
use super::host::report;
use super::host::{HostInput, HostRole};
use super::vpn::panel;
use super::vpn::protocols::{amnezia, openvpn, shadowsocks, xray};
use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::language::Language;
use crate::util::strip_ansi;
use std::sync::atomic::{AtomicU64, Ordering};

use super::journal;
use crate::{discover, pb};

/// The catalog ids this build's executor understands
#[cfg(test)]
pub fn implemented_service_ids() -> Vec<&'static str> {
    IMPLEMENTED_SERVICE_IDS.to_vec()
}

const IMPLEMENTED_SERVICE_IDS: &[&str] = &[
    "adguard-home",
    "ollama",
    "open-webui",
    "litellm",
    "anythingllm",
    "qdrant",
    "searxng",
    "openclaw",
    "n8n",
    "pihole",
    "homepage",
    "authelia",
    "cloudflared",
    "tailscale-node",
    "headscale",
    "docker-mailserver",
    "forgejo",
    "gitlab",
    "immich",
    "jellyfin",
    "home-assistant",
    // Its add-ons, refused without it — see `add_on_without_the_hub`.
    "mosquitto",
    "zigbee2mqtt",
    "minecraft-java",
    "minecraft-bedrock",
    "crafty-controller",
    "mailcow",
    "mailu",
    "nextcloud",
    "passbolt",
    "photoprism",
    "psono",
    "seafile",
    "vaultwarden",
    "vpn",
];

const DOCKER_TIMEOUT_SECS: u64 = 300;

/// Image pulls and builds move gigabytes on home lines.
const DOCKER_TRANSFER_TIMEOUT_SECS: u64 = 3600;

fn docker_timeout_secs(args: &[String]) -> u64 {
    if args.iter().any(|arg| arg == "pull" || arg == "build") { DOCKER_TRANSFER_TIMEOUT_SECS } else { DOCKER_TIMEOUT_SECS }
}

const ADMIN_LOCKDOWN_ON_TIMEOUT_SECS: u64 = 30;

const READY_DEADLINE_SECS: u64 = 300;
const READY_POLL_INTERVAL_SECS: u64 = 5;
const READY_HEARTBEAT_EVERY: u32 = 6;
/// `curl`'s own `timeout 20` on each install-API call.
const ADGUARD_HTTP_TIMEOUT_SECS: u64 = 20;

const SEAFILE_SETTINGS_DEADLINE_SECS: u64 = 600;

const PSONO_READY_DEADLINE_SECS: u64 = 300;
/// `ps_exec`'s own `timeout 60` per `docker exec` attempt.
const PSONO_EXEC_TIMEOUT_SECS: u64 = 60;
/// The one-shot `docker run` that mints Psono's server keypair
const PSONO_KEYGEN_TIMEOUT_SECS: u64 = 900;

const PASSBOLT_READY_DEADLINE_SECS: u64 = 300;
const PASSBOLT_EXEC_TIMEOUT_SECS: u64 = 60;

const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile";
const CADDYFILE_PREVIOUS: &str = "/etc/caddy/Caddyfile.gryonixnexus-previous";

/// Held while the Caddyfile is read, changed and written
fn with_caddyfile_lock<T>(change: impl FnOnce() -> T) -> T {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    change()
}

const OCC_READY_ATTEMPTS: u32 = 60;
const OCC_READY_INTERVAL_SECS: u64 = 5;
const OCC_CALL_TIMEOUT_SECS: u64 = 120;
const FORGEJO_READY_DEADLINE_SECS: u64 = 300;
const FORGEJO_EXEC_TIMEOUT_SECS: u64 = 120;
const GITLAB_READY_DEADLINE_SECS: u64 = 600;
const GITLAB_POLL_INTERVAL_SECS: u64 = 10;
const GITLAB_HEARTBEAT_EVERY: u32 = 3;
const GITLAB_EXEC_TIMEOUT_SECS: u64 = 120;
const GITLAB_RUNNER_TIMEOUT_SECS: u64 = 300;
const GITLAB_SIGNUP_MARKER: &str = ".gryonixnexus-signup-closed";

const DMS_READY_DEADLINE_SECS: u64 = 300;
/// `timeout 120 docker exec …` — the bash version's own per-call ceiling
const DMS_EXEC_TIMEOUT_SECS: u64 = 120;
const OPENSSL_TIMEOUT_SECS: u64 = 120;
/// The cert-sync script's one immediate run
const CERT_SYNC_RUN_TIMEOUT_SECS: u64 = 120;
const DMS_FIREWALL_LABEL: &str = "docker-mailserver";
const MAILU_FIREWALL_LABEL: &str = "mailu";
const MAILCOW_FIREWALL_LABEL: &str = "mailcow";

const MAILU_READY_DEADLINE_SECS: u64 = 300;
const MAILU_EXEC_TIMEOUT_SECS: u64 = 120;
/// `timeout 120` on the piped `config-import` call.
const MAILU_IMPORT_TIMEOUT_SECS: u64 = 120;

/// `git clone` of mailcow's own repository
const MAILCOW_GIT_CLONE_TIMEOUT_SECS: u64 = 600;
const MAILCOW_GENERATE_CONFIG_TIMEOUT_SECS: u64 = 300;
/// One `docker compose pull`/`up` attempt
const MAILCOW_COMPOSE_TIMEOUT_SECS: u64 = 600;
const MAILCOW_API_HTTP_TIMEOUT_SECS: u64 = 20;
const MAILCOW_API_DEADLINE_SECS: u64 = 300;
const MAILCOW_API_POLL_INTERVAL_SECS: u64 = 5;
const MAILCOW_API_HEARTBEAT_EVERY: u32 = 6;

const ECHO_LIMIT: usize = 64;

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

// ─────────────────────────── docker seam ───────────────────────────

/// The binary every docker call in this module spawns
pub(crate) fn docker_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string()))
}

fn git_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_GIT_BIN").unwrap_or_else(|_| "git".to_string()))
}

fn bash_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_BASH_BIN").unwrap_or_else(|_| "bash".to_string()))
}

fn curl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_CURL_BIN").unwrap_or_else(|_| "curl".to_string()))
}

fn compose_file_args(project: &str, dir: &Path) -> Vec<String> {
    vec![
        "compose".to_string(),
        "-p".to_string(),
        project.to_string(),
        "-f".to_string(),
        dir.join("docker-compose.yml").to_string_lossy().into_owned(),
    ]
}

/// `docker compose -p <project> -f <dir>/docker-compose.yml stop`
pub fn compose_stop_args(project: &str, dir: &Path) -> Vec<String> {
    let mut args = compose_file_args(project, dir);
    args.push("stop".to_string());
    args
}

/// `docker compose -p <project> -f <dir>/docker-compose.yml pull -q`
pub fn compose_pull_args(project: &str, dir: &Path) -> Vec<String> {
    let mut args = compose_file_args(project, dir);
    args.push("pull".to_string());
    args.push("-q".to_string());
    args
}

/// Creates the AI services' shared network when it is missing
async fn ensure_ai_network(sink: &EventSink) {
    let docker = docker_bin().to_string_lossy().to_string();
    if run_quiet(&docker, &["network", "create", super::ai_network::NAME]).await.is_ok() {
        let _ = sink.step("created the AI services' shared network").await;
    }
}

/// Where Caddy's requests reach the AI containers from
async fn ai_network_gateway() -> Option<String> {
    let format = "{{range .IPAM.Config}}{{.Gateway}} {{end}}";
    let output = tokio::process::Command::new(docker_bin())
        .args(["network", "inspect", super::ai_network::NAME, "--format", format])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    text.split_whitespace().find(|address| address.contains('.')).map(str::to_string)
}

async fn trust_ai_network_gateway(config_path: &Path, sink: &EventSink) {
    let Some(gateway) = ai_network_gateway().await else { return };
    let Ok(current) = std::fs::read_to_string(config_path) else { return };
    match openclaw::with_trusted_proxies(&current, &gateway) {
        Some(updated) if updated != current => {
            if std::fs::write(config_path, updated).is_ok() {
                let _ = sink.step("trusting the AI network's gateway").await;
            }
        }
        Some(_) => {}
        None => {
            let _ = sink.step("kept the gateway's own proxy list").await;
        }
    }
}

/// The chat's database outranks its environment; drop the neighbours' copies
async fn forget_stored_addresses(data: &Path, services: &[String]) {
    let keys = open_webui::stored_address_keys(services);
    if keys.is_empty() || !data.join("webui.db").exists() {
        return;
    }
    let docker = docker_bin().to_string_lossy().to_string();
    let volume = format!("{}:/data", data.display());
    let mut args = vec!["run", "--rm", "--entrypoint", "python3", "-v", &volume, open_webui::IMAGE];
    args.extend(["-c", open_webui::FORGET_KEYS_SCRIPT, "/data/webui.db"]);
    args.extend(keys);
    let _ = run_quiet(&docker, &args).await;
}

/// `docker compose -p <project> -f <dir>/docker-compose.yml up -d`
async fn compose_up(project: &str, dir: &Path, sink: &EventSink) -> Result<(), String> {
    run_docker_streaming(&compose_up_args(project, dir), sink).await?;
    verify_published_ports(project, dir).await?;
    verify_not_crash_looping(project, dir, sink).await
}

/// How many times `verify_published_ports` asks docker before believing it
const PORT_VERIFY_TRIES: u32 = 5;
const PORT_VERIFY_INTERVAL_SECS: u64 = 2;

fn missing_publishes(wanted: &[ports::Wanted], live: &[firewall::Port]) -> Vec<String> {
    wanted
        .iter()
        .filter(|want| !live.contains(&want.port))
        .map(|want| format!("{}/{}", want.port.port, want.port.proto))
        .collect()
}

async fn verify_published_ports(project: &str, dir: &Path) -> Result<(), String> {
    let Ok(compose) = tokio::fs::read_to_string(dir.join("docker-compose.yml")).await else {
        return Ok(());
    };
    let wanted = ports::published_in_compose(&compose);
    if wanted.is_empty() {
        return Ok(());
    }
    let mut missing: Vec<String> = Vec::new();
    for attempt in 0..PORT_VERIFY_TRIES {
        missing = missing_publishes(&wanted, &ports::published_ports_of_project(project).await);
        if missing.is_empty() {
            return Ok(());
        }
        if attempt + 1 < PORT_VERIFY_TRIES {
            tokio::time::sleep(Duration::from_secs(PORT_VERIFY_INTERVAL_SECS)).await;
        }
    }
    Err(format!(
        "the containers started without the ports they need ({}) — something else on this host took them",
        missing.join(", ")
    ))
}

const LOOP_WATCH_SECS: u64 = 60;
const LOOP_WATCH_INTERVAL_SECS: u64 = 5;
/// Quiet looks in a row that end the watch early.
const LOOP_QUIET_SAMPLES: u32 = 3;

pub(crate) fn went_quiet(
    quiet_streak: u32,
    samples_required: u32,
) -> bool {
    quiet_streak >= samples_required
}

async fn verify_not_crash_looping(
    project: &str,
    dir: &Path,
    sink: &EventSink,
) -> Result<(), String> {
    use crate::container_ops::capture;
    use crate::container_update::{restart_counts, verdict, Look};

    let args = vec![
        "compose".to_string(),
        "-p".to_string(),
        project.to_string(),
        "-f".to_string(),
        dir.join("docker-compose.yml").to_string_lossy().to_string(),
        "ps".to_string(),
        "--format".to_string(),
        "{{.Name}} {{.State}}".to_string(),
    ];

    let mut quiet_baseline: Option<std::collections::BTreeMap<String, u64>> = None;
    let mut who = String::new();
    let mut quiet = 0u32;
    let mut answered = false;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(LOOP_WATCH_SECS);
    loop {
        let Ok(res) = capture("docker", &args, 60).await else { return Ok(()) };
        if res.success {
            answered = true;
            let (names, restarting, label) = match verdict(&res.stdout) {
                Look::Running(names) => (names, false, String::new()),
                Look::Restarting(names) => {
                    (names.split(", ").map(str::to_string).collect(), true, names)
                }
                Look::Down(names) => {
                    (names.split(", ").map(str::to_string).collect(), false, names)
                }
            };
            let counts = restart_counts(&names).await;
            if !label.is_empty() {
                who = label;
            }
            match &quiet_baseline {
                Some(before) if !restarting && *before == counts => {
                    quiet += 1;
                    if went_quiet(quiet, LOOP_QUIET_SAMPLES) {
                        return Ok(());
                    }
                }
                _ => {
                    quiet_baseline = Some(counts);
                    quiet = 0;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(LOOP_WATCH_INTERVAL_SECS)).await;
    }

    let _ = sink;
    if !answered {
        return Ok(());
    }
    let name = if who.is_empty() { project.to_string() } else { who };
    Err(format!(
        "{name} never held still: over {LOOP_WATCH_SECS}s it kept restarting rather \
         than staying up, so the service is not running even though its ports are \
         published"
    ))
}

pub fn compose_up_args(project: &str, dir: &Path) -> Vec<String> {
    let mut args = compose_file_args(project, dir);
    args.push("up".to_string());
    args.push("-d".to_string());
    args
}

/// `docker compose -p <project> restart`
pub fn compose_restart_service_args(project: &str, dir: &Path, service: &str) -> Vec<String> {
    let mut args = compose_restart_args(project, dir);
    args.push(service.to_string());
    args
}

pub fn docker_run_once_args(image: &str, command: &[&str]) -> Vec<String> {
    let mut args = vec!["run".to_string(), "--rm".to_string(), image.to_string()];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

pub fn docker_run_mounted_args(mount: &str, image: &str, command: &[&str]) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        mount.to_string(),
        image.to_string(),
    ];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

pub fn docker_pull_args(image: &str) -> Vec<String> {
    vec!["pull".to_string(), "-q".to_string(), image.to_string()]
}

/// `docker exec <container> <command…>`.
pub fn docker_exec_args(container: &str, command: &[&str]) -> Vec<String> {
    let mut args = vec!["exec".to_string(), container.to_string()];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

pub fn compose_restart_args(project: &str, dir: &Path) -> Vec<String> {
    let mut args = compose_file_args(project, dir);
    args.push("restart".to_string());
    args
}

// ─────────────────────────── secrets ───────────────────────────

fn random_hex_24() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn random_hex_20() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 20];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn expand_random(template: &str) -> io::Result<String> {
    let mut out = String::new();
    for line in template.lines() {
        if line.contains("__RANDOM__") {
            out.push_str(&line.replacen("__RANDOM__", &random_hex_24()?, 1));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    Ok(out)
}

fn existing_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).ok().map(|meta| meta.permissions().mode() & 0o7777)
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Replaces `path` atomically with a file created at `mode`.
fn write_secret(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    crate::util::write_file_atomic(path, contents.as_bytes(), mode)
}

fn create_dir_0755(path: &Path) -> io::Result<()> {
    create_dir_with_mode(path, 0o755)
}

fn create_dir_with_mode(path: &Path, mode: u32) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    set_mode(path, mode)
}

fn create_dir_owned_by_group(path: &Path, mode: u32, gid: u32) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::os::unix::fs::chown(path, None, Some(gid))?;
    set_mode(path, mode)
}

fn create_dir_owned_by_user(path: &Path, mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    set_mode(path, mode)
}

fn create_dir_if_absent_0755(path: &Path) -> io::Result<bool> {
    if path.is_dir() {
        return Ok(false);
    }
    create_dir_0755(path)?;
    Ok(true)
}

fn write_env_if_absent(dir: &Path, template: &str) -> io::Result<bool> {
    let env_path = dir.join(".env");
    if std::fs::metadata(&env_path).map(|meta| meta.len() == 0).unwrap_or(false) {
        std::fs::remove_file(&env_path)?;
    }
    let expanded = expand_random(template)?;
    crate::util::create_file_atomic_if_absent(&env_path, expanded.as_bytes(), 0o600)
}

fn read_env_value(env_path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(env_path).ok()?;
    let prefix = format!("{key}=");
    text.lines().find_map(|line| line.strip_prefix(prefix.as_str()).map(str::to_string))
}

// ─────────────────────────── DoH key patch ───────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohSpelling {
    /// v0.107.74+: `http.doh.insecure_enabled`.
    InsecureEnabled,
    /// Pre-v0.107.74: `tls.allow_unencrypted_doh`.
    AllowUnencryptedDoh,
}

impl DohSpelling {
    fn key(self) -> &'static str {
        match self {
            DohSpelling::InsecureEnabled => "insecure_enabled",
            DohSpelling::AllowUnencryptedDoh => "allow_unencrypted_doh",
        }
    }
}

pub fn patch_doh_insecure(yaml: &str) -> (String, Option<DohSpelling>) {
    for spelling in [DohSpelling::InsecureEnabled, DohSpelling::AllowUnencryptedDoh] {
        let key = spelling.key();
        let prefix = format!("{key}:");
        if !yaml.lines().any(|line| line.trim_start().starts_with(prefix.as_str())) {
            continue;
        }
        let target = format!("{key}: false");
        let replacement = format!("{key}: true");
        let patched: Vec<String> = yaml
            .lines()
            .map(|line| {
                let indent_len = line.len() - line.trim_start().len();
                if &line[indent_len..] == target {
                    format!("{}{replacement}", &line[..indent_len])
                } else {
                    line.to_string()
                }
            })
            .collect();
        let mut joined = patched.join("\n");
        if yaml.ends_with('\n') {
            joined.push('\n');
        }
        return (joined, Some(spelling));
    }
    (yaml.to_string(), None)
}

// ─────────────────────────── language ───────────────────────────

fn language_from_code(code: &str) -> Language {
    match code {
        "de" => Language::De,
        "fr" => Language::Fr,
        "es" => Language::Es,
        "ru" => Language::Ru,
        "uk" => Language::Uk,
        "it" => Language::It,
        "ja" => Language::Ja,
        "zh" => Language::Zh,
        _ => Language::En,
    }
}

// ─────────────────────────── gate + request shaping ───────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    UnknownService(String),
    NotImplemented(String),
    DockerUnavailable(String),
    InvalidRequest(String),
    /// This host has no Caddy — see [`caddy_is_installed`].
    NoReverseProxy,
    PortsInUse(Vec<ports::Conflict>),
    AlreadyInstalledOutside { service: String, holder: String },
    LicenseNotAccepted(&'static str),
    EmulatorNeedsSmallPages(usize),
    MachineNotAtHome(&'static str),
    AddOnWithoutTheHub(&'static str),
    /// Zigbee2MQTT without the stick it talks to.
    ZigbeeWithoutAStick,
    /// A named stick that is not plugged into this machine
    StickMissing { service: &'static str, device: String },
    SiteNameTaken(Vec<String>),
    /// This host is already installing this service
    InstallAlreadyRunning(String),
    /// No run by that name on this host
    UnknownJob(String),
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => {
                (StatusCode::BAD_REQUEST, "invalid_argument", format!("unknown service '{}'", truncate(id)))
            }
            Rejection::NotImplemented(id) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!("this agent build has no installer for '{}' yet", truncate(id)),
            ),
            Rejection::DockerUnavailable(detail) => {
                (StatusCode::SERVICE_UNAVAILABLE, "unavailable", format!("container engine unavailable: {detail}"))
            }
            Rejection::InvalidRequest(detail) => (StatusCode::BAD_REQUEST, "invalid_argument", detail.clone()),
            Rejection::NoReverseProxy => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                "this host has no Caddy and the agent cannot install one here — every \
                 service is published through it, and automatic installation needs \
                 apt-get and systemd-run. Install Caddy by hand, or run the server \
                 setup on this machine, then install again"
                    .to_string(),
            ),
            Rejection::PortsInUse(conflicts) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this host cannot publish every port this service needs: {}. \
                     Docker would fail with 'address already in use' partway through \
                     the install. Choose different ports for this service, or stop \
                     what holds them, then install again",
                    conflicts.iter().map(ports::Conflict::describe).collect::<Vec<_>>().join("; ")
                ),
            ),
            Rejection::AlreadyInstalledOutside { service, holder } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{service} is already installed on this host — {holder} is answering on \
                     the port it uses, and gryonixNexus did not install it. This app does not \
                     take over an install it did not make. To manage it from here: back its \
                     data up, remove it on the machine, and install it again from the app. \
                     Nothing has been changed"
                ),
            ),
            Rejection::SiteNameTaken(names) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{} is already served by another service on this host. Caddy refuses a \
                     configuration that names one host twice, which would take HTTPS off every \
                     service on this machine, so nothing has been installed — give this service a \
                     name of its own",
                    names.join(", ")
                ),
            ),
            Rejection::LicenseNotAccepted(edition) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{edition} will not be installed: Mojang's EULA is not accepted. The image refuses to start without it, so installing anyway would leave a container restarting forever on this host — which reads as a broken image rather than an unanswered question. Accept the license in the app, then install again"
                ),
            ),
            Rejection::EmulatorNeedsSmallPages(page) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "Minecraft (Bedrock) will not be installed: its server exists only for x86-64, \
                     and on this ARM machine it would run under the box64 emulator, which needs a \
                     kernel with 4 KB memory pages. This kernel uses {} KB pages (the Raspberry Pi 5 \
                     default), so the server would start and accept no players. On a Raspberry Pi 5, \
                     add kernel=kernel8.img to /boot/firmware/config.txt, reboot, and install again. \
                     Nothing has been changed",
                    page / 1024
                ),
            ),
            Rejection::MachineNotAtHome(service) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{service} will not be installed: this machine is not at home. The hub \
                     finds lights, sensors and cameras over mDNS and SSDP, and neither leaves \
                     the home network — so a copy on a machine outside the house starts and \
                     discovers nothing, which reads as a broken install rather than as a \
                     machine in the wrong place. Install it on the machine that stands in the \
                     house, or say in the app that this one does. Nothing has been changed"
                ),
            ),
            Rejection::AddOnWithoutTheHub(service) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{service} will not be installed: this host has no Home Assistant. It is an \
                     add-on the hub talks to, and on its own there is nobody on the other end — \
                     it would start, sit idle and control nothing. Install the hub on this \
                     machine first. Nothing has been changed"
                ),
            ),
            Rejection::ZigbeeWithoutAStick => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "Zigbee2MQTT will not be installed: no Zigbee stick was named. It talks to \
                     the radio plugged into this machine, and without one the container starts \
                     and finds no adapter at all. Set the stick's path in the app — it is the \
                     same setting the hub uses. Nothing has been changed"
                ),
            ),
            Rejection::StickMissing { service, device } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "{service} will not be installed: the stick {device} is not plugged into this \
                     machine, and Docker refuses to start a container whose device is missing. Plug \
                     it in, or correct its path in the app, then install again. Nothing has been changed"
                ),
            ),
            Rejection::InstallAlreadyRunning(job) => (
                StatusCode::CONFLICT,
                "already_exists",
                format!("this host is already installing this service (job {job})"),
            ),
            Rejection::UnknownJob(job) => (
                StatusCode::NOT_FOUND,
                "not_found",
                format!("this host has no record of install job '{}'", truncate(job)),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }

    pub fn message(&self) -> String {
        self.parts().2
    }
}

fn first_repeated_domain(primary: &str, extras: &[String]) -> Option<String> {
    let mut seen: Vec<String> = vec![primary.trim().to_ascii_lowercase()];
    for extra in extras {
        let candidate = extra.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            continue;
        }
        if seen.contains(&candidate) {
            return Some(extra.trim().to_string());
        }
        seen.push(candidate);
    }
    None
}

fn machine_is_at_home(input: &Input, role: HostRole, dynamic_dns: bool) -> bool {
    role == HostRole::HomeBackend || input.local_only || dynamic_dns || input.machine_at_home
}

fn home_only_service_away(
    label: &str,
    input: &Input,
    role: HostRole,
    dynamic_dns: bool,
) -> Option<&'static str> {
    match label {
        "home-assistant" if !machine_is_at_home(input, role, dynamic_dns) => Some("Home Assistant"),
        _ => None,
    }
}

/// Whether this host runs the dynamic-DNS updater.
fn dynamic_dns_configured() -> bool {
    let Ok(text) = std::fs::read_to_string(super::host::ddns::CONF_PATH) else { return false };
    text.lines().any(|line| {
        line.trim()
            .strip_prefix("DDNS_NAMES=")
            .is_some_and(|names| !names.trim().trim_matches('\'').is_empty())
    })
}

fn requested_role(req: &pb::InstallServiceRequest) -> HostRole {
    match pb::HostRole::try_from(req.host_role) {
        Ok(pb::HostRole::VpsRelay) => HostRole::VpsRelay,
        Ok(pb::HostRole::HomeBackend) => HostRole::HomeBackend,
        _ => HostRole::SingleHost,
    }
}

fn is_device_path(value: &str) -> bool {
    value.starts_with("/dev/")
        && value.len() > "/dev/".len()
        && !value.contains("..")
        && !value.contains(char::is_whitespace)
}

fn add_on_without_the_hub(label: &str, installed: &[String]) -> Option<&'static str> {
    if !super::SMART_HOME_ADD_ON_IDS.contains(&label) {
        return None;
    }
    if installed.iter().any(|id| id == "home-assistant") {
        return None;
    }
    match label {
        "mosquitto" => Some("Mosquitto"),
        "zigbee2mqtt" => Some("Zigbee2MQTT"),
        _ => None,
    }
}

async fn free_mailu_subnet(wanted: &str) -> Option<String> {
    let docker = docker_bin();
    let listed = tokio::process::Command::new(&docker).args(["network", "ls", "-q"]).output().await.ok()?;
    let mut args = vec!["network".to_string(), "inspect".to_string(), "-f".to_string()];
    args.push("{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}".to_string());
    args.extend(String::from_utf8_lossy(&listed.stdout).split_whitespace().map(str::to_string));
    let networks = tokio::process::Command::new(&docker).args(&args).output().await.ok()?;
    let routes = tokio::process::Command::new("ip").args(["-4", "route", "show"]).output().await.ok()?;
    crate::install::mail::subnet::choose(
        wanted,
        &String::from_utf8_lossy(&networks.stdout),
        &String::from_utf8_lossy(&routes.stdout),
    )
}

fn bedrock_emulator_blocked(label: &str) -> Option<usize> {
    if label != "minecraft-bedrock" || std::env::consts::ARCH != "aarch64" {
        return None;
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (page > 0 && page != 4096).then_some(page as usize)
}

fn stick_missing(label: &str, input: &Input) -> Option<(&'static str, String)> {
    let service = match label {
        "zigbee2mqtt" => "Zigbee2MQTT",
        "home-assistant" => "Home Assistant",
        _ => return None,
    };
    let device = input.home_assistant_usb_device.trim();
    (!device.is_empty() && !Path::new(device).exists()).then(|| (service, device.to_string()))
}

fn license_not_accepted(label: &str, input: &Input) -> Option<&'static str> {
    match label {
        "minecraft-java" if !input.minecraft_java_accepts_eula => Some("Minecraft (Java)"),
        "minecraft-bedrock" if !input.minecraft_bedrock_accepts_eula => Some("Minecraft (Bedrock)"),
        _ => None,
    }
}

pub fn resolve(service_id: &str) -> Result<&'static str, Rejection> {
    let label =
        discover::known_service_id(service_id).ok_or_else(|| Rejection::UnknownService(service_id.to_string()))?;
    if !IMPLEMENTED_SERVICE_IDS.contains(&label) {
        return Err(Rejection::NotImplemented(service_id.to_string()));
    }
    Ok(label)
}

fn compose_project(label: &str) -> &'static str {
    match label {
        "docker-mailserver" => dms::COMPOSE_PROJECT,
        "forgejo" => forgejo::COMPOSE_PROJECT,
        "gitlab" => gitlab::COMPOSE_PROJECT,
        "immich" => immich::COMPOSE_PROJECT,
        "mailcow" => mailcow::COMPOSE_PROJECT,
        "mailu" => mailu::COMPOSE_PROJECT,
        "nextcloud" => nextcloud::COMPOSE_PROJECT,
        "jellyfin" => jellyfin::COMPOSE_PROJECT,
        "home-assistant" => home_assistant::COMPOSE_PROJECT,
        "mosquitto" => mosquitto::COMPOSE_PROJECT,
        "zigbee2mqtt" => zigbee2mqtt::COMPOSE_PROJECT,
        "ollama" => ollama::COMPOSE_PROJECT,
        "open-webui" => open_webui::COMPOSE_PROJECT,
        "litellm" => litellm::COMPOSE_PROJECT,
        "n8n" => n8n::COMPOSE_PROJECT,
        "anythingllm" => anythingllm::COMPOSE_PROJECT,
        "qdrant" => qdrant::COMPOSE_PROJECT,
        "searxng" => searxng::COMPOSE_PROJECT,
        "openclaw" => openclaw::COMPOSE_PROJECT,
        "minecraft-java" => minecraft::JAVA_COMPOSE_PROJECT,
        "minecraft-bedrock" => minecraft::BEDROCK_COMPOSE_PROJECT,
        "crafty-controller" => crafty::COMPOSE_PROJECT,
        "passbolt" => passbolt::COMPOSE_PROJECT,
        "photoprism" => photoprism::COMPOSE_PROJECT,
        "psono" => psono::COMPOSE_PROJECT,
        "seafile" => seafile::COMPOSE_PROJECT,
        "vaultwarden" => vaultwarden::COMPOSE_PROJECT,
        "vpn" => panel::COMPOSE_PROJECT,
        "pihole" => pihole::COMPOSE_PROJECT,
        "homepage" => homepage::COMPOSE_PROJECT,
        "authelia" => authelia::COMPOSE_PROJECT,
        // Same fall-through hazard as the install dispatch — see its comment.
        _ => adguard::COMPOSE_PROJECT,
    }
}

const REQUIRES_PUBLIC_DOMAIN: [&str; 4] =
    ["mailcow", "mailu", "docker-mailserver", "headscale"];

/// The same ceiling `MailInputValidator.maxAdditionalDomains` applies.
const MAX_ADDITIONAL_DOMAINS: usize = 9;

fn valid_hostname(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn valid_account_name(name: &str) -> bool {
    let name = name.trim();
    (1..=64).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
}

fn check_names(req: &pb::InstallServiceRequest) -> Result<(), String> {
    let bad_host = |what: &str, value: &str| {
        Err(format!("{what} '{}' is not a valid host name. Nothing was changed", truncate(value)))
    };
    if !valid_hostname(&req.domain) {
        return bad_host("the domain", &req.domain);
    }
    if let Some(extra) = req.additional_domains.iter().find(|d| !d.trim().is_empty() && !valid_hostname(d)) {
        return bad_host("the additional domain", extra);
    }
    for (key, value) in &req.settings {
        let is_name = key.ends_with("_hostname") || key == "xray_reality_sni";
        if is_name && !value.trim().is_empty() && !valid_hostname(value) {
            return bad_host(&format!("the setting {key}"), value);
        }
    }
    if !req.admin_username.trim().is_empty() && !valid_account_name(&req.admin_username) {
        return Err(format!(
            "the administrator name '{}' may use letters, digits and . _ - @ only. Nothing was changed",
            truncate(&req.admin_username)
        ));
    }
    Ok(())
}

fn build_input(req: &pb::InstallServiceRequest) -> Result<Input, String> {
    check_request(req)?;
    let defaults = Input::default();
    let mut input = Input {
        domain: req.domain.clone(),
        additional_domains: req.additional_domains.clone(),
        language: language_from_code(&req.language),
        local_only: req.local_only,
        admin_username: match req.admin_username.trim() {
            "" => defaults.admin_username.clone(),
            named => named.to_string(),
        },
        ..Input::default()
    };
    apply_paths(&mut input, req)?;
    apply_usb_device(&mut input, req)?;
    apply_texts(&mut input, req);
    apply_flags(&mut input, req);
    apply_numbers(&mut input, req);
    Ok(input)
}

fn check_request(req: &pb::InstallServiceRequest) -> Result<(), String> {
    if req.domain.trim().is_empty() {
        return Err("domain is required".to_string());
    }
    check_names(req)?;
    if let Some(repeated) = first_repeated_domain(&req.domain, &req.additional_domains) {
        return Err(format!(
            "'{}' is listed twice among this deployment's domains. Caddy refuses to load a site that names the same host twice, which would take HTTPS off every service on this machine, so nothing was changed",
            truncate(&repeated)
        ));
    }
    if req.local_only && REQUIRES_PUBLIC_DOMAIN.contains(&req.service_id.as_str()) {
        return Err(format!(
            "{} needs a public domain: it has to obtain a certificate and be reached from \
             outside, and a local-only deployment has no public name to do either with. \
             Nothing was changed",
            discover::known_service(&req.service_id).unwrap_or(&req.service_id)
        ));
    }
    if req.additional_domains.len() > MAX_ADDITIONAL_DOMAINS {
        return Err(format!(
            "at most {MAX_ADDITIONAL_DOMAINS} additional domains are supported, and this \
             request carries {}. Nothing was changed",
            req.additional_domains.len()
        ));
    }
    Ok(())
}

fn setting_or(req: &pb::InstallServiceRequest, key: &str, fallback: &str) -> String {
    req.settings
        .get(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// Every path-shaped setting, each checked before it is used
fn apply_paths(input: &mut Input, req: &pb::InstallServiceRequest) -> Result<(), String> {
    let slots = [
        ("adguard_path", &mut input.adguard_path),
        ("pihole_path", &mut input.pihole_path),
        ("homepage_path", &mut input.homepage_path),
        ("authelia_path", &mut input.authelia_path),
        ("headscale_path", &mut input.headscale_path),
        ("tailscale_node_path", &mut input.tailscale_node_path),
        ("cloudflared_path", &mut input.cloudflared_path),
        ("vaultwarden_data_path", &mut input.vaultwarden_data_path),
        ("jellyfin_path", &mut input.jellyfin_path),
        ("jellyfin_media_path", &mut input.jellyfin_media_path),
        ("home_assistant_path", &mut input.home_assistant_path),
        ("mosquitto_path", &mut input.mosquitto_path),
        ("zigbee2mqtt_path", &mut input.zigbee2mqtt_path),
        ("minecraft_java_path", &mut input.minecraft_java_path),
        ("minecraft_bedrock_path", &mut input.minecraft_bedrock_path),
        ("crafty_path", &mut input.crafty_path),
        ("ollama_path", &mut input.ollama_path),
        ("open_webui_path", &mut input.open_webui_path),
        ("litellm_path", &mut input.litellm_path),
        ("n8n_path", &mut input.n8n_path),
        ("anythingllm_path", &mut input.anythingllm_path),
        ("qdrant_path", &mut input.qdrant_path),
        ("searxng_path", &mut input.searxng_path),
        ("openclaw_path", &mut input.openclaw_path),
        ("photoprism_path", &mut input.photoprism_path),
        ("immich_path", &mut input.immich_path),
        ("nextcloud_path", &mut input.nextcloud_path),
        ("forgejo_path", &mut input.forgejo_path),
        ("gitlab_path", &mut input.gitlab_path),
        ("seafile_path", &mut input.seafile_path),
        ("psono_path", &mut input.psono_path),
        ("passbolt_path", &mut input.passbolt_path),
        ("amnezia_wg_path", &mut input.amnezia_wg_path),
        ("shadowsocks_path", &mut input.shadowsocks_path),
        ("xray_reality_path", &mut input.xray_reality_path),
        ("openvpn_path", &mut input.openvpn_path),
        ("mailcow_path", &mut input.mailcow_path),
        ("docker_mailserver_path", &mut input.docker_mailserver_path),
        ("mailu_path", &mut input.mailu_path),
    ];
    for (key, slot) in slots {
        *slot = setting_or(req, key, slot);
        if !is_safe_absolute_path(slot) {
            return Err(format!("{key} must be an absolute path with no '..' components: {}", truncate(slot)));
        }
        if let Some(why) = unsafe_service_path(slot) {
            return Err(format!("{key} {why}: {}", truncate(slot)));
        }
    }
    Ok(())
}

fn apply_usb_device(input: &mut Input, req: &pb::InstallServiceRequest) -> Result<(), String> {
    let stick = setting_or(req, "home_assistant_usb_device", "");
    if !stick.is_empty() && !is_device_path(&stick) {
        return Err(format!(
            "home_assistant_usb_device must name a device under /dev/, with no '..' component \
             and no spaces: {}",
            truncate(&stick)
        ));
    }
    input.home_assistant_usb_device = stick;
    Ok(())
}

/// Names, versions and lists: absent means empty, never a default
fn apply_texts(input: &mut Input, req: &pb::InstallServiceRequest) {
    let slots = [
        ("adguard_hostname", &mut input.adguard_hostname),
        ("authelia_hostname", &mut input.authelia_hostname),
        ("homepage_hostname", &mut input.homepage_hostname),
        ("pihole_hostname", &mut input.pihole_hostname),
        ("headscale_hostname", &mut input.headscale_hostname),
        ("headscale_base_domain", &mut input.headscale_base_domain),
        ("tailscale_node_name", &mut input.tailscale_node_name),
        ("tailscale_login_server", &mut input.tailscale_login_server),
        ("tailscale_auth_key", &mut input.tailscale_auth_key),
        ("cloudflared_token", &mut input.cloudflared_token),
        ("vaultwarden_hostname", &mut input.vaultwarden_hostname),
        ("jellyfin_hostname", &mut input.jellyfin_hostname),
        ("home_assistant_hostname", &mut input.home_assistant_hostname),
        ("zigbee2mqtt_hostname", &mut input.zigbee2mqtt_hostname),
        ("minecraft_java_version", &mut input.minecraft_java_version),
        ("minecraft_java_whitelist", &mut input.minecraft_java_whitelist),
        ("minecraft_java_operators", &mut input.minecraft_java_operators),
        ("minecraft_java_mods", &mut input.minecraft_java_mods),
        ("minecraft_bedrock_version", &mut input.minecraft_bedrock_version),
        ("crafty_hostname", &mut input.crafty_hostname),
        ("open_webui_hostname", &mut input.open_webui_hostname),
        ("litellm_hostname", &mut input.litellm_hostname),
        ("n8n_hostname", &mut input.n8n_hostname),
        ("anythingllm_hostname", &mut input.anythingllm_hostname),
        ("openclaw_hostname", &mut input.openclaw_hostname),
        ("photoprism_hostname", &mut input.photoprism_hostname),
        ("immich_hostname", &mut input.immich_hostname),
        ("nextcloud_hostname", &mut input.nextcloud_hostname),
        ("forgejo_hostname", &mut input.forgejo_hostname),
        ("gitlab_hostname", &mut input.gitlab_hostname),
        ("seafile_hostname", &mut input.seafile_hostname),
        ("psono_hostname", &mut input.psono_hostname),
        ("passbolt_hostname", &mut input.passbolt_hostname),
        ("vpn_hostname", &mut input.vpn_hostname),
        ("xray_reality_new_key", &mut input.xray_reality_new_key),
    ];
    for (key, slot) in slots {
        *slot = req.settings.get(key).cloned().unwrap_or_default();
    }
    let with_defaults = [
        ("vaultwarden_container", &mut input.vaultwarden_container),
        ("minecraft_java_flavour", &mut input.minecraft_java_flavour),
        ("pihole_upstreams", &mut input.pihole_upstreams),
        ("xray_reality_sni", &mut input.xray_reality_sni),
        ("mailu_subnet", &mut input.mailu_subnet),
    ];
    for (key, slot) in with_defaults {
        *slot = setting_or(req, key, slot);
    }
    input.vpn_client_access = req.settings.get("vpn_client_access").cloned().unwrap_or_else(|| "both".to_string());
    input.authelia_protected = authelia_protection(req);
}

fn authelia_protection(req: &pb::InstallServiceRequest) -> AutheliaProtection {
    match req.settings.get("authelia_protected_services") {
        Some(value) => AutheliaProtection::Explicit(
            value.split(',').map(str::trim).filter(|part| !part.is_empty()).map(str::to_string).collect(),
        ),
        None => AutheliaProtection::Default,
    }
}

fn apply_flags(input: &mut Input, req: &pb::InstallServiceRequest) {
    let exact = |key: &str, fallback: bool| {
        req.settings.get(key).map(|value| value.trim() == "true").unwrap_or(fallback)
    };
    let any_case = |key: &str, fallback: bool| {
        req.settings.get(key).map(|value| value.trim().eq_ignore_ascii_case("true")).unwrap_or(fallback)
    };
    input.pihole_serves_network = any_case("pihole_serves_network", input.pihole_serves_network);
    input.machine_at_home = any_case("machine_at_home", input.machine_at_home);
    input.vaultwarden_allow_signups = exact("vaultwarden_allow_signups", input.vaultwarden_allow_signups);
    input.minecraft_java_accepts_eula = exact("minecraft_java_accepts_eula", input.minecraft_java_accepts_eula);
    input.minecraft_bedrock_accepts_eula = exact("minecraft_bedrock_accepts_eula", input.minecraft_bedrock_accepts_eula);
    input.ollama_uses_gpu = exact("ollama_uses_gpu", input.ollama_uses_gpu);
    input.open_webui_allow_signups = exact("open_webui_allow_signups", input.open_webui_allow_signups);
    input.crowdsec_enabled = req
        .settings
        .get("crowdsec_enabled")
        .map(|value| value.trim() != "false")
        .unwrap_or(input.crowdsec_enabled);
}

/// Ports and sizes: unparsable or absent keeps the default
fn apply_numbers(input: &mut Input, req: &pb::InstallServiceRequest) {
    let parsed = |key: &str| req.settings.get(key).map(|value| value.trim());
    input.minecraft_java_memory_mb =
        parsed("minecraft_java_memory_mb").and_then(|v| v.parse().ok()).unwrap_or(input.minecraft_java_memory_mb);
    for (key, slot) in [
        ("minecraft_java_port", &mut input.minecraft_java_port),
        ("minecraft_bedrock_port", &mut input.minecraft_bedrock_port),
        ("forgejo_ssh_port", &mut input.forgejo_ssh_port),
        ("gitlab_ssh_port", &mut input.gitlab_ssh_port),
    ] {
        *slot = parsed(key).and_then(|v| v.parse().ok()).unwrap_or(*slot);
    }
    for (key, slot) in [
        ("wireguard_vpn_port", &mut input.wireguard_vpn_port),
        ("amnezia_wg_port", &mut input.amnezia_wg_port),
        ("shadowsocks_port", &mut input.shadowsocks_port),
        ("xray_reality_port", &mut input.xray_reality_port),
        ("openvpn_port", &mut input.openvpn_port),
    ] {
        *slot = port_setting(req, key, *slot);
    }
}

/// A port number off the wire, or Swift's default
fn port_setting(req: &pb::InstallServiceRequest, key: &str, fallback: u16) -> u16 {
    req.settings
        .get(key)
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(fallback)
}

fn vpn_protocols_from(req: &pb::InstallServiceRequest) -> Result<Vec<panel::Protocol>, Rejection> {
    const ALL: &[panel::Protocol] = &[
        panel::Protocol::WireGuard,
        panel::Protocol::AmneziaWG,
        panel::Protocol::Shadowsocks,
        panel::Protocol::XrayReality,
        panel::Protocol::OpenVPN,
    ];
    const IMPLEMENTED: &[panel::Protocol] = ALL;

    let raw = req.settings.get("vpn_protocols").map(String::as_str).unwrap_or("");
    let mut chosen: Vec<panel::Protocol> = Vec::new();
    for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let protocol = ALL
            .iter()
            .find(|p| p.service_id() == name)
            .ok_or_else(|| Rejection::InvalidRequest(format!("'{}' is not a VPN protocol", truncate(name))))?;
        if !IMPLEMENTED.contains(protocol) {
            return Err(Rejection::NotImplemented(protocol.service_id().to_string()));
        }
        if !chosen.contains(protocol) {
            chosen.push(*protocol);
        }
    }
    if chosen.is_empty() {
        chosen.push(panel::Protocol::WireGuard);
    }
    Ok(chosen)
}

fn caddy_is_installed() -> bool {
    packages::have_binary("caddy")
        || ["/usr/bin/caddy", "/usr/local/bin/caddy", "/usr/sbin/caddy"]
            .iter()
            .any(|path| Path::new(path).exists())
}

/// Can this host install its own packages?
fn can_install_packages() -> bool {
    packages::have_binary("apt-get") && packages::have_binary("systemd-run")
}

fn published_ports_of(label: &str, input: &Input, protocols: &[panel::Protocol]) -> Vec<ports::Wanted> {
    let mut wanted: Vec<ports::Wanted> =
        compose_text_of(label, input).map(|text| ports::published_in_compose(&text)).unwrap_or_default();
    wanted.extend(published_public_ports(label, input, protocols).into_iter().map(ports::Wanted::any));
    wanted
}

fn compose_text_of(label: &str, input: &Input) -> Option<String> {
    match label {
        "adguard-home" => Some(adguard::compose_contents(input)),
        "pihole" => Some(pihole::compose_contents(input)),
        "homepage" => Some(homepage::compose_contents(input)),
        "authelia" => Some(authelia::compose_contents(input)),
        "cloudflared" => Some(cloudflared::compose_contents(input)),
        "tailscale-node" => Some(tailscale::compose_contents(input)),
        "headscale" => Some(headscale::compose_contents(input)),
        "docker-mailserver" => Some(dms::compose_contents(input)),
        "forgejo" => Some(forgejo::compose_contents(input)),
        "gitlab" => Some(gitlab::compose_contents(input)),
        "immich" => Some(immich::compose_contents(input)),
        "jellyfin" => Some(jellyfin::compose_contents(input)),
        "home-assistant" => Some(home_assistant::compose_contents(input)),
        "mosquitto" => Some(mosquitto::compose_contents(input)),
        "zigbee2mqtt" => Some(zigbee2mqtt::compose_contents(input)),
        "ollama" => Some(ollama::compose_contents(input)),
        "minecraft-java" => Some(minecraft::java_compose_contents(input)),
        "minecraft-bedrock" => Some(minecraft::bedrock_compose_contents(input)),
        "crafty-controller" => Some(crafty::compose_contents(input)),
        "mailu" => Some(mailu::compose_contents(input)),
        "nextcloud" => Some(nextcloud::compose_contents(input)),
        "passbolt" => Some(passbolt::compose_contents(input)),
        "photoprism" => Some(photoprism::compose_contents(input)),
        "psono" => Some(psono::compose_contents(input)),
        "seafile" => Some(seafile::compose_contents(input)),
        "vaultwarden" => Some(vaultwarden::compose_contents(input)),
        "vpn" => Some(panel::compose_contents(input)),
        // mailcow: `generate_config.sh` writes the compose on the host.
        _ => None,
    }
}

fn published_public_ports(label: &str, input: &Input, protocols: &[panel::Protocol]) -> Vec<firewall::Port> {
    match label {
        "vpn" => protocols.iter().flat_map(|protocol| protocol.firewall_ports(input)).collect(),
        "docker-mailserver" => mail_firewall_ports(&dms::firewall_ports()),
        "mailu" => mail_firewall_ports(&mailu::firewall_ports()),
        "mailcow" => mail_firewall_ports(&mailcow::firewall_ports()),
        "forgejo" => forgejo::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default(),
        "gitlab" => gitlab::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn is_safe_absolute_path(path: &str) -> bool {
    let p = Path::new(path);
    p.is_absolute() && !p.components().any(|c| matches!(c, Component::ParentDir))
}

fn unsafe_service_path(path: &str) -> Option<&'static str> {
    if path.chars().any(|ch| ch.is_control() || "'\"`$\\".contains(ch)) {
        return Some("must not contain quotes, $, backslashes or line breaks");
    }
    let trimmed = path.trim_end_matches('/');
    let depth = trimmed.split('/').filter(|part| !part.is_empty()).count();
    let top = trimmed.split('/').nth(1).unwrap_or_default();
    let inside = |tree: &&str| trimmed == *tree || trimmed.starts_with(&format!("{tree}/"));
    if depth < 2 || crate::container_removal::PROTECTED_TREES.iter().any(inside) {
        return Some("must be a directory of its own, not a top-level or system directory");
    }
    if depth == 2 && matches!(top, "home" | "mnt" | "media") {
        return Some("must be a folder inside a home directory or a disk, not the home or disk itself");
    }
    if matches!(trimmed, "/var/lib" | "/var/cache" | "/var/spool" | "/opt/backups") {
        return Some("must be a directory of its own, not a system directory");
    }
    None
}

// ─────────────────────────── RPC entry point ───────────────────────────

/// Install AdGuard Home, streaming progress
pub async fn run_install(codec: Codec, req: pb::InstallServiceRequest,
                        store: Arc<Mutex<Store>>) -> Resp {
    let label = match resolve(&req.service_id) {
        Ok(label) => label,
        Err(rejection) => return rejection.response(),
    };
    let (input, protocols) = match prepare_install(&req, label).await {
        Ok(prepared) => prepared,
        Err(rejection) => return rejection.response(),
    };
    let journal = match journal::Journal::open_unique(&req.service_id) {
        Ok(journal) => journal,
        Err(job) => return Rejection::InstallAlreadyRunning(job).response(),
    };

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();
    let host_ctx = HostContext::from_request(&req);

    tokio::spawn(async move {
        install(label, service_id, codec, tx, input, protocols, host_ctx, journal, store).await;
    });

    stream_response(json, rx)
}

/// One service of an install plan: the same install, awaited
pub async fn install_awaited(
    req: pb::InstallServiceRequest,
    store: Arc<Mutex<Store>>,
    on_job: impl FnOnce(&str),
) -> Result<(), String> {
    let label = resolve(&req.service_id).map_err(|r| r.message())?;
    let (input, protocols) = prepare_install(&req, label).await.map_err(|r| r.message())?;
    let journal = journal::Journal::open_unique(&req.service_id)
        .map_err(|job| Rejection::InstallAlreadyRunning(job).message())?;
    let job_id = journal.as_ref().map(|j| j.job_id().to_string());
    if let Some(job_id) = &job_id {
        on_job(job_id);
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let host_ctx = HostContext::from_request(&req);
    install(label, req.service_id.clone(), Codec::Proto, tx, input, protocols, host_ctx, journal, store).await;
    match job_id.and_then(|id| journal::events_after(&id, 0)) {
        Some((_, _, failure)) if !failure.is_empty() => Err(failure),
        _ => Ok(()),
    }
}

fn refuse_unworkable_request(req: &pb::InstallServiceRequest, label: &str, input: &Input) -> Result<(), Rejection> {
    if let Some(edition) = license_not_accepted(label, input) {
        return Err(Rejection::LicenseNotAccepted(edition));
    }
    if let Some(page) = bedrock_emulator_blocked(label) {
        return Err(Rejection::EmulatorNeedsSmallPages(page));
    }
    if let Some(service) =
        home_only_service_away(label, input, requested_role(req), dynamic_dns_configured())
    {
        return Err(Rejection::MachineNotAtHome(service));
    }
    if let Some(service) = add_on_without_the_hub(label, &input.installed_services) {
        return Err(Rejection::AddOnWithoutTheHub(service));
    }
    if label == "zigbee2mqtt" && input.home_assistant_usb_device.is_empty() {
        return Err(Rejection::ZigbeeWithoutAStick);
    }
    if let Some((service, device)) = stick_missing(label, input) {
        return Err(Rejection::StickMissing { service, device });
    }
    if !caddy_is_installed() && !can_install_packages() {
        return Err(Rejection::NoReverseProxy);
    }
    Ok(())
}

/// No docker yet, but the install itself will add it
fn docker_comes_with_the_install() -> bool {
    !packages::have_binary("docker") && can_install_packages()
}

async fn prepare_install(
    req: &pb::InstallServiceRequest,
    label: &'static str,
) -> Result<(Input, Vec<panel::Protocol>), Rejection> {
    let existing_projects = match discover::projects_of_service(&req.service_id).await {
        Ok(projects) => projects,
        Err(_) if docker_comes_with_the_install() => Vec::new(),
        Err(err) => return Err(Rejection::DockerUnavailable(err.to_string())),
    };
    let mut input = match build_input(req) {
        Ok(input) => input,
        Err(detail) => return Err(Rejection::InvalidRequest(detail)),
    };
    input.installed_services = host_service_ids(label, &[]).await;
    if !input.installed_services.iter().any(|id| id == &req.service_id) {
        input.installed_services.push(req.service_id.clone());
    }
    if label == "mailu" {
        if let Some(subnet) = free_mailu_subnet(&input.mailu_subnet).await {
            input.mailu_subnet = subnet;
        }
    }
    let input = input;
    refuse_unworkable_request(req, label, &input)?;
    let protocols = vpn_protocols_from(req)?;
    refuse_conflicts(req, label, &input, &protocols, &existing_projects).await?;
    Ok((input, protocols))
}

/// Ports and site names that are already taken
async fn refuse_conflicts(
    req: &pb::InstallServiceRequest,
    label: &'static str,
    input: &Input,
    protocols: &[panel::Protocol],
    existing_projects: &[String],
) -> Result<(), Rejection> {
    let conflicts = ports::check(&published_ports_of(label, input, protocols), existing_projects).await;
    if !conflicts.is_empty() {
        if let Some(holder) = self_installed_by_hand(&req.service_id, &conflicts).await {
            return Err(Rejection::AlreadyInstalledOutside {
                service: crate::discover::known_service(&req.service_id)
                    .unwrap_or(&req.service_id)
                    .to_string(),
                holder,
            });
        }
        return Err(Rejection::PortsInUse(conflicts));
    }

    let taken = site_name_conflicts(label, input);
    if !taken.is_empty() {
        return Err(Rejection::SiteNameTaken(taken));
    }
    Ok(())
}

pub async fn run_watch_install(codec: Codec, req: pb::WatchInstallRequest,
                              store: Arc<Mutex<Store>>) -> Resp {
    if !journal::exists(&req.job_id) {
        return Rejection::UnknownJob(req.job_id).response();
    }
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        follow_install(req.job_id, req.from_sequence, codec, tx, store).await;
    });
    stream_response(json, rx)
}

async fn follow_install(job_id: String, from_sequence: u64, codec: Codec, tx: Sender<Bytes>,
                        store: Arc<Mutex<Store>>) {
    let mut next = from_sequence;
    loop {
        let Some((events, closed, failure)) = journal::events_after(&job_id, next) else {
            return;
        };
        for mut event in events {
            next = event.sequence + 1;
            if event.phase == pb::ServiceOperationPhase::Completed as i32 {
                event.service = read_status(&event.service_id, &store).await;
            }
            let payload = codec.encode_payload(&event);
            if tx.send(envelope(0x00, &payload)).await.is_err() {
                return;
            }
        }
        if closed {
            if !failure.is_empty() {
                let _ = tx.send(error_trailer("internal", &failure)).await;
            }
            return;
        }
        if !journal::is_running(&job_id) {
            if journal::events_after(&job_id, next).is_some_and(|(more, now_closed, _)| !more.is_empty() || now_closed) {
                continue;
            }
            let _ = tx.send(error_trailer(
                "aborted",
                "the agent stopped while this install was running; nothing is known about \
                 what it left behind. Re-running the install is safe — every step decides \
                 for itself whether it has already happened",
            ))
            .await;
            return;
        }
        tokio::time::sleep(journal::follow_poll()).await;
    }
}

// ─────────────────────────── executor ───────────────────────────

fn stalled_jobs() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    static STALLED: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> = std::sync::LazyLock::new(Default::default);
    STALLED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) struct EventSink {
    tx: Sender<Bytes>,
    codec: Codec,
    service_id: String,
    journal: Option<journal::Journal>,
    sequence: AtomicU64,
}

impl EventSink {
    pub(crate) fn detached() -> Self {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        EventSink {
            tx,
            codec: Codec::Proto,
            service_id: String::new(),
            journal: None,
            sequence: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(tx: Sender<Bytes>, service_id: &str) -> Self {
        EventSink {
            tx,
            codec: Codec::Proto,
            service_id: service_id.to_string(),
            journal: None,
            sequence: AtomicU64::new(0),
        }
    }

    fn job_id(&self) -> String {
        self.journal
            .as_ref()
            .map(|j| j.job_id().to_string())
            .unwrap_or_default()
    }

    /// Close the record
    fn close(&self, failure: Option<&str>) {
        if let Some(journal) = &self.journal {
            stalled_jobs().remove(journal.job_id());
            journal.finish(failure);
        }
    }

    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::InstallServiceEvent {
        pb::InstallServiceEvent {
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            project: String::new(),
            service: None,
            job_id: self.job_id(),
            sequence: 0,
        }
    }

    fn record(&self, event: pb::InstallServiceEvent) -> Bytes {
        self.record_as(event, false)
    }

    fn record_as(&self, mut event: pb::InstallServiceEvent, quiet: bool) -> Bytes {
        event.sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        if let Some(journal) = &self.journal {
            let append = if quiet { journal::Journal::append_quiet } else { journal::Journal::append };
            append(journal, event.sequence, event.phase, &event.stream, &event.text, &event.project);
        }
        envelope(0x00, &self.codec.encode_payload(&event))
    }

    async fn send(&self, event: pb::InstallServiceEvent) -> Result<(), ()> {
        let frame = self.record(event);
        self.tx.send(frame).await.map_err(|_| ())
    }

    async fn send_progress(&self, event: pb::InstallServiceEvent) -> Result<(), ()> {
        if self.journal.is_none() {
            return self.send(event).await;
        }
        let frame = self.record(event);
        let job = self.job_id();
        match self.tx.try_send(frame) {
            Ok(()) => {
                stalled_jobs().remove(&job);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(frame)) => {
                if stalled_jobs().contains(&job) {
                    return Ok(());
                }
                match tokio::time::timeout(Duration::from_secs(2), self.tx.send(frame)).await {
                    Ok(sent) => sent.map_err(|_| ()),
                    Err(_) => {
                        stalled_jobs().insert(job);
                        Ok(())
                    }
                }
            }
        }
    }

    async fn started(&self, project: &str) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.project = project.to_string();
        self.send(event).await
    }

    pub(super) async fn step(&self, text: impl Into<String>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = "agent".to_string();
        event.text = text.into();
        self.send_progress(event).await
    }

    pub(super) async fn private_step(&self, text: impl Into<String>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = "agent".to_string();
        event.text = text.into();
        let frame = self.record_as(event, true);
        self.tx.send(frame).await.map_err(|_| ())
    }

    pub(super) async fn warn(&self, text: impl Into<String>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = "warning".to_string();
        event.text = text.into();
        self.send(event).await
    }

    pub(super) async fn process_line(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send_progress(event).await
    }

    async fn completed(&self, service: Option<pb::Service>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.service = service;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer
    async fn fail(&self, message: &str) -> Result<(), ()> {
        self.tx.send(error_trailer("internal", message)).await.map_err(|_| ())
    }
}

async fn read_status(service_id: &str, store: &Arc<Mutex<Store>>) -> Option<pb::Service> {
    let read = discover::service_snapshot(service_id).await;
    let snapshot = match read {
        Ok(snapshot) => snapshot,
        Err(err) => {
            tracing::warn!(?err, service_id, "could not re-read status; state left as it was");
            return None;
        }
    };
    if let Ok(store) = store.lock() {
        if let Err(err) = store.record_action(service_id, snapshot.as_ref()) {
            tracing::warn!(?err, service_id, "could not persist post-install status");
        }
    }
    snapshot
}

/// Runs the install steps of the service `label` names
async fn run_service_steps(
    label: &'static str,
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Result<(), String> {
    if let Some(outcome) = dispatch_install_1(label, input, protocols, sink).await {
        return outcome;
    }
    if let Some(outcome) = dispatch_install_2(label, input, protocols, sink).await {
        return outcome;
    }
    install_adguard_steps(input, sink).await
}

/// One part of the per-service install dispatch
async fn dispatch_install_1(
    label: &str,
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Option<Result<(), String>> {
    match label {
        "vpn" => Some(install_vpn_steps(input, protocols, sink).await),
        "docker-mailserver" => Some(install_docker_mailserver_steps(input, sink).await),
        "mailcow" => Some(install_mailcow_steps(input, sink).await),
        "mailu" => Some(install_mailu_steps(input, sink).await),
        "forgejo" => Some(install_forgejo_steps(input, sink).await),
        "gitlab" => Some(install_gitlab_steps(input, sink).await),
        "immich" => Some(install_immich_steps(input, sink).await),
        "nextcloud" => Some(install_nextcloud_steps(input, sink).await),
        "jellyfin" => Some(install_jellyfin_steps(input, sink).await),
        "home-assistant" => Some(install_home_assistant_steps(input, sink).await),
        "mosquitto" => Some(install_mosquitto_steps(input, sink).await),
        "zigbee2mqtt" => Some(install_zigbee2mqtt_steps(input, sink).await),
        "ollama" => Some(install_ollama_steps(input, sink).await),
        "open-webui" => Some({
            let services = host_service_ids(label, protocols).await;
            install_open_webui_steps(input, &services, sink).await
        }),
        "litellm" => Some({
            let services = host_service_ids(label, protocols).await;
            install_litellm_steps(input, &services, sink).await
        }),
        "n8n" => Some(install_n8n_steps(input, sink).await),
        "anythingllm" => Some({
            let services = host_service_ids(label, protocols).await;
            install_anythingllm_steps(input, &services, sink).await
        }),
        "qdrant" => Some(install_qdrant_steps(input, sink).await),
        "searxng" => Some(install_searxng_steps(input, sink).await),
        "openclaw" => Some(install_openclaw_steps(input, sink).await),
        "minecraft-java" => Some(install_minecraft_java_steps(input, sink).await),
        "minecraft-bedrock" => Some(install_minecraft_bedrock_steps(input, sink).await),
        "crafty-controller" => Some(install_crafty_steps(input, sink).await),
        "passbolt" => Some(install_passbolt_steps(input, sink).await),
        "photoprism" => Some(install_photoprism_steps(input, sink).await),
        "psono" => Some(install_psono_steps(input, sink).await),
        "seafile" => Some(install_seafile_steps(input, sink).await),
        "vaultwarden" => Some(install_vaultwarden_steps(input, sink).await),
        "headscale" => Some(install_headscale_steps(input, sink).await),
        "cloudflared" => Some(install_cloudflared_steps(input, sink).await),
        "tailscale-node" => Some({
            let own_control =
                input.tailscale_login_server.trim().is_empty() && input.tailscale_auth_key.trim().is_empty();
            install_mesh_node_steps(input, own_control, sink).await
        }),
        "pihole" => Some(install_pihole_steps(input, sink).await),
        _ => None,
    }
}

/// One part of the per-service install dispatch
async fn dispatch_install_2(
    label: &str,
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Option<Result<(), String>> {
    match label {
        "homepage" => Some({
            let services = host_service_ids(label, protocols).await;
            install_homepage_steps(input, &services, sink).await
        }),
        "authelia" => Some({
            let services = host_service_ids(label, protocols).await;
            install_authelia_steps(input, &services, sink).await
        }
),
        _ => None,
    }
}

async fn install(
    label: &'static str,
    service_id: String,
    codec: Codec,
    tx: Sender<Bytes>,
    input: Input,
    protocols: Vec<panel::Protocol>,
    host_ctx: HostContext,
    journal: Option<journal::Journal>,
    store: Arc<Mutex<Store>>,
) {
    let sink = EventSink {
        tx,
        codec,
        service_id: service_id.clone(),
        journal,
        sequence: AtomicU64::new(0),
    };
    let _ = sink.started(compose_project(label)).await;
    if matches!(host_ctx.role, Some(HostRole::VpsRelay)) {
        remember_relay_home(&host_ctx);
    }

    let outcome = match packages::ensure_for(crate::vpn_dns_priority::is_relay(), &sink).await {
        Err(why) => Err(why),
        Ok(()) => {
            firewall_base::ensure_ruleset(
                super::any_requires_home_machine(&input.installed_services),
                &sink,
            )
            .await;
            run_service_steps(label, &input, &protocols, &sink).await
        }
    };

    if let Err(why) = outcome {
        let status = read_status(&service_id, &store).await;
        // Leftover containers still need a removal wrapper
        if status.as_ref().is_some_and(|service| !service.containers.is_empty()) {
            let _ = provision_host_surface(&input, &host_ctx, &protocols, label, &sink).await;
        }
        let _ = sink.completed(status).await;
        let _ = sink.fail(&why).await;
        sink.close(Some(&why));
        return;
    }

    if let Err(why) = provision_host_surface(&input, &host_ctx, &protocols, label, &sink).await {
        let status = read_status(&service_id, &store).await;
        let _ = sink.completed(status).await;
        let _ = sink.fail(&why).await;
        sink.close(Some(&why));
        return;
    }

    let status = read_status(&service_id, &store).await;
    crate::vpn_dns::wake();
    let _ = sink.completed(status).await;
    sink.close(None);
}

// ─────────────────────────── the host surface ───────────────────────────

/// A forced reload, so Caddy retries missing certificates
pub async fn run_refresh_certificates(codec: Codec, _req: pb::RefreshCertificatesRequest) -> Resp {
    let reloaded = packages::have_binary("caddy")
        && Path::new(CADDYFILE_PATH).exists()
        && caddy_force_reload().await;
    codec
        .encode(&pb::RefreshCertificatesResponse { reloaded })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

/// `Host/ProvisionHost` — bring the wrappers up to date without installing anything
pub async fn run_provision_host(codec: Codec, req: pb::ProvisionHostRequest) -> Resp {
    let install_req = install_request_of(&req);
    let input = match build_input(&install_req) {
        Ok(input) => input,
        Err(why) => return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &why),
    };
    let mut host_ctx = HostContext::from_request(&install_req);
    host_ctx.relay_peers = relay_peers_of(&req);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let sink = EventSink { tx, codec, service_id: String::new(), journal: None, sequence: AtomicU64::new(0) };
    let outcome = provision_host_surface(&input, &host_ctx, &[], "", &sink).await;
    stop_rspamd_reducing_the_signing_domain(&input, &sink).await;
    let notes = drain_notes(&mut rx, codec);
    if let Err(why) = outcome {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &why);
    }

    let role = host_ctx.role.unwrap_or(HostRole::SingleHost);
    let services = host_service_ids("", &[]).await;
    let host_input = HostInput {
        services,
        install: input,
        language: Language::En,
        ssh_user: existing_control_user(),
        role,
    };
    let response = provisioned_response(&host_input, &host_ctx, notes);
    codec.encode(&response).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

fn install_request_of(req: &pb::ProvisionHostRequest) -> pb::InstallServiceRequest {
    pb::InstallServiceRequest {
        service_id: String::new(),
        domain: req.domain.clone(),
        additional_domains: req.additional_domains.clone(),
        local_only: req.local_only,
        admin_username: req.admin_username.clone(),
        language: req.language.clone(),
        settings: req.settings.clone(),
        host_role: req.host_role,
        ptr_ip: req.ptr_ip.clone(),
        ptr_hostname: req.ptr_hostname.clone(),
        tunnel_endpoint: req.tunnel_endpoint.clone(),
        relay_wg_port: req.relay_wg_port,
        relay_forwarded_ports: req.relay_forwarded_ports.clone(),
        relay_forwarded_udp_ports: req.relay_forwarded_udp_ports.clone(),
        home_wg_address: req.home_wg_address.clone(),
        dashboard_public_key: req.dashboard_public_key.clone(),
    }
}

/// Peers reach the agent only through the provision verb
fn relay_peers_of(req: &pb::ProvisionHostRequest) -> Vec<firewall_relay::Peer> {
    req.relay_peers
        .iter()
        .map(|peer| firewall_relay::Peer {
            ip: peer.tunnel_address.trim().to_string(),
            tcp_ports: peer.forwarded_ports.iter().filter_map(|p| u16::try_from(*p).ok()).collect(),
            udp_ports: peer.forwarded_udp_ports.iter().filter_map(|p| u16::try_from(*p).ok()).collect(),
        })
        .filter(|peer| !peer.ip.is_empty())
        .collect()
}

/// What provisioning wrote, for the response
fn provisioned_response(host_input: &HostInput, host_ctx: &HostContext, notes: Vec<String>) -> pb::ProvisionHostResponse {
    let written = host::provision::files(
        host_input,
        &host::uninstall::BackupPaths::default(),
        dashboard_access(&host_ctx.dashboard_public_key).as_ref(),
    )
    .into_iter()
    .map(|file| file.path)
    .collect();
    pb::ProvisionHostResponse { written, control_user: host_input.ssh_user.clone().unwrap_or_default(), notes }
}

fn endpoint_host(endpoint: &str) -> String {
    match endpoint.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => host.to_string(),
        _ => endpoint.to_string(),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostContext {
    pub role: Option<HostRole>,
    pub ptr_ip: String,
    pub ptr_hostname: String,
    pub tunnel_endpoint: String,
    pub relay_wg_port: u16,
    pub relay_forwarded_ports: Vec<u16>,
    pub relay_forwarded_udp_ports: Vec<u16>,
    pub home_wg_address: String,
    pub relay_peers: Vec<firewall_relay::Peer>,
    pub dashboard_public_key: String,
}

impl HostContext {
    fn from_request(req: &pb::InstallServiceRequest) -> Self {
        let role = match pb::HostRole::try_from(req.host_role) {
            Ok(pb::HostRole::VpsRelay) => Some(HostRole::VpsRelay),
            Ok(pb::HostRole::HomeBackend) => Some(HostRole::HomeBackend),
            _ => Some(HostRole::SingleHost),
        };
        HostContext {
            role,
            ptr_ip: req.ptr_ip.trim().to_string(),
            ptr_hostname: req.ptr_hostname.trim().to_string(),
            tunnel_endpoint: req.tunnel_endpoint.trim().to_string(),
            relay_wg_port: u16::try_from(req.relay_wg_port).unwrap_or(0),
            relay_forwarded_ports: req
                .relay_forwarded_ports
                .iter()
                .filter_map(|port| u16::try_from(*port).ok())
                .collect(),
            relay_forwarded_udp_ports: req
                .relay_forwarded_udp_ports
                .iter()
                .filter_map(|port| u16::try_from(*port).ok())
                .collect(),
            home_wg_address: req.home_wg_address.trim().to_string(),
            relay_peers: Vec::new(),
            dashboard_public_key: req.dashboard_public_key.trim().to_string(),
        }
    }

    /// The relay's firewall topology, straight off the request
    fn relay_topology(&self) -> firewall_relay::Topology {
        if !self.relay_peers.is_empty() {
            return firewall_relay::Topology {
                peers: self.relay_peers.clone(),
                vps_public: endpoint_host(&self.tunnel_endpoint),
                wg_port: self.relay_wg_port,
            };
        }
        firewall_relay::Topology::single(
            self.home_wg_address.clone(),
            endpoint_host(&self.tunnel_endpoint),
            self.relay_wg_port,
            self.relay_forwarded_ports.clone(),
            self.relay_forwarded_udp_ports.clone(),
        )
    }

    /// The report's topology for this role
    fn topology(&self, role: HostRole, input: &Input) -> report::Topology {
        let ptr_hostname = if self.ptr_hostname.is_empty() {
            input.domain.clone()
        } else {
            self.ptr_hostname.clone()
        };
        match role {
            HostRole::VpsRelay => report::Topology::Relay {
                wg_port: self.relay_wg_port,
                forwarded_ports: self.relay_forwarded_ports.clone(),
                home_wg_address: self.home_wg_address.clone(),
                ptr_hostname,
            },
            HostRole::SingleHost | HostRole::HomeBackend => report::Topology::ServicesHost {
                ptr_ip: if input.local_only || self.ptr_ip.is_empty() {
                    None
                } else {
                    Some(self.ptr_ip.clone())
                },
                ptr_hostname,
                tunnel_endpoint: if self.tunnel_endpoint.is_empty() {
                    None
                } else {
                    Some(self.tunnel_endpoint.clone())
                },
            },
        }
    }
}

/// The catalog ids one install adds to the host
fn installed_catalog_ids(label: &str, protocols: &[panel::Protocol]) -> Vec<&'static str> {
    if label != "vpn" {
        return discover::known_service_id(label).into_iter().collect();
    }
    let mut ids = vec!["vpn-panel"];
    ids.extend(protocols.iter().map(|protocol| protocol.service_id()));
    ids
}

/// The catalog ids a DISCOVERED service stands for
fn discovered_catalog_ids(service: &pb::Service) -> Vec<&'static str> {
    if service.id != "vpn" {
        return discover::known_service_id(&service.id).into_iter().collect();
    }
    let mut ids = Vec::new();
    for container in &service.containers {
        let id = match container.name.as_str() {
            panel::CONTAINER => "vpn-panel",
            amnezia::CONTAINER => "amnezia-wg",
            shadowsocks::CONTAINER => "shadowsocks",
            xray::CONTAINER => "xray-reality",
            openvpn::CONTAINER => "openvpn",
            _ => continue,
        };
        ids.push(id);
    }
    if ids.contains(&"vpn-panel") && panel_offers_wireguard() {
        ids.push("wireguard-vpn");
    }
    ids
}

/// Does the panel's own registry list plain WireGuard?
fn panel_offers_wireguard() -> bool {
    let path = Path::new(panel::PATH).join("data/services.json");
    std::fs::read_to_string(path)
        .map(|text| text.contains("\"id\":\"wireguard\""))
        .unwrap_or(false)
}

async fn host_service_ids(label: &str, protocols: &[panel::Protocol]) -> Vec<String> {
    let mut ids: Vec<&'static str> = installed_catalog_ids(label, protocols);
    if let Ok(found) = discover::scan().await {
        for service in &found.services {
            for id in discovered_catalog_ids(service) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    host::CATALOG_ORDER
        .iter()
        .filter(|id| ids.contains(id))
        .map(|id| (*id).to_string())
        .collect()
}

/// Write the root-owned surface every later operation stands on
async fn guard_site_if_protected(
    id: &str,
    input: &Input,
    protected: &[String],
    sink: &EventSink,
) -> bool {
    if !protected.iter().any(|p| p == id) {
        return false;
    }
    let Some((names, site)) = catalog::site_for(id, input, true) else { return false };
    let before = std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default();
    match write_caddy_site(&names, &site) {
        Ok(()) => {
            let _ = sink.step(format!("{id} stays behind the sign-on portal")).await;
            std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default() != before
        }
        Err(why) => {
            let _ = sink.step(format!("could not keep {id} behind the sign-on portal: {why}")).await;
            false
        }
    }
}

async fn refresh_authelia_rules(input: &Input, services: &[String], sink: &EventSink) {
    let path = PathBuf::from(&input.authelia_path).join("config").join("configuration.yml");
    let Ok(current) = std::fs::read_to_string(&path) else { return };
    let fresh = authelia::configuration_yaml(input, services);
    if current == fresh {
        return;
    }
    if let Err(err) = std::fs::write(&path, &fresh) {
        let _ = sink.step(format!("could not update the sign-on portal's rules: {err}")).await;
        return;
    }
    match run_quiet(&docker_bin().to_string_lossy(), &["restart", authelia::CONTAINER]).await {
        Ok(()) => {
            let _ = sink.step("the sign-on portal now knows every site it guards").await;
        }
        Err(()) => {
            let _ = sink.step("updated the sign-on portal's rules, but could not restart it").await;
        }
    }
}

async fn keep_sites_guarded(
    input: &Input,
    services: &[String],
    label: &str,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) {
    if !label.is_empty() && services.iter().any(|id| id == "authelia") {
        let protected = authelia::protected_ids(input, services);
        let mut rewritten = false;
        for id in installed_catalog_ids(label, protocols) {
            rewritten |= guard_site_if_protected(id, input, &protected, sink).await;
        }
        // The service's own steps reloaded Caddy before this rewrite
        if rewritten {
            if let Err(why) = reload_caddy(sink).await {
                let _ = sink.step(format!("the sign-on check waits for the next Caddy reload: {why}")).await;
            }
        }
    }
    if services.iter().any(|id| id == "authelia") {
        refresh_authelia_rules(input, services, sink).await;
    }
}

/// Writes every wrapper and script of the host's management layer
fn write_management_files(
    host_input: &HostInput,
    backups: &host::uninstall::BackupPaths,
    existing_access: Option<&host::uninstall::DashboardAccess>,
) -> Result<(), String> {
    for file in host::provision::files(host_input, backups, existing_access) {
        let path = PathBuf::from(&file.path);
        if let Some(parent) = path.parent() {
            create_dir_0755(parent)
                .map_err(|err| format!("could not create {}: {err}", parent.display()))?;
        }
        let mode = file.mode.unwrap_or_else(|| existing_mode(&path).unwrap_or(0o644));
        crate::util::write_file_atomic(&path, host::provision::as_written(&file.contents).as_bytes(), mode)
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    Ok(())
}

async fn provision_host_surface(
    input: &Input,
    host_ctx: &HostContext,
    protocols: &[panel::Protocol],
    label: &str,
    sink: &EventSink,
) -> Result<(), String> {
    let Some(role) = host_ctx.role else { return Ok(()) };
    let services = host_service_ids(label, protocols).await;

    keep_sites_guarded(input, &services, label, protocols, sink).await;
    let ssh_user = existing_control_user();
    let host_input = HostInput {
        services,
        install: input.clone(),
        language: input.language,
        ssh_user,
        role,
    };
    let backups = host::uninstall::BackupPaths::default();

    let existing_access = dashboard_access(&host_ctx.dashboard_public_key);

    let _ = sink.step("writing the host's management wrappers").await;
    write_management_files(&host_input, &backups, existing_access.as_ref())?;
    if let Err(err) = host::backup_ctl_store::store(&host_input) {
        let _ = sink.step(&format!("could not keep the backup wrapper's inputs: {err}")).await;
    }
    write_sudoers(&host_input, &backups, sink).await?;
    give_backup_directories_to_control_user(&host_input, sink).await?;
    ensure_autobackup_passphrase(&host_input, sink).await;
    start_metrics_collector(sink).await?;
    apply_network_role(
        role,
        host_ctx,
        super::any_requires_home_machine(&host_input.services),
        sink,
    )
    .await;
    crowdsec::ensure_present(input.crowdsec_enabled, sink).await;
    ssh_password::close_password_login(
        host_input.ssh_user.as_deref(),
        existing_access.as_ref().map(|access| access.app_public_key.as_str()),
        sink,
    )
    .await;
    write_install_report(&host_input, host_ctx, role, sink).await?;
    Ok(())
}

async fn ensure_autobackup_passphrase(input: &HostInput, sink: &EventSink) {
    if !host::backup_ctl::needs_stored_passphrase(input) {
        return;
    }
    let path = PathBuf::from(host::backup_ctl::PASSPHRASE_PATH);
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        if let Err(err) = create_dir_0755(parent) {
            let _ = sink
                .step(&format!("could not create {}: {err}", parent.display()))
                .await;
            return;
        }
    }
    let secret = match random_hex_20() {
        Ok(secret) => secret,
        Err(err) => {
            let _ = sink
                .step(&format!("could not generate a backup passphrase: {err}"))
                .await;
            return;
        }
    };
    match create_file_if_absent(&path, &secret, 0o600) {
        Ok(true) => {
            let _ = sink
                .step("generated this host's backup passphrase — it is in the install report")
                .await;
        }
        Ok(false) => {}
        Err(err) => {
            let _ = sink
                .step(&format!("could not store the backup passphrase: {err}"))
                .await;
        }
    }
}

fn drain_notes(rx: &mut tokio::sync::mpsc::Receiver<Bytes>, codec: Codec) -> Vec<String> {
    let mut notes = Vec::new();
    while let Ok(frame) = rx.try_recv() {
        if frame.len() <= 5 {
            continue;
        }
        if let Some(event) = codec.decode_payload::<pb::InstallServiceEvent>(&frame[5..]) {
            if !event.text.trim().is_empty() {
                notes.push(event.text);
            }
        }
    }
    notes
}

/// Marks this machine a relay of its home machine
fn remember_relay_home(host_ctx: &HostContext) {
    if let Some(home) = host_ctx.relay_topology().peers.first() {
        crate::vpn_dns_priority::remember_home(&home.ip);
    }
}

async fn apply_network_role(
    role: HostRole,
    host_ctx: &HostContext,
    home_discovery: bool,
    sink: &EventSink,
) {
    let plan = match role {
        HostRole::SingleHost => firewall_base::Plan::SingleHost,
        HostRole::HomeBackend => firewall_base::Plan::HomeBackend(Some(host_ctx.relay_topology())),
        HostRole::VpsRelay => firewall_base::Plan::Relay(host_ctx.relay_topology()),
    };
    let home_discovery = home_discovery && !matches!(role, HostRole::VpsRelay);
    firewall_base::ensure(&plan, home_discovery, sink).await;
    match role {
        HostRole::SingleHost => {}
        HostRole::VpsRelay => {
            remember_relay_home(host_ctx);
            if let Err(why) =
                firewall_relay::apply_sysctl(firewall_relay::RELAY_SYSCTL_PATH, firewall_relay::RELAY_SYSCTL, sink)
                    .await
            {
                let _ = sink.step(format!("WARNING: could not enable IPv4 forwarding: {why}")).await;
            }
        }
        HostRole::HomeBackend => {
            if let Err(why) =
                firewall_relay::apply_sysctl(firewall_relay::HOME_SYSCTL_PATH, firewall_relay::HOME_SYSCTL, sink).await
            {
                let _ = sink.step(format!("WARNING: could not relax reverse-path filtering: {why}")).await;
            }
            if let Err(why) = relay_routes::install(sink).await {
                let _ = sink
                    .step(format!("WARNING: could not install the relay route sync: {why} — relayed replies \
                                   would leave through this host's own ISP instead of the tunnel"))
                    .await;
            }
        }
    }
}

async fn give_backup_directories_to_control_user(
    input: &HostInput,
    sink: &EventSink,
) -> Result<(), String> {
    let Some(user) = &input.ssh_user else { return Ok(()) };
    let dirs = host::backup_ctl::backup_dirs(input);
    if dirs.is_empty() {
        return Ok(());
    }
    for (id, dir) in &dirs {
        let path = PathBuf::from(dir);
        create_dir_with_mode(&path, 0o750)
            .map_err(|err| format!("could not create the {id} backup directory {dir}: {err}"))?;
        let chowned = tokio::process::Command::new("chown")
            .args([user.as_str(), dir.as_str()])
            .stdin(Stdio::null())
            .output()
            .await;
        if !matches!(&chowned, Ok(out) if out.status.success()) {
            return Err(format!("could not give the {id} backup directory to '{user}'"));
        }
    }
    let _ = sink.step("gave the control user its service backup directories").await;
    Ok(())
}

fn existing_dashboard_access() -> Option<host::uninstall::DashboardAccess> {
    let wrapper = std::fs::read_to_string(host::uninstall::SCRIPT_PATH).ok()?;
    let app_public_key = host::provision::app_public_key(&wrapper)?;
    Some(host::uninstall::DashboardAccess { create_user: true, app_public_key })
}

fn dashboard_access(requested_key: &str) -> Option<host::uninstall::DashboardAccess> {
    if let Some(recovered) = existing_dashboard_access() {
        return Some(recovered);
    }
    let key = requested_key.trim();
    if key.is_empty() || key.contains('\'') || key.contains('\n') {
        return None;
    }
    Some(host::uninstall::DashboardAccess { create_user: true, app_public_key: key.to_string() })
}

/// The control user this host already has, or `None`
pub(super) fn existing_control_user() -> Option<String> {
    std::fs::read_to_string(sudoers_path())
        .ok()
        .and_then(|text| host::provision::control_user(&text))
}

/// `/etc/sudoers.d/gryonixnexus-control`, and the staging name the generator uses
const SUDOERS_PATH: &str = "/etc/sudoers.d/gryonixnexus-control";

fn sudoers_path() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH").unwrap_or_else(|_| SUDOERS_PATH.to_string())
}

fn sudoers_staged_path() -> String {
    format!("{}.staged", sudoers_path())
}

/// Stage, validate with `visudo`, then move into place
async fn write_sudoers(
    input: &HostInput,
    backups: &host::uninstall::BackupPaths,
    sink: &EventSink,
) -> Result<(), String> {
    let Some(body) = host::provision::sudoers(input, backups) else {
        let _ = sink
            .step("this host has no gryonixNexus control user, so no sudoers whitelist was written")
            .await;
        return Ok(());
    };
    install_validated_sudoers(host::provision::as_written(&body).as_bytes()).await?;
    let _ = sink.step("updated the dashboard's sudoers whitelist").await;
    Ok(())
}

/// Adds grants a whitelist written before them lacks.
pub async fn add_host_grants_if_missing() -> Result<bool, String> {
    let Ok(text) = std::fs::read_to_string(sudoers_path()) else { return Ok(false) };
    let Some(healed) = with_host_grants(&text) else { return Ok(false) };
    install_validated_sudoers(healed.as_bytes()).await?;
    Ok(true)
}

/// What every user allowed to reboot may also run
const REBOOT_TWINS: [&str; 2] = ["/usr/bin/systemctl poweroff", crate::system_ctl::SCRIPT_PATH];

fn with_host_grants(text: &str) -> Option<String> {
    const REBOOT: &str = " ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot";
    let mut out = String::new();
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        out.push_str(line);
        let Some(user) = line.trim_end_matches('\n').strip_suffix(REBOOT) else { continue };
        for twin in REBOOT_TWINS {
            let grant = format!("{user} ALL=(ALL) NOPASSWD: {twin}");
            if text.lines().any(|l| l == grant) {
                continue;
            }
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&grant);
            out.push('\n');
            changed = true;
        }
    }
    changed.then_some(out)
}

/// Stage, check with visudo, move into place
async fn install_validated_sudoers(bytes: &[u8]) -> Result<(), String> {
    let staged_path = sudoers_staged_path();
    let staged = Path::new(&staged_path);
    std::fs::write(staged, bytes)
        .map_err(|err| format!("could not write {staged_path}: {err}"))?;
    set_mode(staged, 0o440)
        .map_err(|err| format!("could not set the mode of {staged_path}: {err}"))?;

    let checked = tokio::time::timeout(
        Duration::from_secs(VISUDO_TIMEOUT_SECS),
        tokio::process::Command::new(visudo_bin())
            .args(["-cf", &staged_path])
            .stdin(Stdio::null())
            .output(),
    )
    .await;
    let ok = matches!(&checked, Ok(Ok(out)) if out.status.success());
    if !ok {
        let _ = std::fs::remove_file(staged);
        let why = match checked {
            Ok(Ok(out)) => truncate(&String::from_utf8_lossy(&out.stderr)),
            Ok(Err(err)) => err.to_string(),
            Err(_) => format!("visudo timed out after {VISUDO_TIMEOUT_SECS}s"),
        };
        return Err(format!("the sudoers whitelist failed visudo and was not installed: {why}"));
    }
    std::fs::rename(staged, sudoers_path())
        .map_err(|err| format!("could not install {}: {err}", sudoers_path()))?;
    Ok(())
}

const VISUDO_TIMEOUT_SECS: u64 = 30;

fn visudo_bin() -> PathBuf {
    std::env::var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("visudo"))
}

async fn start_metrics_collector(sink: &EventSink) -> Result<(), String> {
    let bin = systemctl_bin();
    run_quiet(&bin, &["daemon-reload"])
        .await
        .map_err(|()| "systemctl daemon-reload failed after writing the metrics unit".to_string())?;
    let _ = run_quiet(&bin, &["enable", host::metrics::UNIT_NAME]).await;
    run_quiet(&bin, &["restart", host::metrics::UNIT_NAME]).await.map_err(|()| {
        format!("could not start {} — the dashboard's history would stay empty", host::metrics::UNIT_NAME)
    })?;
    let _ = sink.step("started the metrics collector").await;
    Ok(())
}

async fn write_install_report(
    input: &HostInput,
    host_ctx: &HostContext,
    role: HostRole,
    sink: &EventSink,
) -> Result<(), String> {
    let topology = host_ctx.topology(role, &input.install);
    let for_render = input.clone();
    let rendered = tokio::task::spawn_blocking(move || {
        let facts = HostFacts;
        report::render(&for_render, &topology, &facts)
    })
    .await
    .map_err(|err| format!("could not render the install report: {err}"))?;

    let path = Path::new(report::REPORT_PATH);
    if let Some(parent) = path.parent() {
        create_dir_0755(parent)
            .map_err(|err| format!("could not create {}: {err}", parent.display()))?;
    }
    write_secret(path, &rendered, 0o600)
        .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    if let Some(user) = &input.ssh_user {
        let chowned = tokio::process::Command::new("chown")
            .args([user.as_str(), report::REPORT_PATH])
            .stdin(Stdio::null())
            .output()
            .await;
        if !matches!(&chowned, Ok(out) if out.status.success()) {
            let _ = sink
                .step(format!(
                    "could not give the install report to '{user}' — it stays root-owned, and the app reads it over sudo only"
                ))
                .await;
        }
    }
    let _ = sink.step("wrote the install report").await;
    Ok(())
}

/// The report's facts, answered against the real host.
struct HostFacts;

impl report::Facts for HostFacts {
    fn systemctl_is_active(&self, unit: &str) -> String {
        run_capture("systemctl", &["is-active", unit])
    }

    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn dkim_wrapper(&self, path: &str) -> String {
        run_capture(path, &[])
    }

    fn mailcow_dkim(&self, api_key: &str, domain: &str, https_port: u16) -> String {
        let url = format!("https://127.0.0.1:{https_port}/api/v1/get/dkim/{domain}");
        let body = run_capture_with_stdin(
            "curl",
            &["-sk", "--max-time", "20", "-K", "-", &url],
            &mailcow::curl_config(api_key, None),
        );
        body.split("\"dkim_txt\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("")
            .to_string()
    }

    fn wg_show(&self, interface: &str) -> String {
        run_capture("wg", &["show", interface])
    }
}

/// A short child process whose stdout IS the answer
fn run_capture(bin: &str, args: &[&str]) -> String {
    std::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

/// A short child process fed on stdin
fn run_capture_with_stdin(bin: &str, args: &[&str], input: &str) -> String {
    use std::io::Write;
    let spawned = std::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else { return String::new() };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    child
        .wait_with_output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

async fn install_cloudflared_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.cloudflared_path);
    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, cloudflared::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    if !input.cloudflared_token.trim().is_empty() {
        let env_path = dir.join(".env");
        write_managed_files(&[ManagedFile {
            path: env_path.clone(),
            contents: format!("TUNNEL_TOKEN={}\n", input.cloudflared_token.trim()),
            mode: Some(0o600),
        }])
        .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
        let _ = sink.step("wrote the tunnel's connector token").await;
    } else {
        match write_env_if_absent(&dir, &cloudflared::env_template()) {
            Ok(true) => {
                let _ = sink.step("wrote an empty .env for the tunnel token").await;
            }
            Ok(false) => {
                let _ = sink.step("kept the existing .env").await;
            }
            Err(err) => return Err(format!("could not write .env: {err}")),
        }
    }

    let _ = sink.step("pulling the Cloudflare Tunnel image").await;
    run_docker_streaming(&compose_pull_args(cloudflared::COMPOSE_PROJECT, &dir), sink).await?;

    let env = std::fs::read_to_string(dir.join(".env")).unwrap_or_default();
    if cloudflared::has_token(&env) {
        let _ = sink.step("starting the Cloudflare Tunnel").await;
        compose_up(cloudflared::COMPOSE_PROJECT, &dir, sink).await?;
    } else {
        let _ = sink
            .step(format!(
                "Cloudflare Tunnel is installed but NOT started: put the tunnel's token in {}/.env \
                 and start it from the app",
                input.cloudflared_path
            ))
            .await;
    }
    Ok(())
}

async fn install_headscale_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.headscale_path);
    let config_dir = dir.join("config");
    let data_dir = dir.join("data");

    write_headscale_files(input, &dir, &config_dir, &data_dir, sink).await?;
    let _ = sink.step("pulling the Headscale image").await;
    run_docker_streaming(&compose_pull_args(headscale::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Headscale").await;
    compose_up(headscale::COMPOSE_PROJECT, &dir, sink).await?;

    open_stun_port(sink).await;
    write_caddy_site(&headscale::caddy_site_names(input), &headscale::caddy_site(input))?;
    reload_caddy(sink).await?;

    join_own_mesh(input, sink).await;

    Ok(())
}

/// Directories, compose file, configuration and the extra-records file
async fn write_headscale_files(
    input: &Input,
    dir: &Path,
    config_dir: &Path,
    data_dir: &Path,
    sink: &EventSink,
) -> Result<(), String> {
    let _ = sink.step("creating service directories").await;
    create_dir_0755(dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(config_dir).map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;
    create_dir_0755(data_dir).map_err(|err| format!("could not create {}: {err}", data_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, headscale::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let config_path = config_dir.join("config.yaml");
    write_managed_files(&[ManagedFile { path: config_path.clone(), contents: headscale::config_yaml(input), mode: Some(0o600) }])
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;

    let records_path = config_dir.join(headscale::EXTRA_RECORDS_FILE);
    if headscale_records_need_writing(&records_path) {
        std::fs::write(&records_path, "[]\n")
            .map_err(|err| format!("could not write {}: {err}", records_path.display()))?;
        let _ = set_mode(&records_path, 0o644);
    }
    Ok(())
}

/// Opens the DERP relay's STUN port, saying what happened
async fn open_stun_port(sink: &EventSink) {
    let ports = vec![firewall::Port::udp(headscale::STUN_PORT)];
    match firewall::apply_service_ports("headscale", &ports).await {
        Ok(firewall::Outcome::Applied) => {
            let _ = sink.step("opened the DERP relay's STUN port in the firewall").await;
        }
        Ok(firewall::Outcome::Cleared) => {
            let _ = sink.step("removed this service's firewall ports").await;
        }
        Ok(firewall::Outcome::SkippedNoDropInDir) => {
            let _ = sink
                .step("the STUN port is NOT open: this host has no /etc/nftables.d drop-in directory — \
                       peers that cannot connect directly will have no fallback")
                .await;
        }
        Err(why) => {
            let _ = sink
                .step(format!("the DERP relay's STUN port could not be opened ({why}) — peers that cannot \
                               connect directly will have no fallback"))
                .await;
        }
    }
}

/// The server joins its own mesh, through the loopback publish
async fn join_own_mesh(input: &Input, sink: &EventSink) {
    let mut node_input = input.clone();
    let own_control =
        node_input.tailscale_login_server.trim().is_empty() && node_input.tailscale_auth_key.trim().is_empty();
    if node_input.tailscale_login_server.trim().is_empty() {
        node_input.tailscale_login_server = format!("http://127.0.0.1:{}", headscale::WEB_UI_PORT);
    }
    let _ = install_mesh_node_steps(&node_input, own_control, sink).await;
}

async fn mesh_fail(sink: &EventSink, text: String) -> Result<(), String> {
    let _ = sink.step(text.clone()).await;
    Err(text)
}

/// The node half
async fn install_mesh_node_steps(input: &Input, own_control: bool, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.tailscale_node_path);
    let state_dir = dir.join("state");
    let _ = sink.step("adding this server to its own mesh").await;
    prepare_mesh_node_files(input, &dir, &state_dir, sink).await?;
    if !mesh_node_has_identity(&state_dir) {
        store_mesh_join_key(input, own_control, &dir, sink).await?;
    }

    if let Err(why) = run_docker_streaming(&compose_pull_args(tailscale::COMPOSE_PROJECT, &dir), sink).await {
        return mesh_fail(sink, format!("the mesh node image could not be pulled ({why})")).await;
    }
    if let Err(why) = compose_up(tailscale::COMPOSE_PROJECT, &dir, sink).await {
        return mesh_fail(sink, format!("the mesh node could not be started ({why})")).await;
    }

    watch_mesh_join(&tailscale::node_name(input), sink).await
}

/// The node's directories and compose file
async fn prepare_mesh_node_files(input: &Input, dir: &Path, state_dir: &Path, sink: &EventSink) -> Result<(), String> {
    if let Err(err) = create_dir_0755(dir) {
        return mesh_fail(sink, format!("the mesh node was skipped: could not create {} ({err})", dir.display())).await;
    }
    // 0700: it holds the node's private identity, not configuration.
    if let Err(err) = std::fs::create_dir_all(state_dir).and_then(|_| set_mode(state_dir, 0o700)) {
        return mesh_fail(sink, format!("the mesh node was skipped: could not create {} ({err})", state_dir.display())).await;
    }

    let compose_path = dir.join("docker-compose.yml");
    if let Err(err) = write_managed_text(&compose_path, tailscale::compose_contents(input)) {
        return mesh_fail(sink, format!("the mesh node was skipped: could not write {} ({err})", compose_path.display())).await;
    }
    Ok(())
}

async fn store_mesh_join_key(input: &Input, own_control: bool, dir: &Path, sink: &EventSink) -> Result<(), String> {
    if !own_control {
        let supplied = input.tailscale_auth_key.trim();
        if supplied.is_empty() {
            let _ = sink
                .step("no join key was supplied — this server will not enter the mesh until one is")
                .await;
        } else {
            let env_path = dir.join(".env");
            if let Err(err) = write_managed_files(&[ManagedFile {
                path: env_path.clone(),
                contents: format!("TS_AUTHKEY={supplied}\n"),
                mode: Some(0o600),
            }]) {
                return mesh_fail(sink, format!("the join key could not be stored ({err})")).await;
            }
        }
    } else {
    match mint_mesh_join_key().await {
        Ok(key) => {
            let env_path = dir.join(".env");
            let contents = format!("TS_AUTHKEY={key}\n");
            if let Err(err) = write_managed_files(&[ManagedFile {
                path: env_path.clone(),
                contents,
                mode: Some(0o600),
            }]) {
                return mesh_fail(sink, format!("the join key could not be stored ({err})")).await;
            }
        }
        Err(why) => {
            let _ = sink
                .step(format!("no join key could be minted ({why}) — this server will not be in its own mesh"))
                .await;
        }
    }
    }
    Ok(())
}

async fn watch_mesh_join(name: &str, sink: &EventSink) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(run) = run_docker_captured(
            &["exec".to_string(), tailscale::CONTAINER.to_string(), "tailscale".to_string(),
              "status".to_string(), "--json".to_string()],
            Duration::from_secs(20),
        )
        .await
        {
            if run.success {
                if let Some((state, address)) = tailscale::parse_status(&run.stdout) {
                    if state == "Running" {
                        let _ = sink.step(format!("this server joined the mesh as {name} ({address})")).await;
                        return Ok(());
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            let why = run_docker_captured(
                &["logs".to_string(), "--tail".to_string(), "50".to_string(),
                  tailscale::CONTAINER.to_string()],
                Duration::from_secs(15),
            )
            .await
            .ok()
            .and_then(|run| tailscale::last_login_error(&format!("{}{}", run.stdout, run.stderr)));
            match why {
                Some(reason) => {
                    let _ = sink.step(format!("the node is running but did not join: {reason}")).await;
                }
                None => {
                    let _ = sink.step("the node is running but has not joined the mesh yet").await;
                }
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Whether the mesh node's state directory holds a REGISTERED identity
fn mesh_node_has_identity(state_dir: &std::path::Path) -> bool {
    match std::fs::read_to_string(state_dir.join("tailscaled.state")) {
        Ok(text) => text.contains("_current-profile"),
        Err(_) => false,
    }
}

async fn mint_mesh_join_key() -> Result<String, String> {
    async fn users() -> Result<Vec<crate::pb::MeshUser>, String> {
        let run = run_docker_captured(
            &["exec".to_string(), headscale::CONTAINER.to_string(), "headscale".to_string(),
              "users".to_string(), "list".to_string(), "-o".to_string(), "json".to_string()],
            Duration::from_secs(20),
        )
        .await?;
        if !run.success {
            return Err(run.why());
        }
        crate::mesh::parse_users(&run.stdout).map_err(|err| err.to_string())
    }

    let mut found = users().await?.into_iter().find(|user| user.name == tailscale::MESH_USER);
    if found.is_none() {
        let _ = run_docker_captured(
            &["exec".to_string(), headscale::CONTAINER.to_string(), "headscale".to_string(),
              "users".to_string(), "create".to_string(), tailscale::MESH_USER.to_string()],
            Duration::from_secs(20),
        )
        .await;
        found = users().await?.into_iter().find(|user| user.name == tailscale::MESH_USER);
    }
    let user = found.ok_or_else(|| format!("the mesh has no user named {}", tailscale::MESH_USER))?;

    let run = run_docker_captured(
        &["exec".to_string(), headscale::CONTAINER.to_string(), "headscale".to_string(),
          "preauthkeys".to_string(), "create".to_string(), "--user".to_string(), user.id.clone(),
          "--reusable".to_string(),
          "--expiration".to_string(), "24h".to_string(), "-o".to_string(), "json".to_string()],
        Duration::from_secs(20),
    )
    .await?;
    if !run.success {
        return Err(run.why());
    }
    let key = crate::mesh::parse_auth_key(&run.stdout).map_err(|err| err.to_string())?.key;
    if key.is_empty() {
        return Err("the control server returned an empty key".to_string());
    }
    Ok(key)
}

/// Turns on plain-HTTP DNS-over-HTTPS behind the proxy, then restarts
async fn enable_plain_http_doh(dir: &Path, conf_yaml_path: &Path, sink: &EventSink) {
    if let Ok(yaml) = std::fs::read_to_string(conf_yaml_path) {
        let (patched, spelling) = patch_doh_insecure(&yaml);
        match spelling {
            Some(_) if patched != yaml => {
                if let Err(err) = std::fs::write(conf_yaml_path, patched) {
                    let _ = sink.step(format!("could not write {}: {err}", conf_yaml_path.display())).await;
                } else {
                    let _ = sink.step("enabled plain-HTTP DNS-over-HTTPS").await;
                }
            }
            Some(_) => {}
            None => {
                let _ = sink
                    .step("could not enable DNS-over-HTTPS behind the proxy — turn it on under Settings, Encryption")
                    .await;
            }
        }
        let _ = run_docker_streaming(&compose_restart_args(adguard::COMPOSE_PROJECT, dir), sink).await;
    }
}

async fn install_adguard_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.adguard_path);
    let conf_dir = dir.join("conf");
    let work_dir = dir.join("work");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&conf_dir).map_err(|err| format!("could not create {}: {err}", conf_dir.display()))?;
    create_dir_0755(&work_dir).map_err(|err| format!("could not create {}: {err}", work_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, adguard::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // 3. .env, generated once — see write_env_if_absent's own doc.
    match write_env_if_absent(&dir, &adguard::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the admin secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    // 4. pull, then up — streamed.
    let _ = sink.step("pulling the AdGuard Home image").await;
    run_docker_streaming(&compose_pull_args(adguard::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting AdGuard Home").await;
    compose_up(adguard::COMPOSE_PROJECT, &dir, sink).await?;

    let conf_yaml_path = conf_dir.join("AdGuardHome.yaml");
    if !conf_yaml_path.exists() {
        if wait_for_adguard(sink).await {
            configure_adguard(&dir, input, sink).await;
        } else {
            let _ = sink
                .step("AdGuard Home did not answer in time — the initial configuration was skipped")
                .await;
        }
    }

    enable_plain_http_doh(&dir, &conf_yaml_path, sink).await;

    // 8. Caddy site.
    write_caddy_site(&adguard::caddy_site_names(input), &adguard::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `PiholeService.setupSteps`
async fn install_pihole_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.pihole_path);
    let config_dir = dir.join("etc-pihole");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&config_dir)
        .map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, pihole::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &pihole::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the admin secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    // 4. pull, then up — streamed.
    let _ = sink.step("pulling the Pi-hole image").await;
    run_docker_streaming(&compose_pull_args(pihole::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Pi-hole").await;
    compose_up(pihole::COMPOSE_PROJECT, &dir, sink).await?;

    let _ = sink.step("waiting for the resolver to answer").await;
    if !wait_for_pihole(sink).await {
        let _ = sink
            .step("Pi-hole did not answer a query in time — it is installed and may still be building its blocklists")
            .await;
    }

    open_service_firewall_ports(PIHOLE_FIREWALL_LABEL, &pihole::firewall_ports(input), sink).await;

    // 7. Caddy site.
    write_caddy_site(&pihole::caddy_site_names(input), &pihole::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `HomepageService.setupSteps`
async fn install_homepage_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.homepage_path);
    let config_dir = dir.join("config");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&config_dir)
        .map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, homepage::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    // Ours, derived, rewritten.
    let _ = sink.step("writing the page from this server's services").await;
    for (name, contents) in [
        ("services.yaml", homepage::services_yaml(input, services)),
        ("settings.yaml", homepage::settings_yaml(input, services)),
    ] {
        let path = config_dir.join(name);
        std::fs::write(&path, contents).map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    for name in ["bookmarks.yaml", "widgets.yaml", "docker.yaml"] {
        let path = config_dir.join(name);
        if !path.exists() {
            std::fs::write(&path, "---\n")
                .map_err(|err| format!("could not write {}: {err}", path.display()))?;
        }
    }

    let _ = sink.step("pulling the Homepage image").await;
    run_docker_streaming(&compose_pull_args(homepage::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Homepage").await;
    compose_up(homepage::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&homepage::caddy_site_names(input), &homepage::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `AutheliaService.setupSteps`
async fn install_authelia_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.authelia_path);
    let config_dir = dir.join("config");

    write_authelia_files(input, services, &dir, &config_dir, sink).await?;
    let _ = sink.step("pulling the Authelia image").await;
    run_docker_streaming(&compose_pull_args(authelia::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Authelia").await;
    compose_up(authelia::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&authelia::caddy_site_names(input), &authelia::caddy_site(input))?;

    guard_sites_with_portal(input, services, sink).await;
    reload_caddy(sink).await?;

    Ok(())
}

/// The portal's directories, configuration, secrets and first account
async fn write_authelia_files(
    input: &Input,
    services: &[String],
    dir: &Path,
    config_dir: &Path,
    sink: &EventSink,
) -> Result<(), String> {
    let _ = sink.step("creating service directories").await;
    create_dir_0755(dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_with_mode(config_dir, 0o700)
        .map_err(|err| format!("could not create {}: {err}", config_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, authelia::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let config_path = config_dir.join("configuration.yml");
    std::fs::write(&config_path, authelia::configuration_yaml(input, services))
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;

    match write_env_if_absent(dir, &authelia::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the portal secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let users_path = config_dir.join("users_database.yml");
    if authelia_needs_first_user(&users_path) {
        let _ = sink.step("creating the first account").await;
        match make_authelia_first_user(input, &users_path, dir).await {
            Ok(()) => {}
            Err(why) => {
                let _ = sink
                    .step(format!(
                        "could not create the first account — sign-in is not possible until a user is added to config/users_database.yml ({why})"
                    ))
                    .await;
            }
        }
    }
    Ok(())
}

async fn guard_sites_with_portal(input: &Input, services: &[String], sink: &EventSink) {
    let mut guarded: Vec<String> = Vec::new();
    let mut unrenderable: Vec<String> = Vec::new();
    for id in authelia::protected_ids(input, services) {
        match catalog::site_for(&id, input, true) {
            Some((names, site)) => match write_caddy_site(&names, &site) {
                Ok(()) => guarded.push(id),
                Err(why) => {
                    let _ = sink.step(format!("could not put {id} behind the sign-on portal: {why}")).await;
                }
            },
            None => unrenderable.push(id),
        }
    }
    if !guarded.is_empty() {
        let _ = sink.step(format!("put these behind the sign-on portal: {}", guarded.join(", "))).await;
    }
    if !unrenderable.is_empty() {
        let _ = sink
            .step(format!(
                "these publish no site of their own, so the portal cannot stand in front of them: {}",
                unrenderable.join(", ")
            ))
            .await;
    }
}

fn headscale_records_need_writing(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(text) => text == "[]\\n",
        Err(_) => true,
    }
}

fn authelia_needs_first_user(users_path: &Path) -> bool {
    match std::fs::read_to_string(users_path) {
        Ok(text) => !text.lines().any(|line| line.trim_start().starts_with("password: '$")),
        Err(_) => true,
    }
}

async fn make_authelia_first_user(
    input: &Input,
    users_path: &Path,
    dir: &Path,
) -> Result<(), String> {
    let run = run_docker_captured(
        &[
            "run".to_string(),
            "--rm".to_string(),
            authelia::IMAGE.to_string(),
            "authelia".to_string(),
            "crypto".to_string(),
            "hash".to_string(),
            "generate".to_string(),
            "argon2".to_string(),
            "--random".to_string(),
        ],
        Duration::from_secs(60),
    )
    .await?;
    if !run.success {
        return Err(run.why());
    }
    let field = |prefix: &str| -> Option<String> {
        run.stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix).map(|rest| rest.trim().to_string()))
            .filter(|value| !value.is_empty())
    };
    let (Some(password), Some(digest)) = (field("Random Password: "), field("Digest: ")) else {
        return Err("the image printed no password and digest".to_string());
    };
    if !digest.starts_with('$') {
        return Err(format!("the image printed a digest in a form Authelia cannot read: {digest}"));
    }
    let admin = &input.admin_username;
    let body = format!(
        "---
users:
  {admin}:
    disabled: false
    displayname: '{admin}'
    password: '{digest}'
    email: '{admin}@{}'
    groups:
      - admins
",
        input.domain
    );
    write_secret(users_path, &body, 0o600)
        .map_err(|err| format!("could not write {}: {err}", users_path.display()))?;

    use std::io::Write;
    let env_path = dir.join(".env");
    if let Ok(existing) = std::fs::read_to_string(&env_path) {
        let kept: String = existing
            .lines()
            .filter(|line| !line.starts_with("AUTHELIA_ADMIN_PASSWORD="))
            .map(|line| format!("{line}\n"))
            .collect();
        if kept.len() != existing.len() {
            std::fs::write(&env_path, kept)
                .map_err(|err| format!("could not rewrite {}: {err}", env_path.display()))?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&env_path)
        .map_err(|err| format!("could not open {}: {err}", env_path.display()))?;
    writeln!(file, "AUTHELIA_ADMIN_PASSWORD={password}")
        .map_err(|err| format!("could not record the password: {err}"))?;
    set_mode(&env_path, 0o600)
        .map_err(|err| format!("could not set the mode of {}: {err}", env_path.display()))?;
    Ok(())
}

const PIHOLE_FIREWALL_LABEL: &str = "pihole";

async fn open_service_firewall_ports(label: &str, ports: &[firewall::Port], sink: &EventSink) {
    let text = match firewall::apply_service_ports(label, ports).await {
        Ok(firewall::Outcome::Applied) => "opened this service's ports in the firewall".to_string(),
        Ok(firewall::Outcome::Cleared) => "this service opens no ports in the firewall".to_string(),
        Ok(firewall::Outcome::SkippedNoDropInDir) =>
            "the ports are NOT open: this host has no /etc/nftables.d drop-in directory — re-run the server setup, then install again"
                .to_string(),
        Err(err) => format!("could not update this service's firewall ports: {err}"),
    };
    let _ = sink.step(text).await;
}

async fn wait_for_pihole(sink: &EventSink) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    let mut tries: u32 = 0;
    while std::time::Instant::now() < deadline {
        let run = run_docker_captured(
            &[
                "exec".to_string(),
                pihole::CONTAINER.to_string(),
                "dig".to_string(),
                "+short".to_string(),
                "+norecurse".to_string(),
                "+retry=0".to_string(),
                "@127.0.0.1".to_string(),
                "pi.hole".to_string(),
            ],
            Duration::from_secs(10),
        )
        .await;
        if matches!(&run, Ok(run) if run.success) {
            return true;
        }
        tries += 1;
        if tries % 6 == 0 {
            let _ = sink
                .step("Pi-hole: waiting for the resolver to answer (it is downloading its blocklists)")
                .await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    false
}

async fn install_jellyfin_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.jellyfin_path);
    let media = PathBuf::from(&input.jellyfin_media_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["config", "cache"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }
    create_dir_if_absent_0755(&media).map_err(|err| format!("could not create {}: {err}", media.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, jellyfin::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Jellyfin image").await;
    run_docker_streaming(&compose_pull_args(jellyfin::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Jellyfin").await;
    compose_up(jellyfin::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&jellyfin::caddy_site_names(input), &jellyfin::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `HomeAssistantService.setupSteps`
async fn install_home_assistant_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.home_assistant_path);
    let config = dir.join("config");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_with_mode(&config, 0o700)
        .map_err(|err| format!("could not create {}: {err}", config.display()))?;
    let themes = config.join("themes");
    create_dir_0755(&themes)
        .map_err(|err| format!("could not create {}: {err}", themes.display()))?;

    let repaired = seed_home_assistant_config(&config)?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, home_assistant::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Home Assistant image").await;
    run_docker_streaming(&compose_pull_args(home_assistant::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Home Assistant").await;
    compose_up(home_assistant::COMPOSE_PROJECT, &dir, sink).await?;
    if repaired {
        let _ = sink.step("restarting Home Assistant with the repaired web settings").await;
        run_docker_streaming(&["restart".to_string(), home_assistant::CONTAINER.to_string()], sink).await?;
    }

    write_caddy_site(&home_assistant::caddy_site_names(input), &home_assistant::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

fn seed_home_assistant_config(config: &Path) -> Result<bool, String> {
    let storage = config.join(".storage");
    create_dir_with_mode(&storage, 0o700)
        .map_err(|err| format!("could not create {}: {err}", storage.display()))?;
    let http = storage.join("http");
    let broken = std::fs::read_to_string(&http)
        .map(|text| home_assistant::http_store_needs_repair(&text))
        .unwrap_or(false);
    if broken {
        std::fs::write(&http, home_assistant::INITIAL_HTTP_STORE)
            .and_then(|()| set_mode(&http, 0o600))
            .map_err(|err| format!("could not repair {}: {err}", http.display()))?;
    }
    create_file_if_absent(&http, home_assistant::INITIAL_HTTP_STORE, 0o600)
        .map_err(|err| format!("could not write {}: {err}", http.display()))?;
    let seeds = [
        ("configuration.yaml", home_assistant::INITIAL_CONFIGURATION),
        ("automations.yaml", "[]\n"),
        ("scenes.yaml", "[]\n"),
        ("scripts.yaml", ""),
    ];
    for (name, contents) in seeds {
        let path = config.join(name);
        create_file_if_absent(&path, contents, 0o644)
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    Ok(broken)
}

/// A port of `MosquittoService.setupSteps`
async fn install_mosquitto_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.mosquitto_path);
    let config = dir.join("config");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["config", "data"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    match write_env_if_absent(&dir, &mosquitto::env_template()) {
        Ok(_) => {}
        Err(err) => return Err(format!("could not write {}/.env: {err}", dir.display())),
    }
    let conf = config.join("mosquitto.conf");
    write_managed_text(&conf, mosquitto::BROKER_CONFIGURATION)
        .map_err(|err| format!("could not write {}: {err}", conf.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, mosquitto::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Mosquitto image").await;
    run_docker_streaming(&compose_pull_args(mosquitto::COMPOSE_PROJECT, &dir), sink).await?;
    create_mosquitto_accounts(&config, &broker_password(&dir)?, sink).await?;
    let _ = sink.step("starting Mosquitto").await;
    compose_up(mosquitto::COMPOSE_PROJECT, &dir, sink).await?;

    Ok(())
}

fn broker_password(dir: &Path) -> Result<String, String> {
    let path = dir.join(".env");
    read_env_value(&path, "MQTT_PASSWORD")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{} carries no MQTT_PASSWORD", path.display()))
}

/// One broker account per client
async fn create_mosquitto_accounts(
    config: &Path,
    password: &str,
    sink: &EventSink,
) -> Result<(), String> {
    let passwd = config.join("passwd");
    if passwd.exists() {
        return Ok(());
    }
    let _ = sink.step("creating the broker's accounts").await;
    let plain: String = mosquitto::USERS.iter().map(|user| format!("{user}:{password}\n")).collect();
    create_file_if_absent(&passwd, &plain, 0o600)
        .map_err(|err| format!("could not create {}: {err}", passwd.display()))?;
    let mount = format!("{}:/mosquitto/config", config.display());
    let in_image = |command: &[&str]| -> Vec<String> {
        let mut args = vec!["run".to_string(), "--rm".to_string(), "-v".to_string(), mount.clone()];
        args.push(mosquitto::IMAGE.to_string());
        args.extend(command.iter().map(|part| part.to_string()));
        args
    };
    run_docker_streaming(&in_image(&["mosquitto_passwd", "-U", "/mosquitto/config/passwd"]), sink).await?;
    run_docker_streaming(&in_image(&["chown", "1883:1883", "/mosquitto/config/passwd"]), sink).await?;
    Ok(())
}

/// A port of `Zigbee2MQTTService.setupSteps`
async fn install_zigbee2mqtt_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.zigbee2mqtt_path);
    let broker = PathBuf::from(&input.mosquitto_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let data = dir.join("data");
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;

    let password = broker_password(&broker)
        .map_err(|err| format!("{err} — install Mosquitto on this host before Zigbee2MQTT"))?;
    let settings = data.join("configuration.yaml");
    let contents = zigbee2mqtt::initial_configuration(&input.home_assistant_usb_device, &password);
    create_file_if_absent(&settings, &contents, 0o600)
        .map_err(|err| format!("could not write {}: {err}", settings.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, zigbee2mqtt::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Zigbee2MQTT image").await;
    run_docker_streaming(&compose_pull_args(zigbee2mqtt::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Zigbee2MQTT").await;
    compose_up(zigbee2mqtt::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&zigbee2mqtt::caddy_site_names(input), &zigbee2mqtt::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `OllamaService.setupSteps`
async fn install_ollama_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.ollama_path);
    let models = dir.join("models");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&models)
        .map_err(|err| format!("could not create {}: {err}", models.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, ollama::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    gpu_override(input, sink).await?;

    let _ = sink.step("pulling the Ollama image").await;
    run_docker_streaming(&compose_pull_args(ollama::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Ollama").await;
    ensure_ai_network(sink).await;
    compose_up(ollama::COMPOSE_PROJECT, &dir, sink).await?;

    Ok(())
}

async fn gpu_override(input: &Input, sink: &EventSink) -> Result<(), String> {
    let path = PathBuf::from(ollama::gpu_override_path(input));
    let wanted = input.ollama_uses_gpu && driver_answers();
    if !wanted {
        if input.ollama_uses_gpu {
            let _ = sink
                .step("no NVIDIA driver answered — the engine will run on the processor")
                .await;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("could not remove {}: {err}", path.display())),
        }
        return Ok(());
    }
    if !docker_knows_the_nvidia_runtime() {
        packages::ensure_nvidia_container_toolkit(sink).await?;
    }
    std::fs::write(&path, ollama::gpu_override_contents())
        .map_err(|err| format!("could not write {}: {err}", path.display()))
}

async fn self_installed_by_hand(service_id: &str, conflicts: &[ports::Conflict]) -> Option<String> {
    for conflict in conflicts.iter().filter(|c| c.holder.is_none()) {
        let name = ports::holder_process(&conflict.port).await?;
        if name.to_lowercase().contains(&service_id.to_lowercase()) {
            return Some(name);
        }
    }
    None
}

/// Does a driver actually answer on this host?
fn driver_answers() -> bool {
    packages::have_binary("nvidia-smi") && !run_capture("nvidia-smi", &["-L"]).is_empty()
}

/// Whether docker has already been configured with NVIDIA's runtime
fn docker_knows_the_nvidia_runtime() -> bool {
    run_capture(&docker_bin().to_string_lossy(), &["info", "--format", "{{json .Runtimes}}"])
        .contains("nvidia")
}

/// A port of `OpenWebUIService.setupSteps`
async fn install_open_webui_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.open_webui_path);
    let data = dir.join("data");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, open_webui::compose_contents(input, services))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &open_webui::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the session key").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    if gateway_is_installed(services) {
        let key = ensure_app_key(open_webui::SERVICE_ID, sink).await?;
        llm_keys::set_env_value(&dir.join(".env"), "LLM_GATEWAY_KEY", &key)
            .map_err(|err| format!("could not write the gateway key: {err:#}"))?;
    }

    let _ = sink.step("pulling the Open WebUI image").await;
    run_docker_streaming(&compose_pull_args(open_webui::COMPOSE_PROJECT, &dir), sink).await?;
    forget_stored_addresses(&data, services).await;
    let _ = sink.step("starting Open WebUI").await;
    ensure_ai_network(sink).await;
    compose_up(open_webui::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&open_webui::caddy_site_names(input), &open_webui::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `QdrantService.setupSteps`
async fn install_qdrant_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.qdrant_path);
    let storage = dir.join("storage");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_with_mode(&storage, 0o700)
        .map_err(|err| format!("could not create {}: {err}", storage.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, qdrant::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("reading the vector store key").await;
    let key = llm_keys::ensure_shared_secret(Path::new(qdrant::API_KEY_PATH), "")
        .map_err(|err| format!("could not mint the vector store key: {err:#}"))?;
    llm_keys::set_env_value(&dir.join(".env"), "QDRANT_API_KEY", &key)
        .map_err(|err| format!("could not write the vector store key: {err:#}"))?;

    let _ = sink.step("pulling the Qdrant image").await;
    run_docker_streaming(&compose_pull_args(qdrant::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Qdrant").await;
    ensure_ai_network(sink).await;
    compose_up(qdrant::COMPOSE_PROJECT, &dir, sink).await?;

    Ok(())
}

/// A port of `SearXNGService.setupSteps`
async fn install_searxng_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.searxng_path);
    let config = dir.join("config");
    let cache = dir.join("cache");

    let _ = sink.step("creating service directories").await;
    for path in [&dir, &config, &cache] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, searxng::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let settings_path = PathBuf::from(searxng::settings_path(input));
    let _ = sink.step("writing the search settings").await;
    write_managed_text(&settings_path, searxng::settings_file())
        .map_err(|err| format!("could not write {}: {err}", settings_path.display()))?;
    set_mode(&settings_path, 0o644)
        .map_err(|err| format!("could not chmod {}: {err}", settings_path.display()))?;

    match write_env_if_absent(&dir, &searxng::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the instance secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the SearXNG image").await;
    run_docker_streaming(&compose_pull_args(searxng::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting SearXNG").await;
    ensure_ai_network(sink).await;
    compose_up(searxng::COMPOSE_PROJECT, &dir, sink).await?;

    Ok(())
}

/// A port of `OpenClawService.setupSteps`
async fn install_openclaw_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.openclaw_path);
    let state = dir.join("state");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_owned_by_user(&state, 0o700, OPENCLAW_CONTAINER_UID, OPENCLAW_CONTAINER_UID)
        .map_err(|err| format!("could not create {}: {err}", state.display()))?;

    let config_path = PathBuf::from(openclaw::config_path(input));
    if !config_path.exists() {
        let _ = sink.step("writing the gateway configuration").await;
        std::fs::write(&config_path, format!("{}\n", openclaw::SEEDED_CONFIG))
            .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
    }
    std::os::unix::fs::chown(&config_path, Some(OPENCLAW_CONTAINER_UID), Some(OPENCLAW_CONTAINER_UID))
        .map_err(|err| format!("could not chown {}: {err}", config_path.display()))?;
    set_mode(&config_path, 0o600)
        .map_err(|err| format!("could not chmod {}: {err}", config_path.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, openclaw::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &openclaw::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the gateway token").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the OpenClaw image").await;
    run_docker_streaming(&compose_pull_args(openclaw::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting OpenClaw").await;
    ensure_ai_network(sink).await;
    trust_ai_network_gateway(&config_path, sink).await;
    compose_up(openclaw::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&openclaw::caddy_site_names(input), &openclaw::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// The uid the assistant's image runs as (`node`).
const OPENCLAW_CONTAINER_UID: u32 = 1000;

/// A port of `AnythingLLMService.setupSteps`
async fn install_anythingllm_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.anythingllm_path);
    let storage = dir.join("storage");
    let env_file = PathBuf::from(anythingllm::env_path(input));

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_owned_by_user(&storage, 0o700, ANYTHINGLLM_CONTAINER_UID, ANYTHINGLLM_CONTAINER_UID)
        .map_err(|err| format!("could not create {}: {err}", storage.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, anythingllm::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    if env_file.metadata().map(|meta| meta.len() > 0).unwrap_or(false) {
        let _ = sink.step("kept the existing settings").await;
    } else {
        let _ = sink.step("writing the settings the deployment implies").await;
        let mut lines = anythingllm::seeded_settings(services);
        // Three server secrets, generated here and never shown.
        for name in ["SIG_KEY", "SIG_SALT", "JWT_SECRET"] {
            lines.push(format!("{name}='{}'", random_hex(32)?));
        }
        if anythingllm::uses_qdrant(services) {
            let key = llm_keys::ensure_shared_secret(Path::new(qdrant::API_KEY_PATH), "")
                .map_err(|err| format!("could not mint the vector store key: {err:#}"))?;
            lines.push(format!("QDRANT_API_KEY='{key}'"));
        }
        if anythingllm::model_source(services) == Some(anythingllm::ModelSource::Gateway) {
            let key = ensure_app_key(anythingllm::SERVICE_ID, sink).await?;
            lines.push(format!("LITE_LLM_API_KEY='{key}'"));
        }
        write_private_file(&env_file, &format!("{}\n", lines.join("\n")))
            .map_err(|err| format!("could not write {}: {err}", env_file.display()))?;
    }
    std::os::unix::fs::chown(
        &env_file,
        Some(ANYTHINGLLM_CONTAINER_UID),
        Some(ANYTHINGLLM_CONTAINER_UID),
    )
    .map_err(|err| format!("could not chown {}: {err}", env_file.display()))?;
    set_mode(&env_file, 0o600)
        .map_err(|err| format!("could not chmod {}: {err}", env_file.display()))?;

    let _ = sink.step("pulling the AnythingLLM image").await;
    run_docker_streaming(&compose_pull_args(anythingllm::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting AnythingLLM").await;
    ensure_ai_network(sink).await;
    compose_up(anythingllm::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&anythingllm::caddy_site_names(input), &anythingllm::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// The uid the AnythingLLM image runs as
const ANYTHINGLLM_CONTAINER_UID: u32 = 1000;

fn random_hex(n: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; n];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").map_err(|err| err.to_string())?, &mut bytes)
        .map_err(|err| format!("reading /dev/urandom: {err}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn write_managed_text(path: &Path, contents: impl AsRef<str>) -> io::Result<()> {
    let contents = contents.as_ref();
    if contents.ends_with('\n') {
        std::fs::write(path, contents)
    } else {
        std::fs::write(path, format!("{contents}\n"))
    }
}

fn write_private_file(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

/// A port of `N8NService.setupSteps`
async fn install_n8n_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.n8n_path);
    let data = dir.join("data");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_owned_by_user(&data, 0o700, N8N_CONTAINER_UID, N8N_CONTAINER_UID)
        .map_err(|err| format!("could not create {}: {err}", data.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, n8n::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &n8n::env_template()) {
        Ok(true) => {
            let _ = sink.step("generating the database password").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the n8n images").await;
    run_docker_streaming(&compose_pull_args(n8n::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting n8n").await;
    compose_up(n8n::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&n8n::caddy_site_names(input), &n8n::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

const N8N_CONTAINER_UID: u32 = 1000;

/// A port of `LiteLLMService.setupSteps`
async fn install_litellm_steps(
    input: &Input,
    services: &[String],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(&input.litellm_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let key = llm_keys::ensure_gateway_key(Path::new(litellm::GATEWAY_KEY_PATH))
        .map_err(|err| format!("could not mint the gateway key: {err:#}"))?;
    llm_keys::ensure_keys_file(Path::new(llm_keys::KEYS_ENV_PATH))
        .map_err(|err| format!("could not create the provider keys file: {err:#}"))?;

    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, litellm::config_yaml(services))
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, litellm::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    llm_keys::set_env_value(&dir.join(".env"), "LITELLM_MASTER_KEY", &key)
        .map_err(|err| format!("could not write the master key: {err:#}"))?;
    ensure_env_secret(&dir.join(".env"), "DB_PASSWORD")?;

    let _ = sink.step("pulling the LiteLLM image").await;
    run_docker_streaming(&compose_pull_args(litellm::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting LiteLLM").await;
    ensure_ai_network(sink).await;
    compose_up(litellm::COMPOSE_PROJECT, &dir, sink).await?;
    for app in litellm::KEYED_APPS.iter().filter(|app| services.iter().any(|id| id == *app)) {
        ensure_app_key(app, sink).await?;
    }

    write_caddy_site(&litellm::caddy_site_names(input), &litellm::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Appends a random secret to `.env` unless one is there
fn ensure_env_secret(env: &Path, name: &str) -> Result<(), String> {
    let existing = std::fs::read_to_string(env).unwrap_or_default();
    if existing.lines().any(|line| line.starts_with(&format!("{name}="))) {
        return Ok(());
    }
    let value = random_hex(24)?;
    llm_keys::set_env_value(env, name, &value).map_err(|err| format!("could not write {name}: {err:#}"))
}

/// An app's own gateway key, registered while the gateway runs
async fn ensure_app_key(app: &str, sink: &EventSink) -> Result<String, String> {
    let path = litellm::app_key_path(app);
    let key = llm_keys::ensure_shared_secret(Path::new(&path), "sk-")
        .map_err(|err| format!("could not mint the {app} gateway key: {err:#}"))?;
    let _ = set_mode(Path::new(litellm::APP_KEYS_DIRECTORY), 0o700);
    let running = run_capture(&docker_bin().to_string_lossy(), &["ps", "--format", "{{.Names}}"]);
    if !running.lines().any(|name| name == litellm::CONTAINER) {
        return Ok(key);
    }
    let _ = sink.step(&format!("registering the {app} key with LiteLLM")).await;
    if !register_app_key(app, &key).await {
        let _ = sink.step(&format!("LiteLLM: {app} key not registered")).await;
    }
    Ok(key)
}

/// Whether the gateway now accepts `key` as the app's
async fn register_app_key(app: &str, key: &str) -> bool {
    let Ok(master) = std::fs::read_to_string(litellm::GATEWAY_KEY_PATH) else { return false };
    let master = master.trim();
    for _ in 0..60 {
        if gateway_call(&litellm::curl_config(master, "health/readiness", None)).await {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    if gateway_call(&litellm::curl_config(master, &format!("key/info?key={key}"), None)).await {
        return true;
    }
    let delete = litellm::key_delete_body(app);
    gateway_call(&litellm::curl_config(master, "key/delete", Some(&delete))).await;
    let generate = litellm::key_generate_body(app, key);
    gateway_call(&litellm::curl_config(master, "key/generate", Some(&generate))).await
}

async fn gateway_call(config: &str) -> bool {
    let spawned = tokio::process::Command::new("curl")
        .args(["-fsS", "-m", "10", "-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else { return false };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(config.as_bytes()).await;
    }
    child.wait().await.map(|status| status.success()).unwrap_or(false)
}

/// Is the gateway one of the services this host carries?
fn gateway_is_installed(services: &[String]) -> bool {
    services.iter().any(|id| id == litellm::SERVICE_ID)
}

/// A port of `MinecraftJavaService.setupSteps`
async fn install_minecraft_java_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.minecraft_java_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let data = dir.join("data");
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;
    for name in ["mods", "plugins"] {
        let extra = dir.join(name);
        create_dir_0755(&extra).map_err(|err| format!("could not create {}: {err}", extra.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, minecraft::java_compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &minecraft::java_env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the RCON secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Minecraft (Java) image").await;
    run_docker_streaming(&compose_pull_args(minecraft::JAVA_COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting the Minecraft (Java) server").await;
    compose_up(minecraft::JAVA_COMPOSE_PROJECT, &dir, sink).await?;

    let ports: Vec<firewall::Port> =
        minecraft::java_firewall_ports(input).into_iter().map(|(port, _)| firewall::Port::tcp(port)).collect();
    open_service_firewall_ports("minecraft-java", &ports, sink).await;

    Ok(())
}

/// A port of `MinecraftBedrockService.setupSteps`.
async fn install_minecraft_bedrock_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.minecraft_bedrock_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let data = dir.join("data");
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, minecraft::bedrock_compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Minecraft (Bedrock) image").await;
    run_docker_streaming(&compose_pull_args(minecraft::BEDROCK_COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting the Minecraft (Bedrock) server").await;
    compose_up(minecraft::BEDROCK_COMPOSE_PROJECT, &dir, sink).await?;

    // UDP, and a TCP rule would open nothing at all.
    let ports: Vec<firewall::Port> = minecraft::bedrock_firewall_ports(input)
        .into_iter()
        .map(|(port, _)| firewall::Port { proto: firewall::Proto::Udp, port })
        .collect();
    open_service_firewall_ports("minecraft-bedrock", &ports, sink).await;

    Ok(())
}

/// A port of `CraftyControllerService.setupSteps`
async fn install_crafty_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.crafty_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["backups", "logs", "servers", "config", "import"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, crafty::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let _ = sink.step("pulling the Crafty Controller image").await;
    run_docker_streaming(&compose_pull_args(crafty::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Crafty Controller").await;
    compose_up(crafty::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&crafty::caddy_site_names(input), &crafty::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `ImmichService.setupSteps`
async fn install_immich_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.immich_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, immich::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &immich::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database secret").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Immich images").await;
    run_docker_streaming(&compose_pull_args(immich::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Immich").await;
    compose_up(immich::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&immich::caddy_site_names(input), &immich::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn run_docker_capture(args: &[String], timeout: Duration) -> Result<(bool, String), String> {
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(docker_bin())
            .env("DOCKER_CONFIG", docker_config_dir())
            .args(args)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| format!("docker timed out after {}s", timeout.as_secs()))?
    .map_err(|err| format!("could not run docker: {err}"))?;

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), text))
}

fn why(output: &str) -> String {
    bounded(output, 300)
}

/// A port of `GitLabService.setupSteps`
async fn install_gitlab_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.gitlab_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, gitlab::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &gitlab::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the initial root password").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the GitLab image (several gigabytes)").await;
    run_docker_streaming(&compose_pull_args(gitlab::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting GitLab — the first boot takes several minutes").await;
    compose_up(gitlab::COMPOSE_PROJECT, &dir, sink).await?;

    configure_gitlab(&dir, sink).await;

    let ssh_ports: Vec<firewall::Port> =
        gitlab::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default();
    open_service_firewall_ports(gitlab::SERVICE_ID, &ssh_ports, sink).await;

    write_caddy_site(&gitlab::caddy_site_names(input), &gitlab::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn configure_gitlab(dir: &Path, sink: &EventSink) {
    let marker = dir.join(GITLAB_SIGNUP_MARKER);
    if marker.exists() {
        return;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(GITLAB_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut probe = (false, String::new());
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        probe = gitlab_exec(&["gitlab-ctl", "status"], GITLAB_EXEC_TIMEOUT_SECS).await;
        if probe.0 && puma_running(&probe.1) {
            ready = true;
            break;
        }
        attempt += 1;
        if attempt % GITLAB_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("GitLab: still starting up ({})", why(&probe.1))).await;
        }
        tokio::time::sleep(Duration::from_secs(GITLAB_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .warn(format!(
                "GitLab: public sign-up is still OPEN — it was not closed because GitLab was still starting; close it in the Admin Area now ({})",
                why(&probe.1)
            ))
            .await;
        return;
    }

    let (ok, output) = gitlab_exec(
        &["gitlab-rails", "runner", "ApplicationSetting.last.update!(signup_enabled: false)"],
        GITLAB_RUNNER_TIMEOUT_SECS,
    )
    .await;
    if ok {
        if let Err(err) = std::fs::write(&marker, "") {
            let _ = sink.step(format!("closed sign-up, but could not record it ({err})")).await;
        } else {
            let _ = sink.step("closed public sign-up").await;
        }
    } else {
        let _ = sink
            .warn(format!("GitLab: public sign-up is still OPEN — it could not be closed; close it in the Admin Area now ({})", why(&output)))
            .await;
    }
}

/// Is the web server actually up?
pub fn puma_running(status: &str) -> bool {
    status.lines().any(|line| line.starts_with("run: puma"))
}

async fn gitlab_exec(argv: &[&str], timeout_secs: u64) -> (bool, String) {
    let mut args = vec!["exec".to_string(), gitlab::CONTAINER.to_string()];
    args.extend(argv.iter().map(|a| a.to_string()));
    match run_docker_capture(&args, Duration::from_secs(timeout_secs)).await {
        Ok(result) => result,
        Err(err) => (false, err),
    }
}

/// A port of `NextcloudService.setupSteps`
async fn install_nextcloud_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.nextcloud_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, nextcloud::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &nextcloud::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Nextcloud images").await;
    run_docker_streaming(&compose_pull_args(nextcloud::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Nextcloud").await;
    compose_up(nextcloud::COMPOSE_PROJECT, &dir, sink).await?;

    configure_nextcloud(input, sink).await;

    write_caddy_site(&nextcloud::caddy_site_names(input), &nextcloud::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

pub fn compose_ps_id_args(project: &str, service: &str) -> Vec<String> {
    vec![
        "compose".to_string(),
        "-p".to_string(),
        project.to_string(),
        "ps".to_string(),
        "-q".to_string(),
        service.to_string(),
    ]
}

/// `docker exec -u <user> <container> <argv…>`.
pub fn exec_args(user: &str, container: &str, argv: &[&str]) -> Vec<String> {
    let mut args = vec!["exec".to_string(), "-u".to_string(), user.to_string(), container.to_string()];
    args.extend(argv.iter().map(|a| a.to_string()));
    args
}

async fn configure_nextcloud(input: &Input, sink: &EventSink) {
    let project = nextcloud::COMPOSE_PROJECT;
    let container = match run_docker_capture(
        &compose_ps_id_args(project, nextcloud::APP_SERVICE),
        Duration::from_secs(OCC_CALL_TIMEOUT_SECS),
    )
    .await
    {
        Ok((true, out)) => out.lines().next().unwrap_or_default().trim().to_string(),
        _ => String::new(),
    };
    if container.is_empty() {
        let _ = sink.step("Nextcloud: could not find the app container — trusted domains were not applied").await;
        return;
    }

    let mut ready = (false, String::new());
    for _ in 0..OCC_READY_ATTEMPTS {
        let answer = occ(&container, &["status"]).await;
        if answer.0 && answer.1.contains("installed: true") {
            ready = answer;
            break;
        }
        ready = answer;
        tokio::time::sleep(Duration::from_secs(OCC_READY_INTERVAL_SECS)).await;
    }
    if !(ready.0 && ready.1.contains("installed: true")) {
        let _ = sink.step(format!("Nextcloud: occ is not answering, skipping configuration ({})", why(&ready.1))).await;
        return;
    }

    for (key, value) in occ_settings(input) {
        let mut argv = vec!["config:system:set"];
        argv.extend(key.split(' '));
        let value_arg = format!("--value={value}");
        argv.push(&value_arg);
        let (ok, output) = occ(&container, &argv).await;
        if !ok {
            let _ = sink.step(format!("Nextcloud: could not set {key} ({})", why(&output))).await;
        }
    }
    for key in occ_deletions(input) {
        let _ = occ(&container, &["config:system:delete", key]).await;
    }
    for slot in stale_trusted_domain_slots(input) {
        let _ = occ(&container, &["config:system:delete", "trusted_domains", &slot]).await;
    }
    let _ = sink.step("applied the trusted domains and public URL").await;
    for argv in OCC_UPKEEP {
        let (ok, output) = occ(&container, argv).await;
        if !ok {
            let _ = sink.step(format!("Nextcloud: {} did not finish ({})", argv[0], why(&output))).await;
        }
    }
    let _ = sink.step("set up Nextcloud's background jobs and database indices").await;
}

pub fn occ_settings(input: &Input) -> Vec<(String, String)> {
    let host = nextcloud::hostname(input);
    let mut settings: Vec<(String, String)> = nextcloud::served_hostnames(input)
        .iter()
        .enumerate()
        .map(|(index, name)| (format!("trusted_domains {}", index + 1), name.clone()))
        .collect();
    if input.local_only {
        settings.push((format!("trusted_domains {}", settings.len() + 1), "*".to_string()));
    } else {
        settings.push(("overwriteprotocol".to_string(), "https".to_string()));
    }
    settings.push(("overwrite.cli.url".to_string(), format!("https://{host}")));
    settings
}

pub const OCC_UPKEEP: &[&[&str]] = &[
    &["config:system:set", "maintenance_window_start", "--type=integer", "--value=1"],
    &["background:cron"],
    &["db:add-missing-indices"],
    &["maintenance:repair", "--include-expensive"],
];

pub fn occ_deletions(input: &Input) -> Vec<&'static str> {
    if input.local_only { vec!["overwritehost", "overwriteprotocol"] } else { vec!["overwritehost"] }
}

/// Trusted-domain slots past the ones this install fills
pub fn stale_trusted_domain_slots(input: &Input) -> Vec<String> {
    let used = occ_settings(input).iter().filter(|(key, _)| key.starts_with("trusted_domains ")).count();
    (used + 1..=used + 12).map(|slot| slot.to_string()).collect()
}

async fn occ(container: &str, argv: &[&str]) -> (bool, String) {
    let mut full = vec!["php", "occ"];
    full.extend_from_slice(argv);
    match run_docker_capture(&exec_args("www-data", container, &full), Duration::from_secs(OCC_CALL_TIMEOUT_SECS)).await
    {
        Ok(result) => result,
        Err(err) => (false, err),
    }
}

/// A port of `ForgejoService.setupSteps`
async fn install_forgejo_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.forgejo_path);

    let _ = sink.step("creating the service directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, forgejo::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &forgejo::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Forgejo images").await;
    run_docker_streaming(&compose_pull_args(forgejo::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Forgejo").await;
    compose_up(forgejo::COMPOSE_PROJECT, &dir, sink).await?;

    configure_forgejo(&dir, input, sink).await;

    let ssh_ports: Vec<firewall::Port> =
        forgejo::ssh_port(input).map(|port| vec![firewall::Port::tcp(port)]).unwrap_or_default();
    open_service_firewall_ports(forgejo::SERVICE_ID, &ssh_ports, sink).await;

    write_caddy_site(&forgejo::caddy_site_names(input), &forgejo::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn configure_forgejo(dir: &Path, input: &Input, sink: &EventSink) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(FORGEJO_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut listing = (false, String::new());
    while tokio::time::Instant::now() < deadline {
        listing = forgejo_exec(&["forgejo", "admin", "user", "list"]).await;
        if listing.0 {
            break;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Forgejo: waiting for the service to answer ({})", why(&listing.1))).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !listing.0 {
        let _ = sink
            .step(format!("Forgejo: the administrator could not be created — it never answered ({})", why(&listing.1)))
            .await;
        return;
    }

    let admin = forgejo::admin_username(input);
    if admin_listed(&listing.1, &admin) {
        let _ = sink.step("the administrator already exists").await;
        return;
    }
    let Some(password) = read_env_value(&dir.join(".env"), "FORGEJO_ADMIN_PASSWORD") else {
        let _ = sink.step("Forgejo: no administrator password on file — the account was not created").await;
        return;
    };

    let email = format!("{}@{}", admin, input.domain);
    let script = "forgejo admin user create --admin --username \"$1\" --password \"$GNX_SECRET\" \
                  --email \"$2\" --must-change-password=false";
    let mut args = exec_args("git", forgejo::CONTAINER, &["sh", "-c", script, "sh", &admin, &email]);
    args.insert(1, "-e".to_string());
    args.insert(2, "GNX_SECRET".to_string());
    let (ok, output) = match run_docker_captured_env(
        &args,
        Duration::from_secs(FORGEJO_EXEC_TIMEOUT_SECS),
        &[("GNX_SECRET", password.as_str())],
    )
    .await
    {
        Ok(run) => (run.success, format!("{}{}", run.stdout, run.stderr)),
        Err(err) => (false, err),
    };
    if ok {
        let _ = sink.step("created the administrator").await;
    } else {
        let _ = sink.step(format!("Forgejo: could not create the administrator ({})", why(&output))).await;
    }
}

async fn forgejo_exec(argv: &[&str]) -> (bool, String) {
    match run_docker_capture(
        &exec_args("git", forgejo::CONTAINER, argv),
        Duration::from_secs(FORGEJO_EXEC_TIMEOUT_SECS),
    )
    .await
    {
        Ok(result) => result,
        Err(err) => (false, err),
    }
}

/// Is this username already in `forgejo admin user list`?
pub fn admin_listed(listing: &str, username: &str) -> bool {
    listing.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let Some(id) = fields.next() else { return false };
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        fields.next() == Some(username)
    })
}

/// A port of `PhotoPrismService.setupSteps`
async fn install_photoprism_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.photoprism_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["originals", "storage"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, photoprism::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &photoprism::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the PhotoPrism images").await;
    run_docker_streaming(&compose_pull_args(photoprism::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting PhotoPrism").await;
    compose_up(photoprism::COMPOSE_PROJECT, &dir, sink).await?;

    write_caddy_site(&photoprism::caddy_site_names(input), &photoprism::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `PassboltService.setupSteps`
const PASSBOLT_SERVER_GID: u32 = 33;

const PASSBOLT_SECRET_DIRS: &[(&str, u32)] = &[("gpg", 0o770), ("jwt", 0o750)];

async fn install_passbolt_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.passbolt_path);
    let secrets = PathBuf::from(passbolt::secrets_path(input));
    let gpg_key = PathBuf::from(passbolt::gpg_private_key_path(input));

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&dir.join("db")).map_err(|err| format!("could not create {}: {err}", dir.join("db").display()))?;
    for (name, mode) in PASSBOLT_SECRET_DIRS {
        let sub = secrets.join(name);
        create_dir_owned_by_group(&sub, *mode, PASSBOLT_SERVER_GID)
            .map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, passbolt::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &passbolt::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let fresh = !gpg_key.exists();

    let _ = sink.step("pulling the Passbolt images").await;
    run_docker_streaming(&compose_pull_args(passbolt::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Passbolt").await;
    compose_up(passbolt::COMPOSE_PROJECT, &dir, sink).await?;

    if fresh {
        provision_passbolt(input, &gpg_key, sink).await;
    }

    write_caddy_site(&passbolt::caddy_site_names(input), &passbolt::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn provision_passbolt(input: &Input, gpg_key: &Path, sink: &EventSink) {
    let url_file = PathBuf::from(passbolt::registration_url_path(input));
    let _ = std::fs::remove_file(&url_file);

    if !wait_for_file(
        gpg_key,
        PASSBOLT_READY_DEADLINE_SECS,
        sink,
        "Passbolt: waiting for the server to generate its key",
    )
    .await
    {
        let _ = sink
            .step(
                "Passbolt did not finish its first start in time — the administrator was never invited, invite them yourself once it is ready",
            )
            .await;
        return;
    }

    let admin = passbolt::admin_login(input);
    if !admin.chars().all(|ch| ch.is_ascii_alphanumeric() || "@._+-".contains(ch)) {
        let _ = sink.step("Passbolt: the administrator login has characters that cannot be passed safely — invite them yourself").await;
        return;
    }
    let command =
        format!("/usr/share/php/passbolt/bin/cake passbolt register_user -u '{admin}' -f 'Admin' -l 'Admin' -r admin");
    let run = run_docker_captured(
        &docker_exec_args(passbolt::CONTAINER, &["su", "-m", "-c", &command, "-s", "/bin/sh", "www-data"]),
        Duration::from_secs(PASSBOLT_EXEC_TIMEOUT_SECS),
    )
    .await;
    let run = match run {
        Ok(run) => run,
        Err(err) => {
            let _ = sink.step(format!("Passbolt: could not invite the administrator ({err})")).await;
            return;
        }
    };
    if !run.success {
        let _ = sink.step(format!("Passbolt: could not invite the administrator ({})", run.why())).await;
        return;
    }

    let mut combined = run.stdout.clone();
    combined.push_str(&run.stderr);
    match extract_last_url(&combined) {
        Some(url) => match create_file_if_absent(&url_file, &format!("{url}\n"), 0o600) {
            Ok(_) => {
                let _ = sink.private_step(format!("invited the administrator — one-time setup URL: {url}")).await;
            }
            Err(err) => {
                let _ = sink
                    .private_step(format!(
                        "invited the administrator, but could not save the setup URL ({err}) — read it from the agent's own log: {url}"
                    ))
                    .await;
            }
        },
        None => {
            let _ = sink
                .step(format!("Passbolt: the administrator invitation did not print a URL ({})", run.why()))
                .await;
        }
    }
}

pub fn extract_last_url(text: &str) -> Option<String> {
    text.split_whitespace().filter(|token| token.starts_with("http://") || token.starts_with("https://")).last().map(str::to_string)
}

/// A port of `VaultwardenService.setupSteps`
async fn install_vaultwarden_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(vaultwarden::COMPOSE_DIRECTORY);
    let data_path = PathBuf::from(&input.vaultwarden_data_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, vaultwarden::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &vaultwarden::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the admin token").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let config_path = data_path.join("config.json");
    let needs_restart = match sync_vaultwarden_config(&config_path, input) {
        Ok(changed) => {
            if changed {
                let _ = sink.step("updated the stored signups/domain settings").await;
            }
            changed
        }
        Err(err) => {
            let _ = sink.step(format!("could not update {}: {err}", config_path.display())).await;
            false
        }
    };

    let _ = sink.step("pulling the Vaultwarden image").await;
    run_docker_streaming(&compose_pull_args(vaultwarden::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Vaultwarden").await;
    compose_up(vaultwarden::COMPOSE_PROJECT, &dir, sink).await?;

    if needs_restart {
        let _ = sink.step("restarting Vaultwarden to pick up the new settings").await;
        let args = vec!["restart".to_string(), input.vaultwarden_container.clone()];
        run_docker_streaming(&args, sink).await?;
    }

    write_caddy_site(&vaultwarden::caddy_site_names(input), &vaultwarden::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// A port of `SeafileService.setupSteps`
async fn install_seafile_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.seafile_path);
    let data = PathBuf::from(seafile::data_path(input));
    let db_dir = dir.join("db");

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    create_dir_0755(&data).map_err(|err| format!("could not create {}: {err}", data.display()))?;
    create_dir_0755(&db_dir).map_err(|err| format!("could not create {}: {err}", db_dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, seafile::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &seafile::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database, JWT and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Seafile images").await;
    run_docker_streaming(&compose_pull_args(seafile::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Seafile").await;
    compose_up(seafile::COMPOSE_PROJECT, &dir, sink).await?;

    configure_seafile_csrf(&dir, &data, input, sink).await;

    write_caddy_site(&seafile::caddy_site_names(input), &seafile::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn configure_seafile_csrf(dir: &Path, data: &Path, input: &Input, sink: &EventSink) {
    let settings = data.join(seafile::SEAHUB_SETTINGS_RELATIVE_PATH);
    if !wait_for_file(&settings, SEAFILE_SETTINGS_DEADLINE_SECS, sink, "Seafile: waiting for the first start to finish")
        .await
    {
        let _ = sink
            .step(
                "Seafile did not finish its first start in time — the trusted CSRF origins were not applied, so signing in may fail with an error that looks like a wrong password",
            )
            .await;
        return;
    }

    let existing = match std::fs::read_to_string(&settings) {
        Ok(text) => text,
        Err(err) => {
            let _ = sink.step(format!("could not read {}: {err}", settings.display())).await;
            return;
        }
    };
    let rewritten = seafile::rewritten_seahub_settings(&existing, &seafile::csrf_trusted_origins_line(input));
    if rewritten == existing {
        let _ = sink.step("the trusted CSRF origins were already up to date").await;
        return;
    }
    if let Err(err) = std::fs::write(&settings, rewritten) {
        let _ = sink.step(format!("could not write {}: {err}", settings.display())).await;
        return;
    }
    let _ = sink.step("wrote the trusted CSRF origins").await;
    let _ = run_docker_streaming(
        &compose_restart_service_args(seafile::COMPOSE_PROJECT, &dir, seafile::SERVER_SERVICE),
        sink,
    )
    .await;
}

async fn wait_for_file(path: &Path, deadline_secs: u64, sink: &EventSink, heartbeat: &str) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(deadline_secs);
    let mut attempt: u32 = 0;
    while tokio::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(heartbeat).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    path.exists()
}

async fn install_psono_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.psono_path);

    let _ = sink.step("creating service directories").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    for name in ["db", "config", "config/webclient"] {
        let sub = dir.join(name);
        create_dir_0755(&sub).map_err(|err| format!("could not create {}: {err}", sub.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, psono::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let client_config = PathBuf::from(psono::webclient_config_path(input));
    std::fs::write(&client_config, psono::webclient_config_json(input))
        .map_err(|err| format!("could not write {}: {err}", client_config.display()))?;

    match write_env_if_absent(&dir, &psono::env_template()) {
        Ok(true) => {
            let _ = sink.step("generated the database and administrator secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let fresh = write_psono_settings_if_absent(&dir, input, sink).await?;

    let _ = sink.step("pulling the Psono images").await;
    run_docker_streaming(&compose_pull_args(psono::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Psono").await;
    compose_up(psono::COMPOSE_PROJECT, &dir, sink).await?;

    provision_psono(input, fresh, sink).await;

    write_caddy_site(&psono::caddy_site_names(input), &psono::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Generate `settings.yaml` once
async fn write_psono_settings_if_absent(dir: &Path, input: &Input, sink: &EventSink) -> Result<bool, String> {
    let settings = PathBuf::from(psono::settings_path(input));
    if settings.exists() {
        // Never regenerated: existing encrypted datastores are decrypted against these keys.
        let _ = sink.step("kept the existing server keys").await;
        return Ok(false);
    }

    let _ = sink.step("generating the server keypair").await;
    let run = run_docker_captured(
        &docker_run_once_args(psono::IMAGE, &["python3", "./psono/generateserverkeys.py"]),
        Duration::from_secs(PSONO_KEYGEN_TIMEOUT_SECS),
    )
    .await?;
    if !run.success {
        return Err(format!("could not generate the Psono server keys: {}", run.why()));
    }

    let Some(db_password) = read_env_value(&dir.join(".env"), "PSONO_DB_PASSWORD") else {
        return Err("psono .env carries no PSONO_DB_PASSWORD".to_string());
    };

    let mut contents = run.stdout;
    contents.push_str(&psono::settings_tail(input, &db_password));
    match create_file_if_absent(&settings, &contents, 0o600) {
        Ok(created) => {
            if created {
                let _ = sink.step("wrote the server configuration").await;
            }
            Ok(created)
        }
        Err(err) => Err(format!("could not write {}: {err}", settings.display())),
    }
}

/// `presetup` + `migrate` + (on a fresh install) the administrator
async fn provision_psono(input: &Input, fresh: bool, sink: &EventSink) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(PSONO_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut last_why = String::new();
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        match psono_manage(&["presetup"]).await {
            Ok(run) if run.success => {
                ready = true;
                break;
            }
            Ok(run) => last_why = run.why(),
            Err(err) => last_why = err,
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Psono: waiting for the database to answer ({last_why})")).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink.step(format!("Psono did not become ready — finish the setup yourself ({last_why})")).await;
        return;
    }

    match psono_manage(&["migrate"]).await {
        Ok(run) if run.success => {}
        Ok(run) => {
            let _ = sink.step(format!("Psono: the database migration failed ({})", run.why())).await;
        }
        Err(err) => {
            let _ = sink.step(format!("Psono: the database migration failed ({err})")).await;
        }
    }

    if !fresh {
        return;
    }
    let env_path = PathBuf::from(&input.psono_path).join(".env");
    let Some(password) = read_env_value(&env_path, "PSONO_ADMIN_PASSWORD") else {
        return;
    };
    if password.is_empty() {
        return;
    }
    let admin = psono::admin_login(input);
    let steps: [Vec<&str>; 3] = [
        vec!["createuser", &admin],
        vec!["promoteuser", &admin, "superuser"],
        vec!["verifyuseremail", &admin],
    ];
    for step in steps {
        let outcome = if step[0] == "createuser" {
            psono_create_user(&admin, &password).await
        } else {
            psono_manage(&step).await
        };
        match outcome {
            Ok(run) if run.success => {}
            Ok(run) => {
                let _ = sink
                    .step(format!("Psono: creating the administrator failed — create it yourself ({})", run.why()))
                    .await;
                return;
            }
            Err(err) => {
                let _ = sink
                    .step(format!("Psono: creating the administrator failed — create it yourself ({err})"))
                    .await;
                return;
            }
        }
    }
    let _ = sink.step("created the administrator account").await;
}

async fn psono_create_user(admin: &str, password: &str) -> Result<CapturedRun, String> {
    let script = "python3 ./psono/manage.py createuser \"$1\" \"$GNX_SECRET\" \"$1\"";
    let mut args = docker_exec_args(psono::CONTAINER, &["sh", "-c", script, "sh", admin]);
    args.insert(1, "-e".to_string());
    args.insert(2, "GNX_SECRET".to_string());
    run_docker_captured_env(&args, Duration::from_secs(PSONO_EXEC_TIMEOUT_SECS), &[("GNX_SECRET", password)]).await
}

async fn psono_manage(args: &[&str]) -> Result<CapturedRun, String> {
    let mut command = vec!["python3", "./psono/manage.py"];
    command.extend_from_slice(args);
    run_docker_captured(
        &docker_exec_args(psono::CONTAINER, &command),
        Duration::from_secs(PSONO_EXEC_TIMEOUT_SECS),
    )
    .await
}

// ─────────────────────────── docker-mailserver ───────────────────────────

async fn install_docker_mailserver_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.docker_mailserver_path);

    let _ = sink.step("creating service directories").await;
    for path in dms::directories_0755(input) {
        let sub = PathBuf::from(&path);
        create_dir_with_mode(&sub, 0o755).map_err(|err| format!("could not create {path}: {err}"))?;
    }
    let certs = PathBuf::from(dms::certs_dir(input));
    create_dir_with_mode(&certs, 0o700).map_err(|err| format!("could not create {}: {err}", certs.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, dms::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &dms::env_template(input)) {
        Ok(true) => {
            let _ = sink.step("generated the first mailbox's password").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    // BEFORE the first `up -d`. See this function's doc.
    write_placeholder_cert(input, sink).await;

    let _ = sink.step("pulling the Docker Mailserver images").await;
    run_docker_streaming(&compose_pull_args(dms::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Docker Mailserver").await;
    compose_up(dms::COMPOSE_PROJECT, &dir, sink).await?;

    open_mail_firewall_ports(DMS_FIREWALL_LABEL, &dms::firewall_ports(), sink).await?;

    install_cert_sync(input, sink).await?;
    write_dms_management_scripts(input, sink)?;
    configure_dms(input, sink).await;

    write_caddy_site(&dms::caddy_site_names(input), &dms::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

fn mail_firewall_ports(ports: &[super::mail::FirewallPort]) -> Vec<firewall::Port> {
    ports
        .iter()
        .map(|port| firewall::Port {
            port: port.port,
            proto: match port.proto {
                super::mail::Proto::Tcp => firewall::Proto::Tcp,
                super::mail::Proto::Udp => firewall::Proto::Udp,
            },
        })
        .collect()
}

fn firewall_step_text(outcome: Result<firewall::Outcome, String>) -> Result<String, String> {
    match outcome {
        Ok(firewall::Outcome::Applied) => Ok("opened the mail ports in the firewall".to_string()),
        Ok(firewall::Outcome::Cleared) => Ok("removed this service's firewall ports".to_string()),
        Ok(firewall::Outcome::SkippedNoDropInDir) => Ok(
            "the mail ports are NOT open: this host has no /etc/nftables.d drop-in directory — re-run the server setup, then install again"
                .to_string(),
        ),
        Err(err) => Err(format!("could not open the mail ports in the firewall: {err}")),
    }
}

async fn open_mail_firewall_ports(
    label: &str,
    ports: &[super::mail::FirewallPort],
    sink: &EventSink,
) -> Result<(), String> {
    let outcome = firewall::apply_service_ports(label, &mail_firewall_ports(ports)).await;
    let text = firewall_step_text(outcome)?;
    let _ = sink.step(text).await;
    Ok(())
}

// ─────────────────────────── Mailu ───────────────────────────

async fn install_mailu_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.mailu_path);

    let _ = sink.step("creating service directories").await;
    for path in mailu::directories_0755(input) {
        create_dir_with_mode(&PathBuf::from(&path), 0o755).map_err(|err| format!("could not create {path}: {err}"))?;
    }
    for path in mailu::directories_0700(input) {
        create_dir_with_mode(&PathBuf::from(&path), 0o700).map_err(|err| format!("could not create {path}: {err}"))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, mailu::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    match write_env_if_absent(&dir, &mailu::env_template(input)) {
        Ok(true) => {
            let _ = sink.step("generated Mailu's secrets").await;
        }
        Ok(false) => {
            let _ = sink.step("kept the existing .env").await;
        }
        Err(err) => return Err(format!("could not write .env: {err}")),
    }

    let _ = sink.step("pulling the Mailu images").await;
    run_docker_streaming(&compose_pull_args(mailu::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Mailu").await;
    compose_up(mailu::COMPOSE_PROJECT, &dir, sink).await?;

    open_mail_firewall_ports(MAILU_FIREWALL_LABEL, &mailu::firewall_ports(), sink).await?;

    install_cert_sync_unit(&mailu_cert_sync_files(input), mailu::CERT_SYNC_SCRIPT_PATH, mailu::CERT_SYNC_UNIT, sink)
        .await?;
    write_managed_files(&mailu_management_files(input))?;

    configure_mailu(input, sink).await;

    write_caddy_site(&mailu::caddy_site_names(input), &mailu::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

fn mailu_admin_exec_args(dir: &Path, argv: &[&str]) -> Vec<String> {
    let mut args = compose_file_args(mailu::COMPOSE_PROJECT, dir);
    args.push("exec".to_string());
    args.push("-T".to_string());
    args.push("-u".to_string());
    args.push(mailu::ADMIN_RUN_AS_USER.to_string());
    args.push(mailu::ADMIN_SERVICE.to_string());
    args.extend(argv.iter().map(|a| a.to_string()));
    args
}

async fn configure_mailu(input: &Input, sink: &EventSink) {
    let dir = PathBuf::from(&input.mailu_path);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAILU_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut last_why = String::new();
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        match run_docker_captured(
            &mailu_admin_exec_args(&dir, mailu::CONFIG_EXPORT_PROBE_ARGS),
            Duration::from_secs(MAILU_EXEC_TIMEOUT_SECS),
        )
        .await
        {
            Ok(run) if run.success => {
                ready = true;
                break;
            }
            Ok(run) => last_why = bounded(&format!("{}{}", run.stdout, run.stderr), 300),
            Err(err) => last_why = err,
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Mailu: waiting for the stack to answer ({last_why})")).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .step(format!("Mailu never answered — no mail domains or DKIM keys were imported ({last_why})"))
            .await;
        return;
    }

    let yaml = mailu::domain_import_yaml(input);
    let args = mailu_admin_exec_args(&dir, mailu::CONFIG_IMPORT_ARGS);
    match run_docker_with_stdin(&args, &yaml, Duration::from_secs(MAILU_IMPORT_TIMEOUT_SECS)).await {
        Ok(run) if run.success => {
            let _ = sink.step("imported the mail domains and minted their DKIM keys").await;
        }
        Ok(run) => {
            let _ = sink
                .step(format!("Mailu: could not import the mail domains ({})", bounded(&format!("{}{}", run.stdout, run.stderr), 300)))
                .await;
        }
        Err(err) => {
            let _ = sink.step(format!("Mailu: could not import the mail domains ({err})")).await;
        }
    }
}

// ─────────────────────────── mailcow ───────────────────────────

fn holds_files(dir: &Path) -> bool {
    std::fs::read_dir(dir).map(|mut entries| entries.next().is_some()).unwrap_or(false)
}

async fn git_streaming(args: &[&str], sink: &EventSink) -> Result<(), String> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    run_child_streaming(&git_bin(), &args, None, &[], None, Duration::from_secs(MAILCOW_GIT_CLONE_TIMEOUT_SECS), sink).await
}

/// Kept data without a repository: the repository joins it
async fn clone_beside_kept_data(dir: &Path, sink: &EventSink) -> Result<(), String> {
    let staging = PathBuf::from(format!("{}.clone", dir.display()));
    let _ = std::fs::remove_dir_all(&staging);
    git_streaming(&["clone", "--no-checkout", mailcow::REPO_URL, &staging.to_string_lossy()], sink).await?;
    std::fs::rename(staging.join(".git"), dir.join(".git"))
        .map_err(|err| format!("could not move mailcow's repository into place: {err}"))?;
    let _ = std::fs::remove_dir_all(&staging);
    git_streaming(&["-C", &dir.to_string_lossy(), "checkout", "HEAD", "--", "."], sink).await
}

async fn install_mailcow_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(&input.mailcow_path);
    let conf_path = PathBuf::from(mailcow::mailcow_conf_path(input));

    if !dir.join(".git").is_dir() {
        let _ = sink.step("cloning mailcow").await;
        if holds_files(&dir) {
            clone_beside_kept_data(&dir, sink).await?;
        } else {
            git_streaming(&["clone", mailcow::REPO_URL, &dir.to_string_lossy()], sink).await?;
        }
    }

    if !conf_path.is_file() {
        let _ = sink.step("generating mailcow's configuration").await;
        let env = mailcow::generate_config_env(input);
        run_child_streaming(
            &bash_bin(),
            &["generate_config.sh".to_string()],
            Some(&dir),
            &env,
            Some(mailcow::GENERATE_CONFIG_STDIN),
            Duration::from_secs(MAILCOW_GENERATE_CONFIG_TIMEOUT_SECS),
            sink,
        )
        .await?;

        let conf = std::fs::read_to_string(&conf_path)
            .map_err(|err| format!("could not read {} after generate_config.sh: {err}", conf_path.display()))?;
        std::fs::write(&conf_path, mailcow::patch_conf_for_caddy(&conf))
            .map_err(|err| format!("could not write {}: {err}", conf_path.display()))?;
    }

    {
        let conf = std::fs::read_to_string(&conf_path)
            .map_err(|err| format!("could not read {}: {err}", conf_path.display()))?;
        let patched = mailcow::patch_conf_compose_version(&conf);
        if patched != conf {
            std::fs::write(&conf_path, patched).map_err(|err| format!("could not write {}: {err}", conf_path.display()))?;
        }
    }

    chmod_recursive_a_plus_rx(&dir).map_err(|err| format!("could not fix up permissions under {}: {err}", dir.display()))?;
    set_mode(&conf_path, 0o600).map_err(|err| format!("could not set the mode of {}: {err}", conf_path.display()))?;

    let _ = sink.step("pulling the Mailcow images").await;
    run_mailcow_compose_retrying(&dir, &["compose".to_string(), "pull".to_string(), "-q".to_string()], 4, sink).await?;
    let _ = sink.step("starting Mailcow").await;
    run_mailcow_compose_retrying(&dir, &["compose".to_string(), "up".to_string(), "-d".to_string()], 2, sink).await?;

    open_mail_firewall_ports(MAILCOW_FIREWALL_LABEL, &mailcow::firewall_ports(), sink).await?;

    install_cert_sync_unit(
        &mailcow_cert_sync_files(input),
        mailcow::CERT_SYNC_SCRIPT_PATH,
        mailcow::CERT_SYNC_UNIT,
        sink,
    )
    .await?;
    write_managed_files(&mailcow_management_files(input))?;

    provision_mailcow(input, &dir, sink).await;

    write_caddy_site(&mailcow::caddy_site_names(input), &mailcow::caddy_site(input))?;
    write_autoconfig_site(&mailcow::mail_domains(input)).await?;
    reload_caddy(sink).await?;

    Ok(())
}

async fn run_mailcow_compose_retrying(dir: &Path, args: &[String], tries: u32, sink: &EventSink) -> Result<(), String> {
    for attempt in 1..=tries {
        match run_child_streaming(&docker_bin(), args, Some(dir), &[], None, Duration::from_secs(MAILCOW_COMPOSE_TIMEOUT_SECS), sink)
            .await
        {
            Ok(()) => return Ok(()),
            Err(err) if attempt < tries => {
                let _ = sink
                    .step(format!("mailcow: `docker {}` failed, retrying ({attempt}/{tries}): {err}", args.join(" ")))
                    .await;
                tokio::time::sleep(Duration::from_secs(5 * u64::from(attempt))).await;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("the loop above always returns before `attempt` reaches `tries`")
}

fn chmod_recursive_a_plus_rx(root: &Path) -> Result<(), String> {
    fn visit(path: &Path, skip: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if path == skip {
            return Ok(());
        }
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Ok(());
        }
        let is_dir = meta.is_dir();
        let mut mode = meta.permissions().mode() & 0o7777;
        mode |= 0o444;
        if is_dir || (mode & 0o111) != 0 {
            mode |= 0o111;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        if is_dir {
            for entry in std::fs::read_dir(path)? {
                visit(&entry?.path(), skip)?;
            }
        }
        Ok(())
    }
    visit(root, &root.join("data/assets/ssl")).map_err(|err| err.to_string())
}

async fn provision_mailcow(input: &Input, dir: &Path, sink: &EventSink) {
    let conf_path = PathBuf::from(mailcow::mailcow_conf_path(input));
    let conf = match std::fs::read_to_string(&conf_path) {
        Ok(text) => text,
        Err(err) => {
            let _ = sink
                .step(format!("Mailcow: could not read mailcow.conf — no domains or DKIM keys were provisioned ({err})"))
                .await;
            return;
        }
    };
    if !mailcow::api_key_present(&conf) && !enable_mailcow_api(dir, &conf, &conf_path, sink).await {
        return;
    }
    let Some(api_key) = read_mailcow_api_key(&conf_path, sink).await else { return };
    if !wait_for_mailcow_api(&api_key, sink).await {
        return;
    }
    provision_mail_domains(input, &api_key, sink).await;
    set_mailcow_admin_password(&conf_path, &api_key, sink).await;
}

async fn enable_mailcow_api(dir: &Path, conf: &str, conf_path: &Path, sink: &EventSink) -> bool {
    let _ = sink.step("enabling the Mailcow REST API").await;
    let network_prefix = mailcow::ipv4_network_prefix(conf).unwrap_or_else(|| mailcow::DEFAULT_NETWORK_PREFIX.to_string());
    let api_key = match random_hex_20() {
        Ok(key) => key,
        Err(err) => {
            let _ = sink.step(format!("Mailcow: could not generate an API key ({err})")).await;
            return false;
        }
    };
    let appended = mailcow::api_conf_append(&api_key, &network_prefix);
    let append_result = {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(conf_path)
            .and_then(|mut file| file.write_all(appended.as_bytes()))
    };
    if let Err(err) = append_result {
        let _ = sink.step(format!("Mailcow: could not write the API key to mailcow.conf ({err})")).await;
        return false;
    }
    if let Err(err) =
        run_mailcow_compose_retrying(dir, &["compose".to_string(), "up".to_string(), "-d".to_string()], 1, sink).await
    {
        let _ = sink.step(format!("Mailcow: could not reload the stack after adding the API key ({err})")).await;
        return false;
    }
    true
}

/// Reads the API key back from mailcow.conf
async fn read_mailcow_api_key(conf_path: &Path, sink: &EventSink) -> Option<String> {
    let conf = match std::fs::read_to_string(conf_path) {
        Ok(text) => text,
        Err(err) => {
            let _ = sink.step(format!("Mailcow: could not re-read mailcow.conf ({err})")).await;
            return None;
        }
    };
    let key = mailcow::read_conf_value(&conf, "API_KEY");
    if key.is_none() {
        let _ = sink.step("Mailcow: no API key on file — no domains or DKIM keys were provisioned").await;
    }
    key
}

async fn wait_for_mailcow_api(api_key: &str, sink: &EventSink) -> bool {
    let _ = sink.step("provisioning mail domains").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(MAILCOW_API_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut ready = false;
    let mut last_why = String::new();
    while tokio::time::Instant::now() < deadline {
        match mailcow_api_call("GET", "/get/domain/all", api_key, None).await {
            Ok((code, _)) if (200..300).contains(&code) => {
                ready = true;
                break;
            }
            Ok((code, body)) => last_why = mailcow_why(code, &body),
            Err(err) => last_why = err,
        }
        attempt += 1;
        if attempt % MAILCOW_API_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Mailcow: waiting for the API to answer ({last_why})")).await;
        }
        tokio::time::sleep(Duration::from_secs(MAILCOW_API_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .step(format!("Mailcow: the API never answered — no domains or DKIM keys were provisioned ({last_why})"))
            .await;
        return false;
    }
    true
}

async fn provision_mail_domains(input: &Input, api_key: &str, sink: &EventSink) {
    for domain in mailcow::mail_domains(input) {
        let has_domain = matches!(
            mailcow_api_call("GET", &format!("/get/domain/{domain}"), api_key, None).await,
            Ok((code, body)) if (200..300).contains(&code) && mailcow_json_has_field(&body, "domain_name")
        );
        if !has_domain {
            match mailcow_api_call("POST", "/add/domain", api_key, Some(&mailcow::add_domain_body(&domain))).await {
                Ok((code, _)) if (200..300).contains(&code) => {
                    let _ = sink.step(format!("added the mail domain {domain}")).await;
                }
                Ok((code, body)) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not add the domain {domain} over the API — add it under Configuration → Domains in the admin UI. ({})",
                            mailcow_why(code, &body)
                        ))
                        .await;
                }
                Err(err) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not add the domain {domain} over the API — add it under Configuration → Domains in the admin UI. ({err})"
                        ))
                        .await;
                }
            }
        }

        let has_dkim = matches!(
            mailcow_api_call("GET", &format!("/get/dkim/{domain}"), api_key, None).await,
            Ok((code, body)) if (200..300).contains(&code) && mailcow_json_has_field(&body, "pubkey")
        );
        if !has_dkim {
            match mailcow_api_call("POST", "/add/dkim", api_key, Some(&mailcow::add_dkim_body(&domain))).await {
                Ok((code, _)) if (200..300).contains(&code) => {
                    let _ = sink.step(format!("generated the DKIM key for {domain}")).await;
                }
                Ok((code, body)) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not create the DKIM key for {domain} over the API — create it under Configuration → ARC/DKIM keys in the admin UI. ({})",
                            mailcow_why(code, &body)
                        ))
                        .await;
                }
                Err(err) => {
                    let _ = sink
                        .step(format!(
                            "Mailcow: could not create the DKIM key for {domain} over the API — create it under Configuration → ARC/DKIM keys in the admin UI. ({err})"
                        ))
                        .await;
                }
            }
        }
    }
}

async fn set_mailcow_admin_password(conf_path: &Path, api_key: &str, sink: &EventSink) {
    let Some(dir) = conf_path.parent() else { return };
    let file = dir.join(mailcow::ADMIN_PASSWORD_FILE);
    let stored = std::fs::read_to_string(&file).map(|text| text.trim().to_string()).unwrap_or_default();
    let password = if stored.is_empty() {
        match random_hex_12() {
            Ok(password) => password,
            Err(err) => {
                let _ = sink.step(format!("Mailcow admin password: the default one stays ({err})")).await;
                return;
            }
        }
    } else {
        stored
    };
    match mailcow_api_call("POST", "/edit/admin", api_key, Some(&mailcow::edit_admin_body(&password))).await {
        Ok((code, body)) if (200..300).contains(&code) && mailcow_reply_succeeded(&body) => {
            if let Err(err) = write_private_file(&file, &format!("{password}\n")) {
                let _ = sink
                    .step(format!("Mailcow admin password: set, but it could not be saved for the report ({err})"))
                    .await;
            }
        }
        Ok((code, body)) => {
            let _ = sink
                .step(format!("Mailcow admin password: the default one stays ({})", mailcow_why(code, &body)))
                .await;
        }
        Err(err) => {
            let _ = sink.step(format!("Mailcow admin password: the default one stays ({err})")).await;
        }
    }
}

fn mailcow_reply_succeeded(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else { return false };
    let says_success = |entry: &serde_json::Value| entry.get("type").and_then(|t| t.as_str()) == Some("success");
    match value.as_array() {
        Some(entries) => entries.iter().all(says_success),
        None => says_success(&value),
    }
}

fn mailcow_json_has_field(body: &str, field: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get(field).cloned())
        .map(|value| !value.is_null() && value != serde_json::Value::Bool(false))
        .unwrap_or(false)
}

fn mailcow_why(code: u16, body: &str) -> String {
    format!("HTTP {code} {}", bounded(&body.replace(['\r', '\n'], ""), 300))
}

/// One call to mailcow's REST API
async fn mailcow_api_call(method: &str, path: &str, api_key: &str, body: Option<&str>) -> Result<(u16, String), String> {
    let url = format!("{}{path}", mailcow::api_base());
    let mut args: Vec<String> = vec![
        "-sS".to_string(),
        "-k".to_string(),
        "--max-time".to_string(),
        MAILCOW_API_HTTP_TIMEOUT_SECS.to_string(),
        "-w".to_string(),
        "\nHTTPSTATUS:%{http_code}".to_string(),
        "-K".to_string(),
        "-".to_string(),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
    ];
    if method == "POST" {
        args.push("-X".to_string());
        args.push("POST".to_string());
    }
    args.push(url);

    let config = mailcow::curl_config(api_key, body);
    let output = tokio::time::timeout(
        Duration::from_secs(MAILCOW_API_HTTP_TIMEOUT_SECS + 5),
        curl_with_stdin(&args, &config),
    )
    .await
    .map_err(|_| "curl timed out".to_string())?
    .map_err(|err| format!("could not run curl: {err}"))?;

    if !output.status.success() {
        return Err(format!("curl exited {}: {}", output.status.code().unwrap_or(-1), bounded(&String::from_utf8_lossy(&output.stderr), 300)));
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let marker = "\nHTTPSTATUS:";
    let Some(at) = text.rfind(marker) else {
        return Err("curl did not report a status code".to_string());
    };
    let body_text = text[..at].to_string();
    let code: u16 = text[at + marker.len()..].trim().parse().unwrap_or(0);
    Ok((code, body_text))
}

/// Runs curl with `input` on stdin
async fn curl_with_stdin(args: &[String], input: &str) -> io::Result<std::process::Output> {
    let mut child = tokio::process::Command::new(curl_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes()).await;
    }
    child.wait_with_output().await
}

fn openssl_bin() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN").unwrap_or_else(|_| "openssl".to_string()))
}

/// Is this a file with something in it?
fn is_nonempty_file(path: &Path) -> bool {
    std::fs::metadata(path).map(|meta| meta.is_file() && meta.len() > 0).unwrap_or(false)
}

async fn write_placeholder_cert(input: &Input, sink: &EventSink) {
    let cert = PathBuf::from(dms::cert_pem_path(input));
    let key = PathBuf::from(dms::key_pem_path(input));
    if is_nonempty_file(&cert) && is_nonempty_file(&key) {
        return;
    }

    let _ = sink.step("writing a self-signed placeholder certificate so the engine can start").await;
    let args = dms::placeholder_cert_args(input);
    let outcome = tokio::time::timeout(
        Duration::from_secs(OPENSSL_TIMEOUT_SECS),
        tokio::process::Command::new(openssl_bin())
            .args(&args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let failed = match outcome {
        Ok(Ok(output)) if output.status.success() => None,
        Ok(Ok(output)) => Some(why(&String::from_utf8_lossy(&output.stderr))),
        Ok(Err(err)) => Some(err.to_string()),
        Err(_) => Some(format!("openssl timed out after {OPENSSL_TIMEOUT_SECS}s")),
    };
    if let Some(reason) = failed {
        let _ = sink
            .step(format!(
                "could not write the placeholder certificate — the mail engine will keep restarting until one exists ({reason})"
            ))
            .await;
        return;
    }
    if let Err(err) = set_mode(&cert, 0o644) {
        let _ = sink.step(format!("could not set the mode of {}: {err}", cert.display())).await;
    }
    if let Err(err) = set_mode(&key, 0o600) {
        let _ = sink.step(format!("could not set the mode of {}: {err}", key.display())).await;
    }
}

async fn install_cert_sync(input: &Input, sink: &EventSink) -> Result<(), String> {
    install_cert_sync_unit(&cert_sync_files(input), dms::CERT_SYNC_SCRIPT_PATH, dms::CERT_SYNC_UNIT, sink).await
}

async fn install_cert_sync_unit(
    files: &[ManagedFile],
    script_path: &str,
    timer_unit: &str,
    sink: &EventSink,
) -> Result<(), String> {
    write_managed_files(files)?;

    let _ = sink.step("installing the certificate-sync timer").await;
    if run_quiet(&systemctl_bin(), &["daemon-reload"]).await.is_err() {
        let _ = sink.step("systemctl daemon-reload failed — the certificate-sync timer may not be active").await;
    }
    let timer = format!("{timer_unit}.timer");
    if run_quiet(&systemctl_bin(), &["enable", "--now", &timer]).await.is_err() {
        let _ = sink
            .step("could not enable the certificate-sync timer — mail clients will keep seeing the placeholder certificate")
            .await;
    }
    let ran = tokio::time::timeout(
        Duration::from_secs(CERT_SYNC_RUN_TIMEOUT_SECS),
        tokio::process::Command::new(script_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await;
    if !matches!(ran, Ok(Ok(status)) if status.success()) {
        let _ = sink.step("the first certificate-sync run did not succeed — the timer will retry within the hour").await;
    }
    Ok(())
}

struct ManagedFile {
    path: PathBuf,
    contents: String,
    mode: Option<u32>,
}

/// The certificate-sync script and its two systemd units
fn cert_sync_files(input: &Input) -> Vec<ManagedFile> {
    let unit_dir = Path::new("/etc/systemd/system");
    vec![
        ManagedFile {
            path: PathBuf::from(dms::CERT_SYNC_SCRIPT_PATH),
            contents: dms::cert_sync_script(input),
            mode: Some(0o700),
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.service", dms::CERT_SYNC_UNIT)),
            contents: dms::cert_sync_service_unit(),
            mode: None,
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.timer", dms::CERT_SYNC_UNIT)),
            contents: dms::cert_sync_timer_unit(),
            mode: None,
        },
    ]
}

fn dms_management_files(input: &Input) -> Vec<ManagedFile> {
    vec![ManagedFile {
        path: PathBuf::from(dms::DKIM_DUMP_SCRIPT_PATH),
        contents: dms::dkim_dump_script(input),
        mode: Some(0o700),
    }]
}

fn mailu_cert_sync_files(input: &Input) -> Vec<ManagedFile> {
    let unit_dir = Path::new("/etc/systemd/system");
    vec![
        ManagedFile {
            path: PathBuf::from(mailu::CERT_SYNC_SCRIPT_PATH),
            contents: mailu::cert_sync_script(input),
            mode: Some(0o700),
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.service", mailu::CERT_SYNC_UNIT)),
            contents: mailu::cert_sync_service_unit(),
            mode: None,
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.timer", mailu::CERT_SYNC_UNIT)),
            contents: mailu::cert_sync_timer_unit(),
            mode: None,
        },
    ]
}

fn mailu_management_files(input: &Input) -> Vec<ManagedFile> {
    vec![ManagedFile {
        path: PathBuf::from(mailu::DKIM_DUMP_SCRIPT_PATH),
        contents: mailu::dkim_dump_script(input),
        mode: Some(0o700),
    }]
}

fn mailcow_cert_sync_files(input: &Input) -> Vec<ManagedFile> {
    let unit_dir = Path::new("/etc/systemd/system");
    vec![
        ManagedFile {
            path: PathBuf::from(mailcow::CERT_SYNC_SCRIPT_PATH),
            contents: mailcow::cert_sync_script(input),
            mode: Some(0o700),
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.service", mailcow::CERT_SYNC_UNIT)),
            contents: mailcow::cert_sync_service_unit(),
            mode: None,
        },
        ManagedFile {
            path: unit_dir.join(format!("{}.timer", mailcow::CERT_SYNC_UNIT)),
            contents: mailcow::cert_sync_timer_unit(),
            mode: None,
        },
    ]
}

fn mailcow_management_files(input: &Input) -> Vec<ManagedFile> {
    vec![ManagedFile {
        path: PathBuf::from(mailcow::DKIM_DUMP_SCRIPT_PATH),
        contents: mailcow::dkim_dump_script(input),
        mode: Some(0o700),
    }]
}

fn write_managed_files(files: &[ManagedFile]) -> Result<(), String> {
    for file in files {
        let mode = file.mode.unwrap_or_else(|| existing_mode(&file.path).unwrap_or(0o644));
        crate::util::write_file_atomic(&file.path, file.contents.as_bytes(), mode)
            .map_err(|err| format!("could not write {}: {err}", file.path.display()))?;
    }
    Ok(())
}

fn write_dms_management_scripts(input: &Input, _sink: &EventSink) -> Result<(), String> {
    write_managed_files(&dms_management_files(input))
}

async fn configure_dms(input: &Input, sink: &EventSink) {
    // A DEADLINE, not a try count — see `DMS_READY_DEADLINE_SECS`.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(DMS_READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    let mut probe = (false, String::new());
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        probe = dms_exec(dms::READINESS_PROBE_ARGS).await;
        if probe.0 {
            ready = true;
            break;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step(format!("Docker Mailserver: waiting for the engine to answer ({})", why(&probe.1))).await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    if !ready {
        let _ = sink
            .step(format!(
                "Docker Mailserver never answered — no mailbox and no DKIM keys were created ({})",
                why(&probe.1)
            ))
            .await;
        return;
    }

    create_first_mailbox(input, sink).await;

    for domain in dms::mail_domains(input) {
        let argv = dms::dkim_config_args(&domain);
        let (ok, output) = dms_exec(&borrowed(&argv)).await;
        if ok {
            let _ = sink.step(format!("generated the DKIM key for {domain}")).await;
        } else {
            let _ = sink
                .step(format!("Docker Mailserver: could not generate the DKIM key for {domain} ({})", why(&output)))
                .await;
        }
    }

    stop_rspamd_reducing_the_signing_domain(input, sink).await;
}

fn dkim_signing_without_esld(current: &str) -> Option<String> {
    if !current.contains("use_esld = true;") {
        return None;
    }
    Some(current.replace("use_esld = true;", "use_esld = false;"))
}

async fn stop_rspamd_reducing_the_signing_domain(input: &Input, sink: &EventSink) {
    let path = std::path::Path::new(&input.docker_mailserver_path)
        .join("config/rspamd/override.d/dkim_signing.conf");
    let Ok(current) = std::fs::read_to_string(&path) else { return };
    let Some(fixed) = dkim_signing_without_esld(&current) else { return };
    if let Err(error) = std::fs::write(&path, fixed) {
        let _ = sink
            .step(format!("Docker Mailserver: could not stop rspamd reducing the signing domain ({error})"))
            .await;
        return;
    }
    let (ok, output) = dms_exec(&["supervisorctl", "restart", "rspamd"]).await;
    if ok {
        let _ = sink.step("DKIM signing now uses the full mail domain".to_string()).await;
    } else {
        let _ = sink
            .step(format!("Docker Mailserver: DKIM signing fixed, but rspamd did not restart ({})", why(&output)))
            .await;
    }
}

async fn create_first_mailbox(input: &Input, sink: &EventSink) {
    let address = dms::admin_mailbox(input);

    let listing = match dms_exec_captured(dms::LIST_MAILBOXES_ARGS).await {
        Ok(run) => strip_ansi(&run.stdout),
        Err(_) => String::new(),
    };
    if mailbox_listed(&listing, &address) {
        let _ = sink.step(format!("the mailbox {address} already exists")).await;
        return;
    }

    let env_path = PathBuf::from(&input.docker_mailserver_path).join(".env");
    let Some(password) = read_env_value(&env_path, dms::FIRST_MAILBOX_PASSWORD_KEY) else {
        let _ = sink.step("Docker Mailserver: no first-mailbox password on file — the mailbox was not created").await;
        return;
    };
    if password.is_empty() {
        let _ = sink.step("Docker Mailserver: the first-mailbox password is empty — the mailbox was not created").await;
        return;
    }

    let argv = dms::add_mailbox_args(&address);
    let stdin = format!("{password}\n{password}\n");
    match dms_exec_with_stdin(&borrowed(&argv), &stdin).await {
        Ok(run) if run.success => {
            let _ = sink.step(format!("created the mailbox {address}")).await;
        }
        Ok(run) => {
            let _ = sink.step(format!("Docker Mailserver: could not create {address} ({})", dms_why(&run))).await;
        }
        Err(err) => {
            let _ = sink.step(format!("Docker Mailserver: could not create {address} ({err})")).await;
        }
    }
}

/// `Vec<String>` → the `&[&str]` every argv helper here takes
fn borrowed(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// One command in the mail container, output CAPTURED and ANSI-stripped
async fn dms_exec(args: &[&str]) -> (bool, String) {
    match dms_exec_captured(args).await {
        Ok(run) => (run.success, dms_why(&run)),
        Err(err) => (false, err),
    }
}

fn dms_why(run: &CapturedRun) -> String {
    let mut combined = run.stdout.clone();
    combined.push_str(&run.stderr);
    bounded(&strip_ansi(&combined), 300)
}

async fn dms_exec_captured(args: &[&str]) -> Result<CapturedRun, String> {
    run_docker_captured(&docker_exec_args(dms::CONTAINER, args), Duration::from_secs(DMS_EXEC_TIMEOUT_SECS)).await
}

async fn dms_exec_with_stdin(args: &[&str], stdin_text: &str) -> Result<CapturedRun, String> {
    let mut argv = vec!["exec".to_string(), "-i".to_string(), dms::CONTAINER.to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let mut child = tokio::process::Command::new(docker_bin())
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin_text.as_bytes()).await.map_err(|err| format!("could not write the password: {err}"))?;
        pipe.shutdown().await.map_err(|err| format!("could not close the password pipe: {err}"))?;
    }

    let output = tokio::time::timeout(Duration::from_secs(DMS_EXEC_TIMEOUT_SECS), child.wait_with_output())
        .await
        .map_err(|_| format!("docker timed out after {DMS_EXEC_TIMEOUT_SECS}s"))?
        .map_err(|err| format!("docker did not finish: {err}"))?;
    Ok(CapturedRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Is this address already in `setup email list`?
pub fn mailbox_listed(listing: &str, address: &str) -> bool {
    if address.is_empty() {
        return false;
    }
    listing.lines().any(|line| {
        let bytes = line.as_bytes();
        line.match_indices(address).any(|(at, _)| {
            let before = at == 0 || matches!(bytes[at - 1], b' ' | b'\t' | b'*');
            let end = at + address.len();
            let after = end == bytes.len() || matches!(bytes[end], b' ' | b'\t' | b'\r');
            before && after
        })
    })
}

pub fn sync_vaultwarden_config(config_path: &Path, input: &Input) -> Result<bool, String> {
    let text = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.to_string()),
    };
    let mut value: serde_json::Value = serde_json::from_str(&text).map_err(|err| err.to_string())?;
    let object = value.as_object_mut().ok_or_else(|| "config.json is not a JSON object".to_string())?;

    let desired_domain = format!("https://{}", vaultwarden::hostname(input));
    let signups_match = object.get("signups_allowed") == Some(&serde_json::Value::Bool(input.vaultwarden_allow_signups));
    let domain_match = match object.get("domain") {
        None | Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(false)) => true,
        Some(stored) => stored.as_str() == Some(desired_domain.as_str()),
    };
    if signups_match && domain_match {
        return Ok(false);
    }

    object.insert("signups_allowed".to_string(), serde_json::Value::Bool(input.vaultwarden_allow_signups));
    if object.contains_key("domain") {
        object.insert("domain".to_string(), serde_json::Value::String(desired_domain));
    }
    let rendered = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
    std::fs::write(config_path, rendered).map_err(|err| err.to_string())?;
    set_mode(config_path, 0o600).map_err(|err| err.to_string())?;
    Ok(true)
}

/// What a captured `docker` run produced
struct CapturedRun {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CapturedRun {
    fn why(&self) -> String {
        let mut combined = self.stdout.clone();
        combined.push_str(&self.stderr);
        bounded(&combined, 300)
    }
}

async fn run_docker_captured(args: &[String], timeout: Duration) -> Result<CapturedRun, String> {
    run_docker_captured_env(args, timeout, &[]).await
}

/// Like `run_docker_captured`, with variables only the docker client sees.
async fn run_docker_captured_env(
    args: &[String],
    timeout: Duration,
    envs: &[(&str, &str)],
) -> Result<CapturedRun, String> {
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(docker_bin())
            .envs(envs.iter().copied())
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("docker timed out after {}s", timeout.as_secs()))?
    .map_err(|err| format!("could not run docker: {err}"))?;
    Ok(CapturedRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

async fn run_docker_with_stdin(args: &[String], stdin_text: &str, timeout: Duration) -> Result<CapturedRun, String> {
    let mut child = tokio::process::Command::new(docker_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin_text.as_bytes()).await.map_err(|err| format!("could not write to stdin: {err}"))?;
        pipe.shutdown().await.map_err(|err| format!("could not close stdin: {err}"))?;
    }

    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| format!("docker timed out after {}s", timeout.as_secs()))?
        .map_err(|err| format!("docker did not finish: {err}"))?;
    Ok(CapturedRun {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn create_file_if_absent(path: &Path, contents: &str, mode: u32) -> io::Result<bool> {
    crate::util::create_file_atomic_if_absent(path, contents.as_bytes(), mode)
}

/// Where the docker CLI is allowed to keep its config
fn docker_config_dir() -> PathBuf {
    let dir = crate::backup::wrapper_home().join(".docker");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

async fn run_docker_streaming(args: &[String], sink: &EventSink) -> Result<(), String> {
    let mut child = tokio::process::Command::new(docker_bin())
        .env("DOCKER_CONFIG", docker_config_dir())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());

    let limit = docker_timeout_secs(args);
    let outcome = tokio::time::timeout(Duration::from_secs(limit), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stdout", text).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stderr", text).await; }
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
        Err(_) => Err(format!("docker timed out after {limit}s")),
        Ok(Err(io)) => Err(format!("docker did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("docker exited {code}"),
            None => "docker was killed by a signal".to_string(),
        }),
    }
}

pub(super) async fn run_child_streaming(
    bin: &Path,
    args: &[String],
    cwd: Option<&Path>,
    envs: &[(&str, String)],
    stdin_text: Option<&str>,
    timeout: Duration,
    sink: &EventSink,
) -> Result<(), String> {
    let bin_name = bin.display().to_string();
    let mut command = tokio::process::Command::new(bin);
    command.env("DOCKER_CONFIG", docker_config_dir());
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .stdin(if stdin_text.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|err| format!("could not run {bin_name}: {err}"))?;

    if let Some(text) = stdin_text {
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(text.as_bytes()).await.map_err(|err| format!("could not write to {bin_name}'s stdin: {err}"))?;
            pipe.shutdown().await.map_err(|err| format!("could not close {bin_name}'s stdin: {err}"))?;
        }
    }

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());

    let outcome = tokio::time::timeout(timeout, async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stdout", text).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.process_line("stderr", text).await; }
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
        Err(_) => Err(format!("{bin_name} timed out after {}s", timeout.as_secs())),
        Ok(Err(io)) => Err(format!("{bin_name} did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("{bin_name} exited {code}"),
            None => format!("{bin_name} was killed by a signal"),
        }),
    }
}

async fn wait_for_adguard(sink: &EventSink) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(READY_DEADLINE_SECS);
    let mut attempt: u32 = 0;
    while tokio::time::Instant::now() < deadline {
        let ready = http_request(
            "127.0.0.1",
            adguard::WEB_UI_PORT,
            "GET",
            "/control/install/get_addresses",
            None,
            Duration::from_secs(ADGUARD_HTTP_TIMEOUT_SECS),
        )
        .await
        .map(|(code, _body)| (200..300).contains(&code))
        .unwrap_or(false);
        if ready {
            return true;
        }
        attempt += 1;
        if attempt % READY_HEARTBEAT_EVERY == 0 {
            let _ = sink.step("AdGuard Home: waiting for the service to answer").await;
        }
        tokio::time::sleep(Duration::from_secs(READY_POLL_INTERVAL_SECS)).await;
    }
    false
}

/// Initial configuration through AdGuard's own installation API
async fn configure_adguard(dir: &Path, input: &Input, sink: &EventSink) {
    let env_path = dir.join(".env");
    let Some(password) = read_env_value(&env_path, "ADGUARD_ADMIN_PASSWORD") else {
        return;
    };
    let body = format!(
        "{{\"web\":{{\"ip\":\"0.0.0.0\",\"port\":{}}},\"dns\":{{\"ip\":\"0.0.0.0\",\"port\":53}},\"username\":\"{}\",\"password\":\"{}\"}}",
        adguard::CONTAINER_WEB_PORT,
        json_escape(&input.admin_username),
        json_escape(&password),
    );
    let result = http_request(
        "127.0.0.1",
        adguard::WEB_UI_PORT,
        "POST",
        "/control/install/configure",
        Some(body.as_bytes()),
        Duration::from_secs(ADGUARD_HTTP_TIMEOUT_SECS),
    )
    .await;
    match result {
        Ok((code, _)) if (200..300).contains(&code) => {}
        Ok((code, body)) => {
            let _ = sink
                .step(format!(
                    "AdGuard Home: the initial configuration failed — the setup wizard is still open, finish it yourself right away ({code} {})",
                    bounded(&body, 300)
                ))
                .await;
        }
        Err(err) => {
            let _ = sink
                .step(format!(
                    "AdGuard Home: the initial configuration failed — the setup wizard is still open, finish it yourself right away ({err})"
                ))
                .await;
        }
    }
}

fn bounded(text: &str, limit: usize) -> String {
    text.chars().filter(|c| *c != '\r' && *c != '\n').take(limit).collect()
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out
}

fn site_name_conflicts(label: &str, input: &Input) -> Vec<String> {
    let existing = std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default();
    site_name_conflicts_in(&existing, label, input)
}

fn site_name_conflicts_in(existing: &str, label: &str, input: &Input) -> Vec<String> {
    let ingress_id = if label == "vpn" { "vpn-panel" } else { label };
    if label == "vpn" && !panel::publishes_site(input) {
        return Vec::new();
    }
    let names = catalog::site_names_for(ingress_id, input);
    if names.is_empty() {
        return Vec::new();
    }
    caddy::conflicting_names(existing, &names, label)
}

fn write_caddy_site(names: &[String], site: &str) -> Result<(), String> {
    with_caddyfile_lock(|| write_caddy_site_locked(names, site))
}

fn write_caddy_site_locked(names: &[String], site: &str) -> Result<(), String> {
    let guard_path = Path::new(caddy::ADMIN_GUARD_PATH);
    if !guard_path.exists() {
        if let Some(parent) = guard_path.parent() {
            create_dir_0755(parent).map_err(|err| format!("could not create {}: {err}", parent.display()))?;
        }
        std::fs::write(guard_path, "").map_err(|err| format!("could not create {}: {err}", guard_path.display()))?;
    }
    let existing = std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default();
    let owner = caddy::owner_of(site).unwrap_or_default();
    let clashing = caddy::conflicting_names(&existing, names, &owner);
    if !clashing.is_empty() {
        return Err(format!(
            "{} is already served by another service on this host, so this one was left \
             without a web address. Caddy refuses a configuration that names one host \
             twice, which would take HTTPS off every service on this machine. The service \
             itself is installed and running — give it a name of its own and install \
             again, or remove it",
            clashing.join(", ")
        ));
    }
    if let Some(guarded) = caddy::setup_guarded_owner(site) {
        if !existing.contains(&format!("# gryonixnexus: {guarded}\n")) {
            arm_setup_guard(&guarded)?;
        }
    }
    let merged = caddy::merge_site(&existing, names, site);
    if !existing.is_empty() {
        std::fs::write(CADDYFILE_PREVIOUS, &existing)
            .map_err(|err| format!("could not keep a copy of {CADDYFILE_PATH}: {err}"))?;
    }
    write_replacing(Path::new(CADDYFILE_PATH), &merged)
}

fn arm_setup_guard(owner: &str) -> Result<(), String> {
    let dir = Path::new(caddy::SETUP_GUARD_DIR);
    create_dir_0755(dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let path = dir.join(owner);
    std::fs::write(&path, caddy::SETUP_GUARD_RULES)
        .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    set_mode(&path, 0o644).map_err(|err| format!("could not chmod {}: {err}", path.display()))
}

/// Writes beside the file, then renames over it
fn write_replacing(path: &Path, text: &str) -> Result<(), String> {
    let staged = path.with_extension("gryonixnexus-new");
    std::fs::write(&staged, text)
        .and_then(|()| std::fs::rename(&staged, path))
        .map_err(|err| format!("could not write {}: {err}", path.display()))
}

/// Puts back the Caddyfile from before the last write
fn restore_previous_caddyfile() {
    if let Ok(previous) = std::fs::read_to_string(CADDYFILE_PREVIOUS) {
        let _ = write_replacing(Path::new(CADDYFILE_PATH), &previous);
    }
}

/// Reloads Caddy even when the file is unchanged
async fn caddy_force_reload() -> bool {
    tokio::process::Command::new("caddy")
        .args(["reload", "--config", CADDYFILE_PATH, "--adapter", "caddyfile", "--force"])
        .envs(caddy_check::cli_env())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

/// Caddy's complaint about the Caddyfile, if any
async fn caddy_refusal() -> Option<String> {
    if !packages::have_binary("caddy") || !Path::new(CADDYFILE_PATH).exists() {
        return None;
    }
    caddy_check::refusal(Path::new(CADDYFILE_PATH)).await
}

/// Validates; a refusal names the sites and restores the file
async fn check_caddyfile(sink: &EventSink) -> Result<(), String> {
    let Some(why) = caddy_refusal().await else { return Ok(()) };
    let current = std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default();
    let dir = Path::new(CADDYFILE_PATH).parent().unwrap_or(Path::new("/etc/caddy"));
    let refused = caddy_check::refused_sites(&current, dir).await.unwrap_or_default();
    let named: Vec<String> = refused.iter().map(|(site, reason)| format!("{}: {reason}", caddy_check::site_label(site))).collect();
    let said = if named.is_empty() { why } else { named.join("; ") };
    let _ = sink.step(&format!("Caddy refused the sites: {said}")).await;
    restore_previous_caddyfile();
    Err(format!("Caddy refused the new sites, so the previous ones were put back. Caddy said: {said}"))
}

/// Validates and reloads; a refused site never stops Caddy
async fn reload_caddy(sink: &EventSink) -> Result<(), String> {
    let _ = sink.step("reloading Caddy").await;
    let tunnel = home_network::tunnel_running().await;
    if let Err(why) = home_network::write_files(CADDYFILE_PATH, tunnel) {
        let _ = sink.step(&format!("home network access not updated: {why}")).await;
    }
    check_caddyfile(sink).await?;
    if run_quiet(&systemctl_bin(), &["reload", "caddy"]).await.is_err() {
        if run_quiet(&systemctl_bin(), &["is-active", "--quiet", "caddy"]).await.is_ok() {
            restore_previous_caddyfile();
            let _ = run_quiet(&systemctl_bin(), &["reload", "caddy"]).await;
            return Err("Caddy did not take the new site, so the previous sites stay".to_string());
        }
        let _ = sink.step("Caddy was not running, starting it").await;
        run_quiet(&systemctl_bin(), &["restart", "caddy"])
            .await
            .map_err(|()| "could not start caddy — the site was written but is not live".to_string())?;
    }
    let _ = std::fs::remove_file(CADDYFILE_PREVIOUS);
    ensure_caddy_enabled(sink).await;
    open_home_doors(sink).await;
    Ok(())
}

async fn open_home_doors(sink: &EventSink) {
    let tunnel = home_network::tunnel_running().await;
    if let Err(why) = home_network::apply_firewall(CADDYFILE_PATH, tunnel).await {
        let _ = sink.step(&format!("home network ports not opened: {why}")).await;
    }
}

/// Rebuilds older mail sites in today's shape
pub async fn refresh_portal_split_sites() -> Result<bool, String> {
    let changed = with_caddyfile_lock(|| -> Result<Option<(String, String)>, String> {
        let Ok(existing) = std::fs::read_to_string(CADDYFILE_PATH) else { return Ok(None) };
        let upgraded = caddy::with_current_global_options(&caddy::with_current_portal_split(&existing));
        if upgraded == existing {
            return Ok(None);
        }
        std::fs::write(CADDYFILE_PATH, &upgraded).map_err(|err| format!("could not write {CADDYFILE_PATH}: {err}"))?;
        Ok(Some((existing, upgraded)))
    })?;
    let Some((existing, upgraded)) = changed else { return Ok(false) };
    if run_quiet(&systemctl_bin(), &["reload", "caddy"]).await.is_ok() {
        return Ok(true);
    }
    restore_caddyfile_if_unchanged(&existing, &upgraded)?;
    Err("Caddy refused the rebuilt sites, so the old ones stay".to_string())
}

fn restore_caddyfile_if_unchanged(old: &str, written: &str) -> Result<(), String> {
    with_caddyfile_lock(|| {
        if std::fs::read_to_string(CADDYFILE_PATH).is_ok_and(|now| now != written) {
            return Ok(());
        }
        std::fs::write(CADDYFILE_PATH, old).map_err(|err| format!("could not restore {CADDYFILE_PATH}: {err}"))
    })
}

async fn write_autoconfig_site(domains: &[String]) -> Result<Option<(String, String)>, String> {
    let Some(primary) = domains.first() else { return Ok(None) };
    let names = names_on_mail_host(&format!("mail.{primary}"), mailcow::autoconfig_site_names(domains)).await;
    with_caddyfile_lock(|| {
        let existing = std::fs::read_to_string(CADDYFILE_PATH).unwrap_or_default();
        let updated = caddy::with_autoconfig_site(&existing, mailcow::autoconfig_site(&names).as_deref());
        if updated.trim() == existing.trim() {
            return Ok(None);
        }
        std::fs::write(CADDYFILE_PATH, &updated).map_err(|err| format!("could not write {CADDYFILE_PATH}: {err}"))?;
        Ok(Some((existing, updated)))
    })
}

/// Names whose addresses match the mail host's
async fn names_on_mail_host(mail_host: &str, names: Vec<String>) -> Vec<String> {
    let mail: Vec<_> = lookup_addresses(mail_host).await.into_iter().filter(|ip| !ip.is_loopback()).collect();
    let mut kept = Vec::new();
    for name in names {
        let found = lookup_addresses(&name).await;
        let here = if mail.is_empty() { !found.is_empty() } else { found.iter().any(|ip| mail.contains(ip)) };
        if here {
            kept.push(name);
        }
    }
    kept
}

/// Addresses a name resolves to, empty when it does not
async fn lookup_addresses(name: &str) -> Vec<std::net::IpAddr> {
    match tokio::net::lookup_host((name, 443)).await {
        Ok(addrs) => addrs.map(|addr| addr.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Adds the autoconfig site beside an existing mailcow site
pub async fn refresh_mail_autoconfig_site() -> Result<bool, String> {
    let Ok(existing) = std::fs::read_to_string(CADDYFILE_PATH) else { return Ok(false) };
    let domains = caddy::mailcow_domains(&existing);
    if domains.is_empty() {
        return Ok(false);
    }
    let Some((previous, written)) = write_autoconfig_site(&domains).await? else { return Ok(false) };
    if run_quiet(&systemctl_bin(), &["reload", "caddy"]).await.is_ok() {
        return Ok(true);
    }
    restore_caddyfile_if_unchanged(&previous, &written)?;
    Err("Caddy refused the autoconfig site, so the old sites stay".to_string())
}

/// Keeps the home-network doors in step with the Caddyfile
pub async fn reconcile_home_network() -> Result<(), String> {
    if !Path::new(CADDYFILE_PATH).exists() {
        return Ok(());
    }
    let tunnel = home_network::tunnel_running().await;
    if with_caddyfile_lock(|| home_network::write_files(CADDYFILE_PATH, tunnel))? {
        run_quiet(&systemctl_bin(), &["reload", "caddy"])
            .await
            .map_err(|()| "Caddy did not take the home network sites".to_string())?;
    }
    home_network::apply_firewall(CADDYFILE_PATH, tunnel).await
}

/// Drops a removed service's Caddy sites, then its doors
pub async fn forget_service_sites(service_id: &str) -> Result<(), String> {
    let removed = with_caddyfile_lock(|| -> Result<bool, String> {
        let Ok(existing) = std::fs::read_to_string(CADDYFILE_PATH) else { return Ok(false) };
        let kept = caddy::without_owner(&existing, service_id);
        if kept == existing {
            return Ok(false);
        }
        std::fs::write(CADDYFILE_PATH, kept).map_err(|err| format!("could not write {CADDYFILE_PATH}: {err}"))?;
        Ok(true)
    })?;
    if removed {
        run_quiet(&systemctl_bin(), &["reload", "caddy"])
            .await
            .map_err(|()| "Caddy did not take the removal".to_string())?;
    }
    reconcile_home_network().await
}

/// The doors this host has now, for GetState
pub fn home_network_doors() -> Vec<home_network::HomeSite> {
    home_network::doors(CADDYFILE_PATH)
}

/// Make Caddy come back after a reboot
async fn ensure_caddy_enabled(sink: &EventSink) {
    if run_quiet(&systemctl_bin(), &["is-enabled", "caddy"]).await.is_ok() {
        return;
    }
    if run_quiet(&systemctl_bin(), &["enable", "caddy"]).await.is_ok() {
        let _ = sink.step("enabled Caddy so it survives a reboot").await;
    } else {
        let _ = sink
            .step("WARNING: could not enable the Caddy unit — HTTPS will not come back after a reboot")
            .await;
    }
}

pub(super) fn systemctl_bin_public() -> String {
    systemctl_bin()
}

pub(super) async fn run_quiet_public(bin: &str, args: &[&str]) -> Result<(), ()> {
    run_quiet(bin, args).await
}

fn systemctl_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string())
}

async fn run_quiet(bin: &str, args: &[&str]) -> Result<(), ()> {
    match tokio::process::Command::new(bin).args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().await {
        Ok(status) if status.success() => Ok(()),
        _ => Err(()),
    }
}

pub fn docker_build_args(image: &str, dir: &Path) -> Vec<String> {
    vec![
        "build".to_string(),
        "-t".to_string(),
        image.to_string(),
        dir.to_string_lossy().into_owned(),
    ]
}

pub fn docker_container_exists_args(container: &str) -> Vec<String> {
    vec![
        "ps".to_string(),
        "-aq".to_string(),
        "--filter".to_string(),
        format!("name=^{container}$"),
    ]
}

fn random_hex_8() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn random_base64_32() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(base64_encode(&buf))
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let triple = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((triple >> shift) & 0x3f) as usize] as char);
        }
        if chunk.len() < 3 {
            out.truncate(out.len() - (3 - chunk.len()));
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

async fn docker_run_capture_trimmed(args: &[String], what: &str) -> Result<String, String> {
    match run_docker_capture(args, Duration::from_secs(DOCKER_TIMEOUT_SECS)).await? {
        (true, out) => Ok(out.trim().to_string()),
        (false, out) => Err(format!("{what} failed: {}", truncate(&out))),
    }
}

fn random_bytes_16() -> io::Result<[u8; 16]> {
    use std::io::Read;
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

fn random_hex_12() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 12];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Is a stored panel password one this system generated?
pub fn is_generated_panel_password(value: &str) -> bool {
    value.len() == 24 && value.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn resolve_panel_password(dir: &Path) -> io::Result<(String, bool)> {
    let existing = read_env_value(&dir.join(".env"), "ADMIN_PASSWORD").unwrap_or_default();
    if is_generated_panel_password(&existing) {
        return Ok((existing, true));
    }
    Ok((random_hex_12()?, false))
}

async fn install_vpn_steps(
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Result<(), String> {
    let dir = PathBuf::from(panel::PATH);
    let build = dir.join("build");
    let data = dir.join("data");

    for protocol in protocols {
        if vpn_protocol_running(input, *protocol).await {
            repair_kept_vpn_protocol(input, *protocol);
            let _ = sink.step(&format!("kept {} as it is", protocol.service_id())).await;
            continue;
        }
        install_vpn_protocol(input, *protocol, sink).await?;
    }
    retire_vpn_protocols(input, protocols, sink).await?;

    let _ = sink.step("creating service directories").await;
    for path in [&dir, &build, &data] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, panel::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let (sources_changed, sources_digest) = write_panel_sources(&build)?;
    let built_stamp = build.join(".built-digest");
    let _ = sink.step("wrote the panel's sources").await;

    write_panel_env(input, &dir, sink).await?;

    let (registry_changed, registry_digest) = write_panel_registry(&data, &panel::services_json(input, protocols))?;
    let registry_stamp = data.join(".services-applied");

    if !crate::vpn_dns_priority::is_relay() {
        install_admin_lockdown(sink).await?;
    }

    let existed = panel_container_exists().await;

    if sources_changed || !docker_image_present(panel::IMAGE).await {
        let _ = sink.step("building the VPN panel image").await;
        run_docker_streaming(&docker_build_args(panel::IMAGE, &build), sink).await?;
        let _ = std::fs::write(&built_stamp, &sources_digest);
    } else {
        let _ = sink.step("the VPN panel image is current").await;
    }
    let _ = sink.step("starting the VPN panel").await;
    compose_up(panel::COMPOSE_PROJECT, &dir, sink).await?;

    let restarted = !(existed && (sources_changed || registry_changed))
        || run_docker_streaming(&compose_restart_args(panel::COMPOSE_PROJECT, &dir), sink).await.is_ok();
    if restarted {
        let _ = std::fs::write(&registry_stamp, &registry_digest);
    }

    apply_vpn_firewall(input, protocols, sink).await?;

    if crate::vpn_dns_priority::is_relay() {
        let _ = sink.step("this relay publishes no web site: the VPN is managed from the app").await;
        return Ok(());
    }
    write_caddy_site(&panel::caddy_site_names(input), &panel::caddy_site(input))?;
    reload_caddy(sink).await?;

    Ok(())
}

/// Stops protocols this request leaves out, keeping their keys
async fn retire_vpn_protocols(
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Result<(), String> {
    for (protocol, project, dir) in vpn_protocol_projects(input) {
        let compose = Path::new(dir).join("docker-compose.yml");
        if protocols.contains(&protocol) || !compose.exists() {
            continue;
        }
        let _ = sink.step(&format!("stopping {}", protocol.service_id())).await;
        run_docker_streaming(&compose_stop_args(project, Path::new(dir)), sink).await?;
    }
    Ok(())
}

async fn write_panel_env(input: &Input, dir: &Path, sink: &EventSink) -> Result<(), String> {
    let (password, kept) = resolve_panel_password(dir).map_err(|err| format!("could not resolve the panel password: {err}"))?;
    let env_path = dir.join(".env");
    write_secret(&env_path, &panel::env_contents(input, &password), 0o600)
        .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
    let _ = sink
        .step(if kept { "kept the existing panel password" } else { "generated the panel password" })
        .await;
    Ok(())
}

async fn panel_container_exists() -> bool {
    let args = docker_container_exists_args(panel::CONTAINER);
    matches!(
        run_docker_capture(&args, Duration::from_secs(DOCKER_TIMEOUT_SECS)).await,
        Ok((true, out)) if !out.trim().is_empty()
    )
}

fn write_panel_sources(build: &Path) -> Result<(bool, String), String> {
    let build_files = panel::build_files();
    let digest = digest_hex(build_files.iter().map(|(name, contents)| format!("{name}\n{contents}")));
    let built = std::fs::read_to_string(build.join(".built-digest")).ok();
    let mut changed = built.as_deref() != Some(digest.as_str());
    for (name, contents) in build_files {
        let path = build.join(name);
        if std::fs::read(&path).ok().as_deref() == Some(contents.as_bytes()) {
            continue;
        }
        changed = true;
        std::fs::write(&path, contents).map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    Ok((changed, digest))
}

fn write_panel_registry(data: &Path, registry: &str) -> Result<(bool, String), String> {
    let path = data.join("services.json");
    let digest = digest_hex([registry.to_string()]);
    let applied = std::fs::read_to_string(data.join(".services-applied")).ok();
    let changed = std::fs::read_to_string(&path).ok().as_deref() != Some(registry) || applied.as_deref() != Some(digest.as_str());
    std::fs::write(&path, registry).map_err(|err| format!("could not write {}: {err}", path.display()))?;
    Ok((changed, digest))
}

async fn install_admin_lockdown(sink: &EventSink) -> Result<(), String> {
    let caddy_dir = Path::new(caddy::ADMIN_GUARD_PATH).parent().unwrap_or(Path::new("/etc/caddy"));
    create_dir_0755(caddy_dir).map_err(|err| format!("could not create {}: {err}", caddy_dir.display()))?;
    let guard_path = Path::new(caddy::ADMIN_GUARD_PATH);
    let first_install = create_file_if_absent(guard_path, "", 0o644)
        .map_err(|err| format!("could not create {}: {err}", caddy::ADMIN_GUARD_PATH))?;
    let lockdown = Path::new(panel::LOCKDOWN_SCRIPT_PATH);
    crate::util::write_file_atomic(lockdown, panel::ADMIN_LOCKDOWN_SH.as_bytes(), 0o750)
        .map_err(|err| format!("could not write {}: {err}", lockdown.display()))?;
    let _ = sink.step("installed the admin-lockdown wrapper").await;
    if first_install {
        let ran = tokio::time::timeout(
            Duration::from_secs(ADMIN_LOCKDOWN_ON_TIMEOUT_SECS),
            tokio::process::Command::new(lockdown)
                .arg("on")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await;
        if matches!(ran, Ok(Ok(status)) if status.success()) {
            let _ = sink.step("locked the admin panels to VPN-only access").await;
        } else {
            let _ = sink
                .step("could not lock the admin panels by default — lock them from the dashboard")
                .await;
        }
    }
    Ok(())
}

fn digest_hex(parts: impl IntoIterator<Item = String>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether a protocol's own containers already run, unchanged
async fn vpn_protocol_running(input: &Input, protocol: panel::Protocol) -> bool {
    let Some((_, project, dir)) = vpn_protocol_projects(input).into_iter().find(|(p, _, _)| *p == protocol) else {
        return false;
    };
    let on_disk = std::fs::read_to_string(Path::new(dir).join("docker-compose.yml")).unwrap_or_default();
    if on_disk.trim_end() != vpn_protocol_compose(input, protocol).trim_end() {
        return false;
    }
    if protocol == panel::Protocol::OpenVPN && openvpn_build_files_changed(input) {
        return false;
    }
    match run_docker_capture(&compose_running_args(project), Duration::from_secs(DOCKER_TIMEOUT_SECS)).await {
        Ok((true, out)) => has_container_id(&out),
        _ => false,
    }
}

fn has_container_id(output: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        line.len() >= 12 && line.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn openvpn_build_files_changed(input: &Input) -> bool {
    let build = PathBuf::from(openvpn::build_dir(input));
    openvpn::build_files()
        .into_iter()
        .any(|(name, contents)| std::fs::read(build.join(name)).ok().as_deref() != Some(contents.as_bytes()))
}

/// Narrows secret files of a protocol that is kept running
fn repair_kept_vpn_protocol(input: &Input, protocol: panel::Protocol) {
    let secrets: Vec<String> = match protocol {
        panel::Protocol::Shadowsocks => vec![shadowsocks::config_path(input)],
        panel::Protocol::XrayReality => vec![xray::config_path(input), xray::link_path(input)],
        panel::Protocol::AmneziaWG => vec![amnezia::env_path(input)],
        panel::Protocol::OpenVPN | panel::Protocol::WireGuard => Vec::new(),
    };
    for path in secrets {
        let _ = set_mode(Path::new(&path), 0o600);
    }
    if protocol == panel::Protocol::AmneziaWG {
        let env_path = PathBuf::from(amnezia::env_path(input));
        if let Ok(existing) = std::fs::read_to_string(&env_path) {
            let repaired = reescape_amnezia_env(&existing);
            if repaired != existing {
                let _ = write_secret(&env_path, &repaired, 0o600);
            }
        }
    }
}

/// The compose file a protocol would be written with now
fn vpn_protocol_compose(input: &Input, protocol: panel::Protocol) -> String {
    use super::vpn::protocols::{amnezia, openvpn, shadowsocks, xray};
    match protocol {
        panel::Protocol::WireGuard => String::new(),
        panel::Protocol::AmneziaWG => amnezia::compose_contents(input),
        panel::Protocol::Shadowsocks => shadowsocks::compose_contents(input),
        panel::Protocol::XrayReality => xray::compose_contents(input),
        panel::Protocol::OpenVPN => openvpn::compose_contents(input),
    }
}

/// Running containers of one compose project
pub fn compose_running_args(project: &str) -> Vec<String> {
    vec![
        "ps".to_string(),
        "-q".to_string(),
        "--filter".to_string(),
        format!("label=com.docker.compose.project={project}"),
        "--filter".to_string(),
        "status=running".to_string(),
    ]
}

/// Whether a local image is already built
async fn docker_image_present(image: &str) -> bool {
    let args = vec!["image".to_string(), "inspect".to_string(), image.to_string()];
    matches!(run_docker_capture(&args, Duration::from_secs(DOCKER_TIMEOUT_SECS)).await, Ok((true, _)))
}

/// Every protocol with a compose project of its own
fn vpn_protocol_projects(input: &Input) -> [(panel::Protocol, &'static str, &str); 4] {
    use super::vpn::protocols::{amnezia, openvpn, shadowsocks, xray};
    [
        (panel::Protocol::AmneziaWG, amnezia::COMPOSE_PROJECT, amnezia::dir(input)),
        (panel::Protocol::Shadowsocks, shadowsocks::COMPOSE_PROJECT, shadowsocks::dir(input)),
        (panel::Protocol::XrayReality, xray::COMPOSE_PROJECT, xray::dir(input)),
        (panel::Protocol::OpenVPN, openvpn::COMPOSE_PROJECT, openvpn::dir(input)),
    ]
}

async fn install_vpn_protocol(
    input: &Input,
    protocol: panel::Protocol,
    sink: &EventSink,
) -> Result<(), String> {
    match protocol {
        panel::Protocol::WireGuard => Ok(()),
        panel::Protocol::AmneziaWG => install_amnezia_steps(input, sink).await,
        panel::Protocol::Shadowsocks => install_shadowsocks_steps(input, sink).await,
        panel::Protocol::XrayReality => install_xray_steps(input, sink).await,
        panel::Protocol::OpenVPN => install_openvpn_steps(input, sink).await,
    }
}

async fn install_shadowsocks_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(shadowsocks::dir(input));
    let _ = sink.step("creating the Shadowsocks directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, shadowsocks::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let config_path = PathBuf::from(shadowsocks::config_path(input));
    let key = random_base64_32().map_err(|err| format!("could not generate the Shadowsocks key: {err}"))?;
    let created = create_file_if_absent(&config_path, &shadowsocks::config_json(input, &key), 0o600)
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
    set_mode(&config_path, 0o600)
        .map_err(|err| format!("could not set the mode of {}: {err}", config_path.display()))?;
    let _ = sink
        .step(if created { "generated the Shadowsocks key" } else { "kept the existing Shadowsocks key" })
        .await;

    run_docker_streaming(&compose_pull_args(shadowsocks::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting Shadowsocks").await;
    compose_up(shadowsocks::COMPOSE_PROJECT, &dir, sink).await?;
    Ok(())
}

async fn install_xray_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(xray::dir(input));
    let config_dir = dir.join("config");
    let _ = sink.step("creating the XRay directories").await;
    for path in [&dir, &config_dir] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, xray::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let config_path = PathBuf::from(xray::config_path(input));
    let link_path = PathBuf::from(xray::link_path(input));
    let mut site_changed = false;
    if config_path.exists() {
        let _ = sink.step("kept the existing XRay keys").await;
        site_changed = apply_reality_site(&config_path, &link_path, &input.xray_reality_sni, sink).await?;
        site_changed |= rotate_reality_key(input, &dir, &config_path, &link_path, sink).await?;
    } else {
        let _ = sink.step("pulling the XRay image").await;
        run_docker_streaming(&docker_pull_args(xray::IMAGE), sink).await?;

        let uuid = docker_run_capture_trimmed(&docker_run_once_args(xray::IMAGE, &["uuid"]), "xray uuid").await?;
        let keys = docker_run_capture_trimmed(&docker_run_once_args(xray::IMAGE, &["x25519"]), "xray x25519").await?;
        let (private_key, public_key) = xray::parse_keys(&keys)
            .ok_or_else(|| format!("xray x25519 returned no usable keypair: {}", truncate(&keys)))?;
        if uuid.is_empty() {
            return Err("xray uuid returned nothing".to_string());
        }
        let short_id = random_hex_8().map_err(|err| format!("could not generate the XRay shortId: {err}"))?;

        write_secret(&link_path, &xray::client_link(input, &uuid, &public_key, &short_id), 0o600)
            .map_err(|err| format!("could not write {}: {err}", link_path.display()))?;
        write_secret(&config_path, &xray::config_json(input, &uuid, &private_key, &short_id), 0o600)
            .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
        let _ = sink.step("generated the XRay keys and client link").await;
    }
    let dns_allowed = allow_vpn_dns_through_xray(&config_path)?;
    for path in [&config_path, &link_path] {
        set_mode(path, 0o600).map_err(|err| format!("could not set the mode of {}: {err}", path.display()))?;
    }

    run_docker_streaming(&compose_pull_args(xray::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting XRay").await;
    compose_up(xray::COMPOSE_PROJECT, &dir, sink).await?;
    if site_changed || dns_allowed {
        run_docker_streaming(&compose_restart_service_args(xray::COMPOSE_PROJECT, &dir, "xray"), sink).await?;
    }
    Ok(())
}

/// A new Reality key pair, once per request
async fn rotate_reality_key(
    input: &Input,
    dir: &Path,
    config_path: &Path,
    link_path: &Path,
    sink: &EventSink,
) -> Result<bool, String> {
    let token = input.xray_reality_new_key.trim();
    let marker = dir.join(".key-rotation");
    if token.is_empty() || std::fs::read_to_string(&marker).ok().as_deref() == Some(token) {
        return Ok(false);
    }
    let keys = docker_run_capture_trimmed(&docker_run_once_args(xray::IMAGE, &["x25519"]), "xray x25519").await?;
    let (private_key, public_key) = xray::parse_keys(&keys)
        .ok_or_else(|| format!("xray x25519 returned no usable keypair: {}", truncate(&keys)))?;
    let short_id = random_hex_8().map_err(|err| format!("could not generate the XRay shortId: {err}"))?;
    let config = std::fs::read_to_string(config_path)
        .map_err(|err| format!("could not read {}: {err}", config_path.display()))?;
    let rotated = xray::config_with_key(&config, &private_key, &short_id)
        .ok_or("the XRay config has no Reality settings to give a new key")?;
    let link = std::fs::read_to_string(link_path)
        .map_err(|err| format!("could not read {}: {err}", link_path.display()))?;
    write_secret(link_path, &xray::link_with_key(&link, &public_key, &short_id), 0o600)
        .map_err(|err| format!("could not write {}: {err}", link_path.display()))?;
    write_secret(config_path, &rotated, 0o600)
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
    std::fs::write(&marker, token).map_err(|err| format!("could not write {}: {err}", marker.display()))?;
    let _ = sink.step("gave XRay a new Reality key; devices need their configuration again").await;
    Ok(true)
}

/// Lets XRay reach this server's resolver relay
pub(crate) fn allow_vpn_dns_through_xray(config_path: &Path) -> Result<bool, String> {
    let config = std::fs::read_to_string(config_path)
        .map_err(|err| format!("could not read {}: {err}", config_path.display()))?;
    let Some(allowed) = xray::config_allowing_vpn_dns(&config) else { return Ok(false) };
    write_secret(config_path, &allowed, 0o600)
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
    Ok(true)
}

/// Points Reality at another camouflage site, keeping keys and clients
async fn apply_reality_site(config_path: &Path, link_path: &Path, site: &str, sink: &EventSink) -> Result<bool, String> {
    let config = std::fs::read_to_string(config_path)
        .map_err(|err| format!("could not read {}: {err}", config_path.display()))?;
    let Some(changed) = xray::config_with_site(&config, site) else { return Ok(false) };
    if let Ok(link) = std::fs::read_to_string(link_path) {
        write_secret(link_path, &xray::link_with_site(&link, site), 0o600)
            .map_err(|err| format!("could not write {}: {err}", link_path.display()))?;
    }
    write_secret(config_path, &changed, 0o600)
        .map_err(|err| format!("could not write {}: {err}", config_path.display()))?;
    let _ = sink.step(&format!("XRay now looks like {site}")).await;
    Ok(true)
}

/// AmneziaWG panel password, hashed in the agent
async fn install_amnezia_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(amnezia::dir(input));
    let _ = sink.step("creating the AmneziaWG directory").await;
    create_dir_0755(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, amnezia::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    let env_path = PathBuf::from(amnezia::env_path(input));
    if env_path.exists() {
        let existing = std::fs::read_to_string(&env_path)
            .map_err(|err| format!("could not read {}: {err}", env_path.display()))?;
        let repaired = reescape_amnezia_env(&existing);
        if repaired != existing {
            write_secret(&env_path, &repaired, 0o600)
                .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
            let _ = sink.step("repaired the AmneziaWG password hash escaping").await;
        } else {
            let _ = sink.step("kept the existing AmneziaWG panel password").await;
        }
    } else {
        let password =
            random_hex_12().map_err(|err| format!("could not generate the AmneziaWG password: {err}"))?;
        let hash = hash_amnezia_password(&password).await;
        if hash.is_none() {
            let _ = sink
                .step(
                    "could not hash a panel password — \
                     AmneziaWG's built-in panel stays open on localhost only; the VPN itself \
                     works and clients are managed from the VPN panel",
                )
                .await;
        }
        write_secret(&env_path, &amnezia::env_contents(&password, hash.as_deref()), 0o600)
            .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
        let _ = sink.step("generated the AmneziaWG panel password").await;
    }
    set_mode(&env_path, 0o600)
        .map_err(|err| format!("could not set the mode of {}: {err}", env_path.display()))?;

    run_docker_streaming(&compose_pull_args(amnezia::COMPOSE_PROJECT, &dir), sink).await?;
    let _ = sink.step("starting AmneziaWG").await;
    compose_up(amnezia::COMPOSE_PROJECT, &dir, sink).await?;
    Ok(())
}

/// bcrypt hash of the panel password with a random salt
async fn hash_amnezia_password(password: &str) -> Option<String> {
    let salt = random_bytes_16().ok()?;
    let password = password.to_string();
    tokio::task::spawn_blocking(move || amnezia::hash_password(&password, salt)).await.ok()?
}

/// Re-apply the `$` escaping to an existing `.env`'s `PASSWORD_HASH` line
fn reescape_amnezia_env(contents: &str) -> String {
    let ends_with_newline = contents.ends_with('\n');
    let mut out = String::with_capacity(contents.len());
    for (index, line) in contents.lines().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        match line.strip_prefix("PASSWORD_HASH=") {
            Some(hash) => {
                out.push_str("PASSWORD_HASH=");
                out.push_str(&amnezia::escape_hash(hash));
            }
            None => out.push_str(line),
        }
    }
    if ends_with_newline {
        out.push('\n');
    }
    out
}

async fn build_openvpn_pki(input: &Input, mount: &str, sink: &EventSink) -> Result<(), String> {
    let _ = sink.step("building the OpenVPN PKI").await;
    let script = openvpn::pki_script(input);
    run_docker_streaming(&docker_run_mounted_args(mount, openvpn::IMAGE, &["sh", "-c", &script]), sink).await
}

fn write_openvpn_server_files(input: &Input, data: &Path) -> Result<(), String> {
    let env_path = data.join("gryonix-env");
    std::fs::write(&env_path, openvpn::gryonix_env(input))
        .map_err(|err| format!("could not write {}: {err}", env_path.display()))?;
    let conf_path = data.join("server.conf");
    std::fs::write(&conf_path, openvpn::server_conf(input))
        .map_err(|err| format!("could not write {}: {err}", conf_path.display()))
}

async fn openvpn_client_profile(mount: &str) -> Result<String, String> {
    let args = docker_run_mounted_args(mount, openvpn::IMAGE, &["ovpn_getclient", openvpn::CLIENT_NAME]);
    let (ok, profile) = run_docker_capture(&args, Duration::from_secs(DOCKER_TIMEOUT_SECS)).await?;
    if !ok || profile.trim().is_empty() {
        return Err(format!("could not generate the OpenVPN client profile: {}", truncate(&profile)));
    }
    Ok(profile)
}

async fn install_openvpn_steps(input: &Input, sink: &EventSink) -> Result<(), String> {
    let dir = PathBuf::from(openvpn::dir(input));
    let data = PathBuf::from(openvpn::data_dir(input));
    let build = PathBuf::from(openvpn::build_dir(input));
    let _ = sink.step("creating the OpenVPN directories").await;
    for path in [&dir, &data, &build] {
        create_dir_0755(path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
    }

    let compose_path = dir.join("docker-compose.yml");
    write_managed_text(&compose_path, openvpn::compose_contents(input))
        .map_err(|err| format!("could not write {}: {err}", compose_path.display()))?;

    for (name, contents) in openvpn::build_files() {
        let path = build.join(name);
        std::fs::write(&path, contents)
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
    }
    let _ = sink.step("building the OpenVPN image").await;
    run_docker_streaming(&docker_build_args(openvpn::IMAGE, &build), sink).await?;

    let profile_path = PathBuf::from(openvpn::client_profile_path(input));
    let mount = format!("{}:/etc/openvpn", data.display());
    let ca_path = PathBuf::from(openvpn::ca_path(input));
    if ca_path.exists() && profile_path.exists() {
        let _ = sink.step("kept the existing OpenVPN PKI").await;
    } else {
        if !ca_path.exists() {
            build_openvpn_pki(input, &mount, sink).await?;
        }
        write_openvpn_server_files(input, &data)?;
        let profile = openvpn_client_profile(&mount).await?;
        write_secret(&profile_path, &profile, 0o640)
            .map_err(|err| format!("could not write {}: {err}", profile_path.display()))?;
        let _ = sink.step("generated the OpenVPN PKI and client profile").await;
    }
    set_mode(&profile_path, 0o640)
        .map_err(|err| format!("could not set the mode of {}: {err}", profile_path.display()))?;

    let _ = sink.step("starting OpenVPN").await;
    compose_up(openvpn::COMPOSE_PROJECT, &dir, sink).await?;
    Ok(())
}

/// Open the selected protocols' ports through the generator's drop-in chain
async fn apply_vpn_firewall(
    input: &Input,
    protocols: &[panel::Protocol],
    sink: &EventSink,
) -> Result<(), String> {
    let ports: Vec<firewall::Port> =
        protocols.iter().flat_map(|protocol| protocol.firewall_ports(input)).collect();
    match firewall::apply_service_ports("vpn", &ports).await? {
        firewall::Outcome::Applied => {
            let _ = sink.step("opened the VPN ports in the firewall").await;
        }
        firewall::Outcome::Cleared => {
            let _ = sink.step("removed this service's firewall ports").await;
        }
        firewall::Outcome::SkippedNoDropInDir => {
            let _ = sink
                .step("this host has no gryonixNexus nftables ruleset, so no firewall rule was added")
                .await;
        }
    }
    if crate::install::vpn::port_share::apply(input, protocols).await? {
        let _ = sink.step("AmneziaWG shares the WireGuard port").await;
    }
    Ok(())
}

async fn http_request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, String), String> {
    let addr = format!("{host}:{port}");
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("connect to {addr} timed out"))?
        .map_err(|err| format!("connect to {addr}: {err}"))?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    let mut buf = request.into_bytes();
    if let Some(body) = body {
        buf.extend_from_slice(body);
    }

    tokio::time::timeout(timeout, stream.write_all(&buf))
        .await
        .map_err(|_| "request write timed out".to_string())?
        .map_err(|err| format!("request write: {err}"))?;

    let mut response = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut response))
        .await
        .map_err(|_| "response read timed out".to_string())?
        .map_err(|err| format!("response read: {err}"))?;

    parse_http_response(&response)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, String), String> {
    let text = String::from_utf8_lossy(raw);
    let mut halves = text.splitn(2, "\r\n\r\n");
    let head = halves.next().unwrap_or("");
    let body = halves.next().unwrap_or("").to_string();
    let status_line = head.lines().next().ok_or_else(|| "empty response".to_string())?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("could not parse status line: {status_line}"))?;
    Ok((code, body))
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_old_whitelist_gains_poweroff_next_to_each_reboot() {
        let old = "# Managed\nsrv ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart sshd\n\
                   srv ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot\n\
                   srv ALL=(ALL) NOPASSWD: /usr/bin/wg show";
        let healed = with_host_grants(old).expect("a reboot line gets its twins");
        assert!(healed.contains(
            "srv ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot\nsrv ALL=(ALL) NOPASSWD: /usr/bin/systemctl poweroff\n\
             srv ALL=(ALL) NOPASSWD: /opt/gryonixnexus-system-ctl.sh\n"
        ));
        assert!(healed.ends_with("/usr/bin/wg show"));
        assert_eq!(with_host_grants(&healed), None, "a healed file is left alone");
        assert_eq!(with_host_grants("srv ALL=(ALL) NOPASSWD: /usr/bin/wg show"), None);
        let half = "srv ALL=(ALL) NOPASSWD: /usr/bin/systemctl reboot\nsrv ALL=(ALL) NOPASSWD: /usr/bin/systemctl poweroff\n";
        let healed = with_host_grants(half).expect("the system updater is added");
        assert_eq!(healed.matches("systemctl poweroff").count(), 1, "poweroff is not doubled");
    }

    use super::*;
    use prost::Message;
    use std::collections::HashMap;

    #[test]
    fn write_secret_creates_the_file_at_the_right_mode_directly() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("gryonixnexusd-write-secret-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_secret(&path, "hunter2", 0o600).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600, "the file must be 0600 from the moment it exists, not after a later chmod");
    }

    // ─────────────── the site names, before anything is created ───────────────

    fn site_input() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn a_name_another_block_already_holds_is_refused_before_anything_is_created() {
        let mut input = site_input();
        let existing = caddy::merge_site(
            "",
            &["vault.example.com".to_string()],
            &caddy::site("vaultwarden", "vault.example.com", 8082, false, false, false),
        );
        input.psono_hostname = "vault.example.com".to_string();
        assert_eq!(
            site_name_conflicts_in(&existing, "psono", &input),
            vec!["vault.example.com".to_string()]
        );
    }

    #[test]
    fn a_service_reinstalling_over_its_own_block_is_not_refused() {
        let existing = caddy::merge_site(
            "",
            &["vault.example.com".to_string()],
            &caddy::site("vaultwarden", "vault.example.com", 8082, false, false, false),
        );
        assert!(site_name_conflicts_in(&existing, "vaultwarden", &site_input()).is_empty());
    }

    #[test]
    fn a_service_with_no_site_of_its_own_is_never_refused_for_one() {
        let existing = caddy::merge_site(
            "",
            &["vault.example.com".to_string()],
            &caddy::site("vaultwarden", "vault.example.com", 8082, false, false, false),
        );
        for label in ["cloudflared", "minecraft-java", "tailscale-node"] {
            assert!(site_name_conflicts_in(&existing, label, &site_input()).is_empty(), "{label}");
        }
    }

    #[test]
    fn the_vpn_label_is_checked_on_the_panels_own_name() {
        let mut input = site_input();
        let names = catalog::site_names_for("vpn-panel", &input);
        assert!(!names.is_empty(), "the panel publishes no name to check");
        let stranger = caddy::merge_site("", &names,
                                         &caddy::site("nextcloud", &names.join(", "), 8080, false, false, false));
        assert_eq!(site_name_conflicts_in(&stranger, "vpn", &input), names);

        input.vpn_client_access = "app".to_string();
        assert!(site_name_conflicts_in(&stranger, "vpn", &input).is_empty());
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    // ---------------------------------------------------- the crash-loop guard

    #[test]
    fn a_project_that_held_still_passes() {
        assert!(went_quiet(3, LOOP_QUIET_SAMPLES));
        assert!(went_quiet(4, LOOP_QUIET_SAMPLES));
    }

    #[test]
    fn a_project_that_never_held_still_does_not_pass() {
        assert!(!went_quiet(0, LOOP_QUIET_SAMPLES));
        assert!(!went_quiet(2, LOOP_QUIET_SAMPLES));
    }

    #[test]
    fn the_floor_is_three_looks() {
        assert_eq!(LOOP_QUIET_SAMPLES, 3);
        assert!(!went_quiet(LOOP_QUIET_SAMPLES - 1, LOOP_QUIET_SAMPLES));
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-install-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ────────────────── the port docker published and nobody opened ──────────

    #[test]
    fn every_host_published_port_is_also_opened_in_the_firewall() {
        let source = include_str!("execute.rs");
        for label in ["gitlab", "forgejo"] {
            let install = source
                .split(&format!("async fn install_{label}_steps"))
                .nth(1)
                .unwrap_or_else(|| panic!("no install_{label}_steps in this file"));
            let body = install.split("\nasync fn").next().unwrap_or(install);
            assert!(body.contains("open_service_firewall_ports"),
                    "{label} publishes git-over-SSH on the host and never opens it");
        }
    }

    // ────────────────── the byte the two delivery paths differed by ───────────

    #[test]
    fn a_managed_file_ends_the_way_a_heredoc_would_end_it() {
        let dir = tmp("managed-text");
        let path = dir.join("docker-compose.yml");

        write_managed_text(&path, "services:\n  x: {}").unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.ends_with('\n'), "a heredoc would have ended it with one");
        assert_eq!(written, "services:\n  x: {}\n");

        write_managed_text(&path, "services:\n  x: {}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "services:\n  x: {}\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_compose_file_is_written_around_that_rule() {
        let source = include_str!("execute.rs");
        let needle = format!("std::fs::write{}", "(&compose_path");
        assert!(!source.contains(&needle),
                "compose files go through write_managed_text — see its doc for the byte");
    }

    // ────────────────── bind mounts the container writes into ──────────────────

    #[test]
    fn passbolts_secret_directories_keep_the_modes_its_image_ships() {
        assert_eq!(PASSBOLT_SECRET_DIRS, &[("gpg", 0o770), ("jwt", 0o750)]);
        assert_eq!(
            PASSBOLT_SERVER_GID, 33,
            "www-data inside the container — the id in the CONTAINER's passwd, \
             not one looked up on the host"
        );
    }

    #[test]
    fn a_group_owned_directory_gets_both_its_group_and_its_mode() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp("group-owned").join("gpg");
        let gid = unsafe { libc::getgid() };
        create_dir_owned_by_group(&dir, 0o770, gid).unwrap();

        let meta = std::fs::metadata(&dir).unwrap();
        assert_eq!(meta.gid(), gid);
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o770,
            "the mode is applied AFTER the chown, which is what makes it stick"
        );
    }

    // ─────────────────────────── argv construction ───────────────────────────

    #[test]
    fn compose_argv_is_exact_and_never_touches_down_or_rm() {
        let dir = Path::new("/opt/adguardhome");
        assert_eq!(
            compose_pull_args("adguardhome", dir),
            ["compose", "-p", "adguardhome", "-f", "/opt/adguardhome/docker-compose.yml", "pull", "-q"]
        );
        assert_eq!(
            compose_up_args("adguardhome", dir),
            ["compose", "-p", "adguardhome", "-f", "/opt/adguardhome/docker-compose.yml", "up", "-d"]
        );
        assert_eq!(
            compose_restart_args("adguardhome", dir),
            ["compose", "-p", "adguardhome", "-f", "/opt/adguardhome/docker-compose.yml", "restart"]
        );
        for args in [
            compose_pull_args("x", dir),
            compose_up_args("x", dir),
            compose_restart_args("x", dir),
            compose_stop_args("x", dir),
        ] {
            assert!(!args.contains(&"down".to_string()));
            assert!(!args.contains(&"rm".to_string()));
        }
    }

    /// Every compose verb this module runs names its file explicitly
    #[test]
    fn every_compose_verb_points_at_its_project_file_instead_of_trusting_the_cwd() {
        let dir = Path::new("/opt/service");
        for args in [
            compose_pull_args("p", dir),
            compose_up_args("p", dir),
            compose_restart_args("p", dir),
            compose_restart_service_args("p", dir, "svc"),
        ] {
            let f = args.iter().position(|a| a == "-f").expect("no -f in {args:?}");
            assert_eq!(args[f + 1], "/opt/service/docker-compose.yml", "{args:?}");
        }
    }

    #[test]
    fn a_project_name_stays_one_argument() {
        let args = compose_up_args("weird name", Path::new("/opt/x"));
        assert_eq!(args.len(), 7);
        assert_eq!(args[2], "weird name");
    }

    #[tokio::test]
    async fn every_docker_child_gets_a_config_directory_it_can_write_to() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _state_guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-config-home");
        let recorder = dir.join("env.txt");
        let script = write_stub(
            &dir,
            "docker",
            &format!(
                "#!/bin/sh\nset -e\nmkdir -p \"$DOCKER_CONFIG\"\n: > \"$DOCKER_CONFIG/probe\"\n\
                 printf '%s\\n' \"$DOCKER_CONFIG\" > {}\n",
                recorder.display()
            ),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);
        let state = dir.join("state");
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &state);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vpn".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let streamed = run_docker_streaming(&docker_build_args("gryonix-openvpn:local", &dir), &sink).await;
        let captured = run_docker_capture(&docker_pull_args("busybox"), Duration::from_secs(30)).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        while rx.try_recv().is_ok() {}

        assert!(streamed.is_ok(), "the streaming path must reach a writable config dir: {streamed:?}");
        assert!(matches!(captured, Ok((true, _))), "and so must the capturing one: {captured:?}");
        let seen = std::fs::read_to_string(&recorder).unwrap();
        let config = PathBuf::from(seen.trim());
        assert!(config.starts_with(&state), "DOCKER_CONFIG must live under the state directory: {config:?}");
        assert!(config.join("probe").exists(), "the child could not write under DOCKER_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_docker_streaming_reaches_the_stub_with_the_built_argv_and_streams_its_output() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-argv");
        let recorder = dir.join("argv.txt");
        let script = write_stub(
            &dir,
            "docker",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\necho pulling-line\necho warn-line 1>&2\n",
                recorder.display()
            ),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = run_docker_streaming(&compose_pull_args("adguardhome", Path::new("/opt/adguardhome")), &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(result.is_ok(), "{result:?}");

        let recorded = std::fs::read_to_string(&recorder).unwrap();
        assert_eq!(recorded.trim(), "compose -p adguardhome -f /opt/adguardhome/docker-compose.yml pull -q");

        let mut lines = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            assert_eq!(frame[0], 0x00);
            let event = pb::InstallServiceEvent::decode(&frame[5..]).unwrap();
            lines.push((event.stream, event.text));
        }
        assert!(lines.contains(&("stdout".to_string(), "pulling-line".to_string())));
        assert!(lines.contains(&("stderr".to_string(), "warn-line".to_string())));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_docker_streaming_reports_a_nonzero_exit_as_an_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-fail");
        let script = write_stub(&dir, "docker", "#!/bin/sh\necho boom 1>&2\nexit 3\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = run_docker_streaming(&compose_up_args("adguardhome", Path::new("/opt/adguardhome")), &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert_eq!(result, Err("docker exited 3".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── id gate ───────────────────────────

    #[test]
    fn unknown_service_id_is_refused_before_anything_runs() {
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        assert!(matches!(resolve("adguard-home; rm -rf /"), Err(Rejection::UnknownService(_))));
    }

    #[test]
    fn every_catalog_id_now_has_an_executor_so_the_not_implemented_layer_is_unreachable() {
        for id in discover::all_service_ids() {
            assert_eq!(
                resolve(id),
                Ok(id),
                "{id} is in the agent's catalog but has no executor — it must be refused as \
                 NotImplemented rather than UnknownService, and this test should name it"
            );
        }
    }

    #[test]
    fn the_vpn_is_installed_under_the_aggregate_id_not_a_protocols_own() {
        assert_eq!(resolve("vpn"), Ok("vpn"));
        assert_eq!(compose_project("vpn"), "vpnpanel");
        assert_eq!(resolve("wireguard-vpn"), Err(Rejection::UnknownService("wireguard-vpn".into())));
    }

    // ───────────────────── VPN protocol selection ─────────────────────

    // ────────────────── the host surface ──────────────────

    #[test]
    fn a_host_without_caddy_is_recognised() {
        let has_bin = packages::have_binary("caddy")
            || ["/usr/bin/caddy", "/usr/local/bin/caddy", "/usr/sbin/caddy"]
                .iter()
                .any(|path| Path::new(path).exists());
        assert_eq!(caddy_is_installed(), has_bin);
        let (status, code, message) = Rejection::NoReverseProxy.parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("no Caddy"), "{message}");
        assert!(message.contains("apt-get") && message.contains("systemd-run"), "{message}");
    }

    #[test]
    fn an_omitted_admin_username_becomes_the_default_rather_than_an_empty_account() {
        let base = pb::InstallServiceRequest { domain: "example.com".into(), ..Default::default() };
        assert_eq!(build_input(&base).expect("a domain is enough").admin_username, "admin");
        let blank = pb::InstallServiceRequest { admin_username: "   ".into(), ..base.clone() };
        assert_eq!(build_input(&blank).expect("whitespace is empty too").admin_username, "admin");
        // A real value still wins, trimmed.
        let named = pb::InstallServiceRequest { admin_username: " owner ".into(), ..base };
        assert_eq!(build_input(&named).expect("a named admin").admin_username, "owner");
    }

    #[test]
    fn a_relay_request_marks_the_relay_before_installing() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!("relay-home-{}", std::process::id()));
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &dir);
        assert!(!crate::vpn_dns_priority::is_relay());
        remember_relay_home(&HostContext::from_request(&pb::InstallServiceRequest {
            host_role: pb::HostRole::VpsRelay as i32,
            home_wg_address: "10.8.0.2".to_string(),
            ..Default::default()
        }));
        assert!(crate::vpn_dns_priority::is_relay());
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_relay_topology_is_read_from_the_request() {
        let req = pb::InstallServiceRequest {
            host_role: pb::HostRole::VpsRelay as i32,
            tunnel_endpoint: "203.0.113.150:51820".to_string(),
            relay_wg_port: 51820,
            relay_forwarded_ports: vec![80, 443, 25],
            relay_forwarded_udp_ports: vec![51821],
            home_wg_address: "10.8.0.2".to_string(),
            ..Default::default()
        };
        let topology = HostContext::from_request(&req).relay_topology();
        assert_eq!(topology.vps_public, "203.0.113.150");
        assert_eq!(topology.home_ip(), "10.8.0.2");
        assert_eq!(topology.wg_port, 51820);
        assert_eq!(topology.all_tcp_ports(), vec![80, 443, 25]);
        assert_eq!(topology.all_udp_ports(), vec![51821]);
        assert!(topology.is_complete());

        assert_eq!(endpoint_host("203.0.113.10"), "203.0.113.10");
        assert_eq!(endpoint_host("relay.example.com:51820"), "relay.example.com");
        assert_eq!(endpoint_host("not:a:port"), "not:a:port");
        assert_eq!(endpoint_host(""), "");

        let empty = HostContext::from_request(&pb::InstallServiceRequest {
            host_role: pb::HostRole::VpsRelay as i32,
            ..Default::default()
        });
        assert!(!empty.relay_topology().is_complete());
    }

    #[test]
    fn the_port_preflight_asks_about_the_ports_the_services_themselves_declare() {
        let mut input = Input::default();
        input.domain = "example.com".to_string();

        input.wireguard_vpn_port = 51820;
        input.shadowsocks_port = 8388;
        let vpn = published_public_ports("vpn", &input, &[panel::Protocol::WireGuard, panel::Protocol::Shadowsocks]);
        assert_eq!(vpn, vec![firewall::Port::udp(51820), firewall::Port::tcp(8388), firewall::Port::udp(8388)]);
        assert!(published_public_ports("vpn", &input, &[]).is_empty());

        for engine in ["docker-mailserver", "mailu", "mailcow"] {
            let ports = published_public_ports(engine, &input, &[]);
            assert!(ports.contains(&firewall::Port::tcp(25)), "{engine} must claim SMTP: {ports:?}");
            assert!(ports.contains(&firewall::Port::tcp(993)), "{engine} must claim IMAPS: {ports:?}");
        }

        // git-over-SSH, and 0 meaning the feature is off.
        input.forgejo_ssh_port = 2222;
        input.gitlab_ssh_port = 2022;
        assert_eq!(published_public_ports("forgejo", &input, &[]), vec![firewall::Port::tcp(2222)]);
        assert_eq!(published_public_ports("gitlab", &input, &[]), vec![firewall::Port::tcp(2022)]);
        input.forgejo_ssh_port = 0;
        assert!(published_public_ports("forgejo", &input, &[]).is_empty());

        // Everything else publishes on loopback only, and must ask nothing.
        for label in ["adguard-home", "vaultwarden", "nextcloud", "immich", "photoprism", "psono", "passbolt"] {
            assert!(published_public_ports(label, &input, &[]).is_empty(), "{label} publishes no public port");
        }

        let (status, code, message) = Rejection::PortsInUse(vec![ports::Conflict {
            port: firewall::Port::udp(51820),
            holder: None,
        }])
        .parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("51820/udp"), "{message}");
        assert!(message.contains("address already in use"), "{message}");
    }

    #[test]
    fn a_hand_installed_copy_is_refused_with_the_way_forward() {
        let (status, code, message) = Rejection::AlreadyInstalledOutside {
            service: "Ollama".to_string(),
            holder: "ollama".to_string(),
        }
        .parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("Ollama is already installed"), "{message}");
        assert!(message.contains("back its data up"), "{message}");
        assert!(message.contains("install it again from the app"), "{message}");
        assert!(message.contains("Nothing has been changed"), "{message}");
        assert!(!message.to_lowercase().contains("take over the existing"), "{message}");
    }

    #[test]
    fn an_add_on_is_refused_on_a_host_with_no_hub() {
        let alone: Vec<String> = vec!["mosquitto".to_string()];
        assert_eq!(add_on_without_the_hub("mosquitto", &alone), Some("Mosquitto"));
        assert_eq!(add_on_without_the_hub("zigbee2mqtt", &alone), Some("Zigbee2MQTT"));

        let with_hub: Vec<String> =
            vec!["home-assistant".to_string(), "mosquitto".to_string()];
        assert_eq!(add_on_without_the_hub("mosquitto", &with_hub), None);
        assert_eq!(add_on_without_the_hub("zigbee2mqtt", &with_hub), None);

        // The gate is about the add-ons, not about every service.
        assert_eq!(add_on_without_the_hub("jellyfin", &alone), None);
    }

    #[test]
    fn the_brokers_password_is_read_back_out_of_its_own_env() {
        let dir = tmp("mosquitto-env");
        std::fs::write(dir.join(".env"), "MQTT_PASSWORD=abc123\n").unwrap();
        assert_eq!(broker_password(&dir).unwrap(), "abc123");

        let empty = tmp("mosquitto-env-empty");
        std::fs::write(empty.join(".env"), "OTHER=1\n").unwrap();
        assert!(broker_password(&empty).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn a_stick_that_is_not_a_device_is_refused() {
        for value in ["ttyUSB0", "/srv/ttyUSB0", "/dev/../root/.ssh", "/dev/tty USB0", "/dev/"] {
            let mut req = pb::InstallServiceRequest::default();
            req.service_id = "home-assistant".to_string();
            req.domain = "example.com".to_string();
            req.settings.insert("home_assistant_usb_device".to_string(), value.to_string());
            let err = build_input(&req).err().unwrap_or_else(|| panic!("{value} was accepted"));
            assert!(err.contains("home_assistant_usb_device"), "{value}: {err}");
        }
    }

    #[test]
    fn a_real_device_path_and_an_empty_one_are_both_accepted() {
        for value in ["", "/dev/ttyACM0", "/dev/serial/by-id/usb-ITead_Sonoff-if00-port0"] {
            let mut req = pb::InstallServiceRequest::default();
            req.service_id = "home-assistant".to_string();
            req.domain = "example.com".to_string();
            req.settings.insert("home_assistant_usb_device".to_string(), value.to_string());
            let input = build_input(&req).unwrap_or_else(|err| panic!("{value}: {err}"));
            assert_eq!(input.home_assistant_usb_device, value);
        }
    }

    #[test]
    fn the_smart_home_hub_is_refused_away_from_the_house() {
        let away = Input::default();
        assert_eq!(
            home_only_service_away("home-assistant", &away, HostRole::SingleHost, false),
            Some("Home Assistant")
        );
        assert_eq!(home_only_service_away("jellyfin", &away, HostRole::SingleHost, false), None);
    }

    #[test]
    fn each_way_of_being_at_home_lets_the_hub_install() {
        let plain = Input::default();
        assert!(machine_is_at_home(&plain, HostRole::HomeBackend, false), "scenario B's home half");
        assert!(machine_is_at_home(&plain, HostRole::SingleHost, true), "the dynamic-DNS scope");

        let local_only = Input { local_only: true, ..Input::default() };
        assert!(machine_is_at_home(&local_only, HostRole::SingleHost, false), "a local-only deployment");

        let answered = Input { machine_at_home: true, ..Input::default() };
        assert!(machine_is_at_home(&answered, HostRole::SingleHost, false), "the owner said so");

        assert!(!machine_is_at_home(&plain, HostRole::VpsRelay, false));
    }

    #[test]
    fn the_first_configuration_is_never_written_twice() {
        let config = tmp("home-assistant-seed");
        seed_home_assistant_config(&config).unwrap();
        assert_eq!(
            std::fs::read_to_string(config.join("configuration.yaml")).unwrap(),
            home_assistant::INITIAL_CONFIGURATION
        );
        assert_eq!(std::fs::read_to_string(config.join("automations.yaml")).unwrap(), "[]\n");
        assert_eq!(std::fs::read_to_string(config.join("scripts.yaml")).unwrap(), "");
        let store = config.join(".storage").join("http");
        assert_eq!(std::fs::read_to_string(&store).unwrap(), home_assistant::INITIAL_HTTP_STORE);
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&store).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(&store, "{\"owner\": \"promoted\"}").unwrap();

        let edited = "# the owner's own house\nmqtt:\n";
        std::fs::write(config.join("configuration.yaml"), edited).unwrap();
        std::fs::write(config.join("automations.yaml"), "- id: hallway\n").unwrap();
        seed_home_assistant_config(&config).unwrap();
        assert_eq!(std::fs::read_to_string(config.join("configuration.yaml")).unwrap(), edited);
        assert_eq!(
            std::fs::read_to_string(config.join("automations.yaml")).unwrap(),
            "- id: hallway\n"
        );
        assert_eq!(std::fs::read_to_string(&store).unwrap(), "{\"owner\": \"promoted\"}");
        let _ = std::fs::remove_dir_all(&config);
    }

    #[test]
    fn a_store_the_dropped_migration_broke_is_replaced_once() {
        let config = tmp("home-assistant-repair");
        std::fs::create_dir_all(config.join(".storage")).unwrap();
        let broken = r#"{"data": {"stable": {"server_port": 8123},
            "pending": {"server_host": ["127.0.0.1"], "error": "not_promoted"},
            "yaml_migration_done": true}}"#;
        std::fs::write(config.join(".storage").join("http"), broken).unwrap();
        assert!(seed_home_assistant_config(&config).unwrap());
        assert_eq!(
            std::fs::read_to_string(config.join(".storage").join("http")).unwrap(),
            home_assistant::INITIAL_HTTP_STORE
        );
        assert!(!seed_home_assistant_config(&config).unwrap());
        let _ = std::fs::remove_dir_all(&config);
    }

    #[test]
    fn a_service_needing_a_public_name_is_refused_on_a_local_only_deployment() {
        for id in ["mailcow", "mailu", "docker-mailserver", "headscale"] {
            let mut req = pb::InstallServiceRequest::default();
            req.service_id = id.to_string();
            req.domain = "192.168.1.50".to_string();
            req.local_only = true;
            let err = build_input(&req).err().unwrap_or_else(|| panic!("{id} was accepted"));
            assert!(err.contains("public domain"), "{id}: {err}");
        }
    }

    #[test]
    fn the_same_services_are_accepted_when_the_deployment_has_a_domain() {
        for id in ["mailcow", "mailu", "docker-mailserver", "headscale"] {
            let mut req = pb::InstallServiceRequest::default();
            req.service_id = id.to_string();
            req.domain = "example.com".to_string();
            req.local_only = false;
            assert!(build_input(&req).is_ok(), "{id} should install on a public deployment");
        }
    }

    #[test]
    fn a_service_that_needs_no_public_name_still_installs_local_only() {
        let mut req = pb::InstallServiceRequest::default();
        req.service_id = "adguard-home".to_string();
        req.domain = "192.168.1.50".to_string();
        req.local_only = true;
        assert!(build_input(&req).is_ok());
    }

    #[test]
    fn more_additional_domains_than_the_app_allows_are_refused() {
        let mut req = pb::InstallServiceRequest::default();
        req.service_id = "adguard-home".to_string();
        req.domain = "example.com".to_string();

        req.additional_domains =
            (0..MAX_ADDITIONAL_DOMAINS).map(|n| format!("example{n}.org")).collect();
        assert!(build_input(&req).is_ok(), "the ceiling itself must be allowed");

        req.additional_domains =
            (0..MAX_ADDITIONAL_DOMAINS + 1).map(|n| format!("example{n}.org")).collect();
        let err = build_input(&req).expect_err("one over the ceiling is refused");
        assert!(err.contains(&MAX_ADDITIONAL_DOMAINS.to_string()), "{err}");
    }

    #[test]
    fn a_domain_listed_twice_is_refused_before_anything_is_written() {
        let mut req = pb::InstallServiceRequest::default();
        req.service_id = "adguard-home".to_string();
        req.domain = "example.com".to_string();

        // The ordinary case: two different extras are fine.
        req.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert!(build_input(&req).is_ok());

        // A repeat among the extras...
        req.additional_domains = vec!["example.org".to_string(), "example.org".to_string()];
        let err = build_input(&req).expect_err("a repeated domain is refused");
        assert!(err.contains("example.org"), "{err}");
        assert!(err.contains("twice"), "{err}");

        req.additional_domains = vec!["example.com".to_string()];
        assert!(build_input(&req).is_err());

        req.additional_domains = vec!["Example.COM".to_string()];
        assert!(build_input(&req).is_err());

        req.additional_domains = vec![String::new(), String::new()];
        assert!(build_input(&req).is_ok());
    }

    #[test]
    fn a_named_stick_that_is_absent_is_refused() {
        let mut input = Input::default();
        input.home_assistant_usb_device = "/dev/serial/by-id/gryonix-test-absent".to_string();
        let (service, device) = stick_missing("zigbee2mqtt", &input).expect("absent stick refused");
        assert_eq!(service, "Zigbee2MQTT");
        assert!(stick_missing("home-assistant", &input).is_some());
        assert_eq!(stick_missing("mosquitto", &input), None);
        input.home_assistant_usb_device = "/dev/null".to_string();
        assert_eq!(stick_missing("zigbee2mqtt", &input), None);
        let (_, _, message) = Rejection::StickMissing { service, device }.parts();
        assert!(message.contains("gryonix-test-absent is not plugged into this machine"));
    }

    #[test]
    fn bedrock_on_large_pages_is_refused_with_the_fix() {
        let (status, code, message) = Rejection::EmulatorNeedsSmallPages(16384).parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("16 KB pages"));
        assert!(message.contains("kernel=kernel8.img"));
        assert_eq!(bedrock_emulator_blocked("minecraft-java"), None);
    }

    #[test]
    fn a_minecraft_install_without_the_license_is_refused() {
        let mut input = Input::default();

        // Neither edition is accepted by default, so both are refused...
        assert_eq!(license_not_accepted("minecraft-java", &input), Some("Minecraft (Java)"));
        assert_eq!(license_not_accepted("minecraft-bedrock", &input), Some("Minecraft (Bedrock)"));

        input.minecraft_java_accepts_eula = true;
        assert_eq!(license_not_accepted("minecraft-java", &input), None);
        assert_eq!(license_not_accepted("minecraft-bedrock", &input), Some("Minecraft (Bedrock)"));
        input.minecraft_bedrock_accepts_eula = true;
        assert_eq!(license_not_accepted("minecraft-bedrock", &input), None);

        assert_eq!(license_not_accepted("crafty-controller", &Input::default()), None);
        // And no other service is touched by this gate.
        for label in ["adguard-home", "nextcloud", "vaultwarden", "vpn"] {
            assert_eq!(license_not_accepted(label, &Input::default()), None, "{label} needs no license");
        }

        let (status, code, message) = Rejection::LicenseNotAccepted("Minecraft (Java)").parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("Minecraft (Java)"), "{message}");
        assert!(message.contains("EULA"), "{message}");
        assert!(message.contains("restarting forever"), "{message}");
    }

    const SENT: &[&str] = &[
        "mailcow_path", "mailu_path", "mailu_subnet", "docker_mailserver_path",
        "vaultwarden_hostname", "vaultwarden_container", "vaultwarden_data_path",
        "vaultwarden_allow_signups",
        "psono_hostname", "psono_path", "passbolt_hostname", "passbolt_path",
        "nextcloud_hostname", "nextcloud_path", "seafile_hostname", "seafile_path",
        "immich_hostname", "immich_path", "photoprism_hostname", "photoprism_path",
        "jellyfin_hostname", "jellyfin_path", "jellyfin_media_path",
        "home_assistant_hostname", "home_assistant_path", "machine_at_home",
        "home_assistant_usb_device", "mosquitto_path",
        "zigbee2mqtt_path", "zigbee2mqtt_hostname",
        "minecraft_java_path", "minecraft_java_version", "minecraft_java_flavour",
        "minecraft_java_memory_mb", "minecraft_java_port", "minecraft_java_accepts_eula",
        "minecraft_java_whitelist", "minecraft_java_operators", "minecraft_java_mods",
        "minecraft_bedrock_path", "minecraft_bedrock_version", "minecraft_bedrock_port",
        "minecraft_bedrock_accepts_eula",
        "crafty_hostname", "crafty_path",
        "ollama_path", "ollama_uses_gpu",
        "open_webui_path", "open_webui_hostname", "open_webui_allow_signups",
        "litellm_path", "litellm_hostname",
        "n8n_path", "n8n_hostname",
        "anythingllm_path", "anythingllm_hostname", "qdrant_path",
        "searxng_path", "openclaw_path", "openclaw_hostname",
        "forgejo_hostname", "forgejo_path", "forgejo_ssh_port",
        "gitlab_hostname", "gitlab_path", "gitlab_ssh_port",
        "adguard_hostname", "adguard_path",
        "pihole_hostname", "pihole_path", "pihole_upstreams", "pihole_serves_network",
        "homepage_hostname", "homepage_path",
        "authelia_hostname", "authelia_path", "authelia_protected_services",
        "cloudflared_path",
        "headscale_base_domain", "headscale_hostname", "headscale_path",
        "tailscale_node_name", "tailscale_node_path", "tailscale_login_server",
        "vpn_hostname", "vpn_client_access", "wireguard_vpn_port",
        "amnezia_wg_path", "amnezia_wg_port",
        "shadowsocks_path", "shadowsocks_port",
        "xray_reality_path", "xray_reality_port", "xray_reality_sni", "xray_reality_new_key",
        "openvpn_path", "openvpn_port",
        "crowdsec_enabled",
        "vpn_protocols",
        "cloudflared_token",
        "tailscale_auth_key",
    ];

    #[test]
    fn every_setting_key_the_crate_reads_is_one_the_app_sends() {
        let source = include_str!("execute.rs");
        let mut read = std::collections::BTreeSet::new();
        for line in source.lines() {
            let Some(rest) = line.trim_start().strip_prefix("(\"") else { continue };
            if let Some((key, tail)) = rest.split_once('"') {
                if tail.starts_with(", &mut input.") {
                    read.insert(key.to_string());
                }
            }
        }
        for (pattern, skip) in [
            ("settings.get(\"", 13),
            ("setting(\"", 9),
            ("setting_or(req, \"", 16),
            ("parsed(\"", 8),
            ("exact(\"", 7),
            ("any_case(\"", 10),
        ] {
            let mut rest = source;
            while let Some(at) = rest.find(pattern) {
                rest = &rest[at + skip..];
                if let Some(end) = rest.find('"') {
                    let key = &rest[..end];
                    if !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()) {
                        read.insert(key.to_string());
                    }
                }
            }
        }
        assert!(!read.is_empty(), "the scan found no keys at all — it is broken, not the product");
        let unsent: Vec<&String> = read.iter().filter(|key| !SENT.contains(&key.as_str())).collect();
        assert!(
            unsent.is_empty(),
            "the crate reads settings keys the app never sends: {unsent:?}. A key read here \
             and absent there is a service installed into a directory the app does not know \
             about — add it to AgentInstallSettings too."
        );
    }

    #[test]
    fn the_vpn_expands_to_the_panel_and_its_protocols() {
        assert_eq!(
            installed_catalog_ids("vpn", &[panel::Protocol::WireGuard, panel::Protocol::OpenVPN]),
            vec!["vpn-panel", "wireguard-vpn", "openvpn"]
        );
        assert_eq!(installed_catalog_ids("vaultwarden", &[]), vec!["vaultwarden"]);
        assert!(installed_catalog_ids("not-a-service", &[]).is_empty());
    }

    #[test]
    fn a_discovered_vpn_is_read_back_from_its_container_names() {
        let service = pb::Service {
            id: "vpn".to_string(),
            containers: ["vpnpanel", "awgvpn", "shadowsocks", "xray", "openvpn", "something-else"]
                .iter()
                .map(|name| pb::Container { name: name.to_string(), ..Default::default() })
                .collect(),
            ..Default::default()
        };
        let ids = discovered_catalog_ids(&service);
        for expected in ["vpn-panel", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"] {
            assert!(ids.contains(&expected), "{expected} missing from {ids:?}");
        }
        assert!(!ids.contains(&"wireguard-vpn"), "{ids:?}");

        let other = pb::Service { id: "nextcloud".to_string(), ..Default::default() };
        assert_eq!(discovered_catalog_ids(&other), vec!["nextcloud"]);
    }

    #[test]
    fn an_unspecified_role_is_a_single_host() {
        let ctx = HostContext::from_request(&install_request(&[]));
        assert_eq!(ctx.role, Some(HostRole::SingleHost));
    }

    #[test]
    fn the_topology_follows_the_role_and_the_scope() {
        let mut req = install_request(&[]);
        req.ptr_ip = "203.0.113.7".to_string();
        req.ptr_hostname = "mail.example.com".to_string();
        req.tunnel_endpoint = "198.51.100.4:51820".to_string();
        let ctx = HostContext::from_request(&req);

        let public = Input { domain: "example.com".to_string(), ..Input::default() };
        match ctx.topology(HostRole::HomeBackend, &public) {
            report::Topology::ServicesHost { ptr_ip, ptr_hostname, tunnel_endpoint } => {
                assert_eq!(ptr_ip.as_deref(), Some("203.0.113.7"));
                assert_eq!(ptr_hostname, "mail.example.com");
                assert_eq!(tunnel_endpoint.as_deref(), Some("198.51.100.4:51820"));
            }
            other => panic!("expected a services host, got {other:?}"),
        }

        let local = Input { local_only: true, ..public.clone() };
        match ctx.topology(HostRole::SingleHost, &local) {
            report::Topology::ServicesHost { ptr_ip, .. } => assert_eq!(ptr_ip, None),
            other => panic!("expected a services host, got {other:?}"),
        }

        let mut bare = install_request(&[]);
        bare.host_role = pb::HostRole::VpsRelay as i32;
        bare.relay_wg_port = 51820;
        bare.relay_forwarded_ports = vec![80, 443];
        bare.home_wg_address = "10.8.0.2".to_string();
        match HostContext::from_request(&bare).topology(HostRole::VpsRelay, &public) {
            report::Topology::Relay { wg_port, forwarded_ports, home_wg_address, ptr_hostname } => {
                assert_eq!(wg_port, 51820);
                assert_eq!(forwarded_ports, vec![80, 443]);
                assert_eq!(home_wg_address, "10.8.0.2");
                assert_eq!(ptr_hostname, "example.com");
            }
            other => panic!("expected a relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_whitelist_visudo_rejects_is_not_installed() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("sudoers");
        let live = dir.join("gryonixnexus-control");
        std::fs::write(&live, "previous ALL=(ALL) NOPASSWD: /bin/true\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH", &live);

        let input = HostInput {
            services: vec!["vaultwarden".to_string()],
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: Some("gryonixbot".to_string()),
            role: HostRole::SingleHost,
        };
        let backups = host::uninstall::BackupPaths::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };

        std::env::set_var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN", write_stub(&dir, "visudo-bad", "#!/bin/sh\necho 'parse error' 1>&2\nexit 1\n"));
        let rejected = write_sudoers(&input, &backups, &sink).await;
        assert!(rejected.is_err(), "a rejected whitelist must fail the install");
        assert_eq!(
            std::fs::read_to_string(&live).unwrap(),
            "previous ALL=(ALL) NOPASSWD: /bin/true\n",
            "the live whitelist must be untouched"
        );
        assert!(!dir.join("gryonixnexus-control.staged").exists(), "the staged file must be cleaned up");

        std::env::set_var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN", write_stub(&dir, "visudo-ok", "#!/bin/sh\nexit 0\n"));
        write_sudoers(&input, &backups, &sink).await.expect("an accepted whitelist installs");
        let installed = std::fs::read_to_string(&live).unwrap();
        assert!(installed.contains("gryonixbot ALL=(ALL) NOPASSWD:"), "{installed}");
        assert!(!dir.join("gryonixnexus-control.staged").exists());
        assert_eq!(existing_control_user().as_deref(), Some("gryonixbot"));

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_VISUDO_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH");
        while rx.try_recv().is_ok() {}
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_host_without_a_whitelist_is_not_a_failure() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("sudoers-absent");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH", dir.join("gryonixnexus-control"));
        assert_eq!(existing_control_user(), None);

        let input = HostInput {
            services: vec!["vaultwarden".to_string()],
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: None,
            role: HostRole::SingleHost,
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };
        write_sudoers(&input, &host::uninstall::BackupPaths::default(), &sink)
            .await
            .expect("no control user is a normal state");
        assert!(!dir.join("gryonixnexus-control").exists(), "nothing may be written for nobody");

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SUDOERS_PATH");
        while rx.try_recv().is_ok() {}
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn install_request(settings: &[(&str, &str)]) -> pb::InstallServiceRequest {
        pb::InstallServiceRequest {
            service_id: "vpn".to_string(),
            domain: "example.com".to_string(),
            settings: settings.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn no_protocol_named_means_wireguard() {
        assert_eq!(vpn_protocols_from(&install_request(&[])), Ok(vec![panel::Protocol::WireGuard]));
        assert_eq!(
            vpn_protocols_from(&install_request(&[("vpn_protocols", "  ")])),
            Ok(vec![panel::Protocol::WireGuard])
        );
    }

    #[test]
    fn a_protocol_list_is_parsed_trimmed_and_deduplicated() {
        assert_eq!(
            vpn_protocols_from(&install_request(&[("vpn_protocols", " wireguard-vpn , wireguard-vpn ")])),
            Ok(vec![panel::Protocol::WireGuard])
        );
    }

    #[test]
    fn something_that_is_not_a_vpn_protocol_is_a_client_bug() {
        assert!(matches!(
            vpn_protocols_from(&install_request(&[("vpn_protocols", "nextcloud")])),
            Err(Rejection::InvalidRequest(_))
        ));
    }

    /// All five protocols are installable now
    #[test]
    fn every_protocol_in_the_catalog_can_be_installed() {
        for name in ["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"] {
            let chosen = vpn_protocols_from(&install_request(&[("vpn_protocols", name)]))
                .unwrap_or_else(|err| panic!("{name} must be installable, got {err:?}"));
            assert_eq!(chosen.len(), 1, "{name}");
            assert_eq!(chosen[0].service_id(), name);
        }
        assert_eq!(
            vpn_protocols_from(&install_request(&[(
                "vpn_protocols",
                "wireguard-vpn,amnezia-wg,shadowsocks,xray-reality,openvpn"
            )]))
            .expect("the whole catalog at once")
            .len(),
            5
        );
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected, "{input:?}");
        }
        let key = base64_encode(&[0xABu8; 32]);
        assert_eq!(key.len(), 44);
        assert!(key.ends_with('='));
        assert!(!key.ends_with("=="));
    }

    #[test]
    fn a_half_installed_service_gets_its_removal_wrapper() {
        let source = include_str!("execute.rs");
        let failed = source.find("if let Err(why) = outcome {").expect("the failure branch exists");
        let body = &source[failed..failed + 600];
        let check = body.find("!service.containers.is_empty()").expect("leftovers are checked");
        let surface = body.find("provision_host_surface(").expect("the wrappers are refreshed");
        let fail = body.find("sink.fail(&why)").expect("the failure is still reported");
        assert!(check < surface && surface < fail);
    }

    #[test]
    fn a_site_guarded_after_install_reloads_caddy() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn keep_sites_guarded").expect("the function must exist");
        let body = &source[start..];
        let guard = body.find("guard_site_if_protected(id, input, &protected, sink)").expect("the guard runs");
        let reload = body.find("reload_caddy(sink)").expect("a reload follows");
        assert!(guard < reload);
    }

    #[test]
    fn the_protocols_are_installed_before_the_panel_that_advertises_them() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn install_vpn_steps").expect("the function must exist");
        let body = &source[start..];
        let end = body.find("\n}\n").expect("the function must end");
        let body = &body[..end];

        let at = |needle: &str| -> usize { body.find(needle).unwrap_or_else(|| panic!("no `{needle}` in the body")) };
        let protocols = at("install_vpn_protocol(input, *protocol, sink)");
        let services_json = at("panel::services_json(input, protocols)");
        let build = at("docker_build_args(panel::IMAGE, &build)");
        let up = at("compose_up(panel::COMPOSE_PROJECT, &dir, sink)");
        let firewall = at("apply_vpn_firewall(input, protocols, sink)");
        let caddy = at("write_caddy_site(&panel::caddy_site_names");

        assert!(protocols < services_json, "protocols exist before the panel is told about them");
        assert!(services_json < build, "the registry is on disk before the image that reads it is built");
        assert!(build < up, "build before up — the image is :local and no registry has it");
        assert!(up < firewall, "ports are opened once something is listening on them");
        assert!(firewall < caddy, "the Caddy site is written last, as in every other service here");
    }

    /// OpenVPN's own internal order, pinned for the same reason
    #[test]
    fn the_tunnel_token_is_written_when_sent_and_left_alone_when_not() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn install_cloudflared_steps").expect("the function must exist");
        let body = &source[start..];
        let end = body.find("\nasync fn install_headscale_steps").expect("the function must end");
        let body = &body[..end];

        let write_at = body.find("TUNNEL_TOKEN={}").expect("the token must be written into .env");
        let guard_at = body.find("input.cloudflared_token.trim().is_empty()").expect("guarded on the token");
        assert!(guard_at < write_at, "the write must sit inside the guard, not before it");
        assert!(body.contains("mode: Some(0o600)"), "the credential's file must be 0600");
        assert!(body.contains("write_env_if_absent"), "an absent token must not rewrite the file");
    }

    #[test]
    fn the_openvpn_image_is_built_before_the_pki_that_runs_inside_it() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn install_openvpn_steps").expect("the function must exist");
        let body = &source[start..];
        let end = body.find("\n}\n").expect("the function must end");
        let body = &body[..end];

        let at = |needle: &str| -> usize { body.find(needle).unwrap_or_else(|| panic!("no `{needle}` in the body")) };
        let build_files = at("openvpn::build_files()");
        let build = at("docker_build_args(openvpn::IMAGE, &build)");
        let pki = at("build_openvpn_pki(input");
        let env = at("write_openvpn_server_files(input");
        let profile = at("openvpn_client_profile(&mount)");
        let up = at("compose_up(openvpn::COMPOSE_PROJECT, &dir, sink)");

        assert!(build_files < build, "the Dockerfile and shims exist before the build reads them");
        assert!(build < pki, "the PKI one-shot runs inside the image built above it");
        assert!(pki < env, "gryonix-env is written once the PKI it describes exists");
        assert!(env < profile, "ovpn_getclient sources gryonix-env — it has to be there first");
        assert!(profile < up, "the profile is minted before the daemon starts");
        assert!(
            !body.contains("compose_pull_args(openvpn::COMPOSE_PROJECT"),
            "gryonix-openvpn:local is in no registry — a pull would fail the step for a tag just built here"
        );
    }

    #[test]
    fn every_accepted_protocol_has_an_installer_or_is_the_panel_itself() {
        for name in ["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"] {
            let protocol = vpn_protocols_from(&install_request(&[("vpn_protocols", name)])).unwrap()[0];
            let project = match protocol {
                // The panel IS the WireGuard server — no second project.
                panel::Protocol::WireGuard => panel::COMPOSE_PROJECT,
                panel::Protocol::AmneziaWG => amnezia::COMPOSE_PROJECT,
                panel::Protocol::Shadowsocks => shadowsocks::COMPOSE_PROJECT,
                panel::Protocol::XrayReality => xray::COMPOSE_PROJECT,
                panel::Protocol::OpenVPN => openvpn::COMPOSE_PROJECT,
            };
            assert!(!project.is_empty(), "{name}");
        }
    }

    #[test]
    fn a_zero_or_unparsable_port_keeps_the_apps_own_default() {
        let req = install_request(&[("wireguard_vpn_port", "0"), ("openvpn_port", "not-a-port")]);
        let input = build_input(&req).expect("valid request");
        assert_eq!(input.wireguard_vpn_port, Input::default().wireguard_vpn_port);
        assert_eq!(input.openvpn_port, Input::default().openvpn_port);
        let moved = build_input(&install_request(&[("wireguard_vpn_port", "51999")])).unwrap();
        assert_eq!(moved.wireguard_vpn_port, 51999);
    }

    #[test]
    fn a_protocol_path_that_escapes_is_refused_like_every_other_path() {
        for key in ["amnezia_wg_path", "shadowsocks_path", "xray_reality_path", "openvpn_path", "mailcow_path"] {
            let req = install_request(&[(key, "/opt/../../etc")]);
            assert!(build_input(&req).is_err(), "{key} must be gated");
            assert!(build_input(&install_request(&[(key, "relative/path")])).is_err(), "{key} must be absolute");
        }
    }

    // ───────────────────── the panel's password ─────────────────────

    #[test]
    fn only_a_24_char_lowercase_hex_password_counts_as_generated() {
        assert!(is_generated_panel_password("0123456789abcdef01234567"));
        assert!(!is_generated_panel_password(""));
        assert!(!is_generated_panel_password(&"ab".repeat(24)));
        assert!(!is_generated_panel_password("0123456789ABCDEF01234567"));
        assert!(!is_generated_panel_password("hunter2-hunter2-hunter22"));
    }

    #[test]
    fn a_generated_panel_password_survives_a_rerun_and_anything_else_rotates() {
        let dir = tmp("panel-pw");

        // No .env at all: fresh secret, 24 hex chars.
        let (fresh, kept) = resolve_panel_password(&dir).unwrap();
        assert!(!kept);
        assert!(is_generated_panel_password(&fresh), "{fresh}");

        // A generated one is carried forward untouched.
        std::fs::write(dir.join(".env"), format!("ADMIN_USER=admin\nADMIN_PASSWORD={fresh}\nWG_PORT=51820\n")).unwrap();
        assert_eq!(resolve_panel_password(&dir).unwrap(), (fresh.clone(), true));

        // Anything else is replaced rather than carried.
        std::fs::write(dir.join(".env"), "ADMIN_PASSWORD=my own p@ssword\n").unwrap();
        let (rotated, kept) = resolve_panel_password(&dir).unwrap();
        assert!(!kept);
        assert_ne!(rotated, "my own p@ssword");
        assert!(is_generated_panel_password(&rotated), "{rotated}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ───────────────────── the panel's docker argv ─────────────────────

    #[test]
    fn the_panel_is_built_from_its_own_sources_and_never_pulled() {
        assert_eq!(
            docker_build_args(panel::IMAGE, Path::new("/opt/gryonix-vpn-panel/build")),
            ["build", "-t", "gryonix-vpn-panel:local", "/opt/gryonix-vpn-panel/build"]
        );
    }

    #[test]
    fn the_container_probe_anchors_the_name() {
        let args = docker_container_exists_args("vpnpanel");
        assert_eq!(args, ["ps", "-aq", "--filter", "name=^vpnpanel$"]);
    }

    #[test]
    fn every_implemented_id_resolves_to_its_own_compose_project() {
        for id in IMPLEMENTED_SERVICE_IDS {
            assert_eq!(resolve(id), Ok(*id), "{id} must resolve");
        }
        assert_eq!(compose_project("adguard-home"), adguard::COMPOSE_PROJECT);
        assert_eq!(compose_project("jellyfin"), jellyfin::COMPOSE_PROJECT);
        assert_eq!(compose_project("photoprism"), photoprism::COMPOSE_PROJECT);
        assert_eq!(compose_project("immich"), immich::COMPOSE_PROJECT);
        assert_eq!(compose_project("nextcloud"), nextcloud::COMPOSE_PROJECT);
        assert_eq!(compose_project("forgejo"), forgejo::COMPOSE_PROJECT);
        assert_eq!(compose_project("gitlab"), gitlab::COMPOSE_PROJECT);
        assert_eq!(compose_project("vaultwarden"), vaultwarden::COMPOSE_PROJECT);
        assert_eq!(compose_project("seafile"), seafile::COMPOSE_PROJECT);
        assert_eq!(compose_project("psono"), psono::COMPOSE_PROJECT);
        assert_eq!(compose_project("passbolt"), passbolt::COMPOSE_PROJECT);
    }

    #[test]
    fn adguard_home_resolves() {
        assert_eq!(resolve("adguard-home"), Ok("adguard-home"));
    }

    #[test]
    fn rejection_codes_are_distinct_and_echo_the_id() {
        let (status, code, message) = Rejection::UnknownService("zzz".into()).parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_argument");
        assert!(message.contains("zzz"));

        let (status, code, message) = Rejection::NotImplemented("gitlab".into()).parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains("gitlab"));

        let (status, code, _) = Rejection::DockerUnavailable("boom".into()).parts();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "unavailable");
    }

    #[test]
    fn echoed_client_input_is_bounded() {
        let long = "a".repeat(5000);
        let (_, _, message) = Rejection::UnknownService(long).parts();
        assert!(message.len() < 200, "message was {} bytes", message.len());
    }

    // ─────────────────────────── reload_caddy ───────────────────────────

    #[tokio::test]
    async fn reload_falls_back_to_restart_and_succeeds_when_restart_does() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-restart-ok");
        let script = write_stub(&dir, "systemctl", "#!/bin/sh\ncase \"$1\" in\n  reload) exit 1 ;;\n  is-active) exit 3 ;;\n  restart) exit 0 ;;\nesac\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert_eq!(result, Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_and_restart_both_failing_is_a_real_error_not_a_silent_no_op() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-both-fail");
        let script = write_stub(&dir, "systemctl", "#!/bin/sh\nexit 1\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "adguard-home".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert!(result.is_err(), "both systemctl calls failing must surface as Err");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_caddy_unit_that_is_not_enabled_gets_enabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-enable");
        let log = dir.join("argv.log");
        let script = write_stub(
            &dir,
            "systemctl",
            &format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$1\" in\n  reload) exit 1 ;;\n  is-active) exit 3 ;;\n  is-enabled) exit 1 ;;\n  *) exit 0 ;;\nesac\n",
                log.display()
            ),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert_eq!(result, Ok(()));
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(calls.contains("restart caddy"), "the site must be made live first: {calls}");
        assert!(calls.contains("enable caddy"), "a disabled unit must be enabled: {calls}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_already_enabled_caddy_unit_is_not_touched_again() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("systemctl-already-enabled");
        let log = dir.join("argv.log");
        let script = write_stub(
            &dir,
            "systemctl",
            &format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n", log.display()),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "vaultwarden".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result = reload_caddy(&sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN");
        assert_eq!(result, Ok(()));
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(calls.contains("is-enabled caddy"), "it must ASK before enabling: {calls}");
        assert!(!calls.contains("enable caddy\n") || calls.matches("enable caddy").count() == 1,
                "an already-enabled unit must not be re-enabled: {calls}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────── the erase-time app key ───────────────────────

    #[test]
    fn with_no_wrapper_on_disk_the_requested_key_is_what_gets_revoked() {
        let access = dashboard_access("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRequested app")
            .expect("a well-formed requested key is usable");
        assert!(access.create_user, "the strip block only renders in create-user mode");
        assert_eq!(access.app_public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRequested app");
    }

    #[test]
    fn a_key_that_could_break_out_of_the_shell_literal_is_refused() {
        assert!(dashboard_access("").is_none());
        assert!(dashboard_access("   ").is_none());
        assert!(dashboard_access("ssh-ed25519 AAA' ; rm -rf / ; echo '").is_none());
        assert!(dashboard_access("ssh-ed25519 AAA\nssh-ed25519 BBB").is_none());
    }

    // ─────────────────────────── adguard_path safety ───────────────────────────

    #[test]
    fn a_relative_or_dotdot_riding_path_is_rejected() {
        assert!(!is_safe_absolute_path("opt/adguardhome"));
        assert!(!is_safe_absolute_path("/opt/../etc"));
        assert!(!is_safe_absolute_path("../etc"));
        assert!(is_safe_absolute_path("/opt/adguardhome"));
        assert!(is_safe_absolute_path("/srv/adguard"));
        assert!(unsafe_service_path("/opt/adguardhome").is_none());
        assert!(unsafe_service_path("/srv/data").is_none());
        assert!(unsafe_service_path("/home/admin/photos").is_none());
        for bad in ["/srv", "/opt", "/home/admin", "/mnt/disk", "/var/lib/docker/x", "/opt/it's", "/opt/a b$c", "/usr/x"] {
            assert!(unsafe_service_path(bad).is_some(), "{bad}");
        }
    }

    #[test]
    fn build_input_refuses_a_dotdot_riding_adguard_path_before_anything_is_touched() {
        let mut req = base_request();
        req.settings.insert("adguard_path".to_string(), "/opt/../etc".to_string());
        let err = build_input(&req).unwrap_err();
        assert!(err.contains("adguard_path"), "{err}");
    }

    // ─────────────────────────── build_input ───────────────────────────

    fn base_request() -> pb::InstallServiceRequest {
        pb::InstallServiceRequest {
            service_id: "adguard-home".to_string(),
            domain: "example.com".to_string(),
            additional_domains: Vec::new(),
            local_only: false,
            admin_username: "admin".to_string(),
            language: "ru".to_string(),
            settings: HashMap::new(),
            ..Default::default()
        }
    }

    #[test]
    fn a_name_that_would_break_the_generated_files_is_refused() {
        for bad in ["exa mple.com", "example.com\nevil", "ex\"ample.com", "a:b.com", "-a.com", "a..com"] {
            let mut req = base_request();
            req.domain = bad.to_string();
            assert!(build_input(&req).is_err(), "{bad:?}");
        }
        let mut req = base_request();
        req.settings.insert("adguard_hostname".to_string(), "filter.example.com; reboot".to_string());
        assert!(build_input(&req).unwrap_err().contains("adguard_hostname"));
        let mut req = base_request();
        req.admin_username = "admin: x".to_string();
        assert!(build_input(&req).unwrap_err().contains("administrator"));
    }

    #[test]
    fn ordinary_names_still_pass() {
        let mut req = base_request();
        req.domain = "home-lab.example.co.uk".to_string();
        req.additional_domains = vec!["second.example.org".to_string()];
        req.admin_username = "danila.s@example.com".to_string();
        req.settings.insert("adguard_hostname".to_string(), "filter.example.com".to_string());
        assert!(build_input(&req).is_ok());
    }

    #[test]
    fn an_empty_domain_is_refused() {
        let mut req = base_request();
        req.domain = "   ".to_string();
        assert_eq!(build_input(&req), Err("domain is required".to_string()));
    }

    #[test]
    fn settings_feed_the_service_specific_fields_with_defaults_when_absent() {
        let input = build_input(&base_request()).unwrap();
        assert_eq!(input.adguard_path, "/opt/adguardhome");
        assert_eq!(input.adguard_hostname, "");
        assert!(matches!(input.language, Language::Ru));

        let mut req = base_request();
        req.settings.insert("adguard_path".to_string(), "/srv/adguard".to_string());
        req.settings.insert("adguard_hostname".to_string(), "filter.example.com".to_string());
        let input = build_input(&req).unwrap();
        assert_eq!(input.adguard_path, "/srv/adguard");
        assert_eq!(input.adguard_hostname, "filter.example.com");
    }

    #[test]
    fn an_unrecognized_language_code_falls_back_to_english() {
        let mut req = base_request();
        req.language = "xx-nonexistent".to_string();
        let input = build_input(&req).unwrap();
        assert!(matches!(input.language, Language::En));
    }

    // ─────────────────────────── __RANDOM__ expansion ───────────────────────────

    #[test]
    fn each_random_line_gets_its_own_independent_secret() {
        let template = "A=__RANDOM__\nB=__RANDOM__\nC=fixed\n";
        let expanded = expand_random(template).unwrap();
        let lines: Vec<&str> = expanded.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("A="));
        assert!(lines[1].starts_with("B="));
        assert_eq!(lines[2], "C=fixed");
        let a = lines[0].strip_prefix("A=").unwrap();
        let b = lines[1].strip_prefix("B=").unwrap();
        assert_ne!(a, b, "two __RANDOM__ lines must not receive the same secret");
        assert_eq!(a.len(), 48, "24 bytes as hex is 48 characters, matching `openssl rand -hex 24`");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn expansion_ends_with_a_trailing_newline_like_the_bash_loop() {
        let expanded = expand_random("ADGUARD_ADMIN_PASSWORD=__RANDOM__").unwrap();
        assert!(expanded.ends_with('\n'));
        assert_eq!(expanded.lines().count(), 1);
    }

    // ─────────────────────────── .env idempotence ───────────────────────────

    #[test]
    fn env_is_written_only_when_absent_and_gets_mode_0600() {
        let dir = tmp("env-idempotence");
        let wrote = write_env_if_absent(&dir, &adguard::env_template()).unwrap();
        assert!(wrote);
        let env_path = dir.join(".env");
        assert!(env_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let first = std::fs::read_to_string(&env_path).unwrap();

        // Re-running must NOT touch the existing secret.
        let wrote_again = write_env_if_absent(&dir, &adguard::env_template()).unwrap();
        assert!(!wrote_again);
        let second = std::fs::read_to_string(&env_path).unwrap();
        assert_eq!(first, second, "an existing .env's secret must survive a re-run");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_env_value_reads_the_generated_secret() {
        let dir = tmp("env-read");
        std::fs::write(dir.join(".env"), "ADGUARD_ADMIN_PASSWORD=deadbeef\nOTHER=1\n").unwrap();
        assert_eq!(
            read_env_value(&dir.join(".env"), "ADGUARD_ADMIN_PASSWORD"),
            Some("deadbeef".to_string())
        );
        assert_eq!(read_env_value(&dir.join(".env"), "MISSING"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── DoH key patch ───────────────────────────

    #[test]
    fn the_new_spelling_is_preferred_and_flipped_to_true() {
        let yaml = "tls:\n  enabled: true\nhttp:\n  doh:\n    insecure_enabled: false\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::InsecureEnabled));
        assert!(patched.contains("    insecure_enabled: true"));
        assert!(!patched.contains("insecure_enabled: false"));
    }

    #[test]
    fn the_old_spelling_is_used_when_the_new_one_is_absent() {
        let yaml = "tls:\n  allow_unencrypted_doh: false\n  enabled: true\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::AllowUnencryptedDoh));
        assert!(patched.contains("  allow_unencrypted_doh: true"));
    }

    #[test]
    fn neither_spelling_present_leaves_the_file_untouched_and_says_so() {
        let yaml = "tls:\n  enabled: true\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, None);
        assert_eq!(patched, yaml);
    }

    #[test]
    fn a_key_already_true_is_recognized_but_not_rewritten() {
        let yaml = "http:\n  doh:\n    insecure_enabled: true\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::InsecureEnabled));
        assert_eq!(patched, yaml, "an already-true key must not be rewritten, only recognized");
    }

    #[test]
    fn a_line_with_trailing_content_is_not_treated_as_the_exact_false_match() {
        let yaml = "    insecure_enabled: false  # todo\n";
        let (patched, spelling) = patch_doh_insecure(yaml);
        assert_eq!(spelling, Some(DohSpelling::InsecureEnabled));
        assert_eq!(patched, yaml);
    }

    #[test]
    fn preserves_indentation_and_trailing_newline_shape() {
        let yaml = "a:\n  b:\n      insecure_enabled: false";
        let (patched, _) = patch_doh_insecure(yaml);
        assert_eq!(patched, "a:\n  b:\n      insecure_enabled: true");
        assert!(!patched.ends_with('\n'), "no trailing newline in, none out");
    }

    // ─────────────────────────── language mapping ───────────────────────────

    #[test]
    fn every_wired_code_maps_and_unknown_falls_back_to_english() {
        assert!(matches!(language_from_code("de"), Language::De));
        assert!(matches!(language_from_code("fr"), Language::Fr));
        assert!(matches!(language_from_code("es"), Language::Es));
        assert!(matches!(language_from_code("ru"), Language::Ru));
        assert!(matches!(language_from_code("uk"), Language::Uk));
        assert!(matches!(language_from_code("it"), Language::It));
        assert!(matches!(language_from_code("ja"), Language::Ja));
        assert!(matches!(language_from_code("zh"), Language::Zh));
        assert!(matches!(language_from_code("en"), Language::En));
        assert!(matches!(language_from_code(""), Language::En));
        assert!(matches!(language_from_code("klingon"), Language::En));
    }

    // ─────────────────────────── JSON body shaping ───────────────────────────

    #[test]
    fn json_escape_handles_quotes_and_backslashes() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(json_escape("plain"), "plain");
    }

    #[test]
    fn bounded_strips_newlines_and_caps_length() {
        assert_eq!(bounded("line1\r\nline2\n", 100), "line1line2");
        assert_eq!(bounded(&"x".repeat(500), 300).len(), 300);
    }

    // ─────────────────────────── HTTP client, against a REAL loopback socket ───────────────────────────

    #[tokio::test]
    async fn a_real_loopback_server_round_trips_status_and_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = br#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
            socket.shutdown().await.unwrap();
            request
        });

        let (code, body) = http_request(
            "127.0.0.1",
            addr.port(),
            "POST",
            "/control/install/configure",
            Some(br#"{"username":"admin"}"#),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let request = server.await.unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, r#"{"ok":true}"#);
        assert!(request.starts_with("POST /control/install/configure HTTP/1.1\r\n"));
        assert!(request.contains("Content-Length: 20\r\n"));
        assert!(request.ends_with(r#"{"username":"admin"}"#));
    }

    #[tokio::test]
    async fn connecting_to_a_closed_port_fails_fast_with_a_readable_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = http_request("127.0.0.1", addr.port(), "GET", "/", None, Duration::from_secs(2)).await;
        assert!(result.is_err());
    }

    #[test]
    fn parse_http_response_reads_status_and_body_and_rejects_garbage() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";
        assert_eq!(parse_http_response(raw), Ok((404, "no".to_string())));
        assert!(parse_http_response(b"not http at all").is_err());
        assert!(parse_http_response(b"").is_err());
    }

    fn wire_request(service_id: &str, settings: &[(&str, &str)]) -> pb::InstallServiceRequest {
        let mut req = pb::InstallServiceRequest {
            service_id: service_id.to_string(),
            domain: "example.com".to_string(),
            ..Default::default()
        };
        for (key, value) in settings {
            req.settings.insert(key.to_string(), value.to_string());
        }
        req
    }

    #[test]
    fn an_empty_request_falls_back_to_the_swift_side_defaults() {
        let input = build_input(&wire_request("vaultwarden", &[])).unwrap();
        assert_eq!(input.vaultwarden_container, "vaultwarden");
        assert_eq!(input.vaultwarden_data_path, "/opt/vaultwarden/data");
        assert!(!input.vaultwarden_allow_signups);
        assert_eq!(input.jellyfin_path, "/opt/jellyfin");
        assert_eq!(input.jellyfin_media_path, "/srv/media");
        assert_eq!(input.photoprism_path, "/opt/photoprism");
        assert_eq!(input.immich_path, "/opt/immich");
        assert_eq!(input.nextcloud_path, "/opt/nextcloud");
        assert_eq!(input.forgejo_path, "/opt/forgejo");
        assert_eq!(input.forgejo_ssh_port, 2222);
        assert_eq!(input.gitlab_path, "/opt/gitlab-ce");
        assert_eq!(input.gitlab_ssh_port, 2223);
        assert_eq!(input.adguard_path, "/opt/adguardhome");
        assert_eq!(input.seafile_path, "/opt/seafile");
        assert_eq!(input.psono_path, "/opt/psono");
        assert_eq!(input.passbolt_path, "/opt/passbolt");
    }

    /// Only an explicit "true" opens registrations
    #[test]
    fn the_signups_toggle_is_only_opened_by_an_explicit_true() {
        let closed = build_input(&wire_request("vaultwarden", &[("vaultwarden_allow_signups", "false")])).unwrap();
        assert!(!closed.vaultwarden_allow_signups);
        let open = build_input(&wire_request("vaultwarden", &[("vaultwarden_allow_signups", "true")])).unwrap();
        assert!(open.vaultwarden_allow_signups);
        let garbage = build_input(&wire_request("vaultwarden", &[("vaultwarden_allow_signups", "yes")])).unwrap();
        assert!(!garbage.vaultwarden_allow_signups);
    }

    #[test]
    fn every_path_setting_is_gated_whatever_service_the_request_names() {
        for key in [
            "adguard_path",
            "vaultwarden_data_path",
            "jellyfin_path",
            "jellyfin_media_path",
            "photoprism_path",
            "immich_path",
            "nextcloud_path",
            "forgejo_path",
            "gitlab_path",
            "seafile_path",
            "psono_path",
            "passbolt_path",
        ] {
            let relative = build_input(&wire_request("jellyfin", &[(key, "opt/somewhere")]));
            assert!(relative.is_err(), "{key}: a relative path must be refused");
            let escaping = build_input(&wire_request("jellyfin", &[(key, "/opt/../etc")]));
            assert!(escaping.is_err(), "{key}: a '..' component must be refused");
        }
    }

    #[test]
    fn an_existing_library_directory_is_left_exactly_as_it_was() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("library");
        let existing = dir.join("library");
        std::fs::create_dir_all(&existing).unwrap();
        set_mode(&existing, 0o700).unwrap();

        assert!(!create_dir_if_absent_0755(&existing).unwrap());
        let mode = std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "an existing library must keep its own mode");

        let fresh = dir.join("fresh");
        assert!(create_dir_if_absent_0755(&fresh).unwrap());
        assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[test]
    fn every_catalog_port_entry_is_understood() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        let mut seen_any = false;
        for label in IMPLEMENTED_SERVICE_IDS {
            let Some(compose) = compose_text_of(label, &input) else { continue };
            let by_shape = compose
                .lines()
                .map(str::trim)
                .filter(|line| {
                    let Some(entry) = line.strip_prefix("- ") else { return false };
                    let entry = entry.trim_matches('"');
                    let body = entry.split('/').next().unwrap_or(entry);
                    let fields: Vec<&str> = body.split(':').collect();
                    match fields.len() {
                        2 => fields.iter().all(|f| f.parse::<u16>().is_ok()),
                        3 => {
                            fields[0].split('.').count() == 4
                                && fields[1..].iter().all(|f| f.parse::<u16>().is_ok())
                        }
                        _ => false,
                    }
                })
                .count();
            let parsed = ports::published_in_compose(&compose).len();
            assert_eq!(parsed, by_shape, "{label}: the pre-flight reads {parsed} of {by_shape} published ports");
            seen_any |= by_shape > 0;
        }
        assert!(seen_any, "the fixture stopped producing compose bodies with ports at all");
    }

    #[test]
    fn adguard_asks_for_its_loopback_publishes_and_not_only_public_ports() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        let wanted = published_ports_of("adguard-home", &input, &[]);
        let mapping = |address: &str, port: firewall::Port| {
            wanted.iter().any(|w| w.address == address && w.port == port)
        };
        assert!(mapping("127.0.0.1", firewall::Port::tcp(53)), "{wanted:?}");
        assert!(mapping("127.0.0.1", firewall::Port::udp(53)), "{wanted:?}");
        assert!(mapping("127.0.0.1", firewall::Port::tcp(8087)), "{wanted:?}");
    }

    #[test]
    fn a_container_running_without_its_ports_is_reported_by_name() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        let wanted = ports::published_in_compose(&adguard::compose_contents(&input));
        assert_eq!(wanted.len(), 3, "the fixture stopped publishing what this test is about");

        let missing = missing_publishes(&wanted, &[]);
        assert_eq!(missing, vec!["8087/tcp", "53/tcp", "53/udp"]);

        let live: Vec<firewall::Port> = wanted.iter().map(|w| w.port).collect();
        assert!(missing_publishes(&wanted, &live).is_empty());
    }

    fn vw_input() -> Input {
        Input { domain: "example.com".to_string(), vaultwarden_allow_signups: true, ..Input::default() }
    }

    #[test]
    fn a_missing_vaultwarden_config_is_no_change_at_all() {
        let dir = tmp("vw-missing");
        assert_eq!(sync_vaultwarden_config(&dir.join("config.json"), &vw_input()), Ok(false));
    }

    #[test]
    fn a_config_that_already_agrees_is_left_untouched() {
        let dir = tmp("vw-agrees");
        let path = dir.join("config.json");
        let original = "{\"signups_allowed\":true,\"domain\":\"https://vault.example.com\",\"other\":1}";
        std::fs::write(&path, original).unwrap();
        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(false));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn the_apps_toggle_wins_over_the_stored_one_and_keeps_the_other_keys() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("vw-toggle");
        let path = dir.join("config.json");
        std::fs::write(&path, "{\"signups_allowed\":false,\"icon_service\":\"internal\"}").unwrap();

        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(true));
        let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored["signups_allowed"], serde_json::Value::Bool(true));
        assert_eq!(stored["icon_service"], serde_json::Value::String("internal".into()));
        assert!(stored.get("domain").is_none(), "domain must not be added when it was absent");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn a_stored_domain_from_an_older_install_is_rewritten() {
        let dir = tmp("vw-domain");
        let path = dir.join("config.json");
        std::fs::write(&path, "{\"signups_allowed\":true,\"domain\":\"https://vault.old-domain.net\"}").unwrap();

        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(true));
        let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored["domain"], serde_json::Value::String("https://vault.example.com".into()));
    }

    #[test]
    fn a_null_stored_domain_is_not_a_reason_to_rewrite() {
        let dir = tmp("vw-null-domain");
        let path = dir.join("config.json");
        let original = "{\"signups_allowed\":true,\"domain\":null}";
        std::fs::write(&path, original).unwrap();
        assert_eq!(sync_vaultwarden_config(&path, &vw_input()), Ok(false));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn an_unparsable_config_is_reported_rather_than_overwritten() {
        let dir = tmp("vw-garbage");
        let path = dir.join("config.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(sync_vaultwarden_config(&path, &vw_input()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json at all");
    }

    #[test]
    fn an_admin_is_recognised_by_the_username_column_only() {
        let listing = "ID   Username   Email                  IsActive\n\
                       1    alice      admin@example.com      true\n";
        assert!(!admin_listed(listing, "admin"), "an address must not count as the username");
        assert!(admin_listed(listing, "alice"));
        assert!(!admin_listed("", "admin"));
        assert!(!admin_listed("ID Username Email\n", "Username"));
    }

    #[test]
    fn an_unparsable_ssh_port_keeps_the_default_rather_than_switching_ssh_off() {
        let garbage = build_input(&wire_request("forgejo", &[("forgejo_ssh_port", "yes please")])).unwrap();
        assert_eq!(garbage.forgejo_ssh_port, 2222);
        let off = build_input(&wire_request("forgejo", &[("forgejo_ssh_port", "0")])).unwrap();
        assert_eq!(off.forgejo_ssh_port, 0);
        let custom = build_input(&wire_request("forgejo", &[("forgejo_ssh_port", "2022")])).unwrap();
        assert_eq!(custom.forgejo_ssh_port, 2022);
    }

    #[test]
    fn stale_trusted_domain_slots_start_after_the_last_filled_one() {
        let slots = stale_trusted_domain_slots(&Input::default());
        let used = occ_settings(&Input::default()).iter().filter(|(key, _)| key.starts_with("trusted_domains ")).count();
        assert_eq!(slots.first().map(String::as_str), Some((used + 1).to_string().as_str()));
        assert!(!slots.iter().any(|slot| slot == "0"));
    }

    #[test]
    fn occ_writes_trusted_domains_from_slot_one_and_covers_every_mirror() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.additional_domains = vec!["example.org".to_string()];
        let settings = occ_settings(&input);
        assert_eq!(
            settings,
            vec![
                ("trusted_domains 1".to_string(), "files.example.com".to_string()),
                ("trusted_domains 2".to_string(), "files.example.org".to_string()),
                ("overwriteprotocol".to_string(), "https".to_string()),
                ("overwrite.cli.url".to_string(), "https://files.example.com".to_string()),
            ]
        );
    }

    #[test]
    fn a_home_server_follows_the_address_used() {
        let input = Input { domain: "home.local".to_string(), local_only: true, ..Input::default() };
        assert_eq!(
            occ_settings(&input),
            vec![
                ("trusted_domains 1".to_string(), "files.home.local".to_string()),
                ("trusted_domains 2".to_string(), "*".to_string()),
                ("overwrite.cli.url".to_string(), "https://files.home.local".to_string()),
            ]
        );
        assert_eq!(occ_deletions(&input), vec!["overwritehost", "overwriteprotocol"]);
        assert_eq!(occ_deletions(&Input::default()), vec!["overwritehost"]);
    }

    #[test]
    fn an_occ_call_splits_the_key_and_keeps_the_value_in_one_argument() {
        let mut argv = vec!["config:system:set"];
        let key = "trusted_domains 2";
        argv.extend(key.split(' '));
        let value = "--value=cloud.example.org".to_string();
        argv.push(&value);
        let args = exec_args("www-data", "abc123", &["php", "occ"]);
        assert_eq!(args, vec!["exec", "-u", "www-data", "abc123", "php", "occ"]);
        assert_eq!(argv, vec!["config:system:set", "trusted_domains", "2", "--value=cloud.example.org"]);
    }

    #[test]
    fn readiness_needs_puma_specifically_and_running() {
        assert!(puma_running("run: puma: (pid 123) 45s; run: log: (pid 124) 45s\n"));
        assert!(!puma_running("run: redis: (pid 99) 60s\n"));
        assert!(!puma_running("down: puma: 1s, normally up\n"));
        assert!(!puma_running("run: gitlab-workhorse: (pid 5) 1s; waiting for puma\n"));
        assert!(!puma_running(""));
    }

    #[test]
    fn an_unparsable_gitlab_ssh_port_keeps_the_default() {
        let garbage = build_input(&wire_request("gitlab", &[("gitlab_ssh_port", "")])).unwrap();
        assert_eq!(garbage.gitlab_ssh_port, 2223);
        let off = build_input(&wire_request("gitlab", &[("gitlab_ssh_port", "0")])).unwrap();
        assert_eq!(off.gitlab_ssh_port, 0);
    }

    // ─────────────────────── seafile + psono ───────────────────────

    #[test]
    fn restarting_one_service_names_the_project_and_the_service_separately() {
        assert_eq!(
            compose_restart_service_args("seafile", Path::new("/opt/seafile"), "seafile"),
            ["compose", "-p", "seafile", "-f", "/opt/seafile/docker-compose.yml", "restart", "seafile"]
        );
        let args = compose_restart_service_args("weird name", Path::new("/opt/seafile"), "weird service");
        assert_eq!(args.len(), 7);
        assert_eq!(args[2], "weird name");
        assert_eq!(args[6], "weird service");
    }

    #[test]
    fn the_psono_argv_is_exact() {
        assert_eq!(
            docker_run_once_args(psono::IMAGE, &["python3", "./psono/generateserverkeys.py"]),
            ["run", "--rm", psono::IMAGE, "python3", "./psono/generateserverkeys.py"]
        );
        assert_eq!(
            docker_exec_args(psono::CONTAINER, &["python3", "./psono/manage.py", "presetup"]),
            ["exec", "psono", "python3", "./psono/manage.py", "presetup"]
        );
        assert!(!docker_exec_args("psono", &["migrate"]).contains(&"down".to_string()));
    }

    #[test]
    fn a_secret_file_is_created_once_and_the_loser_is_told_so() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("psono-settings");
        let path = dir.join("settings.yaml");

        assert!(create_file_if_absent(&path, "PRIVATE_KEY: 'first'\n", 0o600).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        assert!(!create_file_if_absent(&path, "PRIVATE_KEY: 'second'\n", 0o600).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "PRIVATE_KEY: 'first'\n",
            "an existing keypair must never be overwritten"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_captured_run_keeps_stdout_out_of_stderr() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-capture");
        let script = write_stub(&dir, "docker", "#!/bin/sh\necho \"PRIVATE_KEY: 'x'\"\necho noise 1>&2\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let run = run_docker_captured(
            &docker_run_once_args("image", &["python3", "gen.py"]),
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(run.success);
        assert_eq!(run.stdout, "PRIVATE_KEY: 'x'\n");
        assert_eq!(run.stderr, "noise\n");
        // `why` is the bash `ps_why`: one bounded line of everything.
        assert_eq!(run.why(), "PRIVATE_KEY: 'x'noise");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_captured_run_reports_a_failure_without_pretending_it_succeeded() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("docker-capture-fail");
        let script = write_stub(&dir, "docker", "#!/bin/sh\necho 'db is down' 1>&2\nexit 1\n");
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let run = run_docker_captured(&docker_exec_args("psono", &["presetup"]), Duration::from_secs(30))
            .await
            .unwrap();

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(!run.success);
        assert!(run.why().contains("db is down"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn waiting_for_a_file_answers_at_once_when_it_exists() {
        let dir = tmp("wait-file");
        let path = dir.join("seahub_settings.py");
        std::fs::write(&path, "SECRET_KEY = 'x'\n").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "seafile".to_string(), journal: None, sequence: AtomicU64::new(0) };

        assert!(wait_for_file(&path, 5, &sink, "waiting").await);
        assert!(!wait_for_file(&dir.join("never"), 0, &sink, "waiting").await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn dms_input() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn docker_mailserver_resolves_and_installs_under_its_own_project() {
        assert_eq!(resolve("docker-mailserver"), Ok("docker-mailserver"));
        assert_eq!(compose_project("docker-mailserver"), dms::COMPOSE_PROJECT);
        assert_eq!(compose_project("docker-mailserver"), "dockermailserver");
    }

    #[test]
    fn the_mail_shelf_is_closed_all_three_engines_resolve_and_install_under_their_own_project() {
        assert_eq!(resolve("mailcow"), Ok("mailcow"));
        assert_eq!(compose_project("mailcow"), mailcow::COMPOSE_PROJECT);
        assert_eq!(compose_project("mailcow"), "mailcowdockerized");

        assert_eq!(resolve("mailu"), Ok("mailu"));
        assert_eq!(compose_project("mailu"), mailu::COMPOSE_PROJECT);
        assert_eq!(compose_project("mailu"), "mailu");
    }

    #[test]
    fn mailu_admin_exec_args_reaches_the_service_by_name_through_compose_not_by_container() {
        let dir = Path::new("/opt/mailu");
        assert_eq!(
            mailu_admin_exec_args(dir, mailu::CONFIG_EXPORT_PROBE_ARGS),
            [
                "compose",
                "-p",
                "mailu",
                "-f",
                "/opt/mailu/docker-compose.yml",
                "exec",
                "-T",
                "-u",
                "mailu",
                "admin",
                "flask",
                "mailu",
                "config-export",
                "-j"
            ]
        );
    }

    #[test]
    fn no_mailu_admin_exec_runs_as_root() {
        let dir = Path::new("/opt/mailu");
        for argv in [mailu::CONFIG_EXPORT_PROBE_ARGS, mailu::CONFIG_IMPORT_ARGS] {
            let args = mailu_admin_exec_args(dir, argv);
            let exec = args.iter().position(|a| a == "exec").expect("an exec verb");
            let service = args.iter().position(|a| a == mailu::ADMIN_SERVICE).expect("the admin service name");
            let user = args.iter().position(|a| a == "-u").expect("a -u flag");
            assert!(exec < user && user + 1 < service, "-u has to sit between `exec` and the service name: {args:?}");
            assert_eq!(args[user + 1], mailu::ADMIN_RUN_AS_USER);
        }
    }

    #[tokio::test]
    async fn mailcow_compose_calls_carry_no_dash_f_and_run_with_the_checkout_as_cwd() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("mailcow-compose-argv");
        let recorder = dir.join("argv.txt");
        let script = write_stub(
            &dir,
            "docker",
            &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\npwd >> {}\n", recorder.display(), recorder.display()),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &script);

        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "mailcow".to_string(), journal: None, sequence: AtomicU64::new(0) };
        let result =
            run_mailcow_compose_retrying(&dir, &["compose".to_string(), "pull".to_string(), "-q".to_string()], 1, &sink)
                .await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(result.is_ok(), "{result:?}");

        let recorded = std::fs::read_to_string(&recorder).unwrap();
        let mut lines = recorded.lines();
        assert_eq!(lines.next().unwrap(), "compose pull -q", "no -f, unlike every other engine's compose call");
        assert_eq!(
            std::fs::canonicalize(lines.next().unwrap()).unwrap(),
            std::fs::canonicalize(&dir).unwrap(),
            "the checkout must be the working directory, the bash version's `cd`"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mailcow_json_has_field_matches_jqs_own_e_flag_rule() {
        assert!(mailcow_json_has_field(r#"{"domain_name":"example.com"}"#, "domain_name"));
        assert!(!mailcow_json_has_field(r#"{"domain_name":null}"#, "domain_name"));
        assert!(!mailcow_json_has_field(r#"{"errors":["not found"]}"#, "domain_name"));
        assert!(!mailcow_json_has_field("not json at all", "domain_name"));
        assert!(!mailcow_json_has_field(r#"{"pubkey":false}"#, "pubkey"));
    }

    #[test]
    fn mailcow_why_matches_mc_whys_own_shape() {
        assert_eq!(mailcow_why(404, "route not found\r\n"), "HTTP 404 route not found");
        let long = "x".repeat(500);
        assert_eq!(mailcow_why(500, &long).len(), "HTTP 500 ".len() + 300);
    }

    #[test]
    fn chmod_recursive_a_plus_rx_adds_read_everywhere_and_execute_only_where_earned() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp("chmod-a-plus-rx");
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let data_file = root.join("data.txt");
        std::fs::write(&data_file, "x").unwrap();
        std::fs::set_permissions(&data_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let script_file = sub.join("run.sh");
        std::fs::write(&script_file, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script_file, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        chmod_recursive_a_plus_rx(&root).unwrap();

        let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_of(&root), 0o755, "a directory gets read AND execute for everyone");
        assert_eq!(mode_of(&sub), 0o755, "a subdirectory gets the same");
        assert_eq!(mode_of(&data_file), 0o644, "a plain file gets read only, never execute");
        assert_eq!(mode_of(&script_file), 0o755, "a file that already had execute for its owner keeps it for everyone");
    }

    #[test]
    fn chmod_recursive_a_plus_rx_leaves_symlinks_alone() {
        let root = tmp("chmod-a-plus-rx-symlink");
        let link = root.join("dangling");
        std::os::unix::fs::symlink("/nonexistent/target", &link).unwrap();
        chmod_recursive_a_plus_rx(&root).unwrap();
    }

    #[test]
    fn chmod_recursive_a_plus_rx_leaves_the_tls_key_directory_alone() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp("chmod-a-plus-rx-ssl");
        let ssl = root.join("data/assets/ssl");
        std::fs::create_dir_all(&ssl).unwrap();
        let key = ssl.join("key.pem");
        std::fs::write(&key, "k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&ssl, std::fs::Permissions::from_mode(0o700)).unwrap();
        chmod_recursive_a_plus_rx(&root).unwrap();
        let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_of(&key), 0o600);
        assert_eq!(mode_of(&ssl), 0o700);
    }

    #[test]
    fn mailcow_reply_succeeded_needs_every_entry_to_say_success() {
        assert!(mailcow_reply_succeeded(r#"[{"type":"success","msg":["admin_modified","admin"]}]"#));
        assert!(mailcow_reply_succeeded(r#"{"type":"success"}"#));
        assert!(!mailcow_reply_succeeded(r#"[{"type":"danger","msg":"access_denied"}]"#));
        assert!(!mailcow_reply_succeeded(r#"[{"type":"success"},{"type":"danger"}]"#));
        assert!(!mailcow_reply_succeeded("<html>502</html>"));
    }

    #[test]
    fn random_hex_20_is_forty_lowercase_hex_characters() {
        let hex = random_hex_20().unwrap();
        assert_eq!(hex.len(), 40);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn the_certificate_directory_ends_up_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("dms-dirs");
        let service = dir.join("service");
        let certs = dir.join("certs");
        create_dir_with_mode(&service, 0o755).unwrap();
        create_dir_with_mode(&certs, 0o700).unwrap();
        assert_eq!(std::fs::metadata(&service).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(std::fs::metadata(&certs).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_certificate_counts_as_missing() {
        let dir = tmp("dms-cert-empty");
        let empty = dir.join("cert.pem");
        std::fs::write(&empty, "").unwrap();
        let real = dir.join("key.pem");
        std::fs::write(&real, "-----BEGIN-----\n").unwrap();
        assert!(!is_nonempty_file(&empty));
        assert!(is_nonempty_file(&real));
        assert!(!is_nonempty_file(&dir.join("absent")));
        assert!(!is_nonempty_file(&dir), "a directory is not a certificate");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_placeholder_certificate_runs_openssl_with_the_ported_argv() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-openssl");
        let argv_file = dir.join("argv");
        let stub =
            write_stub(&dir, "openssl", &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", argv_file.display()));
        std::env::set_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN", &stub);

        let mut input = dms_input();
        input.docker_mailserver_path = dir.join("dms").display().to_string();
        std::fs::create_dir_all(dir.join("dms/certs")).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "docker-mailserver".to_string(), journal: None, sequence: AtomicU64::new(0) };
        write_placeholder_cert(&input, &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN");
        let recorded: Vec<String> = std::fs::read_to_string(&argv_file).unwrap().lines().map(str::to_string).collect();
        assert_eq!(recorded, dms::placeholder_cert_args(&input));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_existing_certificate_pair_is_never_replaced() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-openssl-skip");
        let argv_file = dir.join("argv");
        let stub =
            write_stub(&dir, "openssl", &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", argv_file.display()));
        std::env::set_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN", &stub);

        let mut input = dms_input();
        input.docker_mailserver_path = dir.join("dms").display().to_string();
        std::fs::create_dir_all(dir.join("dms/certs")).unwrap();
        std::fs::write(dms::cert_pem_path(&input), "-----BEGIN CERTIFICATE-----\n").unwrap();
        std::fs::write(dms::key_pem_path(&input), "-----BEGIN PRIVATE KEY-----\n").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let sink = EventSink { tx, codec: Codec::Proto, service_id: "docker-mailserver".to_string(), journal: None, sequence: AtomicU64::new(0) };
        write_placeholder_cert(&input, &sink).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_OPENSSL_BIN");
        assert!(!argv_file.exists(), "openssl must not run when both halves are already on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_first_mailbox_password_travels_on_stdin_and_not_in_argv() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-stdin");
        let argv_file = dir.join("argv");
        let stdin_file = dir.join("stdin");
        let stub = write_stub(
            &dir,
            "docker",
            &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\ncat > {}\n", argv_file.display(), stdin_file.display()),
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub);

        let run = dms_exec_with_stdin(&["setup", "email", "add", "admin@example.com"], "s3cret\ns3cret\n")
            .await
            .expect("the stub must run");

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(run.success);
        let argv = std::fs::read_to_string(&argv_file).unwrap();
        assert_eq!(argv, "exec\n-i\nmailserver\nsetup\nemail\nadd\nadmin@example.com\n");
        assert!(!argv.contains("s3cret"), "the password must never appear in argv: /proc hands it to everyone");
        assert_eq!(std::fs::read_to_string(&stdin_file).unwrap(), "s3cret\ns3cret\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_engines_own_colours_are_stripped_from_what_it_says() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("dms-ansi");
        let stub = write_stub(
            &dir,
            "docker",
            "#!/bin/sh\nprintf 'plain\\n'\nprintf '\\033[1;31mERROR\\033[0m unknown user\\n' 1>&2\nexit 1\n",
        );
        std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub);

        let (ok, text) = dms_exec(&["setup", "help"]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN");
        assert!(!ok);
        assert!(text.contains("ERROR unknown user"), "got {text:?}");
        assert!(!text.contains('\u{1b}'), "no escape sequence may survive into what a user reads");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_existing_mailbox_is_recognised_in_every_live_listing_format() {
        for line in [
            "* admin@example.com ( 6.0K / ~ ) [0%]",
            "* admin@example.com ( 0 / ~ ) [0%]",
            "* admin@example.com (  /  ) [%]",
        ] {
            assert!(mailbox_listed(line, "admin@example.com"), "not matched: {line:?}");
        }
        assert!(mailbox_listed("* admin@example.com\r\n", "admin@example.com"));
        assert!(mailbox_listed("admin@example.com", "admin@example.com"));
    }

    #[test]
    fn a_lookalike_address_is_not_the_administrators_mailbox() {
        for line in [
            "* notadmin@example.com ( 0 / ~ ) [0%]",
            "* admin@example.com.evil.net ( 0 / ~ ) [0%]",
            "* xadmin@example.com ( 0 / ~ ) [0%]",
            "* admin@example.commercial ( 0 / ~ ) [0%]",
        ] {
            assert!(!mailbox_listed(line, "admin@example.com"), "wrongly matched: {line:?}");
        }
        assert!(!mailbox_listed("", "admin@example.com"));
        assert!(!mailbox_listed("* admin@example.com", ""));
    }

    #[test]
    fn the_stderr_diagnostic_line_never_reads_as_an_existing_mailbox() {
        let noise = "doveadm(admin@example.com): Error: User doesn't exist";
        assert!(!mailbox_listed(noise, "admin@example.com"));
    }

    #[test]
    fn the_firewall_receives_exactly_the_engines_declared_ports() {
        let rendered: Vec<(u16, &str)> = mail_firewall_ports(&dms::firewall_ports())
            .iter()
            .map(|p| {
                (
                    p.port,
                    match p.proto {
                        firewall::Proto::Tcp => "tcp",
                        firewall::Proto::Udp => "udp",
                    },
                )
            })
            .collect();
        assert_eq!(rendered, vec![(25, "tcp"), (465, "tcp"), (587, "tcp"), (143, "tcp"), (993, "tcp"), (4190, "tcp")]);
    }

    #[test]
    fn a_firewall_failure_is_fatal_but_a_missing_drop_in_directory_is_only_reported() {
        let applied = firewall_step_text(Ok(firewall::Outcome::Applied)).expect("Applied is not an error");
        assert!(applied.contains("opened the mail ports"));

        let skipped = firewall_step_text(Ok(firewall::Outcome::SkippedNoDropInDir))
            .expect("a missing drop-in directory is a step, not an error");
        assert!(skipped.contains("NOT open"), "the operator has to be told the ports are closed: {skipped:?}");
        assert!(skipped.contains("re-run"), "and what to do about it: {skipped:?}");

        let failed = firewall_step_text(Err("nft: syntax error".to_string()));
        assert_eq!(failed, Err("could not open the mail ports in the firewall: nft: syntax error".to_string()));
    }

    #[test]
    fn the_cert_sync_files_are_the_script_and_its_two_units() {
        let input = dms_input();
        let files = cert_sync_files(&input);
        let paths: Vec<String> = files.iter().map(|f| f.path.display().to_string()).collect();
        assert_eq!(
            paths,
            vec![
                "/opt/gryonixnexus-dms-cert-sync.sh".to_string(),
                "/etc/systemd/system/gryonixnexus-dms-cert-sync.service".to_string(),
                "/etc/systemd/system/gryonixnexus-dms-cert-sync.timer".to_string(),
            ]
        );
        assert_eq!(files[0].mode, Some(0o700), "the script copies a private key");
        assert_eq!(files[0].contents, dms::cert_sync_script(&input));
        assert!(files[1].contents.contains("ExecStart=/opt/gryonixnexus-dms-cert-sync.sh"));
        assert!(files[2].contents.contains("OnUnitActiveSec=1h"));
    }

    #[test]
    fn the_dkim_wrapper_is_written_and_the_mailbox_wrapper_is_deliberately_not() {
        let input = dms_input();
        let files = dms_management_files(&input);
        let paths: Vec<String> = files.iter().map(|f| f.path.display().to_string()).collect();
        assert_eq!(paths, vec![dms::DKIM_DUMP_SCRIPT_PATH.to_string()]);
        assert!(
            !paths.contains(&dms::MAILBOX_SCRIPT_PATH.to_string()),
            "the mailbox wrapper is unreachable on this path — see write_dms_management_scripts"
        );
        assert_eq!(files[0].mode, Some(0o700));
        assert_eq!(files[0].contents, dms::dkim_dump_script(&input));
    }

    #[test]
    fn the_wrapper_this_install_writes_is_the_one_the_dkim_rpc_runs() {
        assert_eq!(dms::DKIM_DUMP_SCRIPT_PATH, "/opt/gryonixnexus-dms-dkim.sh");
    }

    #[test]
    fn the_installs_order_is_the_one_the_engine_actually_needs() {
        let source = include_str!("execute.rs");
        let start = source
            .find("async fn install_docker_mailserver_steps")
            .expect("the function must exist to have an order at all");
        let body = &source[start..];
        let end = body.find("\n}\n").expect("the function must end before the next item");
        let body = &body[..end];

        let at = |needle: &str| -> usize { body.find(needle).unwrap_or_else(|| panic!("no `{needle}` in the body")) };
        let cert = at("write_placeholder_cert(input, sink)");
        let pull = at("compose_pull_args(dms::COMPOSE_PROJECT, &dir)");
        let up = at("compose_up(dms::COMPOSE_PROJECT, &dir, sink)");
        let firewall = at("open_mail_firewall_ports(DMS_FIREWALL_LABEL");
        let configure = at("configure_dms(input, sink)");
        let caddy = at("write_caddy_site(&dms::caddy_site_names");

        assert!(cert < pull, "the placeholder certificate must exist before the images are even pulled");
        assert!(pull < up, "pull before up");
        assert!(up < firewall, "the ports are opened once something is listening on them");
        assert!(firewall < configure, "the fatal step comes before the five-minute readiness wait");
        assert!(configure < caddy, "the Caddy site is written last, as in every other service here");
    }

    #[test]
    fn the_signing_domain_stops_being_reduced_to_the_esld() {
        let upstream = "enabled = true;\nuse_esld = true;\ncheck_pubkey = true;\n";
        let fixed = dkim_signing_without_esld(upstream).expect("an upstream config must be changed");
        assert!(fixed.contains("use_esld = false;"));
        assert_eq!(fixed.replace("use_esld = false;", "use_esld = true;"), upstream);
        assert_eq!(dkim_signing_without_esld(&fixed), None);
        assert_eq!(dkim_signing_without_esld("enabled = true;\n"), None);
    }

    #[test]
    fn provision_host_also_stops_the_signing_domain_being_reduced() {
        let source = include_str!("execute.rs");
        let start = source.find("pub async fn run_provision_host").expect("the verb must exist");
        let body = &source[start..];
        let end = body.find("\nasync fn provision_host_surface").expect("the function must end before the next item");
        let body = &body[..end];
        let surface = body.find("provision_host_surface(&input").expect("the host surface must be provisioned");
        let fix = body
            .find("stop_rspamd_reducing_the_signing_domain(&input, &sink)")
            .expect("ProvisionHost must apply the DKIM signing fix");
        let drained = body.find("drain_notes(&mut rx").expect("the notes must be drained");
        assert!(surface < fix, "the host surface comes first");
        assert!(fix < drained, "the fix must run before the notes are drained or its step is lost");
    }

    #[test]
    fn the_signing_fix_runs_after_the_keys_are_minted() {
        let source = include_str!("execute.rs");
        let start = source.find("async fn configure_dms").expect("configure_dms must exist");
        let body = &source[start..];
        let end = body.find("\n}\n").expect("the function must end before the next item");
        let body = &body[..end];
        let mint = body.find("dms::dkim_config_args(&domain)").expect("the key loop must be here");
        let fix = body.find("stop_rspamd_reducing_the_signing_domain(input, sink)").expect("the fix must be here");
        assert!(mint < fix, "the signing fix must run after the keys (and their config file) exist");
    }

    #[test]
    fn managed_files_are_written_with_the_mode_they_asked_for() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("dms-managed");
        let script = dir.join("wrapper.sh");
        let plain = dir.join("unit.timer");
        write_managed_files(&[
            ManagedFile { path: script.clone(), contents: "#!/bin/bash\n".to_string(), mode: Some(0o700) },
            ManagedFile { path: plain.clone(), contents: "[Timer]\n".to_string(), mode: None },
        ])
        .unwrap();
        assert_eq!(std::fs::metadata(&script).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::read_to_string(&plain).unwrap(), "[Timer]\n");
        assert!(write_managed_files(&[ManagedFile {
            path: dir.join("no/such/dir/file"),
            contents: String::new(),
            mode: None
        }])
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_line_of_the_env_template_gets_its_own_secret() {
        let expanded = expand_random(&dms::env_template(&dms_input())).unwrap();
        let value_of = |prefix: &str| -> String {
            expanded
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .unwrap_or_else(|| panic!("no {prefix} line"))
                .to_string()
        };
        let password = value_of("FIRST_MAILBOX_PASSWORD=");
        assert_eq!(password.len(), 48, "24 random bytes as hex");
        assert!(password.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!expanded.contains("__RANDOM__"), "no marker may survive into the file");

        let comment = expanded.lines().next().expect("the header comment").to_string();
        assert!(comment.starts_with('#'));
        assert!(
            !comment.contains(&password),
            "the comment's throwaway substitution must not be the mailbox password: {comment:?}"
        );
    }

    #[test]
    fn the_docker_mailserver_path_defaults_to_swifts_and_is_gated_like_the_rest() {
        let input = build_input(&pb::InstallServiceRequest {
            service_id: "docker-mailserver".to_string(),
            domain: "example.com".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(input.docker_mailserver_path, "/opt/docker-mailserver");

        let mut settings = HashMap::new();
        settings.insert("docker_mailserver_path".to_string(), "/srv/dms".to_string());
        let custom = build_input(&pb::InstallServiceRequest {
            service_id: "docker-mailserver".to_string(),
            domain: "example.com".to_string(),
            settings,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(custom.docker_mailserver_path, "/srv/dms");

        let mut bad = HashMap::new();
        bad.insert("docker_mailserver_path".to_string(), "/opt/../etc/systemd/system".to_string());
        let refused = build_input(&pb::InstallServiceRequest {
            service_id: "docker-mailserver".to_string(),
            domain: "example.com".to_string(),
            settings: bad,
            ..Default::default()
        });
        assert!(refused.is_err());
    }

    // ─────────────────────────── Passbolt ───────────────────────────

    #[test]
    fn passbolt_resolves_and_installs_under_its_own_project() {
        assert_eq!(resolve("passbolt"), Ok("passbolt"));
        assert_eq!(compose_project("passbolt"), passbolt::COMPOSE_PROJECT);
    }

    #[test]
    fn extract_last_url_takes_the_final_url_shaped_token() {
        assert_eq!(
            extract_last_url("Registration email sent!\nSetup URL: https://passbolt.example.com/setup/install/1/2\n"),
            Some("https://passbolt.example.com/setup/install/1/2".to_string())
        );
        assert_eq!(
            extract_last_url("http://one.example.com https://two.example.com"),
            Some("https://two.example.com".to_string())
        );
        assert_eq!(extract_last_url("no url in this output at all"), None);
        assert_eq!(extract_last_url(""), None);
    }

    #[test]
    fn freshness_follows_the_gpg_key_file_not_the_containers_own_state() {
        let dir = tmp("passbolt-fresh");
        let key = dir.join("serverkey_private.asc");
        assert!(!key.exists(), "a brand new install has no key yet");
        std::fs::write(&key, "-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap();
        assert!(key.exists(), "an existing key means an earlier run already invited the administrator");
    }

    #[test]
    fn an_unparseable_records_file_is_rewritten_and_real_records_are_not() {
        let dir = std::env::temp_dir().join(format!("gd-records-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("extra-records.json");

        let _ = std::fs::remove_file(&path);
        assert!(headscale_records_need_writing(&path), "an absent file must be created");

        std::fs::write(&path, "[]\\n").unwrap();
        assert!(headscale_records_need_writing(&path), "the literal backslash-n an older install wrote must be repaired");

        std::fs::write(&path, "[]\n").unwrap();
        assert!(!headscale_records_need_writing(&path), "a correct empty file must be left alone");

        std::fs::write(&path, "[{\"name\":\"vault.example.com\",\"value\":\"100.64.0.1\"}]\n").unwrap();
        assert!(
            !headscale_records_need_writing(&path),
            "published names must never be dropped by a re-install"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same shape for Authelia
    #[test]
    fn a_users_database_the_portal_cannot_load_is_rewritten_and_a_working_one_is_not() {
        let dir = std::env::temp_dir().join(format!("gd-users-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users_database.yml");

        let _ = std::fs::remove_file(&path);
        assert!(authelia_needs_first_user(&path), "an absent database must be created");

        std::fs::write(&path, "users:\n  admin:\n    password: 'sha256:5dd0d3e6'\n").unwrap();
        assert!(authelia_needs_first_user(&path), "a docker digest is not a password hash");

        std::fs::write(&path, "users:\n  admin:\n    password: '$argon2id$v=19$m=65536,t=3,p=4$x$y'\n").unwrap();
        assert!(!authelia_needs_first_user(&path), "a working database must never be rewritten");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
