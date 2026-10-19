use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::StatusCode;
use serde::{Deserialize, Serialize};

use crate::api::{connect_error, Codec, Resp};
use crate::health_watch::{self, Checks, Problem};
use crate::notify_send::{self, Alert, Sent};
use crate::pb;
use crate::state::Store;

const KEY: &str = "notify";
const FIRST_CHECK: Duration = Duration::from_secs(60);
const EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Device {
    pub platform: String,
    pub token: String,
    pub app_version: String,
    pub locale: String,
    /// Relay announcements this phone does not want
    #[serde(default)]
    pub muted: Vec<String>,
    /// Hash of the secret only the phone holds
    #[serde(default)]
    pub proof: String,
    /// Shown in the app's list; never sent to the relay
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub added_at: i64,
}

impl Device {
    /// What the relay is told about this device
    fn relay_body(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "platform": self.platform, "token": self.token, "app_version": self.app_version,
            "locale": self.locale, "muted": self.muted, "proof": self.proof,
        }))
        .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub channel: i32,
    pub relay_url: String,
    pub ntfy_url: String,
    pub ntfy_topic: String,
    pub raid: bool,
    pub smart: bool,
    pub space: bool,
    pub space_percent: u32,
    pub services: bool,
    pub backups: bool,
    pub agent_update: bool,
    pub operations: bool,
    pub ssh_logins: bool,
    /// The checks are this server's own, not the app defaults
    pub custom_checks: bool,
    /// App public keys whose SSH sign-ins stay quiet, newest last
    pub quiet_keys: Vec<String>,
    /// Journal position after the last read sshd line
    pub ssh_cursor: String,
    pub ssh_checked_at: i64,
    pub language: String,
    pub server_id: String,
    pub seed: String,
    pub registered_at: String,
    pub devices: Vec<Device>,
    pub last_error: String,
    pub last_check_at: i64,
    pub active: Vec<Problem>,
    pub relay_maintenance: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            channel: pb::NotifyChannel::Off as i32,
            relay_url: String::new(),
            ntfy_url: "https://ntfy.sh".into(),
            ntfy_topic: String::new(),
            raid: true,
            smart: true,
            space: true,
            space_percent: 90,
            services: true,
            backups: true,
            agent_update: true,
            operations: false,
            ssh_logins: true,
            custom_checks: false,
            quiet_keys: Vec::new(),
            ssh_cursor: String::new(),
            ssh_checked_at: 0,
            language: "en".into(),
            server_id: String::new(),
            seed: String::new(),
            registered_at: String::new(),
            devices: Vec::new(),
            last_error: String::new(),
            last_check_at: 0,
            active: Vec::new(),
            relay_maintenance: String::new(),
        }
    }
}

impl Config {
    pub fn channel(&self) -> pb::NotifyChannel {
        pb::NotifyChannel::try_from(self.channel).unwrap_or(pb::NotifyChannel::Off)
    }

    pub fn russian(&self) -> bool {
        self.language.starts_with("ru")
    }

    pub fn seed_bytes(&self) -> Option<[u8; 32]> {
        let bytes: Vec<u8> = (0..self.seed.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(self.seed.get(i..i + 2)?, 16).ok())
            .collect();
        bytes.try_into().ok()
    }

    /// Makes the server id and key once
    fn ensure_identity(&mut self) {
        if self.server_id.is_empty() {
            self.server_id = hex(&random::<16>());
        }
        if self.seed_bytes().is_none() {
            self.seed = hex(&random::<32>());
            self.registered_at.clear();
        }
    }

    fn checks(&self) -> Checks {
        Checks {
            raid: self.raid,
            smart: self.smart,
            space: self.space,
            space_percent: self.space_percent.clamp(50, 99),
            services: self.services,
            backups: self.backups,
            agent_update: self.agent_update,
        }
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut file, &mut bytes);
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Nanoseconds now, for unique file names
pub fn stamp() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn load(store: &Arc<Mutex<Store>>) -> Config {
    let text = store.lock().ok().and_then(|s| s.value(KEY).ok().flatten());
    let mut config: Config = text.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    config.relay_url = current_relay(&config.relay_url);
    config
}

/// The relay that answered on port 8444 before it moved
const RETIRED_RELAY: &str = "https://push.gryonix.com:8444";
const DEFAULT_RELAY: &str = "https://push.gryonix.com";

/// A relay address, the retired one replaced by today's
pub fn current_relay(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    if url == RETIRED_RELAY { DEFAULT_RELAY.to_string() } else { url.to_string() }
}

pub fn save(store: &Arc<Mutex<Store>>, config: &Config) {
    if let (Ok(text), Ok(store)) = (serde_json::to_string(config), store.lock()) {
        let _ = store.set_value(KEY, &text);
    }
}

fn save_keeping_watch_state(store: &Arc<Mutex<Store>>, config: &mut Config) {
    let fresh = load(store);
    config.ssh_cursor = fresh.ssh_cursor;
    config.ssh_checked_at = fresh.ssh_checked_at;
    config.active = fresh.active;
    config.last_check_at = fresh.last_check_at;
    save(store, config);
}

pub fn host() -> String {
    std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string()).unwrap_or_else(|_| "server".into())
}

pub fn settings(config: &Config) -> pb::NotifySettings {
    let russian = config.russian();
    pb::NotifySettings {
        channel: config.channel,
        relay_url: config.relay_url.clone(),
        ntfy_url: config.ntfy_url.clone(),
        ntfy_topic: config.ntfy_topic.clone(),
        checks: Some(pb::NotifyChecks {
            raid: config.raid,
            smart: config.smart,
            disk_space: config.space,
            disk_space_percent: config.space_percent,
            services: config.services,
            backups: config.backups,
            agent_update: config.agent_update,
            operations: config.operations,
            ssh_logins: config.ssh_logins,
        }),
        server_id: config.server_id.clone(),
        devices: config.devices.len() as u32,
        last_error: config.last_error.clone(),
        last_check_at: config.last_check_at,
        active_problems: config.active.iter().map(|p| notify_send::alert(p, true, &host(), russian).body).collect(),
        language: config.language.clone(),
        relay_maintenance: config.relay_maintenance.clone(),
        custom_checks: config.custom_checks,
        quiet_keys: config.quiet_keys.clone(),
        registered: config.devices.iter().map(listed).collect(),
    }
}

fn listed(device: &Device) -> pb::NotifyDevice {
    pb::NotifyDevice {
        platform: device.platform.clone(),
        token: device.token.clone(),
        name: device.name.clone(),
        app_version: device.app_version.clone(),
        added_at: device.added_at,
    }
}

// MARK: delivery

pub fn record(config: &mut Config, sent: &Sent) {
    match sent {
        Sent::Ok => {
            config.last_error.clear();
            config.relay_maintenance.clear();
        }
        Sent::Paused(why) => config.relay_maintenance = why.clone(),
        Sent::Failed(why) => config.last_error = why.clone(),
    }
}

async fn relay_call(config: &Config, method: &str, path: &str, body: &[u8]) -> Sent {
    let Some(seed) = config.seed_bytes() else { return Sent::Failed("no server key".into()) };
    notify_send::relay(&config.relay_url, &seed, method, path, body, now()).await
}

/// An empty relay at the same address
pub fn forgot_server(sent: &Sent) -> bool {
    matches!(sent, Sent::Failed(why) if why == "relay 404: unknown server")
}

/// One relay call, registering again if the relay forgot us
async fn relay_call_known(config: &mut Config, method: &str, path: &str, body: &[u8]) -> Sent {
    let sent = relay_call(config, method, path, body).await;
    if !forgot_server(&sent) {
        return sent;
    }
    config.registered_at.clear();
    let again = register(config).await;
    if again != Sent::Ok {
        return again;
    }
    relay_call(config, method, path, body).await
}

/// Registers this server and its phones again, keeping the result
pub async fn register_again(store: &Arc<Mutex<Store>>) -> Sent {
    let mut config = load(store);
    config.registered_at.clear();
    let sent = register(&mut config).await;
    let mut latest = load(store);
    latest.registered_at = config.registered_at;
    record(&mut latest, &sent);
    save(store, &latest);
    sent
}

/// Tells the relay this server's key, then every phone
async fn register(config: &mut Config) -> Sent {
    config.ensure_identity();
    let path = format!("/v1/servers/{}", config.server_id);
    let Some(seed) = config.seed_bytes() else { return Sent::Failed("no server key".into()) };
    let body = serde_json::json!({ "public_key": notify_send::public_key(&seed) }).to_string();
    let sent = relay_call(config, "PUT", &path, body.as_bytes()).await;
    if sent != Sent::Ok {
        return sent;
    }
    config.registered_at = config.relay_url.clone();
    for device in config.devices.clone() {
        let sent = put_device(config, &device).await;
        if sent != Sent::Ok {
            return sent;
        }
    }
    Sent::Ok
}

async fn put_device(config: &Config, device: &Device) -> Sent {
    let path = format!("/v1/servers/{}/devices", config.server_id);
    relay_call(config, "PUT", &path, &device.relay_body()).await
}

/// Sends one alert through the chosen channel
pub async fn deliver(config: &mut Config, alert: &Alert) -> Sent {
    match config.channel() {
        pb::NotifyChannel::Relay => {
            if config.registered_at != config.relay_url {
                let sent = register(config).await;
                if sent != Sent::Ok {
                    return sent;
                }
            }
            let path = format!("/v1/servers/{}/events", config.server_id);
            let body = notify_send::event_body(alert, &config.server_id);
            relay_call_known(config, "POST", &path, &body).await
        }
        pb::NotifyChannel::Ntfy => notify_send::ntfy(&config.ntfy_url, &config.ntfy_topic, alert).await,
        _ => Sent::Ok,
    }
}

// MARK: checks

/// One check run: sends changes, remembers current problems
pub async fn run_checks(store: &Arc<Mutex<Store>>) {
    let mut config = load(store);
    let failed_groups = store.lock().ok().and_then(|s| s.failed_container_backups().ok()).unwrap_or_default();
    let found = health_watch::probe(&config.checks(), &failed_groups).await;
    let (appeared, cleared) = health_watch::changes(&config.active, &found);
    let host = host();
    // A new agent needs no all-clear once it is installed.
    let cleared = cleared.iter().filter(|p| p.kind != health_watch::Kind::AgentUpdate);
    let alerts = appeared.iter().map(|p| (p, true)).chain(cleared.map(|p| (p, false)));
    let mut all_sent = true;
    for (problem, is_new) in alerts {
        let alert = notify_send::alert(problem, is_new, &host, config.russian());
        let sent = deliver(&mut config, &alert).await;
        all_sent &= sent == Sent::Ok;
        record(&mut config, &sent);
    }
    // Unsent changes stay pending, so the next run retries them.
    if all_sent || config.channel() == pb::NotifyChannel::Off {
        config.active = found;
    }
    config.last_check_at = now();
    let mut latest = load(store);
    latest.active = config.active;
    latest.last_check_at = config.last_check_at;
    latest.last_error = config.last_error;
    latest.relay_maintenance = config.relay_maintenance;
    latest.registered_at = config.registered_at;
    save(store, &latest);
}

/// What a finished run is called, in the settings' language
pub fn run_name(kind: i32, russian: bool) -> &'static str {
    let kind = pb::JobKind::try_from(kind).unwrap_or(pb::JobKind::Unspecified);
    match (kind, russian) {
        (pb::JobKind::Install, false) => "Install",
        (pb::JobKind::Install, true) => "Установка",
        (pb::JobKind::Repair, false) => "Repair",
        (pb::JobKind::Repair, true) => "Починка",
        (pb::JobKind::Reinstall, false) => "Reinstall",
        (pb::JobKind::Reinstall, true) => "Переустановка",
        (pb::JobKind::Update | pb::JobKind::ContainerUpdate, false) => "Update",
        (pb::JobKind::Update | pb::JobKind::ContainerUpdate, true) => "Обновление",
        (pb::JobKind::Backup | pb::JobKind::ContainerBackup, false) => "Backup",
        (pb::JobKind::Backup | pb::JobKind::ContainerBackup, true) => "Резервная копия",
        (pb::JobKind::Restore, false) => "Restore",
        (pb::JobKind::Restore, true) => "Восстановление",
        (pb::JobKind::Move, false) => "Move",
        (pb::JobKind::Move, true) => "Перенос",
        (pb::JobKind::Uninstall | pb::JobKind::ContainerRemoval, false) => "Removal",
        (pb::JobKind::Uninstall | pb::JobKind::ContainerRemoval, true) => "Удаление",
        (_, false) => "Operation",
        (_, true) => "Операция",
    }
}

/// Runs shorter than this are not worth a notification
const LONG_RUN_SECS: i64 = 60;

/// A long run ended while no island showed it
pub fn job_ended(kind: i32, subject: &str, seconds: i64, failure: Option<&str>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    let Some(store) = crate::live::shared_store() else { return };
    let mut config = load(&store);
    if !config.operations || seconds < LONG_RUN_SECS || config.channel() == pb::NotifyChannel::Off {
        return;
    }
    let key = if failure.is_some() { "gnx.alert.operation.failed" } else { "gnx.alert.operation" };
    let alert = notify_send::event_alert(key, &host(), subject, run_name(kind, config.russian()), config.russian());
    runtime.spawn(async move {
        let sent = deliver(&mut config, &alert).await;
        if let Sent::Failed(why) = sent {
            tracing::warn!("run notification not sent: {why}");
        }
    });
}

const START_ANNOUNCE_AFTER: std::time::Duration = std::time::Duration::from_secs(20);

fn announces_start(kind: i32) -> bool {
    use pb::JobKind::*;
    matches!(
        pb::JobKind::try_from(kind),
        Ok(Install | Repair | Reinstall | Update | ContainerUpdate | Backup | ContainerBackup | Restore | Move | Uninstall | ContainerRemoval | AgentUpdate)
    )
}

pub fn job_started(kind: i32, subject: &str, job_id: &str) {
    if !announces_start(kind) {
        return;
    }
    crate::live::job_began(kind, subject, job_id);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    let (subject, job_id) = (subject.to_string(), job_id.to_string());
    runtime.spawn(async move {
        tokio::time::sleep(START_ANNOUNCE_AFTER).await;
        let still_going = crate::jobs::is_running(&job_id) || crate::install::journal::is_running(&job_id);
        let Some(store) = crate::live::shared_store() else { return };
        let mut config = load(&store);
        if !still_going || !config.operations || config.channel() == pb::NotifyChannel::Off {
            return;
        }
        let mut alert = notify_send::event_alert(
            "gnx.alert.operation.started", &host(), &subject, run_name(kind, config.russian()), config.russian(),
        );
        alert.job_id = Some(job_id);
        if let Sent::Failed(why) = deliver(&mut config, &alert).await {
            tracing::warn!("run start notification not sent: {why}");
        }
    });
}

pub fn spawn(store: Arc<Mutex<Store>>) {
    crate::live::init(store.clone());
    crate::ssh_watch::spawn(store.clone());
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            run_checks(&store).await;
            tokio::time::sleep(EVERY).await;
        }
    });
}

// MARK: API

fn encode(codec: Codec, settings: pb::NotifySettings) -> Resp {
    codec.encode(&settings).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

fn refuse(message: &str) -> Resp {
    connect_error(StatusCode::BAD_REQUEST, "invalid_argument", message)
}

fn valid_url(url: &str) -> bool {
    if url.len() <= 8 || url.contains(char::is_whitespace) {
        return false;
    }
    url.starts_with("https://") || url.strip_prefix("http://").is_some_and(is_local_host)
}

fn is_local_host(rest: &str) -> bool {
    let host = rest.split(['/', ':']).next().unwrap_or_default().to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".lan") {
        return true;
    }
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ip.is_loopback() || ip.is_private(),
        Err(_) => false,
    }
}

fn valid_topic(topic: &str) -> bool {
    (1..=64).contains(&topic.len()) && topic.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Applies the request, or says why it cannot
fn apply(config: &mut Config, req: pb::SetNotifySettingsRequest) -> Result<(), &'static str> {
    let channel = pb::NotifyChannel::try_from(req.channel).unwrap_or(pb::NotifyChannel::Unspecified);
    match channel {
        pb::NotifyChannel::Relay if !valid_url(req.relay_url.trim()) => return Err("the relay address must start with https:// (http:// only for a name or address in the home network)"),
        pb::NotifyChannel::Ntfy if !valid_url(req.ntfy_url.trim()) => return Err("the ntfy address must start with https:// (http:// only for a name or address in the home network)"),
        pb::NotifyChannel::Ntfy if !valid_topic(req.ntfy_topic.trim()) => return Err("the ntfy topic may use letters, digits, - and _"),
        pb::NotifyChannel::Unspecified => return Err("choose a channel"),
        _ => {}
    }
    config.channel = channel as i32;
    config.relay_url = current_relay(&req.relay_url);
    config.ntfy_url = req.ntfy_url.trim().trim_end_matches('/').to_string();
    config.ntfy_topic = req.ntfy_topic.trim().to_string();
    if let Some(checks) = req.checks {
        config.raid = checks.raid;
        config.smart = checks.smart;
        config.space = checks.disk_space;
        config.space_percent = if checks.disk_space_percent == 0 { 90 } else { checks.disk_space_percent.clamp(50, 99) };
        config.services = checks.services;
        config.backups = checks.backups;
        config.agent_update = checks.agent_update;
        config.operations = checks.operations;
        config.ssh_logins = checks.ssh_logins;
    }
    config.custom_checks = req.custom_checks;
    crate::ssh_watch::remember_key(&mut config.quiet_keys, &req.app_public_key);
    if !req.language.is_empty() {
        config.language = req.language.chars().take(8).collect();
    }
    Ok(())
}

pub async fn get(codec: Codec, store: Arc<Mutex<Store>>) -> Resp {
    encode(codec, settings(&load(&store)))
}

pub async fn set(codec: Codec, store: Arc<Mutex<Store>>, req: pb::SetNotifySettingsRequest) -> Resp {
    let mut config = load(&store);
    if let Err(why) = apply(&mut config, req) {
        return refuse(why);
    }
    config.last_error.clear();
    if config.channel() == pb::NotifyChannel::Relay {
        let sent = register(&mut config).await;
        record(&mut config, &sent);
    }
    save_keeping_watch_state(&store, &mut config);
    encode(codec, settings(&config))
}

pub async fn register_device(codec: Codec, store: Arc<Mutex<Store>>, req: pb::RegisterNotifyDeviceRequest) -> Resp {
    if !matches!(req.platform.as_str(), "apns" | "fcm") || req.token.is_empty() || req.token.len() > 4096 {
        return refuse("a device needs a platform and a token");
    }
    let mut config = load(&store);
    config.ensure_identity();
    let muted = req.muted.into_iter().filter(|t| t.len() <= 32).take(16).collect();
    let proof = req.device_proof.trim().to_ascii_lowercase();
    let proof = if proof.len() == 64 && proof.chars().all(|c| c.is_ascii_hexdigit()) { proof } else { String::new() };
    let name: String = req.name.trim().chars().take(64).collect();
    let added_at = config.devices.iter().find(|d| d.token == req.token).map_or_else(now, |d| d.added_at);
    let device = Device { platform: req.platform, token: req.token, app_version: req.app_version, locale: req.locale, muted, proof, name, added_at };
    config.devices.retain(|d| d.token != device.token);
    config.devices.push(device.clone());
    if config.channel() == pb::NotifyChannel::Relay && config.registered_at == config.relay_url {
        let path = format!("/v1/servers/{}/devices", config.server_id);
        let sent = relay_call_known(&mut config, "PUT", &path, &device.relay_body()).await;
        record(&mut config, &sent);
    }
    save_keeping_watch_state(&store, &mut config);
    encode(codec, settings(&config))
}

pub async fn unregister_device(codec: Codec, store: Arc<Mutex<Store>>, req: pb::UnregisterNotifyDeviceRequest) -> Resp {
    let mut config = load(&store);
    config.devices.retain(|d| d.token != req.token);
    if config.channel() == pb::NotifyChannel::Relay && config.registered_at == config.relay_url {
        let path = format!("/v1/servers/{}/devices/{}", config.server_id, req.token);
        let sent = relay_call_known(&mut config, "DELETE", &path, b"").await;
        record(&mut config, &sent);
    }
    save_keeping_watch_state(&store, &mut config);
    encode(codec, settings(&config))
}

/// How a job ended, or `None` while it runs
fn ending_of(job: &pb::Job) -> Option<Option<&str>> {
    (job.outcome != pb::JobOutcome::Running as i32).then(|| (!job.failure.is_empty()).then_some(job.failure.as_str()))
}

pub async fn watch_live(codec: Codec, store: Arc<Mutex<Store>>, req: pb::WatchLiveActivityRequest) -> Resp {
    if req.job_id.is_empty() || req.token.is_empty() || req.token.len() > 4096 {
        return refuse("a live activity needs a job and a token");
    }
    let ready = crate::live::relay_ready(&load(&store));
    if ready {
        crate::live::watch(&req.job_id, &req.token, &req.title.chars().take(120).collect::<String>());
        // An already finished job still closes the island.
        if let Some(failure) = crate::jobs::job(&req.job_id).as_ref().and_then(ending_of) {
            crate::live::finished(&req.job_id, failure);
        }
    }
    let message = if ready { String::new() } else { "notifications do not go through a relay".to_string() };
    codec
        .encode(&pb::NotifyTestResult { ok: ready, message })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

/// Plays a sample island card through the relay
pub async fn test_live(codec: Codec, store: Arc<Mutex<Store>>, req: pb::TestLiveActivityRequest) -> Resp {
    if req.token.is_empty() || req.token.len() > 4096 {
        return refuse("a live activity needs a token");
    }
    let ready = crate::live::relay_ready(&load(&store));
    if ready {
        crate::live::run_check(&req.token, &req.title.chars().take(120).collect::<String>());
    }
    let message = if ready { String::new() } else { "notifications do not go through a relay".to_string() };
    codec
        .encode(&pb::NotifyTestResult { ok: ready, message })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

/// Follows a VPN session's Live Activity, through the relay
pub async fn watch_tunnel(codec: Codec, store: Arc<Mutex<Store>>, req: pb::WatchTunnelActivityRequest) -> Resp {
    if req.token.is_empty() || req.token.len() > 4096 {
        return refuse("a live activity needs a token");
    }
    let ready = crate::live::relay_ready(&load(&store));
    let followed = ready && crate::live_tunnel::watch(&req.token, &req.protocol, &req.address, req.started_at, req.stop);
    let message = match (ready, followed) {
        (false, _) => "notifications do not go through a relay",
        (true, false) => "this protocol's sessions are not measured on the server",
        (true, true) => "",
    };
    codec
        .encode(&pb::NotifyTestResult { ok: followed, message: message.to_string() })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn send_test(codec: Codec, store: Arc<Mutex<Store>>) -> Resp {
    let mut config = load(&store);
    let sent = match config.channel() {
        pb::NotifyChannel::Off | pb::NotifyChannel::Unspecified => Sent::Failed("notifications are off".into()),
        _ => {
            let alert = notify_send::test_alert(&host(), config.russian());
            deliver(&mut config, &alert).await
        }
    };
    record(&mut config, &sent);
    save(&store, &config);
    let (ok, message) = match sent {
        Sent::Ok => (true, String::new()),
        Sent::Paused(why) | Sent::Failed(why) => (false, why),
    };
    codec
        .encode(&pb::NotifyTestResult { ok, message })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_retired_relay_port_becomes_todays_address() {
        assert_eq!(current_relay("https://push.gryonix.com:8444"), "https://push.gryonix.com");
        assert_eq!(current_relay("https://push.gryonix.com:8444/"), "https://push.gryonix.com");
        assert_eq!(current_relay("https://relay.example.net:8444"), "https://relay.example.net:8444", "own relays stay");
        assert_eq!(current_relay(" https://push.gryonix.com "), "https://push.gryonix.com");
    }

    #[test]
    fn runs_are_named_in_the_settings_language() {
        assert_eq!(run_name(pb::JobKind::Install as i32, true), "Установка");
        assert_eq!(run_name(pb::JobKind::ContainerBackup as i32, false), "Backup");
    }
    use super::*;

    fn store() -> Arc<Mutex<Store>> {
        Arc::new(Mutex::new(Store::in_memory().unwrap()))
    }

    fn request(channel: pb::NotifyChannel, relay: &str, topic: &str) -> pb::SetNotifySettingsRequest {
        pb::SetNotifySettingsRequest {
            channel: channel as i32,
            relay_url: relay.into(),
            ntfy_url: "https://ntfy.sh".into(),
            ntfy_topic: topic.into(),
            checks: Some(pb::NotifyChecks { raid: true, smart: false, disk_space: true, disk_space_percent: 120, services: true, backups: false, agent_update: true, operations: true, ssh_logins: false }),
            language: "ru".into(),
            custom_checks: true,
            app_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMjhZbMLa1yPZt87ATUHLO4OUNZoQu6+22Re+KW7HKUl phone".into(),
        }
    }

    #[test]
    fn settings_are_checked_before_they_are_kept() {
        let mut config = Config::default();
        assert!(apply(&mut config, request(pb::NotifyChannel::Relay, "push.example.com", "")).is_err());
        assert!(apply(&mut config, request(pb::NotifyChannel::Ntfy, "", "bad topic")).is_err());
        assert!(apply(&mut config, request(pb::NotifyChannel::Unspecified, "", "")).is_err());
        assert!(apply(&mut config, request(pb::NotifyChannel::Ntfy, "", "gnx-alerts_1")).is_ok());
        assert_eq!((config.space_percent, config.smart, config.language.as_str()), (99, false, "ru"));
        assert!(config.custom_checks);
        assert_eq!(config.quiet_keys, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMjhZbMLa1yPZt87ATUHLO4OUNZoQu6+22Re+KW7HKUl"]);
    }

    #[test]
    fn devices_are_listed_with_names_the_relay_never_sees() {
        let mut config = Config::default();
        config.devices.push(Device { platform: "apns".into(), token: "t1".into(), app_version: "26.10".into(), locale: "en".into(), muted: Vec::new(), proof: String::new(), name: "iPhone".into(), added_at: 7 });
        let listed = settings(&config).registered;
        assert_eq!((listed[0].name.as_str(), listed[0].token.as_str(), listed[0].added_at), ("iPhone", "t1", 7));
        let body: serde_json::Value = serde_json::from_slice(&config.devices[0].relay_body()).unwrap();
        assert_eq!(body["token"], "t1");
        assert!(body.get("name").is_none() && body.get("added_at").is_none());
    }

    #[test]
    fn identity_is_made_once() {
        let mut config = Config::default();
        config.ensure_identity();
        let (id, seed) = (config.server_id.clone(), config.seed.clone());
        assert_eq!((id.len(), seed.len()), (32, 64));
        config.ensure_identity();
        assert_eq!((config.server_id, config.seed), (id, seed));
    }

    #[test]
    fn config_survives_the_store() {
        let store = store();
        let mut config = Config::default();
        config.ntfy_topic = "t".into();
        config.devices.push(Device { platform: "apns".into(), token: "abc".into(), app_version: "1".into(), locale: "ru".into(), muted: Vec::new(), proof: String::new(), name: String::new(), added_at: 0 });
        save(&store, &config);
        let back = load(&store);
        assert_eq!((back.ntfy_topic.as_str(), back.devices.len()), ("t", 1));
    }

    /// A relay built in the neighbouring gryonixPush repository
    fn relay_binary() -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../gryonixPush/Server/gryonixpushd/target/debug/gryonixpushd");
        path.is_file().then_some(path)
    }

    #[tokio::test]
    async fn a_real_relay_accepts_this_agent() {
        let Some(binary) = relay_binary() else { return };
        let state = std::env::temp_dir().join(format!("gnx-notify-{}", std::process::id()));
        let port = 21000 + (std::process::id() % 2000);
        let mut relay = std::process::Command::new(binary)
            .env("GRYONIXPUSH_STATE", &state)
            .env("GRYONIXPUSH_LISTEN", format!("127.0.0.1:{port}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..50 {
            if notify_send::http("GET", &format!("http://127.0.0.1:{port}/health"), &[], b"").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut config = Config::default();
        apply(&mut config, request(pb::NotifyChannel::Relay, &format!("http://127.0.0.1:{port}"), "")).unwrap();
        config.devices.push(Device { platform: "apns".into(), token: "aa".repeat(32), app_version: "1.0".into(), locale: "ru".into(), muted: Vec::new(), proof: String::new(), name: String::new(), added_at: 0 });
        let registered = register(&mut config).await;
        let sent = deliver(&mut config, &notify_send::test_alert("test", true)).await;
        let live_body = serde_json::json!({ "token": "activity", "state": crate::live::content_state("x", None, false, None) });
        let path = format!("/v1/servers/{}/live", config.server_id);
        let live = relay_call(&config, "POST", &path, live_body.to_string().as_bytes()).await;
        let _ = relay.kill();
        let _ = std::fs::remove_dir_all(&state);
        assert_eq!(registered, Sent::Ok);
        assert_eq!(sent, Sent::Ok);
        // Signed and accepted; only Apple's key is missing here.
        assert_eq!(live, Sent::Failed("relay 502: Apple key not set".into()));
    }

    fn start_relay(binary: &std::path::Path, state: &std::path::Path, port: u32) -> std::process::Child {
        std::process::Command::new(binary)
            .env("GRYONIXPUSH_STATE", state)
            .env("GRYONIXPUSH_LISTEN", format!("127.0.0.1:{port}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    async fn wait_for(port: u32) {
        for _ in 0..50 {
            if notify_send::http("GET", &format!("http://127.0.0.1:{port}/health"), &[], b"").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn a_new_relay_at_the_same_address_hears_the_server_again() {
        let Some(binary) = relay_binary() else { return };
        let old = std::env::temp_dir().join(format!("gnx-notify-old-{}", std::process::id()));
        let new = std::env::temp_dir().join(format!("gnx-notify-new-{}", std::process::id()));
        let port = 23000 + (std::process::id() % 2000);
        let mut relay = start_relay(&binary, &old, port);
        wait_for(port).await;
        let mut config = Config::default();
        apply(&mut config, request(pb::NotifyChannel::Relay, &format!("http://127.0.0.1:{port}"), "")).unwrap();
        config.devices.push(Device { platform: "apns".into(), token: "bb".repeat(32), app_version: "1.0".into(), locale: "ru".into(), muted: Vec::new(), proof: String::new(), name: String::new(), added_at: 0 });
        let first = deliver(&mut config, &notify_send::test_alert("test", true)).await;
        let _ = relay.kill();
        let _ = relay.wait();

        let mut relay = start_relay(&binary, &new, port);
        wait_for(port).await;
        let blind = relay_call(&config, "POST", &format!("/v1/servers/{}/events", config.server_id), b"{}").await;
        let again = deliver(&mut config, &notify_send::test_alert("test", true)).await;
        let _ = relay.kill();
        let _ = std::fs::remove_dir_all(&old);
        let _ = std::fs::remove_dir_all(&new);
        assert_eq!(first, Sent::Ok);
        assert!(forgot_server(&blind), "the empty relay does not know the server: {blind:?}");
        assert_eq!(again, Sent::Ok, "the agent registers again by itself");
    }

    #[test]
    fn a_running_job_keeps_its_island_open() {
        let mut job = pb::Job { outcome: pb::JobOutcome::Running as i32, ..Default::default() };
        assert_eq!(ending_of(&job), None);
        job.outcome = pb::JobOutcome::Succeeded as i32;
        assert_eq!(ending_of(&job), Some(None));
        job.outcome = pb::JobOutcome::Failed as i32;
        job.failure = "disk full".into();
        assert_eq!(ending_of(&job), Some(Some("disk full")));
    }
}

#[cfg(test)]
mod address_tests {
    use super::valid_url;

    #[test]
    fn plain_http_is_only_for_the_home_network() {
        assert!(valid_url("https://ntfy.sh"));
        assert!(valid_url("http://192.168.1.20:8080"));
        assert!(valid_url("http://nas.local/ntfy"));
        assert!(valid_url("http://localhost:2586"));
        assert!(!valid_url("http://ntfy.example.com"));
        assert!(!valid_url("http://8.8.8.8"));
        assert!(!valid_url("https://"));
    }
}
