use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;
use tokio::io::AsyncBufReadExt;
use serde_json::Value;

use crate::api::{connect_error, Codec, Resp};
use crate::install::packages::have_binary;
use crate::install::ssh_password;
use crate::pb;
use crate::util::strip_ansi;

/// The package's config file
const CONFIG_PATH: &str = "/etc/crowdsec/config.yaml";
const ENGINE_UNIT: &str = "crowdsec";
const BOUNCER_UNIT: &str = "crowdsec-firewall-bouncer";
const CSCLI_BIN: &str = "cscli";

/// One call's deadline
const QUICK_TIMEOUT_SECS: u64 = 20;

/// How many entries the card shows
const TOP_SCENARIOS: usize = 5;
const RECENT_BANS: usize = 8;

fn cscli_bin() -> String {
    std::env::var("GRYONIXNEXUSD_CSCLI_BIN").unwrap_or_else(|_| CSCLI_BIN.to_string())
}

fn config_path() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_CROWDSEC_CONFIG").unwrap_or_else(|_| CONFIG_PATH.to_string()),
    )
}

fn present() -> bool {
    have_binary(&cscli_bin()) && config_path().exists()
}

/// `systemctl is-active <unit>` → true only on a literal `active`.
async fn unit_active(unit: &str) -> bool {
    let Ok(child) = tokio::process::Command::new("systemctl")
        .args(["is-active", unit])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return false;
    };
    let Ok(Ok(output)) =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output()).await
    else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).trim() == "active"
}

async fn cscli(args: &[&str]) -> Option<String> {
    let child = tokio::process::Command::new(cscli_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let output =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
            .await
            .ok()?
            .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(strip_ansi(&String::from_utf8_lossy(&output.stdout)))
}

/// `cscli version` prints `version: v1.8.0-debian-pragmatic-amd64-<hash>` as its first line
fn parse_engine_version(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("version:"))
        .map(str::trim)
        .map(|v| v.split('-').next().unwrap_or(v).to_string())
        .unwrap_or_default()
}

fn parse_alert_count(json: &str) -> u32 {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len() as u32))
        .unwrap_or(0)
}

fn parse_recent_bans(json: &str, limit: usize) -> Vec<pb::SecurityBan> {
    let Ok(Value::Array(alerts)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    alerts
        .iter()
        .filter_map(|alert| {
            let source = alert.get("source")?;
            let ip = source.get("value").and_then(Value::as_str).unwrap_or_default();
            if ip.is_empty() {
                return None;
            }
            Some(pb::SecurityBan {
                ip: ip.to_string(),
                country: source
                    .get("cn")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                scenario: alert
                    .get("scenario")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                at: alert
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .take(limit)
        .collect()
}

fn parse_top_scenarios(metrics: &Value, limit: usize) -> Vec<pb::SecurityScenario> {
    let Some(alerts) = metrics.get("alerts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut rows: Vec<pb::SecurityScenario> = alerts
        .iter()
        .filter_map(|(name, count)| {
            Some(pb::SecurityScenario {
                name: name.clone(),
                count: count.as_u64()? as u32,
            })
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    rows.truncate(limit);
    rows
}

fn parse_community_blocklist_ips(metrics: &Value) -> u32 {
    walk_bouncers(metrics)
        .filter(|(origin, _)| *origin == "CAPI")
        .filter_map(|(_, body)| {
            body.get("active_decisions")
                .and_then(|d| d.get("ip"))
                .and_then(Value::as_u64)
        })
        .sum::<u64>() as u32
}

fn parse_packets_dropped(metrics: &Value) -> u64 {
    walk_bouncers(metrics)
        .filter_map(|(_, body)| {
            body.get("dropped")
                .and_then(|d| d.get("packet"))
                .and_then(Value::as_u64)
        })
        .sum()
}

fn walk_bouncers(metrics: &Value) -> impl Iterator<Item = (&str, &Value)> {
    metrics
        .get("bouncers")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|bouncers| bouncers.values())
        .filter_map(Value::as_object)
        .flat_map(|by_origin| by_origin.iter())
        .map(|(origin, body)| (origin.as_str(), body))
}

/// Assemble the status from the host
pub async fn get_security_status(codec: Codec, _req: pb::GetSecurityStatusRequest) -> Resp {
    let mut status = pb::SecurityStatus::default();

    if !present() {
        return encode(codec, &status);
    }
    status.present = true;

    let (engine_running, bouncer_running, version, alerts_json, decisions_json, recent_json, metrics_json) =
        tokio::join!(
            unit_active(ENGINE_UNIT),
            unit_active(BOUNCER_UNIT),
            cscli(&["version"]),
            cscli(&["alerts", "list", "--since", "24h", "--limit", "0", "-o", "json"]),
            cscli(&["decisions", "list", "--limit", "0", "-o", "json"]),
            cscli(&["alerts", "list", "--limit", "16", "-o", "json"]),
            cscli(&["metrics", "-o", "json"]),
        );
    status.engine_running = engine_running;
    status.bouncer_running = bouncer_running;
    if let Some(version) = version {
        status.engine_version = parse_engine_version(&version);
    }
    if let Some(json) = alerts_json {
        status.alerts_24h = parse_alert_count(&json);
    }
    if let Some(json) = decisions_json {
        status.local_bans = parse_alert_count(&json);
    }
    if let Some(json) = recent_json {
        status.recent_bans = parse_recent_bans(&json, RECENT_BANS);
    }
    if let Some(text) = metrics_json {
        if let Ok(metrics) = serde_json::from_str::<Value>(&text) {
            status.top_scenarios = parse_top_scenarios(&metrics, TOP_SCENARIOS);
            status.community_blocklist_ips = parse_community_blocklist_ips(&metrics);
            status.packets_dropped = parse_packets_dropped(&metrics);
        }
    }

    encode(codec, &status)
}

// ─────────────────────── SSH password login ────────────────────────────

pub async fn get_ssh_password_state(codec: Codec, req: pb::GetSshPasswordStateRequest) -> Resp {
    let state = match ssh_password::read_state(&req.login_user, &req.app_public_key).await {
        Ok(state) => state,
        Err(why) => return encode(codec, &unknown_state(&req.login_user, &why)),
    };
    encode(codec, &into_pb(state, String::new()))
}

pub async fn set_ssh_password_login(codec: Codec, req: pb::SetSshPasswordLoginRequest) -> Resp {
    let verdict = if req.allow_passwords {
        ssh_password::open_password_login_now().await
    } else {
        ssh_password::close_password_login_now(&req.login_user, &req.app_public_key).await
    };
    let detail = match verdict {
        Ok(verdict) => ssh_password::verdict_sentence(&verdict, &req.login_user),
        Err(why) => {
            return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "failed_precondition", &why)
        }
    };
    match ssh_password::read_state(&req.login_user, &req.app_public_key).await {
        Ok(state) => encode(codec, &into_pb(state, detail)),
        Err(why) => encode(codec, &unknown_state(&req.login_user, &format!("{detail}; {why}"))),
    }
}

/// Every account on this host and what its SSH accepts.
pub async fn list_ssh_users(codec: Codec, req: pb::ListSshUsersRequest) -> Resp {
    encode(codec, &users_answer(&req.login_user, &req.app_public_key, String::new()).await)
}

pub async fn set_ssh_key_only_users(codec: Codec, req: pb::SetSshKeyOnlyUsersRequest) -> Resp {
    let scope = if req.everyone {
        ssh_password::KeyOnly::Everyone
    } else {
        ssh_password::KeyOnly::Accounts(req.users.clone())
    };
    let detail = match ssh_password::set_key_only_now(&scope, &req.login_user, &req.app_public_key)
        .await
    {
        Ok(verdict) => ssh_password::verdict_sentence(&verdict, &req.login_user),
        Err(why) => {
            return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "failed_precondition", &why)
        }
    };
    encode(codec, &users_answer(&req.login_user, &req.app_public_key, detail).await)
}

/// The accounts and the host-wide reading, in one answer.
async fn users_answer(login_user: &str, app_public_key: &str, detail: String) -> pb::SshUsers {
    let host = match ssh_password::read_state(login_user, app_public_key).await {
        Ok(state) => into_pb(state, String::new()),
        Err(why) => unknown_state(login_user, &why),
    };
    let asked = host.login_user.clone();
    match ssh_password::list_users(app_public_key).await {
        Ok(users) => pb::SshUsers {
            users: users
                .into_iter()
                .map(|user| pb::SshUser {
                    password_login_open: user.password_open.unwrap_or(false),
                    known: user.password_open.is_some(),
                    carries_keys: user.has_keys,
                    app_key_present: user.app_key_present,
                    is_login_user: user.name == asked,
                    name: user.name,
                })
                .collect(),
            host: Some(host),
            detail,
            known: true,
        },
        Err(why) => pb::SshUsers {
            users: Vec::new(),
            host: Some(host),
            detail: if detail.is_empty() { why } else { format!("{detail}; {why}") },
            known: false,
        },
    }
}

fn into_pb(state: ssh_password::State, detail: String) -> pb::SshPasswordState {
    pb::SshPasswordState {
        password_login_open: state.password_open.unwrap_or(false),
        known: state.password_open.is_some(),
        app_key_present: state.app_key_present,
        drop_in_present: state.drop_in_present,
        sshd_present: state.sshd_present,
        login_user: state.login_user,
        detail,
    }
}

fn unknown_state(login_user: &str, detail: &str) -> pb::SshPasswordState {
    pb::SshPasswordState {
        password_login_open: false,
        known: false,
        app_key_present: false,
        drop_in_present: false,
        sshd_present: false,
        login_user: login_user.to_string(),
        detail: detail.to_string(),
    }
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

// ─────────────────────── ControlSecurity ───────────────────────────

pub async fn control_security(codec: Codec, req: pb::ControlSecurityRequest) -> Resp {
    let action = match pb::SecurityAction::try_from(req.action) {
        Ok(pb::SecurityAction::Unspecified) | Err(_) => {
            return connect_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "no action was named, so nothing was done",
            )
        }
        Ok(action) => action,
    };

    let claim = match crate::jobs::OperationClaim::acquire("security", "crowdsec") {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    if action != pb::SecurityAction::Install && !present() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host has no intrusion defence installed, so there is nothing to run. Install it first — nothing was changed",
        );
    }

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = SecuritySink {
            tx,
            codec,
            action,
            journal: crate::jobs::Journal::open(pb::JobKind::SecurityControl, "crowdsec"),
        };
        let _ = sink.started().await;

        let failure = match action {
            pb::SecurityAction::Install => install(&sink).await,
            _ => run_script(&script_for(action), &sink).await.err(),
        };
        if action == pb::SecurityAction::Remove && failure.is_none() {
            crate::install::crowdsec::remember_removal();
        }

        let status = read_status().await;
        let _ = sink.completed(status).await;

        if let Some(why) = failure {
            let _ = sink.fail(&why).await;
        }
    });

    crate::api::stream_response(json, rx)
}

fn script_for(action: pb::SecurityAction) -> String {
    use crate::install::crowdsec::{BOUNCER_PACKAGE, BOUNCER_UNIT, ENGINE_PACKAGE, ENGINE_UNIT};
    let apt = crate::install::packages::APT_OPTIONS;
    match action {
        pb::SecurityAction::Start => format!(
            "systemctl enable --now {ENGINE_UNIT}\n\
             systemctl enable --now {BOUNCER_UNIT} || true\n"
        ),
        pb::SecurityAction::Stop => format!(
            "systemctl stop {BOUNCER_UNIT} || true\n\
             systemctl stop {ENGINE_UNIT}\n"
        ),
        pb::SecurityAction::Restart => format!(
            "systemctl restart {ENGINE_UNIT}\n\
             systemctl try-restart {BOUNCER_UNIT} || true\n"
        ),
        pb::SecurityAction::Update => format!(
            "set -e\n\
             export DEBIAN_FRONTEND=noninteractive\n\
             apt-get {apt} update\n\
             apt-get {apt} install -y --only-upgrade {ENGINE_PACKAGE} {BOUNCER_PACKAGE}\n\
             cscli hub update --error || true\n\
             cscli hub upgrade --error || true\n\
             systemctl restart {ENGINE_UNIT}\n\
             systemctl try-restart {BOUNCER_UNIT} || true\n"
        ),
        pb::SecurityAction::Remove => format!(
            "export DEBIAN_FRONTEND=noninteractive\n\
             systemctl disable --now {BOUNCER_UNIT} >/dev/null 2>&1 || true\n\
             systemctl disable --now {ENGINE_UNIT} >/dev/null 2>&1 || true\n\
             apt-get {apt} purge -y {BOUNCER_PACKAGE} {ENGINE_PACKAGE}\n\
             apt-get {apt} autoremove -y || true\n\
             rm -rf /etc/crowdsec\n"
        ),
        // Handled by `install` above; never reached.
        pb::SecurityAction::Install | pb::SecurityAction::Unspecified => String::new(),
    }
}

/// Put CrowdSec back on a host that has none
async fn install(sink: &SecuritySink) -> Option<String> {
    let _ = sink
        .progress("agent", "installing the host's intrusion defence — this takes a few minutes".into())
        .await;
    crate::install::crowdsec::forget_removal();
    crate::install::crowdsec::ensure_present(true, &crate::install::execute::EventSink::detached()).await;
    if crate::install::crowdsec::engine_configured() {
        let _ = sink.progress("agent", "CrowdSec is installed".into()).await;
        None
    } else {
        Some("CrowdSec did not finish installing; the host is unchanged apart from any packages apt left behind".into())
    }
}

async fn run_script(script: &str, sink: &SecuritySink) -> Result<(), String> {
    let mut child = tokio::process::Command::new(systemd_run_bin())
        .args([
            "--quiet",
            "--collect",
            "--wait",
            "--pipe",
            "--service-type=oneshot",
            "/bin/sh",
            "-c",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run systemd-run: {err}"))?;

    let (lines_tx, mut lines_rx) = tokio::sync::mpsc::channel::<(&'static str, String)>(64);
    if let Some(pipe) = child.stdout.take() {
        let tx = lines_tx.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(pipe).lines();
            while let Ok(Some(text)) = lines.next_line().await {
                if tx.send(("stdout", strip_ansi(&text))).await.is_err() {
                    return;
                }
            }
        });
    }
    if let Some(pipe) = child.stderr.take() {
        let tx = lines_tx.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(pipe).lines();
            while let Ok(Some(text)) = lines.next_line().await {
                if tx.send(("stderr", strip_ansi(&text))).await.is_err() {
                    return;
                }
            }
        });
    }
    drop(lines_tx);

    let forwarding = async {
        while let Some((stream, text)) = lines_rx.recv().await {
            let _ = sink.progress(stream, text).await;
        }
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(ACTION_TIMEOUT_SECS),
        async {
            let (_, status) = tokio::join!(forwarding, child.wait());
            status
        },
    )
    .await;

    match outcome {
        Err(_) => Err(format!("timed out after {ACTION_TIMEOUT_SECS}s")),
        Ok(Err(io)) => Err(format!("the command did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("the command exited {code}"),
            None => "the command was killed by a signal".to_string(),
        }),
    }
}

/// How long one action may take
const ACTION_TIMEOUT_SECS: u64 = 900;

fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

/// The whole status, re-read after an action
async fn read_status() -> pb::SecurityStatus {
    let mut status = pb::SecurityStatus::default();
    if !present() {
        return status;
    }
    status.present = true;
    status.engine_running = unit_active(ENGINE_UNIT).await;
    status.bouncer_running = unit_active(BOUNCER_UNIT).await;
    if let Some(version) = cscli(&["version"]).await {
        status.engine_version = parse_engine_version(&version);
    }
    status
}

pub(crate) struct SecuritySink {
    tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    codec: Codec,
    action: pb::SecurityAction,
    journal: Option<crate::jobs::Journal>,
}

impl SecuritySink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::SecurityOperationEvent {
        pb::SecurityOperationEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            action: self.action as i32,
            text: String::new(),
            stream: String::new(),
            status: None,
        }
    }

    async fn send(&self, event: pb::SecurityOperationEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(crate::api::envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self) -> Result<(), ()> {
        self.send(self.event(pb::ServiceOperationPhase::Started)).await
    }

    pub(crate) async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, status: pb::SecurityStatus) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.status = Some(status);
        self.send(event).await
    }

    async fn fail(&self, message: &str) -> Result<(), ()> {
        crate::jobs::finish(&self.journal, Some(message));
        self.tx
            .send(crate::api::error_trailer("internal", message))
            .await
            .map_err(|_| ())
    }
}

// ─────────────────── Decisions and the allowlist ───────────────────

/// The allowlist this product owns
const ALLOWLIST_NAME: &str = "gryonixnexus";

/// The most decisions the agent will hand over
const DECISIONS_LIMIT: usize = 200;

const MANUAL_REASON: &str = "gryonixnexus: added by hand";

/// Run `cscli` and keep the failure
async fn cscli_checked(args: &[&str]) -> Result<String, String> {
    let child = tokio::process::Command::new(cscli_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("cscli could not be started: {err}"))?;
    let output =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
            .await
            .map_err(|_| "cscli did not answer in time".to_string())?
            .map_err(|err| format!("cscli failed: {err}"))?;
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
    let detail = [stderr.trim(), stdout.trim()]
        .into_iter()
        .find(|text| !text.is_empty())
        .unwrap_or("cscli refused the request")
        .to_string();
    Err(detail)
}

/// An IPv4/IPv6 address or a CIDR range, and nothing else
fn valid_target(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    match prefix {
        None => true,
        Some(prefix) => {
            let ceiling = if address.is_ipv4() { 32 } else { 128 };
            if prefix.is_empty()
                || prefix.len() > 3
                || !prefix.chars().all(|c| c.is_ascii_digit())
                || (prefix.len() > 1 && prefix.starts_with('0'))
            {
                return false;
            }
            matches!(prefix.parse::<u32>(), Ok(bits) if bits <= ceiling)
        }
    }
}

fn duration_arg(seconds: u64) -> Option<String> {
    (seconds > 0).then(|| format!("{seconds}s"))
}

fn parse_decisions(json: &str, limit: usize) -> Vec<pb::SecurityDecision> {
    let Ok(Value::Array(alerts)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for alert in &alerts {
        let source = alert.get("source");
        let country = source
            .and_then(|s| s.get("cn"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let as_name = source
            .and_then(|s| s.get("as_name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let events = alert
            .get("events_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let Some(Value::Array(decisions)) = alert.get("decisions") else {
            continue;
        };
        for decision in decisions {
            let value = decision
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if value.is_empty() {
                continue;
            }
            rows.push(pb::SecurityDecision {
                id: decision
                    .get("id")
                    .and_then(Value::as_u64)
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                scope: decision.get("scope").and_then(Value::as_str).unwrap_or_default().to_string(),
                value: value.to_string(),
                action: decision.get("type").and_then(Value::as_str).unwrap_or_default().to_string(),
                reason: decision
                    .get("scenario")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                country: country.clone(),
                as_name: as_name.clone(),
                source: decision.get("origin").and_then(Value::as_str).unwrap_or_default().to_string(),
                expires_in: decision
                    .get("duration")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                events,
            });
            if rows.len() >= limit {
                return rows;
            }
        }
    }
    rows
}

async fn ssh_client_ips() -> Vec<String> {
    let args = ss_peer_args(&crate::install::firewall_base::sshd_ports());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some(text) = run_capture("ss", &args).await else {
        return Vec::new();
    };
    parse_ss_peers(&text)
}

fn ss_peer_args(ports: &[u16]) -> Vec<String> {
    let mut args: Vec<String> = ["-H", "-t", "-n", "state", "established", "("].map(String::from).to_vec();
    for (index, port) in ports.iter().enumerate() {
        if index > 0 {
            args.push("or".into());
        }
        args.extend(["sport".into(), "=".into(), format!(":{port}")]);
    }
    args.push(")".into());
    args
}

/// The peer address out of each `ss` row
fn parse_ss_peers(text: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for line in text.lines() {
        let peer = line
            .split_whitespace()
            .rev()
            .find_map(|field| {
                let (address, _port) = field.rsplit_once(':')?;
                let address = address.trim_start_matches('[').trim_end_matches(']');
                address.parse::<std::net::IpAddr>().ok().map(|_| address.to_string())
            });
        let Some(address) = peer else { continue };
        if !seen.iter().any(|known| known == &address) {
            seen.push(address);
        }
    }
    seen
}

async fn run_capture(bin: &str, args: &[&str]) -> Option<String> {
    let child = tokio::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let output =
        tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
            .await
            .ok()?
            .ok()?;
    output
        .status
        .success()
        .then(|| strip_ansi(&String::from_utf8_lossy(&output.stdout)))
}

/// The decision list as the host has it now.
async fn read_decisions() -> pb::SecurityDecisions {
    let mut answer = pb::SecurityDecisions::default();
    if !present() {
        return answer;
    }
    answer.present = true;
    if let Some(json) = cscli(&["decisions", "list", "--limit", "0", "-o", "json"]).await {
        answer.decisions = parse_decisions(&json, DECISIONS_LIMIT);
    }
    if let Some(text) = cscli(&["metrics", "-o", "json"]).await {
        if let Ok(metrics) = serde_json::from_str::<Value>(&text) {
            answer.community_count = parse_community_blocklist_ips(&metrics);
        }
    }
    answer.ssh_client_ips = ssh_client_ips().await;
    answer
}

pub async fn get_security_decisions(codec: Codec, _req: pb::GetSecurityDecisionsRequest) -> Resp {
    let answer = read_decisions().await;
    encode(codec, &answer)
}

/// Ban an address by hand, or lift a ban
pub async fn set_security_decision(codec: Codec, req: pb::SetSecurityDecisionRequest) -> Resp {
    if !present() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host has no CrowdSec installed",
        );
    }
    let value = req.value.trim().to_string();
    let id = req.id.trim().to_string();
    let by_id = !id.is_empty() && !req.banned;
    if !by_id && !valid_target(&value) {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "an address or a CIDR range is required, for example 203.0.113.9 or 203.0.113.0/24",
        );
    }
    if by_id && !id.chars().all(|c| c.is_ascii_digit()) {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "a decision id is a number",
        );
    }

    let range = value.contains('/');
    let duration = duration_arg(req.duration_seconds);
    let reason = {
        let typed = req.reason.trim();
        if typed.is_empty() { MANUAL_REASON.to_string() } else { typed.to_string() }
    };

    let mut args: Vec<&str> = vec!["decisions"];
    if req.banned {
        args.push("add");
        args.push(if range { "--range" } else { "--ip" });
        args.push(&value);
        args.push("--reason");
        args.push(&reason);
        if let Some(duration) = duration.as_deref() {
            args.push("--duration");
            args.push(duration);
        }
    } else {
        args.push("delete");
        if by_id {
            args.push("--id");
            args.push(&id);
        } else {
            args.push(if range { "--range" } else { "--ip" });
            args.push(&value);
        }
    }

    if let Err(detail) = cscli_checked(&args).await {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &detail);
    }
    let answer = read_decisions().await;
    encode(codec, &answer)
}

fn parse_allowlist_items(json: &str) -> Vec<pb::SecurityAllowlistEntry> {
    let Ok(list) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let object = match &list {
        Value::Array(lists) => lists
            .iter()
            .find(|entry| entry.get("name").and_then(Value::as_str) == Some(ALLOWLIST_NAME)),
        Value::Object(_) => Some(&list),
        _ => None,
    };
    let Some(Some(Value::Array(items))) = object.map(|o| o.get("items")) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let value = item.get("value").and_then(Value::as_str)?;
            Some(pb::SecurityAllowlistEntry {
                value: value.to_string(),
                comment: item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                expires_in: item
                    .get("expiration")
                    .and_then(Value::as_str)
                    .filter(|at| !at.starts_with("0001-01-01"))
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

async fn read_allowlist() -> pb::SecurityAllowlist {
    let mut answer = pb::SecurityAllowlist {
        name: ALLOWLIST_NAME.to_string(),
        ..Default::default()
    };
    if !present() {
        return answer;
    }
    answer.present = true;
    let Ok(listed) = cscli_checked(&["allowlists", "list", "-o", "json"]).await else {
        return answer;
    };
    answer.supported = true;
    answer.entries = parse_allowlist_items(&listed);
    answer.ssh_client_ips = ssh_client_ips().await;
    answer
}

pub async fn get_security_allowlist(codec: Codec, _req: pb::GetSecurityAllowlistRequest) -> Resp {
    let answer = read_allowlist().await;
    encode(codec, &answer)
}

/// Put an address beyond banning, or stop protecting it
pub async fn set_security_allowlist(codec: Codec, req: pb::SetSecurityAllowlistRequest) -> Resp {
    if !present() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host has no CrowdSec installed",
        );
    }
    let value = req.value.trim().to_string();
    if !valid_target(&value) {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "an address or a CIDR range is required, for example 203.0.113.9 or 203.0.113.0/24",
        );
    }

    if req.allowed {
        let _ = cscli_checked(&[
            "allowlists",
            "create",
            ALLOWLIST_NAME,
            "-d",
            "Addresses gryonixNexus was told never to ban",
        ])
        .await;
        let comment = {
            let typed = req.comment.trim();
            if typed.is_empty() { "added from gryonixNexus".to_string() } else { typed.to_string() }
        };
        let duration = duration_arg(req.duration_seconds);
        let mut args: Vec<&str> = vec!["allowlists", "add", ALLOWLIST_NAME, &value, "-d", &comment];
        if let Some(duration) = duration.as_deref() {
            args.push("-e");
            args.push(duration);
        }
        if let Err(detail) = cscli_checked(&args).await {
            return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &detail);
        }
        let by = if value.contains('/') { "--range" } else { "--ip" };
        let _ = cscli_checked(&["decisions", "delete", by, &value]).await;
    } else if let Err(detail) =
        cscli_checked(&["allowlists", "remove", ALLOWLIST_NAME, &value]).await
    {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &detail);
    }

    let answer = read_allowlist().await;
    encode(codec, &answer)
}

fn parse_wg_endpoints(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some(endpoint) = line.split_whitespace().nth(2) else { continue };
        let host = match endpoint.rsplit_once(':') {
            Some((host, port)) if port.parse::<u16>().is_ok() => host.trim_matches(['[', ']']),
            _ => continue,
        };
        if host.parse::<std::net::IpAddr>().is_ok() && !found.iter().any(|known| known == host) {
            found.push(host.to_string());
        }
    }
    found
}

async fn tunnel_peer_addresses() -> Vec<String> {
    let Ok(child) = tokio::process::Command::new("wg")
        .args(["show", "all", "endpoints"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return Vec::new();
    };
    let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output()).await
    else {
        return Vec::new();
    };
    parse_wg_endpoints(&String::from_utf8_lossy(&output.stdout))
}

/// One quick command's output, empty when it fails
async fn quick_output(program: &str, args: &[&str]) -> String {
    let Ok(child) = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return String::new();
    };
    match tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output()).await {
        Ok(Ok(output)) if output.status.success() => String::from_utf8_lossy(&output.stdout).into_owned(),
        _ => String::new(),
    }
}

pub async fn keep_trusted_sources() -> Result<usize, String> {
    use crate::trusted_sources as trusted;
    let peers = tunnel_peer_addresses().await;
    let wg = quick_output("ip", &["-4", "-o", "addr", "show", "dev", "wg0"]).await;
    let wanted = trusted::trusted(trusted::role(trusted::tunnel_address(&wg).as_deref()), &peers);
    let mut changed = usize::from(keep_sshd_exemption(&wanted).await?);
    if !present() || quick_output("systemctl", &["is-active", "crowdsec"]).await.trim() != "active" {
        return Ok(changed);
    }
    let entries = read_allowlist().await.entries;
    let _ = cscli_checked(&["allowlists", "create", ALLOWLIST_NAME, "-d", "Addresses gryonixNexus was told never to ban"]).await;
    for value in wanted.iter().filter(|value| !entries.iter().any(|entry| &entry.value == *value)) {
        cscli_checked(&["allowlists", "add", ALLOWLIST_NAME, value, "-d", trusted::OWN_COMMENTS[0]]).await?;
        let scope = if value.contains('/') { "--range" } else { "--ip" };
        let _ = cscli_checked(&["decisions", "delete", scope, value]).await;
        changed += 1;
    }
    let stale = entries.iter().filter(|entry| {
        trusted::OWN_COMMENTS.contains(&entry.comment.as_str()) && !wanted.contains(&entry.value)
    });
    for entry in stale {
        cscli_checked(&["allowlists", "remove", ALLOWLIST_NAME, &entry.value]).await?;
        changed += 1;
    }
    Ok(changed)
}

async fn keep_sshd_exemption(wanted: &[String]) -> Result<bool, String> {
    use crate::trusted_sources as trusted;
    if !quick_output("sshd", &["-T"]).await.to_ascii_lowercase().contains("persourcepenalties") {
        return Ok(false);
    }
    if trusted::sshd_exemption_current(std::path::Path::new(trusted::SSHD_DROP_IN), wanted) {
        return Ok(false);
    }
    let script = trusted::sshd_exemption_script(trusted::SSHD_DROP_IN, wanted);
    let run = tokio::process::Command::new(systemd_run_bin())
        .args(["--quiet", "--collect", "--wait", "--service-type=oneshot", "/bin/sh", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status();
    match tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS * 4), run).await {
        Ok(Ok(status)) if status.success() => Ok(true),
        Ok(Ok(_)) => Err("sshd refused the trusted-source list, the previous one stays".into()),
        Ok(Err(err)) => Err(format!("could not run systemd-run: {err}")),
        Err(_) => Err("writing the trusted-source list timed out".into()),
    }
}

#[cfg(test)]
mod tunnel_peer_tests {
    use super::*;

    #[test]
    fn peer_endpoints_are_read_once_each_and_none_is_skipped() {
        let text = "wg0\tAAA=\t203.0.113.7:51820\nwg0\tBBB=\t(none)\nwg1\tCCC=\t[2001:db8::5]:1234\nwg1\tDDD=\t203.0.113.7:9\n";
        assert_eq!(parse_wg_endpoints(text), vec!["203.0.113.7", "2001:db8::5"]);
        assert!(parse_wg_endpoints("").is_empty());
    }
}

#[cfg(test)]
mod ssh_port_query_tests {
    use super::ss_peer_args;

    #[test]
    fn every_sshd_port_is_asked_about() {
        assert_eq!(
            ss_peer_args(&[22, 2222]).join(" "),
            "-H -t -n state established ( sport = :22 or sport = :2222 )"
        );
    }
}

#[cfg(test)]
mod tests {
    // ─────────────── ControlSecurity ───────────────

    #[test]
    fn the_bouncer_follows_the_engine_up_and_leads_it_down() {
        let start = script_for(pb::SecurityAction::Start);
        let engine = start.find("enable --now crowdsec\n").expect("the engine is started");
        let bouncer = start.find("crowdsec-firewall-bouncer").expect("the bouncer is started");
        assert!(engine < bouncer, "the bouncer must not start before the engine:\n{start}");

        let stop = script_for(pb::SecurityAction::Stop);
        let stop_bouncer = stop.find("crowdsec-firewall-bouncer").expect("the bouncer is stopped");
        let stop_engine = stop.rfind("stop crowdsec\n").expect("the engine is stopped");
        assert!(stop_bouncer < stop_engine, "the engine must not stop first:\n{stop}");
    }

    #[test]
    fn starting_survives_a_reboot() {
        let start = script_for(pb::SecurityAction::Start);
        assert!(start.contains("enable --now"), "{start}");
        assert!(!start.contains("systemctl start "), "a bare start does not survive a reboot: {start}");
    }

    #[test]
    fn stopping_does_not_disable() {
        assert!(!script_for(pb::SecurityAction::Stop).contains("disable"));
    }

    #[test]
    fn updating_moves_the_hub_as_well_as_the_packages() {
        let update = script_for(pb::SecurityAction::Update);
        assert!(update.contains("--only-upgrade"), "{update}");
        assert!(update.contains("cscli hub update"), "{update}");
        assert!(update.contains("cscli hub upgrade"), "{update}");
        assert!(update.contains("systemctl restart crowdsec"), "{update}");
    }

    #[test]
    fn removing_purges_the_packages_and_the_configuration() {
        let remove = script_for(pb::SecurityAction::Remove);
        assert!(remove.contains("purge -y"), "{remove}");
        assert!(!remove.contains(" remove -y"), "remove is not enough: {remove}");
        assert!(remove.contains("rm -rf /etc/crowdsec"), "{remove}");
        assert!(remove.contains("disable --now"), "the units must not come back on reboot: {remove}");
    }

    #[test]
    fn the_scripts_interpolate_nothing_a_caller_controls() {
        for action in [
            pb::SecurityAction::Start,
            pb::SecurityAction::Stop,
            pb::SecurityAction::Restart,
            pb::SecurityAction::Update,
            pb::SecurityAction::Remove,
        ] {
            let script = script_for(action);
            assert!(!script.is_empty(), "{action:?} has no script");
            for name in script.split_whitespace().filter(|word| word.starts_with("crowdsec")) {
                assert!(
                    name.starts_with("crowdsec"),
                    "{action:?} names something other than the two units/packages: {script}"
                );
            }
        }
        assert!(script_for(pb::SecurityAction::Install).is_empty());
    }

    #[tokio::test]
    async fn an_action_nobody_named_is_refused() {
        let response = control_security(
            Codec::Json,
            pb::ControlSecurityRequest { action: pb::SecurityAction::Unspecified as i32 },
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/security")
                .join(name),
        )
        .unwrap_or_else(|err| panic!("read fixture {name}: {err}"))
    }

    #[test]
    fn engine_version_is_the_version_not_the_build_string() {
        assert_eq!(parse_engine_version(&fixture("version.txt")), "v1.8.0");
        assert_eq!(parse_engine_version(""), "");
        assert_eq!(parse_engine_version("Codename: alphaga\nversion: v2.0.0-x"), "v2.0.0");
    }

    #[test]
    fn alert_count_is_the_array_length() {
        assert_eq!(parse_alert_count(&fixture("alerts-24h.json")), 4);
        assert_eq!(parse_alert_count(&fixture("decisions.json")), 0);
        assert_eq!(parse_alert_count("not json"), 0);
        assert_eq!(parse_alert_count("{\"error\":\"nope\"}"), 0);
    }

    #[test]
    fn recent_bans_carry_ip_country_and_scenario_and_honour_the_limit() {
        let bans = parse_recent_bans(&fixture("alerts-recent.json"), 3);
        assert_eq!(bans.len(), 3);
        assert_eq!(bans[0].ip, "193.233.199.37");
        assert_eq!(bans[0].country, "RU");
        assert_eq!(bans[0].scenario, "crowdsecurity/ssh-slow-bf");
        assert_eq!(bans[0].at, "2026-09-01T16:25:37Z");
    }

    #[test]
    fn a_row_without_a_source_address_is_dropped_not_blanked() {
        let json = r#"[
            {"scenario":"x","created_at":"t","source":{"value":"1.2.3.4","cn":"US"}},
            {"scenario":"y","created_at":"t","source":{"scope":"Country"}},
            {"scenario":"z","created_at":"t"}
        ]"#;
        let bans = parse_recent_bans(json, 8);
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "1.2.3.4");
    }

    #[test]
    fn top_scenarios_are_count_descending_and_capped() {
        let metrics: Value = serde_json::from_str(&fixture("metrics.json")).unwrap();
        let top = parse_top_scenarios(&metrics, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "crowdsecurity/ssh-bf");
        assert_eq!(top[0].count, 37);
        assert_eq!(top[1].name, "crowdsecurity/ssh-slow-bf");
        assert_eq!(top[1].count, 11);
    }

    #[test]
    fn top_scenarios_break_a_tie_by_name_so_the_list_is_stable() {
        let metrics = serde_json::json!({ "alerts": { "b/two": 5, "a/one": 5, "c/three": 9 } });
        let top = parse_top_scenarios(&metrics, 3);
        assert_eq!(
            top.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["c/three", "a/one", "b/two"]
        );
    }

    #[test]
    fn community_blocklist_is_the_capi_active_decision_count() {
        let metrics: Value = serde_json::from_str(&fixture("metrics.json")).unwrap();
        assert_eq!(parse_community_blocklist_ips(&metrics), 15737);
    }

    #[test]
    fn packets_dropped_sum_every_origin_of_every_bouncer() {
        let metrics: Value = serde_json::from_str(&fixture("metrics.json")).unwrap();
        // CAPI 1620 + crowdsec 19409 + cscli 0.
        assert_eq!(parse_packets_dropped(&metrics), 21029);
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn stub_cscli(dir: &std::path::Path) -> std::path::PathBuf {
        let log = dir.join("argv.log");
        let bin = dir.join("cscli");
        std::fs::write(
            &bin,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '[]'\n", log.display()),
        )
        .expect("write the stub");
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("make the stub executable");
        bin
    }

    #[tokio::test]
    async fn the_counting_calls_ask_for_every_row() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-cscli-argv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let bin = stub_cscli(&dir);
        let config = dir.join("config.yaml");
        std::fs::write(&config, "# present\n").expect("write the config");
        std::env::set_var("GRYONIXNEXUSD_CSCLI_BIN", &bin);
        std::env::set_var("GRYONIXNEXUSD_CROWDSEC_CONFIG", &config);

        let _ = get_security_status(Codec::Json, pb::GetSecurityStatusRequest::default()).await;

        std::env::remove_var("GRYONIXNEXUSD_CSCLI_BIN");
        std::env::remove_var("GRYONIXNEXUSD_CROWDSEC_CONFIG");

        let argv = std::fs::read_to_string(dir.join("argv.log")).expect("the stub ran");
        let alerts = argv
            .lines()
            .find(|line| line.starts_with("alerts list --since 24h"))
            .expect("the 24h alert count is asked for");
        assert!(alerts.contains("--limit 0"), "alerts asked without a limit: {alerts}");
        let decisions = argv
            .lines()
            .find(|line| line.starts_with("decisions list"))
            .expect("the local ban count is asked for");
        assert!(decisions.contains("--limit 0"), "decisions asked without a limit: {decisions}");
        let recent = argv
            .lines()
            .find(|line| line.starts_with("alerts list --limit 16"))
            .expect("the recent bans are asked for");
        assert!(!recent.contains("--limit 0"), "the recent list must stay short: {recent}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────── Decisions and the allowlist ───────────────

    const DECISIONS_JSON: &str = r#"[
     {
      "created_at": "2026-09-12T16:57:17Z",
      "decisions": [
       {
        "duration": "4m58s",
        "id": 270038,
        "origin": "cscli",
        "scenario": "gryonixnexus shape probe",
        "scope": "Ip",
        "simulated": false,
        "type": "ban",
        "value": "198.51.100.7"
       }
      ],
      "events_count": 1,
      "id": 70,
      "source": { "ip": "198.51.100.7", "scope": "Ip", "value": "198.51.100.7",
                  "cn": "DE", "as_name": "58243 TELE AG" }
     }
    ]"#;

    #[test]
    fn a_decision_carries_what_the_row_shows() {
        let rows = parse_decisions(DECISIONS_JSON, 200);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.value, "198.51.100.7");
        assert_eq!(row.id, "270038");
        assert_eq!(row.action, "ban");
        assert_eq!(row.source, "cscli");
        assert_eq!(row.reason, "gryonixnexus shape probe");
        assert_eq!(row.expires_in, "4m58s");
        assert_eq!(row.country, "DE");
        assert_eq!(row.as_name, "58243 TELE AG");
        assert_eq!(row.events, 1);
    }

    #[test]
    fn the_decision_parser_survives_shapes_it_does_not_recognise() {
        assert!(parse_decisions("[]", 200).is_empty());
        assert!(parse_decisions("not json", 200).is_empty());
        assert!(parse_decisions(r#"[{"decisions": null}]"#, 200).is_empty());
        assert!(parse_decisions(r#"[{"decisions":[{"id":1,"value":""}]}]"#, 200).is_empty());
    }

    #[test]
    fn the_cap_counts_decisions_and_not_alerts() {
        let json = r#"[{"events_count":1,"decisions":[
            {"id":1,"value":"203.0.113.1","type":"ban"},
            {"id":2,"value":"203.0.113.2","type":"ban"},
            {"id":3,"value":"203.0.113.3","type":"ban"}]}]"#;
        assert_eq!(parse_decisions(json, 2).len(), 2);
    }

    #[test]
    fn the_allowlist_parser_reads_both_shapes_and_only_our_list() {
        let inspect = r#"{"name":"gryonixnexus","items":[
            {"value":"203.0.113.9","description":"office","expiration":"2026-09-12T17:02:00.925Z"}]}"#;
        let from_inspect = parse_allowlist_items(inspect);
        assert_eq!(from_inspect.len(), 1);
        assert_eq!(from_inspect[0].value, "203.0.113.9");
        assert_eq!(from_inspect[0].comment, "office");
        assert!(!from_inspect[0].expires_in.is_empty());

        let forever = r#"{"name":"gryonixnexus","items":[
            {"value":"203.0.113.5","description":"office","expiration":"0001-01-01T00:00:00.000Z"}]}"#;
        assert!(parse_allowlist_items(forever)[0].expires_in.is_empty());

        let listed = r#"[{"name":"somebody-else","items":[{"value":"198.51.100.1"}]},
                         {"name":"gryonixnexus","items":[{"value":"203.0.113.9"}]}]"#;
        let from_list = parse_allowlist_items(listed);
        assert_eq!(from_list.len(), 1, "another product's list must not be reported");
        assert_eq!(from_list[0].value, "203.0.113.9");
        // An entry that never expires carries no expiration at all.
        assert!(from_list[0].expires_in.is_empty());
    }

    #[test]
    fn the_ssh_peers_are_read_from_either_shape_of_ss_output() {
        let filtered = "0      228    203.0.113.80:22  198.51.100.9:58830\n                        0      0      203.0.113.80:22 187.40.41.85:31294";
        assert_eq!(parse_ss_peers(filtered), vec!["198.51.100.9", "187.40.41.85"]);

        let with_state = "ESTAB 0 0 [2001:db8::1]:22 [2001:db8::9]:54321";
        assert_eq!(parse_ss_peers(with_state), vec!["2001:db8::9"]);

        let noisy = "Recv-Q Send-Q Local Address:Port Peer Address:Port\n                     0 0 10.0.0.1:22 203.0.113.9:2222 users:((\"sshd\",pid=1,fd=4))";
        assert_eq!(parse_ss_peers(noisy), vec!["203.0.113.9"]);

        // One address with two sessions is one address.
        let twice = "0 0 10.0.0.1:22 203.0.113.9:1\n0 0 10.0.0.1:22 203.0.113.9:2";
        assert_eq!(parse_ss_peers(twice), vec!["203.0.113.9"]);
    }

    #[test]
    fn only_an_address_or_a_range_may_be_banned() {
        for good in ["203.0.113.9", "203.0.113.0/24", "2001:db8::1", "2001:db8::/32", " 203.0.113.9 "] {
            assert!(valid_target(good), "{good} is an address");
        }
        for bad in ["", "  ", "example.com", "203.0.113.9; rm -rf /", "203.0.113.9/33",
                    "2001:db8::/129", "203.0.113.9/", "203.0.113.9/007", "203.0.113",
                    "-i", "--ip"] {
            assert!(!valid_target(bad), "{bad} is not an address");
        }
    }

    #[test]
    fn a_zero_duration_passes_no_flag_at_all() {
        assert_eq!(duration_arg(0), None);
        assert_eq!(duration_arg(3600).as_deref(), Some("3600s"));
    }

    #[test]
    fn metrics_parsers_survive_a_shape_they_do_not_recognise() {
        let empty = serde_json::json!({});
        assert_eq!(parse_top_scenarios(&empty, 5).len(), 0);
        assert_eq!(parse_community_blocklist_ips(&empty), 0);
        assert_eq!(parse_packets_dropped(&empty), 0);
        let odd = serde_json::json!({ "bouncers": { "b": { "CAPI": "not an object" } } });
        assert_eq!(parse_community_blocklist_ips(&odd), 0);
    }
}

fn auto_rules_path() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_SECURITY_RULES")
            .unwrap_or_else(|_| "/etc/gryonixnexus/crowdsec-rules.json".to_string()),
    )
}

fn profiles_path() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_CROWDSEC_PROFILES")
            .unwrap_or_else(|_| "/etc/crowdsec/profiles.yaml".to_string()),
    )
}

const RULES_BEGIN: &str = "# >>> gryonixNexus managed profiles — do not edit between these markers";
const RULES_END: &str = "# <<< gryonixNexus managed profiles";

/// Whether this host can answer about COUNTRIES at all
async fn geoip_available() -> bool {
    let Some(listed) = cscli(&["parsers", "list", "-o", "json"]).await else {
        return false;
    };
    listed.contains("geoip-enrich")
}

fn read_auto_rules() -> pb::SecurityAutoRules {
    let text = std::fs::read_to_string(auto_rules_path()).unwrap_or_default();
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return pb::SecurityAutoRules::default();
    };
    let list = |key: &str| -> Vec<String> {
        value
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let number = |key: &str| value.get(key).and_then(Value::as_u64).unwrap_or(0);
    let flag = |key: &str| value.get(key).and_then(Value::as_bool).unwrap_or(false);
    let services = value
        .get("services")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(pb::SecurityServiceRule {
                        service: item.get("service")?.as_str()?.to_string(),
                        attempt_threshold: item
                            .get("attempt_threshold")
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as u32,
                        ban_seconds: item.get("ban_seconds").and_then(Value::as_u64).unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    pb::SecurityAutoRules {
        enabled: flag("enabled"),
        countries: list("countries"),
        countries_are_allowlist: flag("countries_are_allowlist"),
        attempt_threshold: number("attempt_threshold") as u32,
        attempt_window_minutes: number("attempt_window_minutes") as u32,
        ban_subnet: flag("ban_subnet"),
        ban_seconds: number("ban_seconds"),
        services,
        geoip_available: false,
    }
}

/// CrowdSec's duration grammar
fn crowdsec_duration(seconds: u64) -> Option<String> {
    (seconds > 0).then(|| format!("{seconds}s"))
}

fn yaml_country_list(codes: &[String]) -> String {
    let cleaned: Vec<String> = codes
        .iter()
        .map(|code| code.trim().to_uppercase())
        .filter(|code| code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()))
        .map(|code| format!("'{code}'"))
        .collect();
    format!("[{}]", cleaned.join(", "))
}

/// The managed block, built from the rules
fn country_profile(out: &mut String, rules: &pb::SecurityAutoRules, scope: &str, duration: &str) {
    if !rules.countries.is_empty() {
        let codes = yaml_country_list(&rules.countries);
        let comparison = if rules.countries_are_allowlist {
            format!("not (Alert.Source.Cn in {codes})")
        } else {
            format!("Alert.Source.Cn in {codes}")
        };
        out.push_str("---\n");
        out.push_str("name: gryonixnexus/countries\n");
        out.push_str(&format!(
            "filters:\n  - \"Alert.Remediation == true && Alert.Source.Cn != '' && {comparison}\"\n"
        ));
        out.push_str("decisions:\n");
        out.push_str(&format!("  - type: ban\n    scope: {scope}\n    duration: {duration}\n"));
        out.push_str("on_success: break\n");
    }
}

/// The profile that bans after a number of attempts
fn threshold_profile(out: &mut String, rules: &pb::SecurityAutoRules, scope: &str, duration: &str) {
    if rules.attempt_threshold > 0 {
        out.push_str("---\n");
        out.push_str("name: gryonixnexus/threshold\n");
        out.push_str(&format!(
            "filters:\n  - \"Alert.Remediation == true && Alert.GetEventsCount() >= {}\"\n",
            rules.attempt_threshold
        ));
        out.push_str("decisions:\n");
        out.push_str(&format!("  - type: ban\n    scope: {scope}\n    duration: {duration}\n"));
        out.push_str("on_success: break\n");
    }
}

/// One profile per service rule
fn service_profiles(out: &mut String, rules: &pb::SecurityAutoRules, scope: &str, duration: &str) {
    for rule in &rules.services {
        let name: String = rule
            .service
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if name.is_empty() {
            continue;
        }
        let service_duration =
            crowdsec_duration(rule.ban_seconds).unwrap_or_else(|| duration.to_string());
        out.push_str("---\n");
        out.push_str(&format!("name: gryonixnexus/service-{name}\n"));
        let threshold = if rule.attempt_threshold > 0 { rule.attempt_threshold } else { 1 };
        out.push_str(&format!(
            "filters:\n  - \"Alert.Remediation == true && Alert.GetScenario() contains '{name}' && Alert.GetEventsCount() >= {threshold}\"\n"
        ));
        out.push_str("decisions:\n");
        out.push_str(&format!(
            "  - type: ban\n    scope: {scope}\n    duration: {service_duration}\n"
        ));
        out.push_str("on_success: break\n");
    }
}

fn render_profiles(rules: &pb::SecurityAutoRules) -> String {
    let mut out = String::new();
    out.push_str(RULES_BEGIN);
    out.push('\n');
    out.push_str("# Written by gryonixNexus from the app's \"Automatic blocking\" screen.\n");
    out.push_str("# Everything between the markers is regenerated on every change.\n");

    let scope = "Ip";
    let _ = rules.ban_subnet;
    let duration = crowdsec_duration(rules.ban_seconds).unwrap_or_else(|| "4h".to_string());

    country_profile(&mut out, rules, scope, &duration);
    threshold_profile(&mut out, rules, scope, &duration);
    service_profiles(&mut out, rules, scope, &duration);
    out.push_str(RULES_END);
    out.push('\n');
    out
}

fn profiles_with_block(existing: &str, block: Option<&str>) -> String {
    let mut kept = String::new();
    let mut inside = false;
    let mut drop_separator = false;
    for line in existing.lines() {
        if line.trim_start().starts_with(RULES_BEGIN) {
            inside = true;
            continue;
        }
        if inside {
            if line.trim_start().starts_with(RULES_END) {
                inside = false;
                drop_separator = true;
            }
            continue;
        }
        if drop_separator {
            drop_separator = false;
            if line.trim() == "---" {
                continue;
            }
        }
        kept.push_str(line);
        kept.push('\n');
    }
    match block {
        Some(block) if kept.trim().is_empty() => block.to_string(),
        Some(block) => format!("{block}---\n{kept}"),
        None => kept,
    }
}

pub async fn get_security_auto_rules(
    codec: Codec,
    _req: pb::GetSecurityAutoRulesRequest,
) -> Resp {
    let mut rules = read_auto_rules();
    rules.geoip_available = geoip_available().await;
    encode(codec, &rules)
}

/// Writes the rules and makes the host act on them
async fn refuse_country_rules(rules: &pb::SecurityAutoRules) -> Option<Resp> {
    if rules.enabled && !rules.countries.is_empty() && !geoip_available().await {
        return Some(connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host's CrowdSec has no GeoIP enrichment, so a country rule would never match. \
             Install the crowdsecurity/geoip-enrich parser first.",
        ));
    }
    None
}

async fn put_profiles_in_force(rules: &pb::SecurityAutoRules) -> Result<(), Resp> {
    let path = profiles_path();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let block = rules.enabled.then(|| render_profiles(&rules));
    let updated = profiles_with_block(&existing, block.as_deref());

    let candidate = path.with_extension("yaml.gryonixnexus-next");
    if let Err(err) = std::fs::write(&candidate, &updated) {
        return Err(connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("could not write {}: {err}", candidate.display()),
        ));
    }
    let verdict = validate_profiles(&candidate).await;
    let _ = std::fs::remove_file(&candidate);
    if let Err(detail) = verdict {
        return Err(connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            &format!("CrowdSec refused the new rules: {detail}"),
        ));
    }

    let backup = path.with_extension("yaml.gryonixnexus-prev");
    if path.exists() {
        let _ = std::fs::copy(&path, &backup);
    }
    if let Err(err) = std::fs::write(&path, &updated) {
        return Err(connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("could not write {}: {err}", path.display()),
        ));
    }

    if let Err(detail) = reload_crowdsec().await {
        if backup.exists() {
            let _ = std::fs::copy(&backup, &path);
            let _ = reload_crowdsec().await;
        }
        return Err(connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!("CrowdSec refused the new rules: {detail}"),
        ));
    }
    let _ = std::fs::remove_file(&backup);
    Ok(())
}

fn record_auto_rules(rules: &pb::SecurityAutoRules) -> Result<(), Resp> {
    if let Some(parent) = auto_rules_path().parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let stored = serde_json::json!({
        "enabled": rules.enabled,
        "countries": rules.countries,
        "countries_are_allowlist": rules.countries_are_allowlist,
        "attempt_threshold": rules.attempt_threshold,
        "attempt_window_minutes": rules.attempt_window_minutes,
        "ban_subnet": rules.ban_subnet,
        "ban_seconds": rules.ban_seconds,
        "services": rules.services.iter().map(|rule| serde_json::json!({
            "service": rule.service,
            "attempt_threshold": rule.attempt_threshold,
            "ban_seconds": rule.ban_seconds,
        })).collect::<Vec<_>>(),
    });
    if let Err(err) = std::fs::write(auto_rules_path(), stored.to_string()) {
        return Err(connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!(
                "the rules are in force on this host, but could not be recorded in {}: {err} \
                 — the app will keep showing the previous ones until this is fixed",
                auto_rules_path().display()
            ),
        ));
    }
    Ok(())
}

pub async fn set_security_auto_rules(codec: Codec, req: pb::SetSecurityAutoRulesRequest) -> Resp {
    if !present() {
        return connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this host has no CrowdSec installed",
        );
    }
    let rules = req.rules.unwrap_or_default();
    if let Some(refusal) = refuse_country_rules(&rules).await {
        return refusal;
    }
    if let Err(refusal) = put_profiles_in_force(&rules).await {
        return refusal;
    }
    if let Err(refusal) = record_auto_rules(&rules) {
        return refusal;
    }

    let mut answer = read_auto_rules();
    if answer.enabled != rules.enabled || answer.countries != rules.countries {
        return connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &format!(
                "the rules are in force on this host, but {} reads back as different orders \
                 — the app would show those instead",
                auto_rules_path().display()
            ),
        );
    }
    answer.geoip_available = geoip_available().await;
    encode(codec, &answer)
}

async fn validate_profiles(candidate: &Path) -> Result<(), String> {
    let config = PathBuf::from("/etc/crowdsec/config.yaml");
    let Ok(text) = std::fs::read_to_string(&config) else { return Ok(()) };
    let mut rewritten = String::with_capacity(text.len());
    let mut pointed = false;
    for line in text.lines() {
        if let Some(indent) = line.find("profiles_path:") {
            rewritten.push_str(&line[..indent]);
            rewritten.push_str(&format!("profiles_path: {}
", candidate.display()));
            pointed = true;
        } else {
            rewritten.push_str(line);
            rewritten.push('\n');
        }
    }
    if !pointed {
        return Ok(());
    }
    let probe = candidate.with_extension("check-config.yaml");
    if std::fs::write(&probe, rewritten).is_err() {
        return Ok(());
    }
    let result = tokio::process::Command::new("crowdsec")
        .args(["-c".as_ref(), probe.as_os_str(), "-t".as_ref(), "-error".as_ref()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), result).await;
    let _ = std::fs::remove_file(&probe);
    match out {
        Err(_) | Ok(Err(_)) => Ok(()),
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => {
            let said = String::from_utf8_lossy(&output.stderr);
            let line = said
                .lines()
                .find(|l| l.to_lowercase().contains("while") || l.to_lowercase().contains("error"))
                .unwrap_or_else(|| said.lines().last().unwrap_or("the engine refused the file"));
            Err(strip_ansi(line.trim()).chars().take(400).collect())
        }
    }
}

async fn reload_crowdsec() -> Result<(), String> {
    let was_active = unit_active("crowdsec").await;
    let verbs: &[&str] = if was_active { &["reload"] } else { &["restart", "start"] };
    for verb in verbs {
        let Ok(child) = tokio::process::Command::new("systemctl")
            .args([*verb, "crowdsec"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        else {
            continue;
        };
        let Ok(Ok(output)) = tokio::time::timeout(
            Duration::from_secs(QUICK_TIMEOUT_SECS),
            child.wait_with_output(),
        )
        .await
        else {
            return Err("crowdsec did not finish reloading in time".to_string());
        };
        if output.status.success() {
            return if unit_active("crowdsec").await {
                Ok(())
            } else {
                Err("crowdsec is not running after the reload".to_string())
            };
        }
    }
    Err("crowdsec refused to reload".to_string())
}

#[cfg(test)]
mod auto_rules_tests {
    use super::*;

    fn rules() -> pb::SecurityAutoRules {
        pb::SecurityAutoRules {
            enabled: true,
            countries: vec!["ru".to_string(), "CN".to_string()],
            countries_are_allowlist: false,
            attempt_threshold: 5,
            attempt_window_minutes: 10,
            ban_subnet: true,
            ban_seconds: 86_400,
            services: vec![pb::SecurityServiceRule {
                service: "ssh".to_string(),
                attempt_threshold: 3,
                ban_seconds: 0,
            }],
            geoip_available: true,
        }
    }

    #[test]
    fn dump_profiles_for_a_live_engine() {
        let Ok(dir) = std::env::var("GRYONIXNEXUS_DUMP_DIR") else { return };
        let mut rules = rules();
        if let Ok(countries) = std::env::var("GRYONIXNEXUS_DUMP_COUNTRIES") {
            rules.countries =
                countries.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
        }
        if let Ok(threshold) = std::env::var("GRYONIXNEXUS_DUMP_THRESHOLD") {
            rules.attempt_threshold = threshold.parse().unwrap_or(rules.attempt_threshold);
            for rule in &mut rules.services {
                rule.attempt_threshold = rules.attempt_threshold;
            }
        }
        let path = std::path::Path::new(&dir).join("crowdsec-profiles-block.yaml");
        std::fs::create_dir_all(&dir).expect("dump directory");
        std::fs::write(&path, render_profiles(&rules)).expect("write the block");
        if let Ok(existing) = std::env::var("GRYONIXNEXUS_PROFILES_IN") {
            let stock = std::fs::read_to_string(&existing).expect("the stock profiles file");
            let merged = profiles_with_block(&stock, Some(&render_profiles(&rules)));
            std::fs::write(std::path::Path::new(&dir).join("crowdsec-profiles-merged.yaml"), merged)
                .expect("write the merged file");
        }
    }

    #[test]
    fn the_block_states_every_order_it_was_given() {
        let text = render_profiles(&rules());
        assert!(text.starts_with(RULES_BEGIN), "the block must be delimited");
        assert!(text.trim_end().ends_with(RULES_END));
        assert!(text.contains("name: gryonixnexus/countries"));
        assert!(text.contains(r#"Alert.Source.Cn in ['RU', 'CN']"#), "{text}");
        // `filters`, a list: the profile schema has no `filter` key.
        assert!(text.contains("filters:\n  - \""), "{text}");
        assert!(!text.contains("\nfilter:"), "{text}");
        assert!(text.contains("scope: Ip"), "{text}");
        assert!(!text.contains("scope: Range"), "{text}");
        assert!(text.contains("duration: 86400s"));
        assert!(text.contains("Alert.GetEventsCount() >= 5"));
        assert!(text.contains("name: gryonixnexus/service-ssh"));
        assert!(text.contains("Alert.GetScenario() contains 'ssh'"));
        assert_eq!(text.matches("on_success: break").count(), 3);
    }

    #[test]
    fn an_allowlist_refuses_everything_not_on_it() {
        let mut rules = rules();
        rules.countries_are_allowlist = true;
        let text = render_profiles(&rules);
        assert!(text.contains(r#"not (Alert.Source.Cn in ['RU', 'CN'])"#), "{text}");
    }

    #[test]
    fn only_real_country_codes_reach_the_filter() {
        assert_eq!(
            yaml_country_list(&[
                "de".to_string(),
                "\" || true || \"".to_string(),
                "DEU".to_string(),
                "".to_string(),
            ]),
            r#"['DE']"#
        );
    }

    #[test]
    fn an_unset_duration_falls_back_rather_than_banning_for_nothing() {
        assert_eq!(crowdsec_duration(0), None);
        assert_eq!(crowdsec_duration(3600).as_deref(), Some("3600s"));
        let mut rules = rules();
        rules.ban_seconds = 0;
        assert!(render_profiles(&rules).contains("duration: 4h"));
    }

    #[test]
    fn a_write_replaces_only_the_managed_block() {
        let existing = format!(
            "{RULES_BEGIN}\nname: gryonixnexus/old\n{RULES_END}\n\
             ---\nname: default_ip_remediation\nfilter: true\n"
        );
        let updated = profiles_with_block(&existing, Some("BLOCK\n"));
        assert!(updated.starts_with("BLOCK\n"), "{updated}");
        assert!(updated.contains("name: default_ip_remediation"));
        assert!(!updated.contains("gryonixnexus/old"));
    }

    #[test]
    fn turning_the_rules_off_leaves_the_hosts_own_profiles_alone() {
        let existing = format!("{RULES_BEGIN}\nname: gryonixnexus/x\n{RULES_END}\n---\nname: theirs\n");
        let updated = profiles_with_block(&existing, None);
        assert!(!updated.contains("gryonixnexus"));
        assert!(updated.contains("name: theirs"));
    }

    #[test]
    fn on_then_off_restores_the_file_exactly() {
        let stock = "name: default_ip_remediation\nfilters:\n  - true\non_success: break\n---\nname: default_range_remediation\non_success: break\n";
        let block = format!("{RULES_BEGIN}\nname: gryonixnexus/x\non_success: break\n{RULES_END}\n");
        let on = profiles_with_block(stock, Some(&block));
        assert!(on.starts_with(RULES_BEGIN), "{on}");
        assert!(on.contains(&format!("{RULES_END}\n---\nname: default_ip_remediation")), "{on}");
        assert_eq!(profiles_with_block(&on, None), stock);

        let again = profiles_with_block(&on, Some(&block));
        assert_eq!(again.matches("\n---\n").count(), stock.matches("\n---\n").count() + 1, "{again}");
        assert_eq!(profiles_with_block(&again, None), stock);
    }

    #[test]
    fn a_host_with_no_rules_file_has_no_orders() {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("crowdsec-rules.json");
        let _ = std::fs::remove_file(&path);
        std::env::set_var("GRYONIXNEXUSD_SECURITY_RULES", &path);
        let rules = read_auto_rules();
        assert!(!rules.enabled);
        assert!(rules.countries.is_empty());
        std::env::remove_var("GRYONIXNEXUSD_SECURITY_RULES");
    }
}
