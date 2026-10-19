//! The Containers section: every container on this host, not only the ones the configurator installed

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper::StatusCode;
use serde::Deserialize;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::pb;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    ComposeProject,
    Standalone,
}

impl GroupKind {
    fn as_pb(self) -> pb::ContainerGroupKind {
        match self {
            GroupKind::ComposeProject => pb::ContainerGroupKind::ComposeProject,
            GroupKind::Standalone => pb::ContainerGroupKind::Standalone,
        }
    }
}

pub async fn inventory(names: &[(String, String)]) -> Result<pb::ContainerInventory> {
    let projects = match compose_projects().await {
        Ok(projects) => projects,
        Err(err) => {
            return Ok(pb::ContainerInventory {
                groups: Vec::new(),
                unavailable_reason: err.to_string(),
            })
        }
    };

    let mut read = Vec::new();
    for project in &projects {
        let containers = crate::discover::containers_for(&project.name)
            .await
            .unwrap_or_default();
        read.push((project, containers));
    }
    let loose = all_containers().await.unwrap_or_default();

    Ok(assemble(&read, &loose, names))
}

fn assemble(
    projects: &[(&ComposeProject, Vec<pb::Container>)],
    all: &[pb::Container],
    names: &[(String, String)],
) -> pb::ContainerInventory {
    let mut groups = Vec::new();
    let mut claimed: Vec<&str> = Vec::new();

    for (project, containers) in projects {
        claimed.extend(containers.iter().map(|c| c.name.as_str()));
        let status = crate::discover::status_from_containers(containers)
            .unwrap_or_else(|| crate::discover::status_of(&project.status));
        groups.push(group(
            &project.name,
            GroupKind::ComposeProject,
            status,
            containers.clone(),
            split_config_files(&project.config_files),
            crate::discover::catalog_id_of_project(&project.name, &project.config_files),
            names,
        ));
    }

    for container in all {
        if claimed.contains(&container.name.as_str()) {
            continue;
        }
        let status = crate::discover::status_from_containers(std::slice::from_ref(container))
            .unwrap_or(pb::ServiceStatus::Unspecified);
        groups.push(group(
            &container.name,
            GroupKind::Standalone,
            status,
            vec![container.clone()],
            Vec::new(),
            None,
            names,
        ));
    }

    disambiguate(&mut groups);
    groups.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    pb::ContainerInventory {
        groups,
        unavailable_reason: String::new(),
    }
}

fn disambiguate(groups: &mut [pb::ContainerGroup]) {
    let mut classes: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (index, group) in groups.iter().enumerate() {
        classes
            .entry(group.derived_name.to_lowercase())
            .or_default()
            .push(index);
    }

    for members in classes.into_values() {
        if members.len() < 2 {
            continue;
        }
        for level in 1..=LAST_QUALIFIER_LEVEL {
            let named: Vec<String> = members
                .iter()
                .map(|&index| qualified(&groups[index], level))
                .collect();
            let distinct = {
                let mut seen: Vec<String> = named.iter().map(|n| n.to_lowercase()).collect();
                seen.sort();
                seen.dedup();
                seen.len() == named.len()
            };
            if !distinct && level < LAST_QUALIFIER_LEVEL {
                continue;
            }
            for (&index, name) in members.iter().zip(named.iter()) {
                let group = &mut groups[index];
                if !group.renamed {
                    group.display_name = name.clone();
                }
                group.derived_name = name.clone();
            }
            break;
        }
    }
}

/// The last level `qualified` answers for
const LAST_QUALIFIER_LEVEL: u8 = 3;

/// One group's name at a given level of insistence
fn qualified(group: &pb::ContainerGroup, level: u8) -> String {
    let base = &group.derived_name;
    match level {
        1 => format!(
            "{base} \u{00b7} {}",
            qualifier(&group.key, &group.service_id, base)
        ),
        2 => format!("{base} \u{00b7} {}", group.key),
        _ => {
            let kind = if group.kind == pb::ContainerGroupKind::Standalone as i32 {
                "container"
            } else {
                "project"
            };
            format!("{base} ({kind})")
        }
    }
}

/// What tells two rows with the same base name apart
fn qualifier(key: &str, service_id: &str, base: &str) -> String {
    if service_id == "vpn" {
        if let Some((_, piece)) = VPN_PIECES.iter().find(|(name, _)| *name == normalise(key)) {
            return (*piece).to_string();
        }
    }
    let derived = display_name_for(key);
    if !derived.is_empty() && !derived.eq_ignore_ascii_case(base) {
        return derived;
    }
    key.to_string()
}

/// Which piece of the VPN a compose project is
const VPN_PIECES: &[(&str, &str)] = &[
    ("vpnpanel", "panel"),
    ("gryonixvpnpanel", "panel"),
    ("awgvpn", "AmneziaWG"),
    ("amneziawg", "AmneziaWG"),
    ("wireguard", "WireGuard"),
    ("shadowsocks", "Shadowsocks"),
    ("xray", "XRay"),
    ("openvpn", "OpenVPN"),
];

/// Assemble one row
fn group(
    key: &str,
    kind: GroupKind,
    status: pb::ServiceStatus,
    containers: Vec<pb::Container>,
    config_files: Vec<String>,
    service: Option<(&'static str, &'static str)>,
    names: &[(String, String)],
) -> pb::ContainerGroup {
    let derived = match service {
        Some((_, display)) => display.to_string(),
        None => display_name_for(key),
    };
    let chosen = names
        .iter()
        .find(|(stored, _)| stored == key)
        .map(|(_, name)| name.clone());
    pb::ContainerGroup {
        key: key.to_string(),
        kind: kind.as_pb() as i32,
        display_name: chosen.clone().unwrap_or_else(|| derived.clone()),
        derived_name: derived,
        renamed: chosen.is_some(),
        service_id: service.map(|(id, _)| id.to_string()).unwrap_or_default(),
        status: status as i32,
        containers,
        config_files,
    }
}

/// Is this a key the host currently reports?
pub fn resolve<'a>(inv: &'a pb::ContainerInventory, key: &str) -> Option<&'a pb::ContainerGroup> {
    inv.groups.iter().find(|g| g.key == key)
}

// ─────────────────────────────── docker reads ───────────────────────────────

#[derive(Debug, Deserialize)]
struct ComposeProject {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "ConfigFiles", default)]
    config_files: String,
}

async fn compose_projects() -> Result<Vec<ComposeProject>> {
    let output = Command::new("docker")
        .args(["compose", "ls", "--all", "--format", "json"])
        .output()
        .await
        .context("run `docker compose ls`")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker compose ls failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let trimmed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&trimmed).context("parse `docker compose ls` json")
}

/// Every container `docker ps` knows, with no filter
async fn all_containers() -> Result<Vec<pb::Container>> {
    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "json"])
        .output()
        .await
        .context("run `docker ps`")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(crate::discover::parse_docker_ps(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

/// `docker compose ls` joins several compose files with a comma.
fn split_config_files(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

const NAME_LIMIT: usize = 64;

pub fn sanitise_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.chars().count() > NAME_LIMIT {
        return Err(format!("a name may be at most {NAME_LIMIT} characters"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("a name may not contain control characters".to_string());
    }
    Ok(trimmed.to_string())
}

// ────────────────────────────── the naming rule ──────────────────────────────

pub fn display_name_for(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(full) = WHOLE_NAMES
        .iter()
        .find(|(key, _)| *key == normalise(trimmed))
    {
        return full.1.to_string();
    }
    let tokens: Vec<String> = split_tokens(trimmed);
    if tokens.is_empty() {
        return trimmed.to_string();
    }
    tokens
        .iter()
        .map(|token| spell(token))
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalise(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn split_tokens(raw: &str) -> Vec<String> {
    let mut tokens: Vec<String> = raw
        .split(|c: char| c == '-' || c == '_' || c == '.' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    if tokens.len() > 1 {
        if let Some(last) = tokens.last() {
            if last.chars().all(|c| c.is_ascii_digit()) {
                tokens.pop();
            }
        }
    }
    tokens
}

/// One token, spelled the way its product spells itself
fn spell(token: &str) -> String {
    let key = normalise(token);
    if let Some((_, spelled)) = TOKENS.iter().find(|(k, _)| *k == key) {
        return spelled.to_string();
    }
    let mut chars = token.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

const WHOLE_NAMES: &[(&str, &str)] = &[
    ("adguardhome", "AdGuard Home"),
    ("audiobookshelf", "Audiobookshelf"),
    ("dockermailserver", "Docker Mailserver"),
    ("homeassistant", "Home Assistant"),
    ("mailcowdockerized", "Mailcow"),
    ("nginxproxymanager", "Nginx Proxy Manager"),
    ("nodered", "Node-RED"),
    ("paperlessngx", "Paperless-ngx"),
    ("uptimekuma", "Uptime Kuma"),
    ("zigbee2mqtt", "Zigbee2MQTT"),
];

/// Per-token spellings
const TOKENS: &[(&str, &str)] = &[
    ("adguard", "AdGuard"),
    ("adminer", "Adminer"),
    ("amneziawg", "AmneziaWG"),
    ("api", "API"),
    ("authelia", "Authelia"),
    ("bookstack", "BookStack"),
    ("caddy", "Caddy"),
    ("calibre", "Calibre"),
    ("clamav", "ClamAV"),
    ("cloudflared", "Cloudflared"),
    ("db", "DB"),
    ("dns", "DNS"),
    ("dovecot", "Dovecot"),
    ("forgejo", "Forgejo"),
    ("fpm", "FPM"),
    ("freshrss", "FreshRSS"),
    ("frigate", "Frigate"),
    ("gitea", "Gitea"),
    ("github", "GitHub"),
    ("gitlab", "GitLab"),
    ("grafana", "Grafana"),
    ("headscale", "Headscale"),
    ("imap", "IMAP"),
    ("immich", "Immich"),
    ("influxdb", "InfluxDB"),
    ("ipv6", "IPv6"),
    ("jellyfin", "Jellyfin"),
    ("jellyseerr", "Jellyseerr"),
    ("jenkins", "Jenkins"),
    ("keycloak", "Keycloak"),
    ("komga", "Komga"),
    ("loki", "Loki"),
    ("mailcow", "Mailcow"),
    ("mailu", "Mailu"),
    ("mariadb", "MariaDB"),
    ("meilisearch", "Meilisearch"),
    ("memcached", "Memcached"),
    ("minio", "MinIO"),
    ("mongo", "MongoDB"),
    ("mongodb", "MongoDB"),
    ("mosquitto", "Mosquitto"),
    ("mysql", "MySQL"),
    ("navidrome", "Navidrome"),
    ("nextcloud", "Nextcloud"),
    ("nginx", "Nginx"),
    ("openvpn", "OpenVPN"),
    ("outline", "Outline"),
    ("owncloud", "ownCloud"),
    ("passbolt", "Passbolt"),
    ("pgadmin", "pgAdmin"),
    ("php", "PHP"),
    ("phpmyadmin", "phpMyAdmin"),
    ("photoprism", "PhotoPrism"),
    ("pihole", "Pi-hole"),
    ("plex", "Plex"),
    ("postfix", "Postfix"),
    ("postgres", "Postgres"),
    ("postgresql", "PostgreSQL"),
    ("prometheus", "Prometheus"),
    ("psono", "Psono"),
    ("qbittorrent", "qBittorrent"),
    ("rabbitmq", "RabbitMQ"),
    ("redis", "Redis"),
    ("rspamd", "Rspamd"),
    ("sabnzbd", "SABnzbd"),
    ("seafile", "Seafile"),
    ("shadowsocks", "Shadowsocks"),
    ("smtp", "SMTP"),
    ("solr", "Solr"),
    ("sql", "SQL"),
    ("ssl", "SSL"),
    ("syncthing", "Syncthing"),
    ("tailscale", "Tailscale"),
    ("telegraf", "Telegraf"),
    ("traefik", "Traefik"),
    ("transmission", "Transmission"),
    ("ui", "UI"),
    ("unifi", "UniFi"),
    ("valkey", "Valkey"),
    ("vaultwarden", "Vaultwarden"),
    ("vpn", "VPN"),
    ("watchtower", "Watchtower"),
    ("wireguard", "WireGuard"),
    ("wordpress", "WordPress"),
    ("xray", "XRay"),
];

// ───────────────────────────── control by key ───────────────────────────────

const GROUP_TIMEOUT_SECS: u64 = 600;

pub enum Refusal {
    /// Not a key this host reports. The gate.
    UnknownKey,
    UnspecifiedAction,
    /// The container engine itself would not answer.
    EngineUnavailable(String),
}

impl Refusal {
    pub fn reason(&self) -> String {
        match self {
            Refusal::UnknownKey => "this host reports no container group with that key".to_string(),
            Refusal::UnspecifiedAction => "action is required (start, stop or restart)".to_string(),
            Refusal::EngineUnavailable(detail) => format!("container engine unavailable: {detail}"),
        }
    }

    pub fn response(&self) -> Resp {
        match self {
            Refusal::UnknownKey => connect_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "this host reports no container group with that key",
            ),
            Refusal::UnspecifiedAction => connect_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "action is required (start, stop or restart)",
            ),
            Refusal::EngineUnavailable(detail) => connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("container engine unavailable: {detail}"),
            ),
        }
    }
}

/// The argv for one group's action
pub fn docker_args(key: &str, kind: GroupKind, action: pb::ServiceAction) -> Vec<String> {
    let verb = match action {
        pb::ServiceAction::Start => "start",
        pb::ServiceAction::Stop => "stop",
        pb::ServiceAction::Restart | pb::ServiceAction::Unspecified => "restart",
    };
    match kind {
        GroupKind::ComposeProject => vec![
            "compose".to_string(),
            "-p".to_string(),
            key.to_string(),
            verb.to_string(),
        ],
        GroupKind::Standalone => vec![verb.to_string(), key.to_string()],
    }
}

pub fn kind_of_group(group: &pb::ContainerGroup) -> GroupKind {
    kind_of(group)
}

fn kind_of(group: &pb::ContainerGroup) -> GroupKind {
    if group.kind == pb::ContainerGroupKind::Standalone as i32 {
        GroupKind::Standalone
    } else {
        GroupKind::ComposeProject
    }
}

/// Start / stop / restart one group, streaming progress
pub async fn control_group(
    codec: Codec,
    req: pb::ControlContainerGroupRequest,
    names: Vec<(String, String)>,
) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("container", &req.key) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let action = pb::ServiceAction::try_from(req.action).unwrap_or(pb::ServiceAction::Unspecified);
    if action == pb::ServiceAction::Unspecified {
        return Refusal::UnspecifiedAction.response();
    }
    let inv = match inventory(&names).await {
        Ok(inv) => inv,
        Err(err) => return Refusal::EngineUnavailable(err.to_string()).response(),
    };
    if !inv.unavailable_reason.is_empty() {
        return Refusal::EngineUnavailable(inv.unavailable_reason).response();
    }
    let Some(group) = resolve(&inv, &req.key) else {
        return Refusal::UnknownKey.response();
    };

    let key = group.key.clone();
    let kind = kind_of(group);
    let container_names: Vec<String> = group.containers.iter().map(|c| c.name.clone()).collect();

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = GroupSink {
            tx,
            codec,
            key: key.clone(),
            action,
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerControl, &key),
        };
        let _ = sink.started(&container_names).await;

        let failure = run_group(&key, kind, action, &sink).await.err();

        let mut problems: Vec<String> = failure.into_iter().collect();
        match inventory(&names).await {
            Ok(fresh) => {
                let _ = sink.completed(resolve(&fresh, &key).cloned()).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    });

    stream_response(json, rx)
}

/// Run one group's action, forwarding output line by line
async fn run_group(
    key: &str,
    kind: GroupKind,
    action: pb::ServiceAction,
    sink: &GroupSink,
) -> Result<(), String> {
    let args = docker_args(key, kind, action);
    let mut child = Command::new("docker")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run docker: {err}"))?;

    let mut out = child.stdout.take().map(|s| BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| BufReader::new(s).lines());

    let outcome = tokio::time::timeout(Duration::from_secs(GROUP_TIMEOUT_SECS), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.progress("stdout", text).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = sink.progress("stderr", text).await; }
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
        Err(_) => Err(format!("timed out after {GROUP_TIMEOUT_SECS}s")),
        Ok(Err(io)) => Err(format!("docker did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("docker exited {code}"),
            None => "docker was killed by a signal".to_string(),
        }),
    }
}

/// Frames and pushes one operation's events
struct GroupSink {
    tx: Sender<bytes::Bytes>,
    codec: Codec,
    key: String,
    action: pb::ServiceAction,
    journal: Option<crate::jobs::Journal>,
}

impl GroupSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerOperationEvent {
        pb::ContainerOperationEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            action: self.action as i32,
            text: String::new(),
            stream: String::new(),
            containers: Vec::new(),
            group: None,
        }
    }

    async fn send(&self, event: pb::ContainerOperationEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, containers: &[String]) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.containers = containers.to_vec();
        self.send(event).await
    }

    async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, group: Option<pb::ContainerGroup>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.group = group;
        self.send(event).await
    }

    /// End the stream with a Connect error trailer
    async fn fail(&self, message: &str) -> Result<(), ()> {
        crate::jobs::finish(&self.journal, Some(message));
        self.tx
            .send(error_trailer("internal", message))
            .await
            .map_err(|_| ())
    }
}

/// The container names of one group, for the logs verb
pub async fn containers_of_group(
    key: &str,
    names: &[(String, String)],
) -> Result<(String, Vec<String>), Refusal> {
    let inv = inventory(names)
        .await
        .map_err(|err| Refusal::EngineUnavailable(err.to_string()))?;
    if !inv.unavailable_reason.is_empty() {
        return Err(Refusal::EngineUnavailable(inv.unavailable_reason));
    }
    let group = resolve(&inv, key).ok_or(Refusal::UnknownKey)?;
    Ok((
        group.key.clone(),
        group.containers.iter().map(|c| c.name.clone()).collect(),
    ))
}

// ─────────────────────────────── one container ───────────────────────────────

/// Everything about one container that the list does not carry
pub async fn inspect(
    codec: Codec,
    req: pb::InspectContainerRequest,
    names: &[(String, String)],
) -> Resp {
    let inv = match inventory(names).await {
        Ok(inv) => inv,
        Err(err) => return Refusal::EngineUnavailable(err.to_string()).response(),
    };
    if !inv.unavailable_reason.is_empty() {
        return Refusal::EngineUnavailable(inv.unavailable_reason).response();
    }
    let Some(container) = inv
        .groups
        .iter()
        .flat_map(|g| g.containers.iter())
        .find(|c| c.name == req.name)
    else {
        return connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "this host reports no container with that name",
        );
    };

    let name = container.name.clone();
    let raw = match run_inspect(&name).await {
        Ok(raw) => raw,
        Err(err) => return Refusal::EngineUnavailable(err.to_string()).response(),
    };
    let detail = build_detail(container.clone(), raw.as_deref());
    codec.encode(&detail).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

async fn run_inspect(name: &str) -> Result<Option<String>> {
    let output = Command::new("docker")
        .args(["inspect", name])
        .output()
        .await
        .context("run `docker inspect`")?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

fn build_detail(container: pb::Container, raw: Option<&str>) -> pb::ContainerDetail {
    let mut detail = pb::ContainerDetail {
        container: Some(container),
        ..Default::default()
    };
    let Some(rows) = raw.and_then(|raw| serde_json::from_str::<Vec<InspectRow>>(raw).ok()) else {
        return detail;
    };
    let Some(row) = rows.into_iter().next() else {
        return detail;
    };

    detail.created_at = row.created;
    detail.restart_policy = row.host_config.restart_policy.name;
    detail.compose_project = row
        .config
        .labels
        .get("com.docker.compose.project")
        .cloned()
        .unwrap_or_default();
    detail.compose_service = row
        .config
        .labels
        .get("com.docker.compose.service")
        .cloned()
        .unwrap_or_default();
    detail.command = row.config.cmd.unwrap_or_default().join(" ");
    detail.env = row
        .config
        .env
        .into_iter()
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            Some(pb::ContainerEnvVar {
                sensitive: looks_sensitive(key),
                key: key.to_string(),
                value: value.to_string(),
            })
        })
        .collect();
    detail.mounts = row
        .mounts
        .into_iter()
        .map(|mount| pb::ContainerMount {
            name: mount.name.clone(),
            source: if mount.source.is_empty() { mount.name } else { mount.source },
            destination: mount.destination,
            mode: if mount.rw { "rw".to_string() } else { "ro".to_string() },
            kind: mount.kind,
        })
        .collect();
    detail
}

/// Does this variable name look like a credential?
fn looks_sensitive(key: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "AUTH", "SALT",
        "PRIVATE", "URL", "URI", "DSN", "CERT", "SIGNATURE", "SESSION", "COOKIE", "API",
    ];
    let upper = key.to_uppercase();
    NEEDLES.iter().any(|needle| upper.contains(needle))
}

#[derive(Debug, Deserialize)]
struct InspectRow {
    #[serde(rename = "Created", default)]
    created: String,
    #[serde(rename = "Config", default)]
    config: InspectConfig,
    #[serde(rename = "HostConfig", default)]
    host_config: InspectHostConfig,
    #[serde(rename = "Mounts", default)]
    mounts: Vec<InspectMount>,
}

#[derive(Debug, Default, Deserialize)]
struct InspectConfig {
    #[serde(rename = "Env", default)]
    env: Vec<String>,
    #[serde(rename = "Cmd", default)]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Labels", default)]
    labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct InspectHostConfig {
    #[serde(rename = "RestartPolicy", default)]
    restart_policy: InspectRestartPolicy,
}

#[derive(Debug, Default, Deserialize)]
struct InspectRestartPolicy {
    #[serde(rename = "Name", default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct InspectMount {
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
    #[serde(rename = "RW", default)]
    rw: bool,
}

/// Inspect every container of one group
pub async fn details_of_group(
    key: &str,
    names: &[(String, String)],
) -> Result<(pb::ContainerGroup, Vec<pb::ContainerDetail>), Refusal> {
    let inv = inventory(names)
        .await
        .map_err(|err| Refusal::EngineUnavailable(err.to_string()))?;
    if !inv.unavailable_reason.is_empty() {
        return Err(Refusal::EngineUnavailable(inv.unavailable_reason));
    }
    let group = resolve(&inv, key).ok_or(Refusal::UnknownKey)?.clone();

    let mut details = Vec::new();
    for container in &group.containers {
        let raw = run_inspect(&container.name).await.ok().flatten();
        details.push(build_detail(container.clone(), raw.as_deref()));
    }
    Ok((group, details))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(name: &str, status: &str, files: &str) -> ComposeProject {
        ComposeProject {
            name: name.to_string(),
            status: status.to_string(),
            config_files: files.to_string(),
        }
    }

    fn container(name: &str, state: &str) -> pb::Container {
        pb::Container {
            name: name.to_string(),
            image: "img:1".to_string(),
            state: state.to_string(),
            health: String::new(),
            ports: String::new(),
        }
    }

    // ───────────────────────────── the naming rule ─────────────────────────

    #[test]
    fn the_replica_index_is_dropped_and_the_words_are_spelled() {
        assert_eq!(display_name_for("mailcow-dockerized-1"), "Mailcow Dockerized");
        assert_eq!(display_name_for("nextcloud_db_1"), "Nextcloud DB");
        assert_eq!(display_name_for("some-random-stack"), "Some Random Stack");
    }

    #[test]
    fn products_are_spelled_the_way_they_spell_themselves() {
        assert_eq!(display_name_for("gitlab"), "GitLab");
        assert_eq!(display_name_for("postgresql"), "PostgreSQL");
        assert_eq!(display_name_for("phpmyadmin"), "phpMyAdmin");
        assert_eq!(display_name_for("pihole"), "Pi-hole");
        assert_eq!(display_name_for("photoprism-worker"), "PhotoPrism Worker");
    }

    #[test]
    fn one_word_names_that_are_two_words_are_a_whole_name_lookup() {
        assert_eq!(display_name_for("adguardhome"), "AdGuard Home");
        assert_eq!(display_name_for("adguard-home"), "AdGuard Home");
        assert_eq!(display_name_for("adguard_home"), "AdGuard Home");
        assert_eq!(display_name_for("uptimekuma"), "Uptime Kuma");
    }

    #[test]
    fn only_a_trailing_standalone_digit_is_a_replica_index() {
        assert_eq!(display_name_for("web2"), "Web2");
        assert_eq!(display_name_for("s3-1-backup"), "S3 1 Backup");
        assert_eq!(display_name_for("2048"), "2048");
    }

    #[test]
    fn a_leading_slash_and_surrounding_space_are_not_part_of_the_name() {
        assert_eq!(display_name_for("/vaultwarden"), "Vaultwarden");
        assert_eq!(display_name_for("  redis  "), "Redis");
    }

    // ────────────────────────────── the inventory ───────────────────────────

    #[test]
    fn a_container_no_project_claimed_is_its_own_row() {
        let projects = vec![project("nextcloud", "running(2)", "/opt/nextcloud/compose.yml")];
        let members = vec![container("nextcloud-app-1", "running"), container("nextcloud-db-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let mut all = members;
        all.push(container("watchtower", "running"));

        let inv = assemble(&read, &all, &[]);
        let names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        assert_eq!(names, vec!["Nextcloud", "Watchtower"]);

        let loose = inv.groups.iter().find(|g| g.key == "watchtower").unwrap();
        assert_eq!(loose.kind, pb::ContainerGroupKind::Standalone as i32);
        assert_eq!(loose.containers.len(), 1);
        assert!(loose.config_files.is_empty());
    }

    #[test]
    fn a_stranger_stack_is_a_row_with_a_status_and_no_service_id() {
        let projects = vec![project("some-random-stack", "running(1)", "/srv/x/compose.yml")];
        let members = vec![container("some-random-stack-web-1", "running")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        assert_eq!(inv.groups.len(), 1);
        let row = &inv.groups[0];
        assert_eq!(row.display_name, "Some Random Stack");
        assert_eq!(row.service_id, "");
        assert_eq!(row.status, pb::ServiceStatus::Running as i32);
        assert_eq!(row.config_files, vec!["/srv/x/compose.yml".to_string()]);
    }

    #[test]
    fn a_catalog_service_keeps_its_catalog_name_and_id() {
        let projects = vec![project("gryonix-vpn-panel", "running(3)", "/opt/vpn-panel/docker-compose.yml")];
        let members = vec![container("gryonix-vpn-panel-panel-1", "running")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        let row = &inv.groups[0];
        assert_eq!(row.service_id, "vpn");
        assert_eq!(row.display_name, "VPN");
        assert_eq!(row.derived_name, "VPN");
        assert_eq!(display_name_for("gryonix-vpn-panel"), "Gryonix VPN Panel");
    }

    #[test]
    fn an_owner_name_wins_and_the_derived_one_still_travels() {
        let projects = vec![project("some-random-stack", "running(1)", "/srv/x/compose.yml")];
        let members = vec![container("some-random-stack-web-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let names = vec![("some-random-stack".to_string(), "Photo backup".to_string())];

        let inv = assemble(&read, &members, &names);
        let row = &inv.groups[0];
        assert_eq!(row.display_name, "Photo backup");
        assert_eq!(row.derived_name, "Some Random Stack");
        assert!(row.renamed);
    }

    // ───────────────────────── no two rows share a name ─────────────────────

    #[test]
    fn several_vpn_pieces_are_told_apart_by_which_piece_they_are() {
        let projects = vec![
            project("vpnpanel", "running(1)", "/opt/vpn-panel/docker-compose.yml"),
            project("shadowsocks", "running(1)", "/opt/shadowsocks/docker-compose.yml"),
            project("xray", "running(1)", "/opt/xray/docker-compose.yml"),
            project("awgvpn", "running(1)", "/opt/amnezia/docker-compose.yml"),
            project("openvpn", "running(1)", "/opt/openvpn/docker-compose.yml"),
        ];
        let members: Vec<Vec<pb::Container>> = projects
            .iter()
            .map(|p| vec![container(&format!("{}-svc-1", p.name), "running")])
            .collect();
        let read: Vec<(&ComposeProject, Vec<pb::Container>)> = projects
            .iter()
            .zip(members.iter().cloned())
            .collect();
        let all: Vec<pb::Container> = members.iter().flatten().cloned().collect();

        let inv = assemble(&read, &all, &[]);
        let mut names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "VPN \u{00b7} AmneziaWG",
                "VPN \u{00b7} OpenVPN",
                "VPN \u{00b7} Shadowsocks",
                "VPN \u{00b7} XRay",
                "VPN \u{00b7} panel",
            ]
        );
        for group in &inv.groups {
            assert_eq!(group.service_id, "vpn");
        }
        assert!(inv.groups.iter().any(|g| g.key == "awgvpn"));
    }

    #[test]
    fn a_single_group_is_never_qualified() {
        let projects = vec![project("vpnpanel", "running(1)", "/opt/vpn-panel/docker-compose.yml")];
        let members = vec![container("vpnpanel-panel-1", "running")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        assert_eq!(inv.groups[0].display_name, "VPN");
        assert_eq!(inv.groups[0].derived_name, "VPN");
    }

    #[test]
    fn two_strangers_that_spell_the_same_are_parted_by_their_keys() {
        let projects = vec![project("nextcloud-db", "running(1)", "/srv/a/compose.yml")];
        let members = vec![container("nextcloud-db-pg-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let mut all = members;
        all.push(container("nextcloud_db_1", "running"));

        let inv = assemble(&read, &all, &[]);
        let mut names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "Nextcloud DB \u{00b7} nextcloud-db",
                "Nextcloud DB \u{00b7} nextcloud_db_1",
            ]
        );
    }

    #[test]
    fn a_project_and_a_container_sharing_a_key_are_parted_by_what_they_are() {
        let projects = vec![project("redis", "running(1)", "/srv/r/compose.yml")];
        let members = vec![container("redis-server-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let mut all = members;
        all.push(container("redis", "running"));

        let inv = assemble(&read, &all, &[]);
        let mut names: Vec<&str> = inv.groups.iter().map(|g| g.display_name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["Redis (container)", "Redis (project)"]);
    }

    #[test]
    fn an_owner_name_is_left_alone_while_the_one_underneath_is_parted() {
        let projects = vec![
            project("vpnpanel", "running(1)", "/opt/vpn-panel/docker-compose.yml"),
            project("shadowsocks", "running(1)", "/opt/shadowsocks/docker-compose.yml"),
        ];
        let members: Vec<Vec<pb::Container>> = projects
            .iter()
            .map(|p| vec![container(&format!("{}-svc-1", p.name), "running")])
            .collect();
        let read: Vec<(&ComposeProject, Vec<pb::Container>)> =
            projects.iter().zip(members.iter().cloned()).collect();
        let all: Vec<pb::Container> = members.iter().flatten().cloned().collect();
        let names = vec![("vpnpanel".to_string(), "My VPN".to_string())];

        let inv = assemble(&read, &all, &names);
        let panel = inv.groups.iter().find(|g| g.key == "vpnpanel").unwrap();
        assert_eq!(panel.display_name, "My VPN");
        assert_eq!(panel.derived_name, "VPN \u{00b7} panel");
        let ss = inv.groups.iter().find(|g| g.key == "shadowsocks").unwrap();
        assert_eq!(ss.display_name, "VPN \u{00b7} Shadowsocks");
    }

    /// A stopped project still has a row
    #[test]
    fn a_stopped_project_is_listed_with_a_stopped_status() {
        let projects = vec![project("vaultwarden", "exited(1)", "/opt/vaultwarden/compose.yml")];
        let members = vec![container("vaultwarden", "exited")];
        let read = vec![(&projects[0], members.clone())];

        let inv = assemble(&read, &members, &[]);
        assert_eq!(inv.groups[0].status, pb::ServiceStatus::Stopped as i32);
    }

    // ───────────────────────────────── the gate ─────────────────────────────

    #[test]
    fn resolve_answers_only_for_a_key_the_host_reports() {
        let projects = vec![project("nextcloud", "running(1)", "/opt/nextcloud/compose.yml")];
        let members = vec![container("nextcloud-app-1", "running")];
        let read = vec![(&projects[0], members.clone())];
        let inv = assemble(&read, &members, &[]);

        assert!(resolve(&inv, "nextcloud").is_some());
        assert!(resolve(&inv, "nextcloud; rm -rf /").is_none());
        assert!(resolve(&inv, "").is_none());
    }

    // ──────────────────────── control argv and inspect ─────────────────────

    #[test]
    fn a_project_and_a_lone_container_take_different_commands() {
        assert_eq!(
            docker_args("nextcloud", GroupKind::ComposeProject, pb::ServiceAction::Restart),
            vec!["compose", "-p", "nextcloud", "restart"]
        );
        assert_eq!(
            docker_args("watchtower", GroupKind::Standalone, pb::ServiceAction::Restart),
            vec!["restart", "watchtower"]
        );
    }

    #[test]
    fn stop_is_stop_and_never_down() {
        for kind in [GroupKind::ComposeProject, GroupKind::Standalone] {
            let args = docker_args("x", kind, pb::ServiceAction::Stop);
            assert!(args.iter().any(|a| a == "stop"), "{args:?}");
            assert!(!args.iter().any(|a| a == "down"), "{args:?}");
            assert!(!args.iter().any(|a| a == "rm"), "{args:?}");
        }
    }

    #[test]
    fn a_hostile_key_stays_a_single_argument() {
        let args = docker_args("x; rm -rf /", GroupKind::Standalone, pb::ServiceAction::Stop);
        assert_eq!(args, vec!["stop", "x; rm -rf /"]);
    }

    #[test]
    fn a_connection_string_counts_as_a_credential() {
        assert!(looks_sensitive("DATABASE_URL"));
        assert!(looks_sensitive("POSTGRES_PASSWORD"));
        assert!(looks_sensitive("admin_token"));
        assert!(looks_sensitive("JWT_SECRET"));
        assert!(!looks_sensitive("TZ"));
        assert!(!looks_sensitive("PUID"));
        assert!(!looks_sensitive("LANG"));
    }

    const INSPECT: &str = r#"[{
      "Created": "2026-08-01T10:00:00Z",
      "Config": {
        "Env": ["TZ=Europe/Berlin", "DATABASE_URL=postgres://u:p@db/x?a=b", "EMPTY="],
        "Cmd": ["nginx", "-g", "daemon off;"],
        "Labels": {"com.docker.compose.project": "some-stack", "com.docker.compose.service": "web"}
      },
      "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
      "Mounts": [
        {"Type": "bind", "Source": "/srv/data", "Destination": "/data", "RW": true},
        {"Type": "volume", "Name": "cache", "Source": "", "Destination": "/cache", "RW": false}
      ]
    }]"#;

    #[test]
    fn env_splits_on_the_first_equals_and_marks_the_credential() {
        let detail = build_detail(container("web", "running"), Some(INSPECT));
        let url = detail.env.iter().find(|e| e.key == "DATABASE_URL").unwrap();
        assert_eq!(url.value, "postgres://u:p@db/x?a=b");
        assert!(url.sensitive);
        let tz = detail.env.iter().find(|e| e.key == "TZ").unwrap();
        assert_eq!(tz.value, "Europe/Berlin");
        assert!(!tz.sensitive);
        let empty = detail.env.iter().find(|e| e.key == "EMPTY").unwrap();
        assert_eq!(empty.value, "");
    }

    #[test]
    fn mounts_carry_where_they_come_from_and_whether_they_are_writable() {
        let detail = build_detail(container("web", "running"), Some(INSPECT));
        assert_eq!(detail.mounts.len(), 2);
        assert_eq!(detail.mounts[0].source, "/srv/data");
        assert_eq!(detail.mounts[0].mode, "rw");
        assert_eq!(detail.mounts[0].kind, "bind");
        assert_eq!(detail.mounts[1].source, "cache");
        assert_eq!(detail.mounts[1].mode, "ro");
        assert_eq!(detail.restart_policy, "unless-stopped");
        assert_eq!(detail.compose_project, "some-stack");
        assert_eq!(detail.command, "nginx -g daemon off;");
    }

    #[test]
    fn missing_detail_is_a_thinner_answer_not_a_failure() {
        for raw in [None, Some("not json"), Some("[]")] {
            let detail = build_detail(container("web", "running"), raw);
            assert_eq!(detail.container.as_ref().unwrap().name, "web");
            assert!(detail.env.is_empty());
            assert!(detail.mounts.is_empty());
        }
    }

    #[test]
    fn stopped_things_are_asked_for_explicitly() {
        let src = include_str!("containers.rs");
        let body = |name: &str| -> String {
            let start = src.find(name).expect("function present");
            src[start..].chars().take(600).collect()
        };
        let ps = body("async fn all_containers(");
        assert!(ps.contains(r#""ps", "-a""#), "docker ps must ask for stopped containers too");
        let ls = body("async fn compose_projects(");
        assert!(ls.contains(r#""--all""#), "docker compose ls must ask for stopped projects too");
    }

    #[test]
    fn an_owner_name_is_bounded_and_empty_means_undo() {
        assert_eq!(sanitise_name("  Photo backup "), Ok("Photo backup".to_string()));
        assert_eq!(sanitise_name(""), Ok(String::new()));
        assert_eq!(sanitise_name("   "), Ok(String::new()));
        assert!(sanitise_name(&"x".repeat(NAME_LIMIT + 1)).is_err());
        assert!(sanitise_name("two\nlines").is_err());
    }
}
