//! Adoption scan: inspect an already-configured host and report what is installed, so a device with no prior state can take it over

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;

use crate::pb;

/// The running/known compose projects on the host (`docker compose ls`).
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
    parse_compose_ls(&String::from_utf8_lossy(&output.stdout))
}

pub async fn containers_of_service(service_id: &str) -> Result<Vec<String>> {
    let projects = compose_projects().await?;
    let mut names = Vec::new();
    for project in members_of(&projects, service_id) {
        names.extend(containers_for(&project.name).await?.into_iter().map(|c| c.name));
    }
    Ok(names)
}

pub async fn projects_of_service(service_id: &str) -> Result<Vec<String>> {
    let projects = compose_projects().await?;
    Ok(members_of(&projects, service_id)
        .into_iter()
        .map(|p| p.name.clone())
        .collect())
}

pub async fn directory_of_service(service_id: &str) -> Result<Option<std::path::PathBuf>> {
    let projects = compose_projects().await?;
    for project in members_of(&projects, service_id) {
        let first = project.config_files.split(',').next().unwrap_or("").trim();
        if first.is_empty() {
            continue;
        }
        if let Some(dir) = std::path::Path::new(first).parent() {
            return Ok(Some(dir.to_path_buf()));
        }
    }
    Ok(None)
}

pub struct InstalledProject {
    pub service_id: &'static str,
    pub project: String,
    pub directory: std::path::PathBuf,
}

/// Catalog services' compose projects with their folders
pub async fn installed_projects() -> Result<Vec<InstalledProject>> {
    let projects = compose_projects().await?;
    Ok(projects
        .iter()
        .filter_map(|project| {
            let (service_id, _) = catalog_id(project)?;
            let first = project.config_files.split(',').next().unwrap_or("").trim();
            let directory = std::path::Path::new(first).parent()?.to_path_buf();
            (!first.is_empty()).then(|| InstalledProject { service_id, project: project.name.clone(), directory })
        })
        .collect())
}

pub async fn service_snapshot(service_id: &str) -> Result<Option<pb::Service>> {
    let projects = compose_projects().await?;
    let members = members_of(&projects, service_id);
    if members.is_empty() {
        return Ok(None);
    }
    let display = catalog_id(members[0]).map(|(_, name)| name).unwrap_or(service_id);
    Ok(Some(build_service(service_id, display, &members).await))
}

/// Projects belonging to one catalog id, first-seen order preserved.
fn members_of<'a>(projects: &'a [ComposeProject], service_id: &str) -> Vec<&'a ComposeProject> {
    projects
        .iter()
        .filter(|p| catalog_id(p).map(|(id, _)| id) == Some(service_id))
        .collect()
}

async fn build_service(id: &str, display: &str, members: &[&ComposeProject]) -> pb::Service {
    let mut containers = Vec::new();
    for project in members {
        if let Ok(mut found) = containers_for(&project.name).await {
            containers.append(&mut found);
        }
    }
    let status = status_from_containers(&containers)
        .unwrap_or_else(|| status_of(&members[0].status));
    let version = version_of(id, &containers);
    pb::Service {
        id: id.to_string(),
        display_name: display.to_string(),
        status: status as i32,
        version,
        containers,
        installed_outside: false,
    }
}

pub async fn scan() -> Result<pb::DiscoverResult> {
    let projects = compose_projects().await?;
    let (groups, notes) = group_projects(&projects);

    let mut services = Vec::new();
    for (id, display, members) in &groups {
        services.push(build_service(id, display, members).await);
    }
    Ok(pb::DiscoverResult { services, notes })
}

fn group_projects<'a>(
    projects: &'a [ComposeProject],
) -> (Vec<(&'static str, &'static str, Vec<&'a ComposeProject>)>, Vec<String>) {
    let mut groups: Vec<(&'static str, &'static str, Vec<&'a ComposeProject>)> = Vec::new();
    let mut notes = Vec::new();
    for project in projects {
        match catalog_id(project) {
            Some((id, display)) => match groups.iter_mut().find(|g| g.0 == id) {
                Some(group) => group.2.push(project),
                None => groups.push((id, display, vec![project])),
            },
            None => notes.push(format!(
                "unrecognized compose project '{}' ({})",
                project.name, project.config_files
            )),
        }
    }
    (groups, notes)
}

/// The containers of one compose project, via its compose label
pub(crate) async fn containers_for(project: &str) -> Result<Vec<pb::Container>> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            "json",
        ])
        .output()
        .await
        .context("run `docker ps`")?;
    if !output.status.success() {
        anyhow::bail!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_docker_ps(&String::from_utf8_lossy(&output.stdout)))
}

/// One row of `docker compose ls --format json`.
#[derive(Debug, Deserialize)]
struct ComposeProject {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "ConfigFiles", default)]
    config_files: String,
}

fn parse_compose_ls(stdout: &str) -> Result<Vec<ComposeProject>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).context("parse `docker compose ls` json")
}

const CATALOG: &[(&str, &str, &str)] = &[
    ("mailcowdockerized", "mailcow", "Mailcow"),
    ("mailu", "mailu", "Mailu"),
    ("dockermailserver", "docker-mailserver", "Docker Mailserver"),
    ("vaultwarden", "vaultwarden", "Vaultwarden"),
    ("nextcloud", "nextcloud", "Nextcloud"),
    ("immich", "immich", "Immich"),
    ("forgejo", "forgejo", "Forgejo"),
    ("gitlab", "gitlab", "GitLab"),
    ("jellyfin", "jellyfin", "Jellyfin"),
    ("home-assistant", "home-assistant", "Home Assistant"),
    ("mosquitto", "mosquitto", "Mosquitto"),
    ("zigbee2mqtt", "zigbee2mqtt", "Zigbee2MQTT"),
    ("photoprism", "photoprism", "PhotoPrism"),
    ("seafile", "seafile", "Seafile"),
    ("psono", "psono", "Psono"),
    ("passbolt", "passbolt", "Passbolt"),
    ("adguardhome", "adguard-home", "AdGuard Home"),
    ("pihole", "pihole", "Pi-hole"),
    // The start page. Last, like its shelf.
    ("homepage", "homepage", "Homepage"),
    // Single sign-on in front of the panels.
    ("authelia", "authelia", "Authelia"),
    ("headscale", "headscale", "Headscale"),
    ("tailscale", "tailscale-node", "Tailscale"),
    ("cloudflared", "cloudflared", "Cloudflare Tunnel"),
    ("minecraft-java", "minecraft-java", "Minecraft (Java)"),
    ("minecraft-bedrock", "minecraft-bedrock", "Minecraft (Bedrock)"),
    ("crafty", "crafty-controller", "Crafty Controller"),
    ("ollama", "ollama", "Ollama"),
    ("open-webui", "open-webui", "Open WebUI"),
    ("litellm", "litellm", "LiteLLM"),
    ("n8n", "n8n", "n8n"),
    ("anythingllm", "anythingllm", "AnythingLLM"),
    ("qdrant", "qdrant", "Qdrant"),
    ("searxng", "searxng", "SearXNG"),
    ("openclaw", "openclaw", "OpenClaw"),
];

const VPN_SERVICE: (&str, &str) = ("vpn", "VPN");

/// Map a compose project to a catalog id
fn catalog_id(project: &ComposeProject) -> Option<(&'static str, &'static str)> {
    if let Some(entry) = CATALOG.iter().find(|(name, _, _)| *name == project.name) {
        return Some((entry.1, entry.2));
    }
    if is_vpn_project(project) {
        return Some(VPN_SERVICE);
    }
    None
}

pub(crate) fn catalog_id_of_project(
    name: &str,
    config_files: &str,
) -> Option<(&'static str, &'static str)> {
    catalog_id(&ComposeProject {
        name: name.to_string(),
        status: String::new(),
        config_files: config_files.to_string(),
    })
}

pub fn known_service(service_id: &str) -> Option<&'static str> {
    if service_id == VPN_SERVICE.0 {
        return Some(VPN_SERVICE.1);
    }
    CATALOG
        .iter()
        .find(|(_, id, _)| *id == service_id)
        .map(|(_, _, display)| *display)
}

pub fn known_service_id(service_id: &str) -> Option<&'static str> {
    if service_id == VPN_SERVICE.0 {
        return Some(VPN_SERVICE.0);
    }
    CATALOG
        .iter()
        .find(|(_, id, _)| *id == service_id)
        .map(|(_, id, _)| *id)
}

pub fn all_service_ids() -> Vec<&'static str> {
    CATALOG
        .iter()
        .map(|(_, id, _)| *id)
        .chain(std::iter::once(VPN_SERVICE.0))
        .collect()
}

fn is_vpn_project(project: &ComposeProject) -> bool {
    const VPN_PROJECTS: &[&str] = &[
        "vpnpanel",
        "vpn-panel",
        "gryonix-vpn-panel",
        "openvpn",
        "awgvpn",
        "amneziawg",
        "wireguard",
        "shadowsocks",
        "xray",
    ];
    let name = project.name.to_lowercase();
    VPN_PROJECTS.contains(&name.as_str())
        || name.starts_with("gryonix-vpn")
        || project.config_files.contains("vpn-panel")
}

/// `docker compose ls` reports e.g
pub(crate) fn status_of(status: &str) -> pb::ServiceStatus {
    let running = status.contains("running");
    let stopped =
        status.contains("exited") || status.contains("created") || status.contains("dead");
    match (running, stopped) {
        (true, true) => pb::ServiceStatus::Partial,
        (true, false) => pb::ServiceStatus::Running,
        (false, true) => pb::ServiceStatus::Stopped,
        (false, false) => pb::ServiceStatus::Unspecified,
    }
}

/// One row of `docker ps --format json`
#[derive(Debug, Deserialize)]
struct DockerPsRow {
    #[serde(rename = "Names", default)]
    names: String,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Ports", default)]
    ports: String,
}

/// `docker ps --format json` is NDJSON — one object per line
pub(crate) fn parse_docker_ps(stdout: &str) -> Vec<pb::Container> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|line| serde_json::from_str::<DockerPsRow>(line).ok())
        .map(|row| pb::Container {
            name: row.names,
            image: row.image,
            health: health_from_status(&row.status),
            state: row.state,
            ports: row.ports,
        })
        .collect()
}

pub(crate) fn health_from_status(status: &str) -> String {
    for token in ["unhealthy", "healthy", "starting"] {
        if status.contains(token) {
            return token.to_string();
        }
    }
    String::new()
}

pub(crate) fn status_from_containers(containers: &[pb::Container]) -> Option<pb::ServiceStatus> {
    if containers.is_empty() {
        return None;
    }
    let running = containers.iter().filter(|c| c.state == "running").count();
    let unhealthy = containers.iter().any(|c| c.health == "unhealthy");
    Some(if unhealthy {
        pb::ServiceStatus::Error
    } else if running == containers.len() {
        pb::ServiceStatus::Running
    } else if running == 0 {
        pb::ServiceStatus::Stopped
    } else {
        pb::ServiceStatus::Partial
    })
}

fn version_of(id: &str, containers: &[pb::Container]) -> String {
    let squeeze = |text: &str| text.to_lowercase().replace(['-', '_'], "");
    let wanted = squeeze(id);
    containers
        .iter()
        .find(|c| squeeze(&c.image).contains(&wanted))
        .and_then(|c| c.image.rsplit_once(':').map(|(_, tag)| tag.to_string()))
        .filter(|tag| !tag.contains('/'))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
        {"Name":"mailcowdockerized","Status":"running(20)","ConfigFiles":"/opt/mailcow-dockerized/docker-compose.yml"},
        {"Name":"vaultwarden","Status":"exited(1)","ConfigFiles":"/opt/vaultwarden/docker-compose.yml"},
        {"Name":"gryonix-vpn-panel","Status":"running(3), exited(1)","ConfigFiles":"/opt/vpn-panel/docker-compose.yml"},
        {"Name":"randomstack","Status":"running(2)","ConfigFiles":"/srv/random/compose.yml"}
    ]"#;

    #[test]
    fn groups_known_projects_and_notes_the_rest() {
        let projects = parse_compose_ls(SAMPLE).unwrap();
        let (groups, notes) = group_projects(&projects);

        let ids: Vec<_> = groups.iter().map(|g| g.0).collect();
        assert_eq!(ids, ["mailcow", "vaultwarden", "vpn"]);
        // Each group here has exactly one member project.
        assert!(groups.iter().all(|g| g.2.len() == 1));

        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("randomstack"));
    }

    #[test]
    fn forgejo_is_recognized_with_its_database() {
        let sample = r#"[
            {"Name":"forgejo","Status":"running(2)","ConfigFiles":"/opt/forgejo/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "forgejo");
        assert!(notes.is_empty());
    }

    #[test]
    fn both_git_forges_are_recognized_side_by_side() {
        let sample = r#"[
            {"Name":"forgejo","Status":"running(2)","ConfigFiles":"/opt/forgejo/docker-compose.yml"},
            {"Name":"gitlab","Status":"running(1)","ConfigFiles":"/opt/gitlab-ce/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        let ids: Vec<_> = groups.iter().map(|g| g.0).collect();
        assert_eq!(ids, ["forgejo", "gitlab"]);
        assert!(notes.is_empty());
    }

    #[test]
    fn every_vpn_project_collapses_into_one_service() {
        let sample = r#"[
            {"Name":"vpnpanel","Status":"running(1)","ConfigFiles":"/opt/gryonix-vpn-panel/docker-compose.yml"},
            {"Name":"openvpn","Status":"running(1)","ConfigFiles":"/opt/openvpn/docker-compose.yml"},
            {"Name":"awgvpn","Status":"running(1)","ConfigFiles":"/opt/awgvpn/docker-compose.yml"},
            {"Name":"shadowsocks","Status":"running(1)","ConfigFiles":"/opt/shadowsocks/docker-compose.yml"},
            {"Name":"xray","Status":"running(1)","ConfigFiles":"/opt/xray/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "vpn");
        assert_eq!(groups[0].2.len(), 5, "panel + 4 protocols in one group");
        assert!(notes.is_empty(), "shadowsocks and xray are recognized as VPN");
    }

    #[test]
    fn an_unhealthy_container_is_not_reported_healthy() {
        assert_eq!(health_from_status("Up 2 hours (unhealthy)"), "unhealthy");
        assert_eq!(health_from_status("Up 2 hours (healthy)"), "healthy");
        assert_eq!(health_from_status("Up 5 seconds (health: starting)"), "starting");
    }

    #[test]
    fn a_strangers_vpn_stack_is_not_ours() {
        let projects = parse_compose_ls(
            r#"[{"Name":"gluetun-vpn","Status":"running(1)","ConfigFiles":"/srv/gluetun/compose.yml"},
                {"Name":"myvpn","Status":"running(1)","ConfigFiles":"/home/me/myvpn/compose.yml"},
                {"Name":"openvpn","Status":"running(1)","ConfigFiles":"/opt/openvpn/docker-compose.yml"}]"#,
        )
        .unwrap();
        let ours: Vec<&str> = projects.iter().filter(|p| is_vpn_project(p)).map(|p| p.name.as_str()).collect();
        assert_eq!(ours, ["openvpn"]);
    }

    #[test]
    fn a_version_is_found_when_the_id_and_image_spell_it_differently() {
        let image = |image: &str| pb::Container { image: image.into(), ..Default::default() };
        assert_eq!(version_of("adguard-home", &[image("adguard/adguardhome:v0.107.5")]), "v0.107.5");
    }

    #[test]
    fn empty_output_is_no_services() {
        assert!(parse_compose_ls("").unwrap().is_empty());
        assert!(parse_compose_ls("   \n").unwrap().is_empty());
    }

    const DOCKER_PS: &str = r#"{"Names":"vaultwarden","Image":"vaultwarden/server:1.32.0","State":"running","Status":"Up 3 minutes (healthy)"}
{"Names":"vaultwarden-backup","Image":"alpine:3.20","State":"exited","Status":"Exited (0) 2 minutes ago"}
"#;

    #[test]
    fn parses_docker_ps_ndjson_with_health() {
        let containers = parse_docker_ps(DOCKER_PS);
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].name, "vaultwarden");
        assert_eq!(containers[0].image, "vaultwarden/server:1.32.0");
        assert_eq!(containers[0].state, "running");
        assert_eq!(containers[0].health, "healthy");
        assert_eq!(containers[1].state, "exited");
        assert_eq!(containers[1].health, "");
    }

    #[test]
    fn skips_malformed_docker_ps_lines() {
        let containers = parse_docker_ps("not json\n{\"Names\":\"ok\",\"State\":\"running\"}\n");
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].name, "ok");
    }

    #[test]
    fn status_from_containers_mix_is_partial() {
        let containers = parse_docker_ps(DOCKER_PS);
        assert_eq!(
            status_from_containers(&containers),
            Some(pb::ServiceStatus::Partial)
        );
    }

    #[test]
    fn status_from_containers_unhealthy_is_error() {
        let containers = vec![pb::Container {
            name: "x".into(),
            image: "img:1".into(),
            state: "running".into(),
            health: "unhealthy".into(),
            ports: String::new(),
        }];
        assert_eq!(
            status_from_containers(&containers),
            Some(pb::ServiceStatus::Error)
        );
    }

    #[test]
    fn status_from_containers_empty_defers_to_string() {
        assert_eq!(status_from_containers(&[]), None);
    }

    #[test]
    fn service_id_resolves_project_including_loose_vpn_match() {
        let projects = parse_compose_ls(SAMPLE).unwrap();
        let of = |sid: &str| -> Vec<&str> {
            projects
                .iter()
                .filter(|p| catalog_id(p).map(|(id, _)| id) == Some(sid))
                .map(|p| p.name.as_str())
                .collect()
        };
        assert_eq!(of("mailcow"), ["mailcowdockerized"]);
        assert_eq!(of("vpn"), ["gryonix-vpn-panel"]);
        assert!(of("nextcloud").is_empty());
    }

    #[test]
    fn the_catalog_answers_for_every_service_the_app_can_install() {
        for id in [
            "mailcow",
            "mailu",
            "docker-mailserver",
            "vaultwarden",
            "psono",
            "passbolt",
            "nextcloud",
            "seafile",
            "immich",
            "photoprism",
            "gitlab",
            "forgejo",
            "jellyfin",
            "adguard-home",
            "headscale",
            "cloudflared",
            "vpn",
        ] {
            assert!(
                known_service(id).is_some(),
                "{id} is in the app's catalog but not the agent's: the scan reports it as an \
                 unrecognised project and every management call for it is refused"
            );
        }
    }

    #[test]
    fn every_id_the_scan_can_report_is_a_known_service() {
        for (project, id, display) in CATALOG {
            assert_eq!(known_service(id), Some(*display), "catalog id {id} ({project})");
        }
        assert_eq!(known_service(VPN_SERVICE.0), Some(VPN_SERVICE.1));
        assert_eq!(known_service("no-such-service"), None);
        assert!(!CATALOG.iter().any(|(name, _, _)| *name == VPN_SERVICE.0));
        for (project, id, _) in CATALOG {
            assert!(
                crate::backup::wrapper_target(id).is_some(),
                "catalog id {id} ({project}) has no backup wrapper label"
            );
        }
        assert!(crate::backup::wrapper_target(VPN_SERVICE.0).is_some());
    }

    #[test]
    fn all_three_mail_engines_are_recognized() {
        let sample = r#"[
            {"Name":"dockermailserver","Status":"running(2)","ConfigFiles":"/opt/dockermailserver/docker-compose.yml"}
        ]"#;
        let projects = parse_compose_ls(sample).unwrap();
        let (groups, notes) = group_projects(&projects);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "docker-mailserver");
        assert!(notes.is_empty());
    }

    #[test]
    fn members_of_groups_every_vpn_project_and_nothing_else() {
        let projects = parse_compose_ls(SAMPLE).unwrap();
        let names: Vec<&str> = members_of(&projects, "vpn").iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["gryonix-vpn-panel"]);
        assert!(members_of(&projects, "nextcloud").is_empty());
    }

    #[test]
    fn version_from_matching_image_tag() {
        let containers = parse_docker_ps(DOCKER_PS);
        assert_eq!(version_of("vaultwarden", &containers), "1.32.0");
    }
}
