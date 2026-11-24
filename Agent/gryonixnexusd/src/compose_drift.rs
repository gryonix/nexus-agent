//! Recreates running containers whose compose file changed; stopped ones stay stopped.

use std::collections::HashMap;
use std::time::Duration;

use tokio::process::Command;

/// Lets docker finish starting before anything is compared
const SETTLE: Duration = Duration::from_secs(30);

pub async fn heal_at_startup() {
    tokio::time::sleep(SETTLE).await;
    let projects = match crate::discover::running_known_projects().await {
        Ok(projects) => projects,
        Err(err) => return tracing::warn!(%err, "could not list compose projects"),
    };
    for (project, files) in projects {
        if let Err(why) = heal(&project, &files).await {
            tracing::warn!(%why, project, "could not bring containers to their compose file");
        }
    }
}

async fn heal(project: &str, files: &[String]) -> Result<(), String> {
    let wanted = parse_hashes(&docker(&compose_args(project, files, &["config", "--hash", "*"])).await?);
    let live = parse_live(&docker(&live_args(project)).await?);
    let services = drifted(&wanted, &live);
    if services.is_empty() {
        return Ok(());
    }
    let mut args = vec!["up", "-d", "--no-deps"];
    args.extend(services.iter().map(String::as_str));
    docker(&compose_args(project, files, &args)).await?;
    tracing::info!(project, ?services, "recreated containers from the current compose file");
    Ok(())
}

fn compose_args(project: &str, files: &[String], tail: &[&str]) -> Vec<String> {
    let mut args = vec!["compose".to_string(), "-p".to_string(), project.to_string()];
    for file in files {
        args.push("-f".to_string());
        args.push(file.clone());
    }
    args.extend(tail.iter().map(|part| part.to_string()));
    args
}

fn live_args(project: &str) -> Vec<String> {
    [
        "ps",
        "-a",
        "--filter",
        &format!("label=com.docker.compose.project={project}"),
        "--format",
        "{{.Label \"com.docker.compose.service\"}}\t{{.Label \"com.docker.compose.config-hash\"}}\t{{.State}}",
    ]
    .iter()
    .map(|part| part.to_string())
    .collect()
}

async fn docker(args: &[String]) -> Result<String, String> {
    let run = Command::new("docker").args(args).output();
    let output = tokio::time::timeout(Duration::from_secs(300), run)
        .await
        .map_err(|_| "docker did not answer in time".to_string())?
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// `config --hash` lines: service, then hash
fn parse_hashes(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .map(|(service, hash)| (service.to_string(), hash.trim().to_string()))
        .collect()
}

/// One live container: service, hash, state
struct Live {
    service: String,
    hash: String,
    running: bool,
}

fn parse_live(text: &str) -> Vec<Live> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            Some(Live {
                service: parts.next()?.to_string(),
                hash: parts.next()?.to_string(),
                running: parts.next()? == "running",
            })
        })
        .collect()
}

/// Running services whose container differs from the file
fn drifted(wanted: &HashMap<String, String>, live: &[Live]) -> Vec<String> {
    let mut services: Vec<String> = live
        .iter()
        .filter(|container| container.running)
        .filter(|container| wanted.get(&container.service).is_some_and(|hash| *hash != container.hash))
        .map(|container| container.service.clone())
        .collect();
    services.sort();
    services.dedup();
    services
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(service: &str, hash: &str, running: bool) -> Live {
        Live { service: service.to_string(), hash: hash.to_string(), running }
    }

    #[test]
    fn only_running_containers_with_a_changed_file_are_recreated() {
        let wanted = parse_hashes("doh aaa\nweb bbb\ndb ccc\nworker ddd\n");
        let containers = [
            live("doh", "old", true),
            live("web", "bbb", true),
            live("db", "old", false),
            live("extra", "zzz", true),
        ];
        assert_eq!(drifted(&wanted, &containers), vec!["doh".to_string()]);
    }

    #[test]
    fn the_live_listing_is_read_by_tabs() {
        let rows = parse_live("doh\tabc\trunning\nweb\tdef\texited\n");
        assert_eq!(rows.len(), 2);
        assert!(rows[0].running && !rows[1].running);
        assert_eq!(rows[1].hash, "def");
    }

    #[test]
    fn every_compose_file_is_passed() {
        let args = compose_args("mailcow", &["/a.yml".to_string(), "/b.yml".to_string()], &["up", "-d"]);
        assert_eq!(args, ["compose", "-p", "mailcow", "-f", "/a.yml", "-f", "/b.yml", "up", "-d"]);
    }
}
