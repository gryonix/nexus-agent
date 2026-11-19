//! Containers that already hold a name a service's compose file wants

use hyper::StatusCode;
use tokio::process::Command;

use crate::api::{connect_error, connect_refusal, Codec, Resp};
use crate::pb;

const LISTING_FORMAT: &str = "{{.Names}}\t{{.Label \"com.docker.compose.project\"}}";

/// Who holds a wanted name
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// A container started by hand, outside any compose project
    Manual(String),
    /// A container of another compose project
    Project { container: String, project: String },
}

/// The `container_name` values of a compose file
pub fn names_in_compose(compose: &str) -> Vec<String> {
    compose
        .lines()
        .filter_map(|line| line.trim().strip_prefix("container_name:"))
        .map(|value| value.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

/// (name, project) pairs from `docker ps -a`
pub fn parse_listing(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let (name, project) = line.split_once('\t')?;
            (!name.trim().is_empty()).then(|| (name.trim().to_string(), project.trim().to_string()))
        })
        .collect()
}

/// Wanted names held by foreign containers
pub fn foreign_holders(wanted: &[String], listing: &[(String, String)], own_projects: &[String]) -> Vec<Holder> {
    wanted
        .iter()
        .filter_map(|name| {
            let (_, project) = listing.iter().find(|(held, _)| held == name)?;
            if own_projects.contains(project) {
                None
            } else if project.is_empty() {
                Some(Holder::Manual(name.clone()))
            } else {
                Some(Holder::Project { container: name.clone(), project: project.clone() })
            }
        })
        .collect()
}

async fn listing() -> Vec<(String, String)> {
    let output = Command::new("docker").args(["ps", "-a", "--format", LISTING_FORMAT]).output().await;
    match output {
        Ok(output) if output.status.success() => parse_listing(&String::from_utf8_lossy(&output.stdout)),
        _ => Vec::new(),
    }
}

/// Foreign holders of the names in a compose file
pub async fn check(compose: &str, own_projects: &[String]) -> Vec<Holder> {
    let wanted = names_in_compose(compose);
    if wanted.is_empty() {
        return Vec::new();
    }
    foreign_holders(&wanted, &listing().await, own_projects)
}

/// Why a container cannot be removed this way
#[derive(Debug, PartialEq, Eq)]
pub enum RemoveRefusal {
    NotFound,
    InComposeProject(String),
    Failed(String),
}

/// The listed name, when removal is allowed
pub fn removable<'a>(asked: &str, listing: &'a [(String, String)]) -> Result<&'a str, RemoveRefusal> {
    let (name, project) = listing.iter().find(|(held, _)| held == asked).ok_or(RemoveRefusal::NotFound)?;
    if project.is_empty() { Ok(name) } else { Err(RemoveRefusal::InComposeProject(project.clone())) }
}

/// Removes one hand-started container, stopping it first
pub async fn remove_manual(asked: &str) -> Result<(), RemoveRefusal> {
    let held = listing().await;
    let name = removable(asked, &held)?;
    let output = Command::new("docker")
        .args(["rm", "-f", name])
        .output()
        .await
        .map_err(|err| RemoveRefusal::Failed(err.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RemoveRefusal::Failed(String::from_utf8_lossy(&output.stderr).trim().to_string()))
    }
}

/// The RPC answer for a removal
pub async fn remove_response(codec: Codec, asked: &str) -> Resp {
    match remove_manual(asked).await {
        Ok(()) => codec.encode(&pb::RemoveForeignContainerResult { removed: asked.to_string() }).unwrap_or_else(|err| {
            connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
        }),
        Err(RemoveRefusal::NotFound) => {
            connect_error(StatusCode::NOT_FOUND, "not_found", "this host reports no container with that name")
        }
        Err(RemoveRefusal::InComposeProject(project)) => connect_refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "that container belongs to a compose project, so it is removed with its project",
            "containers.in_compose_project",
            &[project],
        ),
        Err(RemoveRefusal::Failed(detail)) => connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPOSE: &str = "services:\n  shairport-sync:\n    image: x\n    container_name: shairport-sync\n  db:\n    container_name: \"shairport-db\"\n    image: y\n";

    fn listing() -> Vec<(String, String)> {
        parse_listing("shairport-sync\t\nshairport-db\tshairport-sync\nother\tstack\n")
    }

    #[test]
    fn the_names_come_from_the_compose_file() {
        assert_eq!(names_in_compose(COMPOSE), ["shairport-sync", "shairport-db"]);
        assert!(names_in_compose("services:\n  a:\n    image: x\n").is_empty());
    }

    #[test]
    fn the_listing_pairs_names_with_projects() {
        assert_eq!(listing()[0], ("shairport-sync".to_string(), String::new()));
        assert_eq!(listing()[2], ("other".to_string(), "stack".to_string()));
        assert!(parse_listing("").is_empty());
    }

    #[test]
    fn a_hand_started_container_with_a_wanted_name_is_foreign() {
        let wanted = names_in_compose(COMPOSE);
        let holders = foreign_holders(&wanted, &listing(), &["shairport-sync".to_string()]);
        assert_eq!(holders, [Holder::Manual("shairport-sync".to_string())]);
    }

    #[test]
    fn a_container_of_another_project_is_named_with_its_project() {
        let wanted = vec!["other".to_string()];
        assert_eq!(
            foreign_holders(&wanted, &listing(), &["shairport-sync".to_string()]),
            [Holder::Project { container: "other".into(), project: "stack".into() }]
        );
    }

    #[test]
    fn the_services_own_containers_and_free_names_are_fine() {
        let own = vec!["shairport-sync".to_string()];
        let wanted = vec!["shairport-db".to_string(), "nobody-has-this".to_string()];
        assert!(foreign_holders(&wanted, &listing(), &own).is_empty());
    }

    #[test]
    fn only_a_container_outside_every_compose_project_may_be_removed() {
        let held = listing();
        assert_eq!(removable("shairport-sync", &held), Ok("shairport-sync"));
        assert_eq!(removable("other", &held), Err(RemoveRefusal::InComposeProject("stack".into())));
        assert_eq!(removable("missing", &held), Err(RemoveRefusal::NotFound));
        assert_eq!(removable("shairport-sync; rm -rf /", &held), Err(RemoveRefusal::NotFound));
    }
}
