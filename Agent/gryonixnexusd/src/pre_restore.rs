//! Lists and deletes the `.pre-restore-*` data copies that restores leave beside a service's data.

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hyper::StatusCode;
use serde::Deserialize;
use tokio::process::Command;

use crate::api::{connect_error, Codec, Resp};
use crate::{discover, pb};

const MARKER: &str = ".pre-restore-";
const SIZE_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    service_id: String,
    path: PathBuf,
}

struct Roots {
    service_id: String,
    directory: PathBuf,
    bind_sources: Vec<PathBuf>,
}

#[derive(Deserialize)]
struct MountRow {
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Source", default)]
    source: String,
}

pub async fn list(codec: Codec, req: pb::ListPreRestoreCopiesRequest) -> Resp {
    match scan(&req.service_id).await {
        Ok(found) => encode(codec, &describe(found).await),
        Err(err) => connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()),
    }
}

pub async fn delete(codec: Codec, req: pb::DeletePreRestoreCopyRequest) -> Resp {
    let path = PathBuf::from(&req.path);
    if !acceptable_path(&path) {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", "that is not an old copy's path");
    }
    let found = match scan("").await {
        Ok(found) => found,
        Err(err) => return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()),
    };
    let Some(target) = found.iter().find(|candidate| candidate.path == path) else {
        return connect_error(StatusCode::NOT_FOUND, "not_found", "this server has no such old copy");
    };
    let service_id = target.service_id.clone();
    let _claim = match crate::jobs::OperationClaim::acquire("service", &service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let removing = path.clone();
    match tokio::task::spawn_blocking(move || remove_copy(&removing)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()),
        Err(err) => return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()),
    }
    match scan(&service_id).await {
        Ok(left) => encode(codec, &describe(left).await),
        Err(err) => connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()),
    }
}

/// Removes a real folder; refuses a symlink or a file
fn remove_copy(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a plain folder"));
    }
    std::fs::remove_dir_all(path)
}

fn encode(codec: Codec, list: &pb::PreRestoreCopyList) -> Resp {
    codec.encode(list).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

async fn scan(service_filter: &str) -> Result<Vec<Found>> {
    let mut roots = Vec::new();
    for project in discover::installed_projects().await? {
        if !service_filter.is_empty() && project.service_id != service_filter {
            continue;
        }
        let bind_sources = bind_sources(&project.project).await.unwrap_or_default();
        roots.push(Roots {
            service_id: project.service_id.to_string(),
            directory: project.directory,
            bind_sources,
        });
    }
    Ok(collect(&roots))
}

async fn bind_sources(project: &str) -> Result<Vec<PathBuf>> {
    let ids = Command::new("docker")
        .args(["ps", "-aq", "--filter", &format!("label=com.docker.compose.project={project}")])
        .output()
        .await
        .context("run `docker ps`")?;
    let ids: Vec<String> = String::from_utf8_lossy(&ids.stdout).split_whitespace().map(str::to_string).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let inspected = Command::new("docker")
        .args(["inspect", "--format", "{{json .Mounts}}"])
        .args(&ids)
        .output()
        .await
        .context("run `docker inspect`")?;
    Ok(parse_bind_sources(&String::from_utf8_lossy(&inspected.stdout)))
}

fn parse_bind_sources(output: &str) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    for line in output.lines() {
        let Ok(rows) = serde_json::from_str::<Vec<MountRow>>(line.trim()) else { continue };
        for row in rows {
            if row.kind == "bind" && row.source.starts_with('/') {
                let path = PathBuf::from(row.source);
                if !sources.contains(&path) {
                    sources.push(path);
                }
            }
        }
    }
    sources
}

/// Old copies beside each service's directory, data and mounts
fn collect(roots: &[Roots]) -> Vec<Found> {
    let mut found: Vec<Found> = Vec::new();
    for root in roots {
        let mut paths = copies_in(&root.directory, None);
        if let (Some(parent), Some(name)) = (root.directory.parent(), root.directory.file_name()) {
            paths.extend(copies_in(parent, Some(&name.to_string_lossy())));
        }
        for source in &root.bind_sources {
            if let (Some(parent), Some(name)) = (source.parent(), source.file_name()) {
                paths.extend(copies_in(parent, Some(&name.to_string_lossy())));
            }
        }
        for path in paths {
            if !found.iter().any(|known| known.path == path) {
                found.push(Found { service_id: root.service_id.clone(), path });
            }
        }
    }
    found.sort_by(|a, b| (&a.service_id, &a.path).cmp(&(&b.service_id, &b.path)));
    found
}

/// Old-copy folders in a directory, optionally of one data folder
fn copies_in(dir: &Path, data_name: Option<&str>) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_copy_name(&name) {
            continue;
        }
        if let Some(wanted) = data_name {
            if !name.starts_with(&format!("{wanted}{MARKER}")) {
                continue;
            }
        }
        match std::fs::symlink_metadata(entry.path()) {
            Ok(meta) if meta.is_dir() => paths.push(entry.path()),
            _ => {}
        }
    }
    paths
}

fn is_copy_name(name: &str) -> bool {
    let Some(at) = name.find(MARKER) else { return false };
    let stamp = &name[at + MARKER.len()..];
    at > 0 && !stamp.is_empty() && stamp.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn acceptable_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|part| !matches!(part, Component::ParentDir | Component::CurDir))
        && path.file_name().map(|name| is_copy_name(&name.to_string_lossy())).unwrap_or(false)
}

async fn describe(found: Vec<Found>) -> pb::PreRestoreCopyList {
    let copies = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + SIZE_BUDGET;
        found.into_iter().map(|item| describe_one(item, deadline)).collect()
    })
    .await
    .unwrap_or_default();
    pb::PreRestoreCopyList { copies }
}

fn describe_one(item: Found, deadline: Instant) -> pb::PreRestoreCopy {
    let size = directory_size(&item.path, deadline);
    let moved = std::fs::symlink_metadata(&item.path).map(|meta| meta.ctime()).unwrap_or(0);
    pb::PreRestoreCopy {
        service_id: item.service_id,
        path: item.path.to_string_lossy().to_string(),
        size_bytes: size.unwrap_or(0),
        size_known: size.is_some(),
        moved_aside_unix: moved,
    }
}

/// Total file bytes, or None when the time ran out
fn directory_size(root: &Path, deadline: Instant) -> Option<u64> {
    let mut total = 0u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        if Instant::now() > deadline {
            return None;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else { continue };
            if meta.is_dir() {
                pending.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gnx-prerestore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn roots(service: &str, directory: &Path, sources: &[&Path]) -> Roots {
        Roots {
            service_id: service.to_string(),
            directory: directory.to_path_buf(),
            bind_sources: sources.iter().map(|path| path.to_path_buf()).collect(),
        }
    }

    #[test]
    fn only_a_data_folder_with_a_stamp_is_an_old_copy() {
        assert!(is_copy_name("data.pre-restore-20261005-143012"));
        assert!(is_copy_name("library.pre-restore-1"));
        assert!(!is_copy_name("data"));
        assert!(!is_copy_name(".pre-restore-20261005"));
        assert!(!is_copy_name("data.pre-restore-"));
        assert!(!is_copy_name("data.pre-restore-a b"));
        assert!(!is_copy_name("data.before-cache"));
    }

    #[test]
    fn a_delete_path_must_be_absolute_plain_and_named_like_a_copy() {
        assert!(acceptable_path(Path::new("/opt/nextcloud/data.pre-restore-20261005-143012")));
        assert!(!acceptable_path(Path::new("opt/nextcloud/data.pre-restore-1")));
        assert!(!acceptable_path(Path::new("/opt/nextcloud/../data.pre-restore-1")));
        assert!(!acceptable_path(Path::new("/opt/nextcloud/data")));
        assert!(!acceptable_path(Path::new("/opt/nextcloud/data.pre-restore-1/..")));
        assert!(!acceptable_path(Path::new("/")));
    }

    #[test]
    fn copies_beside_the_directory_its_data_folders_and_its_mounts_are_found() {
        let base = scratch("collect");
        let compose = base.join("nextcloud");
        let vault_data = base.join("vault").join("data");
        std::fs::create_dir_all(compose.join("data.pre-restore-20261005-101010")).unwrap();
        std::fs::create_dir_all(base.join("nextcloud.pre-restore-20261005-111111")).unwrap();
        std::fs::create_dir_all(base.join("vault").join("data.pre-restore-20261005-121212")).unwrap();
        std::fs::create_dir_all(base.join("vault").join("other.pre-restore-20261005-131313")).unwrap();
        std::fs::create_dir_all(compose.join("data")).unwrap();
        std::fs::write(compose.join("data.pre-restore-file"), b"not a folder").unwrap();

        let found = collect(&[
            roots("nextcloud", &compose, &[]),
            roots("vaultwarden", &base.join("elsewhere"), &[&vault_data]),
        ]);

        let names: Vec<(String, String)> = found
            .iter()
            .map(|item| {
                (
                    item.service_id.clone(),
                    item.path.strip_prefix(&base).unwrap().to_string_lossy().to_string(),
                )
            })
            .collect();
        assert_eq!(
            names,
            vec![
                ("nextcloud".to_string(), "nextcloud/data.pre-restore-20261005-101010".to_string()),
                ("nextcloud".to_string(), "nextcloud.pre-restore-20261005-111111".to_string()),
                ("vaultwarden".to_string(), "vault/data.pre-restore-20261005-121212".to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_symlink_named_like_a_copy_is_not_a_copy() {
        let base = scratch("symlink");
        let target = base.join("precious");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, base.join("data.pre-restore-1")).unwrap();
        assert!(copies_in(&base, None).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn removing_a_copy_deletes_the_folder_with_everything_in_it() {
        let base = scratch("remove");
        let copy = base.join("data.pre-restore-1");
        std::fs::create_dir_all(copy.join("nested")).unwrap();
        std::fs::write(copy.join("nested/file"), b"x").unwrap();
        std::fs::create_dir_all(base.join("data")).unwrap();
        remove_copy(&copy).unwrap();
        assert!(!copy.exists());
        assert!(base.join("data").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn removing_through_a_symlink_leaves_its_target_alone() {
        let base = scratch("remove-link");
        let target = base.join("precious");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("file"), b"keep").unwrap();
        let link = base.join("data.pre-restore-1");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(remove_copy(&link).is_err());
        assert!(target.join("file").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn removing_a_plain_file_or_a_missing_path_fails() {
        let base = scratch("remove-file");
        let file = base.join("data.pre-restore-1");
        std::fs::write(&file, b"x").unwrap();
        assert!(remove_copy(&file).is_err());
        assert!(file.exists());
        assert!(remove_copy(&base.join("gone.pre-restore-1")).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_size_counts_every_file_below() {
        let base = scratch("size");
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        std::fs::write(base.join("one"), vec![0u8; 100]).unwrap();
        std::fs::write(base.join("a/two"), vec![0u8; 20]).unwrap();
        std::fs::write(base.join("a/b/three"), vec![0u8; 3]).unwrap();
        assert_eq!(directory_size(&base, Instant::now() + Duration::from_secs(5)), Some(123));
        assert_eq!(directory_size(&base, Instant::now() - Duration::from_secs(1)), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn bind_mounts_come_out_of_inspect_output_once_each() {
        let output = concat!(
            r#"[{"Type":"bind","Source":"/srv/vault/data","Destination":"/data"},"#,
            r#"{"Type":"volume","Source":"/var/lib/docker/volumes/x/_data","Destination":"/x"}]"#,
            "\n",
            r#"[{"Type":"bind","Source":"/srv/vault/data","Destination":"/data"}]"#,
            "\nnot json\n"
        );
        assert_eq!(parse_bind_sources(output), vec![PathBuf::from("/srv/vault/data")]);
    }

    #[test]
    fn a_description_carries_size_and_time() {
        let base = scratch("describe");
        let copy = base.join("data.pre-restore-20261005-101010");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("file"), vec![0u8; 42]).unwrap();
        let item = describe_one(
            Found { service_id: "nextcloud".to_string(), path: copy.clone() },
            Instant::now() + Duration::from_secs(5),
        );
        assert_eq!(item.service_id, "nextcloud");
        assert_eq!(item.path, copy.to_string_lossy());
        assert_eq!(item.size_bytes, 42);
        assert!(item.size_known);
        assert!(item.moved_aside_unix > 1_000_000_000);
        let _ = std::fs::remove_dir_all(&base);
    }
}
