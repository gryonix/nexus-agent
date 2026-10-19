//! Removing a group the configurator never installed

use std::path::Path;

use bytes::Bytes;
use tokio::sync::mpsc::Sender;

use crate::api::{envelope, error_trailer, stream_response, Codec, Resp};
use crate::container_ops::run_streaming;
use crate::containers::{self, GroupKind, Refusal};
use crate::pb;

const REMOVE_TIMEOUT_SECS: u64 = 900;

/// Directories that are never deleted, whatever a mount claims
const NEVER_DELETED: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt", "/proc", "/root",
    "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
];

pub(crate) const PROTECTED_TREES: &[&str] = &[
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin", "/sys", "/usr",
    "/var/lib/docker", "/var/lib/gryonixnexus", "/var/lib/containerd", "/var/log", "/opt/backups",
    "/opt/gryonixnexus",
];

/// Work out what removal would delete, without deleting anything.
pub async fn preview(
    codec: Codec,
    req: pb::PreviewContainerGroupRemovalRequest,
    names: &[(String, String)],
) -> Resp {
    match containers::details_of_group(&req.key, names).await {
        Err(refusal) => refusal.response(),
        Ok((group, details)) => {
            let plan = build_preview(&group, &details, req.purge_data, req.purge_backups);
            match codec.encode(&plan) {
                Ok(resp) => resp,
                Err(_) => Refusal::EngineUnavailable("could not encode the preview".to_string()).response(),
            }
        }
    }
}

pub fn build_preview(
    group: &pb::ContainerGroup,
    details: &[pb::ContainerDetail],
    purge_data: bool,
    purge_backups: bool,
) -> pb::ContainerRemovalPreview {
    let mut out = pb::ContainerRemovalPreview {
        key: group.key.clone(),
        containers: group.containers.iter().map(|c| c.name.clone()).collect(),
        volumes: Vec::new(),
        paths: Vec::new(),
        backup_paths: Vec::new(),
        notes: Vec::new(),
    };

    if purge_data {
        for detail in details {
            for mount in &detail.mounts {
                if mount.source.is_empty() {
                    continue;
                }
                match mount.kind.as_str() {
                    "bind" => match deletable(&mount.source) {
                        Ok(()) => push_unique(&mut out.paths, &mount.source),
                        Err(why) => {
                            let note = format!("{} is left alone: {why}", mount.source);
                            push_unique(&mut out.notes, &note);
                        }
                    },
                    "volume" => push_unique(&mut out.volumes, &crate::container_backup::volume_id(mount)),
                    _ => {}
                }
            }
        }
        if out.paths.is_empty() && out.volumes.is_empty() {
            out.notes.push("this group has no data of its own that the host can name".to_string());
        }
    }

    if purge_backups {
        let dir = crate::container_backup_run::backup_root().join(&group.key);
        if dir.exists() {
            out.backup_paths.push(dir.display().to_string());
        } else {
            out.notes.push("this group has no backups taken by this app".to_string());
        }
    }

    out
}

/// May this host path be deleted?
fn deletable(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("it is not an absolute path".to_string());
    }
    if path.contains("..") {
        return Err("it contains ..".to_string());
    }
    let trimmed = path.trim_end_matches('/');
    let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
    if NEVER_DELETED.iter().any(|deny| *deny == trimmed) {
        return Err("it is a system directory".to_string());
    }
    let depth = trimmed.split('/').filter(|part| !part.is_empty()).count();
    if depth < 2 {
        return Err("it sits at the top of the filesystem".to_string());
    }
    let inside = |tree: &&str| trimmed == *tree || trimmed.starts_with(&format!("{tree}/"));
    if PROTECTED_TREES.iter().any(inside) {
        return Err("it is part of the system or of this app".to_string());
    }
    if PROTECTED_TREES.iter().any(|tree| tree.starts_with(&format!("{trimmed}/"))) {
        return Err("it contains system directories".to_string());
    }
    let top = trimmed.split('/').nth(1).unwrap_or_default();
    if depth == 2 && matches!(top, "home" | "mnt" | "media" | "srv") {
        return Err("it is a home directory or a mount point".to_string());
    }
    if trimmed == "/var/lib" || trimmed == "/var/cache" || trimmed == "/var/spool" {
        return Err("it is a system directory".to_string());
    }
    Ok(())
}

fn push_unique(into: &mut Vec<String>, value: &str) {
    if !into.iter().any(|existing| existing == value) {
        into.push(value.to_string());
    }
}

/// Remove one group, streaming progress.
pub async fn remove(
    codec: Codec,
    req: pb::RemoveContainerGroupRequest,
    names: Vec<(String, String)>,
    after_gone: impl FnOnce() + Send + 'static,
) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("container", &req.key) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let (group, details) = match containers::details_of_group(&req.key, &names).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };

    let key = group.key.clone();
    let kind = containers::kind_of_group(&group);
    let compose_file = group.config_files.first().cloned();
    let plan = build_preview(&group, &details, req.purge_data, req.purge_backups);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = RemovalSink {
            tx,
            codec,
            key: key.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerRemoval, &key),
        };
        let _ = sink.started(plan.clone()).await;

        let failure = execute(&key, kind, &plan, compose_file.as_deref(), &sink).await.err();

        let mut problems: Vec<String> = failure.into_iter().collect();
        match containers::inventory(&names).await {
            Ok(fresh) => {
                let remaining = containers::resolve(&fresh, &key).cloned();
                if remaining.is_none() {
                    after_gone();
                }
                let _ = sink.completed(remaining).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    });

    stream_response(json, rx)
}

async fn execute(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerRemovalPreview,
    compose_file: Option<&str>,
    sink: &RemovalSink,
) -> Result<(), String> {
    let args: Vec<String> = match kind {
        GroupKind::ComposeProject => {
            let mut args = vec!["compose".to_string(), "-p".to_string(), key.to_string()];
            if let Some(file) = compose_file {
                args.push("-f".to_string());
                args.push(file.to_string());
            }
            args.push("down".to_string());
            args.push("--remove-orphans".to_string());
            args
        }
        GroupKind::Standalone => vec!["rm".into(), "-f".into(), key.to_string()],
    };
    let _ = sink.progress("agent", format!("removing the containers of {key}")).await;
    run_streaming("docker", &args, REMOVE_TIMEOUT_SECS, &sink.tx, &sink.encoder())
        .await
        .map_err(|err| format!("could not remove the containers: {err}"))?;

    for volume in &plan.volumes {
        let _ = sink.progress("agent", format!("removing volume {volume}")).await;
        let args = vec!["volume".into(), "rm".into(), volume.clone()];
        if let Err(err) = run_streaming("docker", &args, 120, &sink.tx, &sink.encoder()).await {
            let _ = sink.progress("agent", format!("WARNING: volume {volume} was left in place: {err}")).await;
        }
    }

    for path in plan.paths.iter().chain(plan.backup_paths.iter()) {
        if let Err(why) = deletable(path) {
            let _ = sink.progress("agent", format!("WARNING: {path} was left alone: {why}")).await;
            continue;
        }
        let _ = sink.progress("agent", format!("deleting {path}")).await;
        if let Err(err) = std::fs::remove_dir_all(path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                let _ = sink.progress("agent", format!("WARNING: could not delete {path}: {err}")).await;
            }
        }
    }

    Ok(())
}

struct RemovalSink {
    tx: Sender<Bytes>,
    codec: Codec,
    key: String,
    journal: Option<crate::jobs::Journal>,
}

impl RemovalSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerRemovalEvent {
        pb::ContainerRemovalEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            text: String::new(),
            stream: String::new(),
            removing: None,
            group: None,
        }
    }

    fn encoder(&self) -> impl Fn(&'static str, String) -> Bytes + Sync + '_ {
        move |stream: &'static str, text: String| {
            let mut event = self.event(pb::ServiceOperationPhase::Progress);
            event.stream = stream.to_string();
            event.text = text;
            envelope(0x00, &self.codec.encode_payload(&event))
        }
    }

    async fn send(&self, event: pb::ContainerRemovalEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, plan: pb::ContainerRemovalPreview) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.removing = Some(plan);
        self.send(event).await
    }

    async fn progress(&self, stream: &'static str, text: String) -> Result<(), ()> {
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

    async fn fail(&self, message: &str) -> Result<(), ()> {
        crate::jobs::finish(&self.journal, Some(message));
        self.tx.send(error_trailer("internal", message)).await.map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(kind: &str, source: &str, destination: &str) -> pb::ContainerMount {
        pb::ContainerMount {
            name: if kind == "volume" { source.to_string() } else { String::new() },
            source: if kind == "volume" {
                format!("/var/lib/docker/volumes/{source}/_data")
            } else {
                source.to_string()
            },
            destination: destination.to_string(),
            mode: "rw".to_string(),
            kind: kind.to_string(),
        }
    }

    fn detail(name: &str, mounts: Vec<pb::ContainerMount>) -> pb::ContainerDetail {
        pb::ContainerDetail {
            container: Some(pb::Container {
                name: name.to_string(),
                ..Default::default()
            }),
            created_at: String::new(),
            restart_policy: String::new(),
            compose_project: "stack".to_string(),
            compose_service: name.to_string(),
            command: String::new(),
            env: Vec::new(),
            mounts,
        }
    }

    fn group(key: &str, containers: &[&str]) -> pb::ContainerGroup {
        pb::ContainerGroup {
            key: key.to_string(),
            containers: containers
                .iter()
                .map(|n| pb::Container { name: n.to_string(), ..Default::default() })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_system_directory_is_never_deleted_and_the_refusal_is_named() {
        for path in ["/", "/etc", "/home", "/usr", "/var", "/opt", "/root"] {
            assert!(deletable(path).is_err(), "{path} must not be deletable");
        }
        assert!(deletable("/data").is_err(), "a top-level directory is not deletable");
        assert!(deletable("/opt/mystack/data").is_ok());
        assert!(deletable("/var/lib/mystack").is_ok());
        for path in ["/var/lib", "/var/lib/docker", "/var/lib/docker/volumes", "/var/log", "/home/admin", "/mnt/disk", "/opt/backups", "/opt/backups/containers", "/usr/share/x", "/mnt/disk/torrents/../x"] {
            assert!(deletable(path).is_err(), "{path} must not be deletable");
        }
        assert!(deletable("/mnt/disk/torrents").is_ok());
        assert!(deletable("/home/admin/stack").is_ok());
        // Traversal and relative paths are refused outright.
        assert!(deletable("/opt/stack/../../etc").is_err());
        assert!(deletable("relative/path").is_err());

        let details = vec![detail("app", vec![mount("bind", "/etc", "/host-etc")])];
        let preview = build_preview(&group("stack", &["app"]), &details, true, false);
        assert!(preview.paths.is_empty(), "no system path may be listed for deletion");
        assert!(
            preview.notes.iter().any(|n| n.contains("/etc") && n.contains("system directory")),
            "the refusal must be named: {:?}",
            preview.notes
        );
    }

    /// The toggles are independent, and BOTH default to keeping
    #[test]
    fn data_and_backups_are_separate_toggles_and_default_to_keeping() {
        let details = vec![detail(
            "app",
            vec![mount("bind", "/opt/mystack/data", "/data"), mount("volume", "mystack_db", "/var/lib/postgresql/data")],
        )];
        let g = group("mystack", &["app"]);

        // Neither toggle: the containers go, nothing else is even listed.
        let plain = build_preview(&g, &details, false, false);
        assert_eq!(plain.containers, vec!["app".to_string()]);
        assert!(plain.paths.is_empty() && plain.volumes.is_empty() && plain.backup_paths.is_empty());

        // Data only: paths and volumes, still no backups.
        let with_data = build_preview(&g, &details, true, false);
        assert_eq!(with_data.paths, vec!["/opt/mystack/data".to_string()]);
        assert_eq!(with_data.volumes, vec!["mystack_db".to_string()]);
        assert!(with_data.backup_paths.is_empty());
    }

    #[test]
    fn a_mount_that_is_neither_bind_nor_volume_is_left_alone() {
        let details = vec![detail("app", vec![mount("tmpfs", "/tmp/scratch", "/scratch")])];
        let preview = build_preview(&group("stack", &["app"]), &details, true, false);
        assert!(preview.paths.is_empty() && preview.volumes.is_empty());
    }
}
