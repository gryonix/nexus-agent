//! Updating a group the configurator never installed

use std::collections::BTreeMap;

use bytes::Bytes;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::container_ops::{capture, first_lines, run_streaming};
use crate::containers::{self, GroupKind};
use crate::pb;
use hyper::StatusCode;

const PULL_TIMEOUT_SECS: u64 = 60 * 60;
const RECREATE_TIMEOUT_SECS: u64 = 900;
const HEALTH_DEADLINE_SECS: u64 = 180;
const HEALTH_POLL_SECS: u64 = 5;
const HEALTH_SETTLE_SAMPLES: usize = 3;

fn plan_names_nothing(plan: &pb::ContainerBackupPlan) -> bool {
    plan.paths.is_empty() && plan.volumes.is_empty() && plan.databases.is_empty()
}

pub async fn run(
    codec: Codec,
    req: pb::UpdateContainerGroupRequest,
    names: Vec<(String, String)>,
    stored: Option<pb::ContainerBackupPlan>,
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
    let plan = crate::container_backup::effective(&key, &details, stored);

    if let Some(refusal) = refuse(&req, &plan, kind) {
        return refusal;
    }

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let job = UpdateJob { claim, codec, tx, key, kind, skip_backup: req.skip_backup, plan, details, compose_file, names };
    tokio::spawn(job.run());

    stream_response(json, rx)
}

/// Everything the background update needs
struct UpdateJob {
    claim: crate::jobs::OperationClaim,
    codec: Codec,
    tx: Sender<Bytes>,
    key: String,
    kind: GroupKind,
    skip_backup: bool,
    plan: pb::ContainerBackupPlan,
    details: Vec<pb::ContainerDetail>,
    compose_file: Option<String>,
    names: Vec<(String, String)>,
}

/// The refusals that come before the stream opens
fn refuse(req: &pb::UpdateContainerGroupRequest, plan: &pb::ContainerBackupPlan, kind: GroupKind) -> Option<Resp> {
    // Refused BEFORE the stream opens, like every other precondition here.
    if req.skip_backup && !plan.databases.is_empty() {
        return Some(connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "this group has a database that would be dumped, so its update cannot skip the backup: \
             a new image that migrates a schema is exactly the case a backup is kept for, and this \
             stack has no install recipe to rebuild it from",
        ));
    }
    if !req.skip_backup && plan_names_nothing(&plan) {
        return Some(connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "nothing_to_archive: this group stores nothing outside its images — no volume, no bind mount and no database — so a backup before the update would archive nothing. Update it without one, or give it a backup plan first",
        ));
    }
    if kind == GroupKind::Standalone {
        return Some(connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "failed_precondition",
            "this is a single container started outside compose, so the agent cannot recreate it \
             from anything: pulling a newer image would change nothing that is running. Recreate it \
             with whatever started it",
        ));
    }
    None
}

impl UpdateJob {
    async fn run(self) {
        let _claim = self.claim;
        let key = self.key;
        let sink = UpdateSink {
            tx: self.tx,
            codec: self.codec,
            key: key.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerUpdate, &key),
        };

        let previous = image_ids(&self.details).await;
        let _ = sink.started(previous.clone()).await;

        let compose_file = self.compose_file.as_deref();
        let outcome =
            execute(&key, self.kind, &previous, self.skip_backup, &self.plan, &self.details, compose_file, &sink).await;

        let (rolled_back, already_current, failure) = match outcome {
            Ok(Outcome::Updated) => (false, false, None),
            Ok(Outcome::AlreadyCurrent) => (false, true, None),
            Ok(Outcome::RolledBack(why)) => (true, false, Some(why)),
            Err(err) => (false, false, Some(err)),
        };

        let mut problems: Vec<String> = failure.into_iter().collect();
        match containers::inventory(&self.names).await {
            Ok(fresh) => {
                let group = containers::resolve(&fresh, &key).cloned();
                let _ = sink.completed(rolled_back, already_current, group).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    }
}

/// `docker compose -p <key> [-f <file>] <verb…>`
fn compose_args(key: &str, compose_file: Option<&str>, verb: &[&str]) -> Vec<String> {
    let mut args = vec!["compose".to_string(), "-p".to_string(), key.to_string()];
    if let Some(file) = compose_file {
        args.push("-f".to_string());
        args.push(file.to_string());
    }
    args.extend(verb.iter().map(|v| v.to_string()));
    args
}

enum Outcome {
    Updated,
    AlreadyCurrent,
    RolledBack(String),
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    key: &str,
    kind: GroupKind,
    previous: &BTreeMap<String, String>,
    skip_backup: bool,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    compose_file: Option<&str>,
    sink: &UpdateSink,
) -> Result<Outcome, String> {
    if skip_backup {
        let _ = sink.progress("agent", "skipping the backup, as asked".to_string()).await;
    } else {
        let _ = sink.progress("agent", "backing up before the pull".to_string()).await;
        back_up_first(key, kind, plan, details, sink).await?;
    }

    let _ = sink.progress("agent", "pulling newer images".to_string()).await;
    let pull = compose_args(key, compose_file, &["pull"]);
    run_streaming("docker", &pull, PULL_TIMEOUT_SECS, &sink.tx, &sink.encoder())
        .await
        .map_err(|err| format!("pulling failed: {err}"))?;

    let after = pulled_ids(previous.keys()).await;
    if !previous.is_empty() && after == *previous {
        let _ = sink.progress("agent", "every image is already the newest published".to_string()).await;
        return Ok(Outcome::AlreadyCurrent);
    }

    let _ = sink.progress("agent", "recreating the containers".to_string()).await;
    let up = compose_args(key, compose_file, &["up", "-d"]);
    if let Err(err) = run_streaming("docker", &up, RECREATE_TIMEOUT_SECS, &sink.tx, &sink.encoder()).await {
        let why = format!("recreating failed: {err}");
        return rollback(key, kind, previous, compose_file, &why, sink).await;
    }

    let _ = sink.progress("agent", "waiting for the group to come back".to_string()).await;
    if let Err(err) = wait_healthy(key, sink).await {
        return rollback(key, kind, previous, compose_file, &err, sink).await;
    }

    Ok(Outcome::Updated)
}

async fn back_up_first(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    sink: &UpdateSink,
) -> Result<(), String> {
    match crate::container_backup_run::run_for_update(key, kind, plan, details, &sink.tx, &sink.encoder()).await {
        Ok(archive) => {
            let _ = sink.progress("agent", format!("backed up to {}", archive.path)).await;
            Ok(())
        }
        Err(err) => Err(format!("the backup before this update failed, so nothing was pulled: {err}")),
    }
}

async fn rollback(
    key: &str,
    _kind: GroupKind,
    previous: &BTreeMap<String, String>,
    compose_file: Option<&str>,
    why: &str,
    sink: &UpdateSink,
) -> Result<Outcome, String> {
    let _ = sink.progress("agent", format!("rolling back: {why}")).await;
    if previous.is_empty() {
        return Err(format!("{why}; and there was no previous image id to roll back to"));
    }
    for (reference, id) in previous {
        let args = vec!["tag".to_string(), id.clone(), reference.clone()];
        if let Err(err) = run_streaming("docker", &args, 120, &sink.tx, &sink.encoder()).await {
            let _ = sink.progress("agent", format!("WARNING: could not restore {reference}: {err}")).await;
        }
    }
    let up = compose_args(key, compose_file, &["up", "-d"]);
    match run_streaming("docker", &up, RECREATE_TIMEOUT_SECS, &sink.tx, &sink.encoder()).await {
        Ok(()) => Ok(Outcome::RolledBack(why.to_string())),
        Err(err) => Err(format!("{why}; and the rollback did not come up either: {err}")),
    }
}

/// image reference → image id, for the containers running right now.
async fn image_ids(details: &[pb::ContainerDetail]) -> BTreeMap<String, String> {
    let mut refs: Vec<String> = Vec::new();
    for detail in details {
        if let Some(container) = detail.container.as_ref() {
            if !container.image.is_empty() && !refs.contains(&container.image) {
                refs.push(container.image.clone());
            }
        }
    }
    pulled_ids(refs.iter()).await
}

async fn pulled_ids<'a>(refs: impl Iterator<Item = &'a String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for reference in refs {
        let args = vec![
            "image".to_string(),
            "inspect".to_string(),
            reference.clone(),
            "--format".to_string(),
            "{{.Id}}".to_string(),
        ];
        if let Ok(res) = capture("docker", &args, 60).await {
            if res.success {
                let id = res.stdout.trim().to_string();
                if !id.is_empty() {
                    out.insert(reference.clone(), id);
                }
            }
        }
    }
    out
}

async fn wait_healthy(key: &str, sink: &UpdateSink) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(HEALTH_DEADLINE_SECS);
    let mut last;
    let mut clean = 0usize;
    let mut counts_at_first_clean: BTreeMap<String, u64> = BTreeMap::new();
    loop {
        let args = vec![
            "compose".to_string(),
            "-p".to_string(),
            key.to_string(),
            "ps".to_string(),
            "--format".to_string(),
            "{{.Name}} {{.State}}".to_string(),
        ];
        let res = capture("docker", &args, 60).await?;
        if res.success {
            match verdict(&res.stdout) {
                Look::Restarting(who) => {
                    return Err(format!("{who} is restarting in a loop after the update"))
                }
                Look::Running(names) => {
                    let counts = restart_counts(&names).await;
                    if clean == 0 {
                        counts_at_first_clean = counts;
                        clean = 1;
                    } else if counts != counts_at_first_clean {
                        let moved: Vec<&str> = counts
                            .iter()
                            .filter(|(name, count)| {
                                counts_at_first_clean.get(*name) != Some(*count)
                            })
                            .map(|(name, _)| name.as_str())
                            .collect();
                        return Err(format!(
                            "{} restarted while the update was watching it",
                            moved.join(", ")
                        ));
                    } else {
                        clean += 1;
                    }
                    if clean >= HEALTH_SETTLE_SAMPLES {
                        return Ok(());
                    }
                    last = String::new();
                }
                Look::Down(who) => {
                    clean = 0;
                    last = who;
                }
            }
        } else {
            clean = 0;
            last = first_lines(res.stderr.trim(), 1);
        }
        if std::time::Instant::now() >= deadline {
            let detail = if last.is_empty() { "the group did not report itself running".to_string() } else { last };
            return Err(format!("after {HEALTH_DEADLINE_SECS}s: {detail}"));
        }
        let _ = sink.progress("agent", "still waiting for the group".to_string()).await;
        tokio::time::sleep(std::time::Duration::from_secs(HEALTH_POLL_SECS)).await;
    }
}

/// What one look at `docker compose ps` says.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Look {
    /// Every container is running; carries their names, for the counters.
    Running(Vec<String>),
    Restarting(String),
    Down(String),
}

pub(crate) fn verdict(stdout: &str) -> Look {
    let mut running: Vec<String> = Vec::new();
    let mut restarting: Vec<&str> = Vec::new();
    let mut down: Vec<&str> = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(state)) = (parts.next(), parts.next()) else { continue };
        match state {
            "running" => running.push(name.to_string()),
            "restarting" => restarting.push(name),
            _ => down.push(name),
        }
    }
    if !restarting.is_empty() {
        return Look::Restarting(restarting.join(", "));
    }
    if !down.is_empty() {
        return Look::Down(down.join(", "));
    }
    if running.is_empty() {
        return Look::Down("the group reported no containers at all".to_string());
    }
    Look::Running(running)
}

pub(crate) async fn restart_counts(names: &[String]) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    if names.is_empty() {
        return out;
    }
    let mut args = vec!["inspect".to_string(), "--format".to_string(),
                        "{{.Name}} {{.RestartCount}}".to_string()];
    args.extend(names.iter().cloned());
    if let Ok(res) = capture("docker", &args, 60).await {
        if res.success {
            out = parse_restart_counts(&res.stdout);
        }
    }
    out
}

fn parse_restart_counts(stdout: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(count)) = (parts.next(), parts.next()) else { continue };
        if let Ok(count) = count.parse::<u64>() {
            out.insert(name.trim_start_matches('/').to_string(), count);
        }
    }
    out
}

struct UpdateSink {
    tx: Sender<Bytes>,
    codec: Codec,
    key: String,
    journal: Option<crate::jobs::Journal>,
}

impl UpdateSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerUpdateEvent {
        pb::ContainerUpdateEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            text: String::new(),
            stream: String::new(),
            previous_images: std::collections::HashMap::new(),
            rolled_back: false,
            already_current: false,
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

    async fn send(&self, event: pb::ContainerUpdateEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, previous: BTreeMap<String, String>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.previous_images = previous.into_iter().collect();
        self.send(event).await
    }

    async fn progress(&self, stream: &'static str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(
        &self,
        rolled_back: bool,
        already_current: bool,
        group: Option<pb::ContainerGroup>,
    ) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.rolled_back = rolled_back;
        event.already_current = already_current;
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

    fn plan(paths: &[&str], volumes: &[&str], databases: usize) -> pb::ContainerBackupPlan {
        pb::ContainerBackupPlan {
            key: "shopdemo".to_string(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            volumes: volumes.iter().map(|v| v.to_string()).collect(),
            databases: (0..databases)
                .map(|i| pb::ContainerDatabaseDump {
                    container: format!("db-{i}"),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_plan_naming_no_path_no_volume_and_no_database_names_nothing() {
        assert!(plan_names_nothing(&plan(&[], &[], 0)));
    }

    #[test]
    fn any_one_of_the_three_makes_it_a_plan() {
        assert!(!plan_names_nothing(&plan(&["/srv/data"], &[], 0)), "a bind mount was ignored");
        assert!(!plan_names_nothing(&plan(&[], &["shopdemo_db"], 0)), "a volume was ignored");
        assert!(!plan_names_nothing(&plan(&[], &[], 1)), "a database was ignored");
    }

    #[test]
    fn a_plan_whose_sources_have_vanished_is_still_a_plan() {
        assert!(!plan_names_nothing(&plan(&["/srv/gone"], &["renamed_away"], 0)));
    }

    #[test]
    fn a_compose_verb_that_needs_the_file_is_given_the_one_the_host_named() {
        let with = compose_args("shopdemo", Some("/opt/shopdemo/docker-compose.yml"), &["pull"]);
        assert_eq!(
            with,
            vec!["compose", "-p", "shopdemo", "-f", "/opt/shopdemo/docker-compose.yml", "pull"]
        );

        let up = compose_args("shopdemo", Some("/opt/shopdemo/docker-compose.yml"), &["up", "-d"]);
        assert_eq!(up.last().map(String::as_str), Some("-d"));
        assert_eq!(up[up.len() - 2], "up");

        let without = compose_args("shopdemo", None, &["pull"]);
        assert_eq!(without, vec!["compose", "-p", "shopdemo", "pull"]);
        assert!(!without.iter().any(|a| a == "-f"));
    }

    #[test]
    fn one_look_at_a_crash_loop_can_say_running() {
        assert_eq!(
            verdict("probe-roll-app-1 running\n"),
            Look::Running(vec!["probe-roll-app-1".to_string()])
        );
        assert_eq!(
            verdict("probe-roll-app-1 restarting\n"),
            Look::Restarting("probe-roll-app-1".to_string())
        );
        assert_eq!(
            verdict("a running\nb restarting\n"),
            Look::Restarting("b".to_string())
        );
        assert_eq!(verdict("a running\nb exited\n"), Look::Down("b".to_string()));
        match verdict("") {
            Look::Down(_) => {}
            other => panic!("empty output read as {other:?}"),
        }
    }

    #[test]
    fn restart_counters_are_read_by_the_name_the_group_uses() {
        let first = parse_restart_counts("/probe-roll-app-1 4\n");
        assert_eq!(first.get("probe-roll-app-1"), Some(&4));
        assert_eq!(first, parse_restart_counts("/probe-roll-app-1 4\n"));
        // A crash loop does not.
        assert_ne!(first, parse_restart_counts("/probe-roll-app-1 5\n"));
        assert!(parse_restart_counts("/probe-roll-app-1 not-a-number\n").is_empty());
    }
}
