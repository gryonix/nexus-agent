//! Executing a stranger's backup plan

use std::path::{Path, PathBuf};

use bytes::Bytes;
use tokio::sync::mpsc::Sender;

use hyper::StatusCode;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::container_ops::{capture, capture_to_file, first_lines, run_streaming};
use crate::containers::{self, GroupKind};
use crate::pb;

/// Where a stranger's archives live
const CONTAINER_BACKUP_ROOT: &str = "/opt/backups/containers";

const BACKUP_TIMEOUT_SECS: u64 = 60 * 60 * 6;
const DUMP_TIMEOUT_SECS: u64 = 60 * 60;
const STOP_TIMEOUT_SECS: u64 = 300;

pub fn backup_root() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT")
            .unwrap_or_else(|_| CONTAINER_BACKUP_ROOT.to_string()),
    )
}

/// What one group's backup directory holds, newest first
pub fn list(key: &str) -> Result<pb::ContainerBackupList, Resp> {
    let dir = backup_root().join(key);
    match crate::backup::read_directory(&dir) {
        Ok(archives) => Ok(pb::ContainerBackupList {
            key: key.to_string(),
            directory: dir.to_string_lossy().to_string(),
            archives,
        }),
        Err(err) => Err(connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            &format!("could not read {}: {err}", dir.display()),
        )),
    }
}

/// Run one group's plan, streaming progress
pub async fn run(
    codec: Codec,
    req: pb::RunContainerGroupBackupRequest,
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

    // From here the strings are the HOST's, never the caller's.
    let key = group.key.clone();
    let kind = containers::kind_of_group(&group);
    let container_names: Vec<String> = group.containers.iter().map(|c| c.name.clone()).collect();
    let plan = crate::container_backup::effective(&key, &details, stored);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let sink = BackupSink {
            tx,
            codec,
            key: key.clone(),
            journal: crate::jobs::Journal::open(pb::JobKind::ContainerBackup, &key),
        };
        let _ = sink.started(plan.clone()).await;

        let outcome = execute(&key, kind, &plan, &details, &container_names, &sink.tx, &sink.encoder()).await;
        let (archive, failure) = match outcome {
            Ok(archive) => (Some(archive), None),
            Err(err) => (None, Some(err)),
        };

        let mut problems: Vec<String> = failure.into_iter().collect();
        match containers::inventory(&names).await {
            Ok(fresh) => {
                let _ = sink.completed(archive, containers::resolve(&fresh, &key).cloned()).await;
            }
            Err(err) => problems.push(format!("status re-read: {err}")),
        }
        if !problems.is_empty() {
            let _ = sink.fail(&problems.join("; ")).await;
        }
    });

    stream_response(json, rx)
}

const KEEP_ARCHIVES: usize = 7;

/// Deletes the group's oldest archives beyond `keep`, returning their names.
fn rotate(dir: &Path, key: &str, keep: usize) -> Vec<String> {
    let prefix = format!("{key}-");
    let mut archives: Vec<(std::time::SystemTime, String)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(&prefix) || !name.ends_with(".tar.gz") {
                return None;
            }
            Some((entry.metadata().ok()?.modified().ok()?, name))
        })
        .collect();
    archives.sort_by(|a, b| b.cmp(a));
    archives
        .into_iter()
        .skip(keep)
        .filter(|(_, name)| std::fs::remove_file(dir.join(name)).is_ok())
        .map(|(_, name)| name)
        .collect()
}

/// The plan, in the one order it can safely run.
async fn execute(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    container_names: &[String],
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    let dir = backup_root().join(key);
    std::fs::create_dir_all(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    restrict(&dir);

    let stamp = timestamp();
    let staging = dir.join(format!(".incoming-{stamp}"));
    std::fs::create_dir_all(&staging)
        .map_err(|err| format!("could not create {}: {err}", staging.display()))?;
    restrict(&staging);

    let result =
        fill_and_pack(key, kind, plan, details, container_names, &dir, &staging, &stamp, tx, encode).await;
    let _ = std::fs::remove_dir_all(&staging);
    if result.is_ok() {
        for old in rotate(&dir, key, KEEP_ARCHIVES) {
            let _ = tx.send(encode("agent", format!("removed the oldest archive {old} (keeping {KEEP_ARCHIVES})"))).await;
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn fill_and_pack(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    container_names: &[String],
    dir: &Path,
    staging: &Path,
    stamp: &str,
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    for dump in &plan.databases {
        let engine = pb::ContainerDatabaseEngine::try_from(dump.engine)
            .unwrap_or(pb::ContainerDatabaseEngine::Unspecified);
        let file = staging.join(format!("{}.{}.dump", sanitise_component(&dump.container), suffix(engine)));
        let _ = tx.send(encode("agent", format!("dumping {} from {}", dump.database, dump.container))).await;
        let args = dump_args(dump, engine)?;
        let bytes = capture_to_file("docker", &args, &file, DUMP_TIMEOUT_SECS)
            .await
            .map_err(|err| format!("dumping {} failed: {err}", dump.container))?;
        if bytes == 0 {
            return Err(format!("dumping {} produced an empty file", dump.container));
        }
        let _ = tx.send(encode("agent", format!("dumped {bytes} bytes from {}", dump.container))).await;
    }

    let stopped = if plan.stop_while_archiving {
        let _ = tx.send(encode("agent", "stopping the group so the archive is consistent".to_string())).await;
        let args = containers::docker_args(key, kind, pb::ServiceAction::Stop);
        run_streaming("docker", &args, STOP_TIMEOUT_SECS, tx, encode)
            .await
            .map_err(|err| format!("could not stop the group: {err}"))?;
        true
    } else {
        false
    };

    let packed = pack(plan, details, staging, dir, key, stamp, tx, encode).await;

    if stopped {
        let _ = tx.send(encode("agent", "starting the group again".to_string())).await;
        let args = containers::docker_args(key, kind, pb::ServiceAction::Start);
        if let Err(err) = run_streaming("docker", &args, STOP_TIMEOUT_SECS, tx, encode).await {
            let _ = tx.send(encode("agent", format!("WARNING: could not start the group again: {err}"))).await;
            return match packed {
                Ok(_) => Err(format!("the archive was written but the group did not start again: {err}")),
                Err(first) => Err(format!("{first}; and the group did not start again: {err}")),
            };
        }
    }
    let _ = container_names;
    packed
}

/// tar the plan's paths, volumes and dumps into one archive
async fn backup_sources(
    plan: &pb::ContainerBackupPlan,
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Vec<String> {
    let mut sources: Vec<String> = Vec::new();
    for path in &plan.paths {
        if !Path::new(path).exists() {
            let _ = tx.send(encode("agent", format!("skipping {path}: it is not on this host"))).await;
            continue;
        }
        sources.push(path.clone());
    }
    for volume in &plan.volumes {
        match volume_mountpoint(volume).await {
            Ok(Some(path)) => sources.push(path),
            Ok(None) => {
                let _ = tx.send(encode("agent", format!("skipping volume {volume}: the engine reports no mountpoint"))).await;
            }
            Err(err) => {
                let _ = tx.send(encode("agent", format!("skipping volume {volume}: {err}"))).await;
            }
        }
    }
    sources
}

async fn pack(
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    staging: &Path,
    dir: &Path,
    key: &str,
    stamp: &str,
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    let excludes = dump_covered_dirs(plan, details);
    let sources = backup_sources(plan, tx, encode).await;
    let has_dumps = std::fs::read_dir(staging).map(|mut d| d.next().is_some()).unwrap_or(false);

    if sources.is_empty() && !has_dumps {
        return Err("this plan names nothing that exists on the host — nothing was archived".to_string());
    }

    let archive = dir.join(format!("{key}-{stamp}.tar.gz"));
    let mut args: Vec<String> = vec!["-czf".into(), archive.display().to_string()];
    for dir in &excludes {
        args.push(format!("--exclude={dir}"));
    }
    args.push("-P".into());
    args.extend(sources.iter().cloned());
    if has_dumps {
        args.push("-C".into());
        args.push(staging.display().to_string());
        args.push(".".into());
    }

    let _ = tx.send(encode("agent", format!("archiving into {}", archive.display()))).await;
    run_streaming("tar", &args, BACKUP_TIMEOUT_SECS, tx, encode)
        .await
        .map_err(|err| {
            let _ = std::fs::remove_file(&archive);
            format!("archiving failed: {err}")
        })?;
    restrict_file(&archive);

    let size = std::fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    Ok(pb::BackupArchive {
        name: archive.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        path: archive.display().to_string(),
        size_bytes: size as i64,
        modified_at: (stamp.parse::<i64>().unwrap_or(0)) * 1000,
        directory: false,
        drive: String::new(),
    })
}

fn dump_covered_dirs(plan: &pb::ContainerBackupPlan, details: &[pb::ContainerDetail]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for dump in &plan.databases {
        let Some(detail) = details
            .iter()
            .find(|d| d.container.as_ref().is_some_and(|c| c.name == dump.container))
        else {
            continue;
        };
        for mount in &detail.mounts {
            if crate::container_backup::is_database_dir(&mount.destination) && !mount.source.is_empty() {
                if !out.iter().any(|existing| existing == &mount.source) {
                    out.push(mount.source.clone());
                }
            }
        }
    }
    out
}

/// The dump command for one engine
fn dump_args(dump: &pb::ContainerDatabaseDump, engine: pb::ContainerDatabaseEngine) -> Result<Vec<String>, String> {
    let container = &dump.container;
    let db = &dump.database;
    let user = if dump.user.is_empty() { "root" } else { &dump.user };
    let pw = &dump.password_env;
    let script = match engine {
        pb::ContainerDatabaseEngine::Postgres => {
            if pw.is_empty() {
                format!("pg_dump -U {} {}", shq(user), shq(db))
            } else {
                format!("PGPASSWORD=\"${pw}\" pg_dump -U {} {}", shq(user), shq(db))
            }
        }
        pb::ContainerDatabaseEngine::Mysql | pb::ContainerDatabaseEngine::Mariadb => {
            let auth = if pw.is_empty() { String::new() } else { format!(" -p\"${pw}\"") };
            format!("mysqldump --single-transaction -u {}{} {}", shq(user), auth, shq(db))
        }
        pb::ContainerDatabaseEngine::Mongo => {
            let auth = if pw.is_empty() { String::new() } else { format!(" -p \"${pw}\"") };
            format!("mongodump --archive -u {}{} --db {}", shq(user), auth, shq(db))
        }
        pb::ContainerDatabaseEngine::Unspecified => {
            return Err(format!("no dump command is known for {container}"))
        }
    };
    Ok(vec!["exec".into(), container.clone(), "sh".into(), "-c".into(), script])
}

/// Single-quote for the shell that runs INSIDE the container
fn shq(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn suffix(engine: pb::ContainerDatabaseEngine) -> &'static str {
    match engine {
        pb::ContainerDatabaseEngine::Postgres => "pgsql",
        pb::ContainerDatabaseEngine::Mysql | pb::ContainerDatabaseEngine::Mariadb => "sql",
        pb::ContainerDatabaseEngine::Mongo => "mongo",
        pb::ContainerDatabaseEngine::Unspecified => "bin",
    }
}

fn sanitise_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches('.').to_string();
    if trimmed.is_empty() { "container".to_string() } else { trimmed }
}

async fn volume_mountpoint(volume: &str) -> Result<Option<String>, String> {
    let out = capture(
        "docker",
        &["volume".into(), "inspect".into(), volume.into(), "--format".into(), "{{.Mountpoint}}".into()],
        30,
    )
    .await?;
    if !out.success {
        return Err(first_lines(out.stderr.trim(), 1));
    }
    let path = out.stdout.trim().to_string();
    Ok(if path.is_empty() { None } else { Some(path) })
}

fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{now}")
}

fn restrict(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The same archive, driven by ANOTHER verb's stream
pub(crate) async fn run_for_update(
    key: &str,
    kind: GroupKind,
    plan: &pb::ContainerBackupPlan,
    details: &[pb::ContainerDetail],
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<pb::BackupArchive, String> {
    let container_names: Vec<String> = details
        .iter()
        .filter_map(|d| d.container.as_ref().map(|c| c.name.clone()))
        .collect();
    execute(key, kind, plan, details, &container_names, tx, encode).await
}

struct BackupSink {
    tx: Sender<Bytes>,
    codec: Codec,
    key: String,
    journal: Option<crate::jobs::Journal>,
}

impl BackupSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::ContainerBackupEvent {
        pb::ContainerBackupEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            key: self.key.clone(),
            text: String::new(),
            stream: String::new(),
            plan: None,
            archive: None,
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

    async fn send(&self, event: pb::ContainerBackupEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self, plan: pb::ContainerBackupPlan) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Started);
        event.plan = Some(plan);
        self.send(event).await
    }

    async fn completed(
        &self,
        archive: Option<pb::BackupArchive>,
        group: Option<pb::ContainerGroup>,
    ) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.archive = archive;
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

    fn dump(container: &str, engine: pb::ContainerDatabaseEngine, pw: &str) -> pb::ContainerDatabaseDump {
        pb::ContainerDatabaseDump {
            container: container.to_string(),
            engine: engine as i32,
            database: "appdb".to_string(),
            user: "appuser".to_string(),
            password_env: pw.to_string(),
        }
    }

    #[test]
    fn a_dump_command_carries_the_variable_name_and_never_its_value() {
        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Postgres, "POSTGRES_PASSWORD"), pb::ContainerDatabaseEngine::Postgres).unwrap();
        let joined = args.join(" ");
        // The variable is DEREFERENCED inside the container...
        assert!(joined.contains("PGPASSWORD=\"$POSTGRES_PASSWORD\""), "{joined}");
        assert_eq!(args[0], "exec");
        assert_eq!(args[1], "db");
        assert_eq!(args[2], "sh");

        for engine in [pb::ContainerDatabaseEngine::Mysql, pb::ContainerDatabaseEngine::Mariadb] {
            let args = dump_args(&dump("db", engine, "MYSQL_PASSWORD"), engine).unwrap();
            assert!(args.join(" ").contains("$MYSQL_PASSWORD"), "{engine:?}");
        }
        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Mongo, "MONGO_PW"), pb::ContainerDatabaseEngine::Mongo).unwrap();
        assert!(args.join(" ").contains("$MONGO_PW"));
    }

    #[test]
    fn a_dump_without_a_password_variable_omits_the_flag_entirely() {
        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Postgres, ""), pb::ContainerDatabaseEngine::Postgres).unwrap();
        let joined = args.join(" ");
        assert!(!joined.contains("PGPASSWORD"), "{joined}");
        assert!(joined.contains("pg_dump -U 'appuser' 'appdb'"), "{joined}");

        let args = dump_args(&dump("db", pb::ContainerDatabaseEngine::Mysql, ""), pb::ContainerDatabaseEngine::Mysql).unwrap();
        assert!(!args.join(" ").contains("-p"), "{:?}", args);
    }

    #[test]
    fn a_quote_in_a_name_cannot_end_the_quoted_string() {
        let mut d = dump("db", pb::ContainerDatabaseEngine::Postgres, "PW");
        d.database = "ap'p".to_string();
        let args = dump_args(&d, pb::ContainerDatabaseEngine::Postgres).unwrap();
        let script = args.last().unwrap();
        assert!(script.contains(r"'ap'\''p'"), "{script}");
    }

    #[test]
    fn an_unknown_engine_is_refused() {
        let d = dump("db", pb::ContainerDatabaseEngine::Unspecified, "PW");
        assert!(dump_args(&d, pb::ContainerDatabaseEngine::Unspecified).is_err());
    }

    /// A container name becomes ONE filename component
    #[test]
    fn a_container_name_becomes_one_safe_filename_component() {
        assert_eq!(sanitise_component("stack-db-1"), "stack-db-1");
        assert_eq!(sanitise_component("../../etc/passwd"), "_.._etc_passwd");
        assert!(!sanitise_component("..").contains(".."));
        assert_eq!(sanitise_component(""), "container");
    }

    #[test]
    fn a_groups_archives_come_back_newest_first_from_a_derived_path() {
        let root = std::env::temp_dir()
            .join(format!("gryonixnexusd-cbl-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("acme-stack");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("older.tar.gz"), b"x").unwrap();
        for name in [".incoming-20260904", ".work-abc"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(dir.join("newer.tar.gz"), b"x").unwrap();

        std::env::set_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT", &root);
        let listed = list("acme-stack").expect("a readable directory is not a failure");
        std::env::remove_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT");

        assert_eq!(listed.key, "acme-stack");
        assert_eq!(listed.directory, dir.to_string_lossy());
        assert_eq!(
            listed.archives.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            vec!["newer.tar.gz", "older.tar.gz"],
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_that_cannot_be_read_is_a_failure_rather_than_an_empty_list() {
        let root = std::env::temp_dir()
            .join(format!("gryonixnexusd-cbl-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        // Where the group's directory should be, there is a file.
        std::fs::write(root.join("blocked"), b"not a directory").unwrap();

        std::env::set_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT", &root);
        let outcome = list("blocked");
        std::env::remove_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT");

        assert!(outcome.is_err(), "an unreadable directory was reported as no backups");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_group_with_no_backups_yet_is_empty_rather_than_a_failure() {
        let root = std::env::temp_dir()
            .join(format!("gryonixnexusd-cbl-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT", &root);
        let listed = list("never-backed-up").expect("a missing directory is not a failure");
        std::env::remove_var("GRYONIXNEXUSD_CONTAINER_BACKUP_ROOT");
        assert!(listed.archives.is_empty());
        assert!(listed.directory.ends_with("never-backed-up"));
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::rotate;

    #[test]
    fn only_the_newest_archives_of_this_group_are_kept() {
        let dir = std::env::temp_dir().join(format!("rotate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for stamp in 1..=5 {
            let path = dir.join(format!("web-2026010{stamp}.tar.gz"));
            std::fs::write(&path, b"x").unwrap();
            let when = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000 + stamp * 100);
            std::fs::File::options().write(true).open(&path).unwrap().set_modified(when).unwrap();
        }
        std::fs::write(dir.join("other-20260101.tar.gz"), b"x").unwrap();
        let removed = rotate(&dir, "web", 2);
        assert_eq!(removed.len(), 3);
        assert!(dir.join("web-20260105.tar.gz").exists() && dir.join("web-20260104.tar.gz").exists());
        assert!(dir.join("other-20260101.tar.gz").exists(), "another group's archive is not ours to delete");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
