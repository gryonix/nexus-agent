//! What a long operation leaves behind, so the phone does not have to stay

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::StatusCode;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::pb;

pub struct OperationClaim(String);

fn claimed() -> &'static Mutex<std::collections::HashSet<String>> {
    static CLAIMED: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    CLAIMED.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

impl OperationClaim {
    pub fn acquire(namespace: &str, subject: &str) -> Result<Self, Resp> {
        let key = format!("{namespace}:{subject}");
        let mut held = claimed().lock().unwrap_or_else(|e| e.into_inner());
        if !held.insert(key.clone()) {
            return Err(connect_error(StatusCode::CONFLICT, "already_exists",
                "An operation is already running for this service or container group. Wait for it to finish."));
        }
        Ok(Self(key))
    }
}

impl Drop for OperationClaim {
    fn drop(&mut self) {
        claimed().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
    }
}

const STATE_DIR_ENV: &str = "GRYONIXNEXUSD_STATE_DIR";
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";

/// How many runs are kept across all kinds
const KEEP_JOBS: usize = 80;

const FOLLOW_POLL: Duration = Duration::from_millis(250);

fn state_dir() -> PathBuf {
    PathBuf::from(std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string()))
}

fn journal_dir() -> PathBuf {
    state_dir().join("jobs")
}

fn legacy_install_dir() -> PathBuf {
    state_dir().join("installs")
}

fn path_for(job_id: &str) -> PathBuf {
    journal_dir().join(format!("{job_id}.jsonl"))
}

fn is_valid_job_id(job_id: &str) -> bool {
    let mut groups = job_id.split('-');
    let three_hex_groups =
        (0..3).all(|_| groups.next().is_some_and(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_hexdigit())));
    three_hex_groups && groups.next().is_none()
}

fn running() -> &'static Mutex<HashMap<String, i32>> {
    static RUNNING: OnceLock<Mutex<HashMap<String, i32>>> = OnceLock::new();
    RUNNING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn running_guard() -> std::sync::MutexGuard<'static, HashMap<String, i32>> {
    running().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn mint_job_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}-{:x}", now_unix(), std::process::id(), n)
}

fn write_line(path: &PathBuf, line: &serde_json::Value) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}

/// The handle a running operation writes through
#[derive(Clone)]
pub struct Journal(std::sync::Arc<Inner>);

struct Inner {
    job_id: String,
    kind: i32,
    subject: String,
    started: i64,
    path: PathBuf,
    /// The next sequence number
    next: AtomicU64,
    /// Whether an ending has been written
    closed: std::sync::atomic::AtomicBool,
    /// Whether the run narrated a COMPLETED phase
    completed: std::sync::atomic::AtomicBool,
}

impl Journal {
    /// Open a journal for a run about to start
    pub fn open(kind: pb::JobKind, subject: &str) -> Option<Journal> {
        let dir = journal_dir();
        if let Err(err) = fs::create_dir_all(&dir) {
            tracing::warn!("job journal unavailable ({err}); this run cannot be reattached to");
            return None;
        }
        let job_id = mint_job_id();
        let path = path_for(&job_id);
        let meta = serde_json::json!({
            "kind": "meta",
            "job": job_id,
            "job_kind": kind as i32,
            "subject": subject,
            "started": now_unix(),
        });
        if let Err(err) = write_line(&path, &meta) {
            tracing::warn!("job journal unavailable ({err}); this run cannot be reattached to");
            return None;
        }
        running_guard().insert(job_id.clone(), kind as i32);
        prune(&dir);
        crate::notify::job_started(kind as i32, subject, &job_id);
        Some(Journal(std::sync::Arc::new(Inner {
            job_id,
            kind: kind as i32,
            subject: subject.to_string(),
            started: now_unix(),
            path,
            next: AtomicU64::new(0),
            closed: std::sync::atomic::AtomicBool::new(false),
            completed: std::sync::atomic::AtomicBool::new(false),
        })))
    }

    pub fn job_id(&self) -> &str {
        &self.0.job_id
    }

    /// Record one narrated line
    pub fn append(&self, phase: pb::JobPhase, stream: &str, text: &str) {
        crate::live::line(&self.0.job_id, text);
        self.append_quiet(phase, stream, text);
    }

    /// Record one line without showing it on the lock screen
    pub fn append_quiet(&self, phase: pb::JobPhase, stream: &str, text: &str) {
        if phase == pb::JobPhase::Completed {
            self.0.completed.store(true, Ordering::SeqCst);
        }
        let sequence = self.0.next.fetch_add(1, Ordering::Relaxed);
        let line = serde_json::json!({
            "kind": "event",
            "seq": sequence,
            "phase": phase as i32,
            "stream": stream,
            "text": text,
        });
        if let Err(err) = write_line(&self.0.path, &line) {
            tracing::warn!("could not append to the job journal: {err}");
        }
    }

    /// Close the journal
    pub fn finish(&self, failure: Option<&str>) {
        self.0.close(failure, false);
    }

    /// Close it as STOPPED ON REQUEST
    pub fn cancelled(&self, note: &str) {
        self.append(pb::JobPhase::Completed, "agent", note);
        self.0.close(None, true);
    }
}

impl Inner {
    fn close(&self, failure: Option<&str>, cancelled: bool) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let line = serde_json::json!({
            "kind": "end",
            "finished": now_unix(),
            "failure": failure.unwrap_or(""),
            "cancelled": cancelled,
        });
        if let Err(err) = write_line(&self.path, &line) {
            tracing::warn!("could not close the job journal: {err}");
        }
        running_guard().remove(&self.job_id);
        let shown_on_island = crate::live::finished(&self.job_id, failure);
        if !shown_on_island && !cancelled {
            crate::notify::job_ended(self.kind, &self.subject, now_unix() - self.started, failure);
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if self.completed.load(Ordering::SeqCst) {
            self.close(None, false);
            return;
        }
        self.close(
            Some("the run ended without reporting an outcome; what it left behind is not known"),
            false,
        );
    }
}

pub fn id_of(journal: &Option<Journal>) -> String {
    journal
        .as_ref()
        .map(|j| j.job_id().to_string())
        .unwrap_or_default()
}

pub fn phase_of(service_operation_phase: i32) -> pb::JobPhase {
    match service_operation_phase {
        x if x == pb::ServiceOperationPhase::Started as i32 => pb::JobPhase::Started,
        x if x == pb::ServiceOperationPhase::Completed as i32 => pb::JobPhase::Completed,
        _ => pb::JobPhase::Progress,
    }
}

/// Copy one narrated event into the run's record
pub fn tee(journal: &Option<Journal>, phase: i32, stream: &str, text: &str) {
    if let Some(journal) = journal {
        journal.append(phase_of(phase), stream, text);
    }
}

/// Close a run's record, if it has one.
pub fn finish(journal: &Option<Journal>, failure: Option<&str>) {
    if let Some(journal) = journal {
        journal.finish(failure);
    }
}

/// Drop the oldest journals once there are more than [`KEEP_JOBS`]
fn prune(dir: &PathBuf) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut files: Vec<(SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| {
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((modified, e.path()))
        })
        .collect();
    if files.len() <= KEEP_JOBS {
        return;
    }
    files.sort_by_key(|(when, _)| *when);
    for (_, path) in files.iter().take(files.len() - KEEP_JOBS) {
        let _ = fs::remove_file(path);
    }
}

/// What one journal file says about itself.
struct Parsed {
    job_id: String,
    kind: i32,
    subject: String,
    started: i64,
    finished: i64,
    failure: String,
    closed: bool,
    cancelled: bool,
    events: Vec<pb::JobEvent>,
}

fn apply_line(parsed: &mut Parsed, value: &serde_json::Value) {
    match value.get("kind").and_then(|k| k.as_str()) {
        Some("meta") => {
            parsed.subject = value
                .get("subject")
                .or_else(|| value.get("service"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            parsed.started = value.get("started").and_then(|v| v.as_i64()).unwrap_or(0);
            if let Some(kind) = value.get("job_kind").and_then(|v| v.as_i64()) {
                parsed.kind = kind as i32;
            }
        }
        Some("event") => parsed.events.push(pb::JobEvent {
            job_id: parsed.job_id.clone(),
            sequence: value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            kind: parsed.kind,
            phase: value.get("phase").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            text: value
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            stream: value
                .get("stream")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            subject: parsed.subject.clone(),
        }),
        Some("end") => {
            parsed.closed = true;
            parsed.finished = value.get("finished").and_then(|v| v.as_i64()).unwrap_or(0);
            parsed.failure = value
                .get("failure")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            parsed.cancelled = value
                .get("cancelled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        }
        _ => {}
    }
}

/// Parse one file
fn parse_file(path: &PathBuf, job_id: &str, default_kind: i32) -> Option<Parsed> {
    let file = File::open(path).ok()?;
    let mut parsed = Parsed {
        job_id: job_id.to_string(),
        kind: default_kind,
        subject: String::new(),
        started: 0,
        finished: 0,
        failure: String::new(),
        closed: false,
        cancelled: false,
        events: Vec::new(),
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        apply_line(&mut parsed, &value);
    }
    if parsed.subject.is_empty() && parsed.events.is_empty() {
        return None;
    }
    Some(parsed)
}

fn locate(job_id: &str) -> Option<(PathBuf, i32)> {
    let own = path_for(job_id);
    if own.exists() {
        return Some((own, pb::JobKind::Unspecified as i32));
    }
    let legacy = legacy_install_dir().join(format!("{job_id}.jsonl"));
    if legacy.exists() {
        return Some((legacy, pb::JobKind::Install as i32));
    }
    None
}

fn parse(job_id: &str) -> Option<Parsed> {
    let (path, default_kind) = locate(job_id)?;
    parse_file(&path, job_id, default_kind)
}

fn outcome_of(parsed: &Parsed) -> pb::JobOutcome {
    if !parsed.closed {
        return if running_guard().contains_key(&parsed.job_id)
            || crate::install::journal::is_running(&parsed.job_id)
        {
            pb::JobOutcome::Running
        } else {
            pb::JobOutcome::Abandoned
        };
    }
    if parsed.cancelled {
        return pb::JobOutcome::Cancelled;
    }
    if parsed.failure.is_empty() {
        pb::JobOutcome::Succeeded
    } else {
        pb::JobOutcome::Failed
    }
}

fn ids_in(dir: PathBuf) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().is_some_and(|x| x == "jsonl") {
                path.file_stem()?.to_str().map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn job_of(parsed: &Parsed) -> pb::Job {
    pb::Job {
        job_id: parsed.job_id.clone(),
        kind: parsed.kind,
        subject: parsed.subject.clone(),
        started_unix: parsed.started,
        finished_unix: parsed.finished,
        outcome: outcome_of(parsed) as i32,
        failure: parsed.failure.clone(),
        events: parsed.events.len() as u64,
        part_of: crate::install::plan::part_of(&parsed.job_id).unwrap_or_default(),
        plan_purpose: crate::install::plan::purpose_of(&parsed.job_id).unwrap_or_default(),
    }
}

pub fn list(kind: pb::JobKind, running_only: bool) -> Vec<pb::Job> {
    let mut jobs: Vec<pb::Job> = ids_in(journal_dir())
        .into_iter()
        .chain(ids_in(legacy_install_dir()))
        .filter_map(|id| parse(&id))
        .map(|parsed| job_of(&parsed))
        .filter(|job| kind == pb::JobKind::Unspecified || job.kind == kind as i32)
        .filter(|job| !running_only || job.outcome == pb::JobOutcome::Running as i32)
        .collect();
    jobs.sort_by(|a, b| b.started_unix.cmp(&a.started_unix));
    jobs
}

pub fn job(job_id: &str) -> Option<pb::Job> {
    parse(job_id).map(|parsed| job_of(&parsed))
}

/// A journal read forward from where the last read stopped
struct Tail {
    path: PathBuf,
    offset: u64,
    parsed: Parsed,
}

impl Tail {
    fn open(job_id: &str) -> Option<Tail> {
        let (path, default_kind) = locate(job_id)?;
        let parsed = Parsed {
            job_id: job_id.to_string(),
            kind: default_kind,
            subject: String::new(),
            started: 0,
            finished: 0,
            failure: String::new(),
            closed: false,
            cancelled: false,
            events: Vec::new(),
        };
        Some(Tail { path, offset: 0, parsed })
    }

    fn has_unread(&self) -> bool {
        fs::metadata(&self.path).is_ok_and(|meta| meta.len() > self.offset)
    }

    fn read_new(&mut self) -> Option<Vec<pb::JobEvent>> {
        let mut file = File::open(&self.path).ok()?;
        file.seek(SeekFrom::Start(self.offset)).ok()?;
        let mut text = String::new();
        BufReader::new(file).read_to_string(&mut text).ok()?;
        let complete = text.rfind('\n').map_or(0, |end| end + 1);
        self.offset += complete as u64;
        for line in text[..complete].lines() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                apply_line(&mut self.parsed, &value);
            }
        }
        Some(std::mem::take(&mut self.parsed.events))
    }
}

/// Whether any run is still going on this host
pub fn any_running() -> bool {
    !running_guard().is_empty()
}

pub fn is_running(job_id: &str) -> bool {
    running_guard().contains_key(job_id)
}

/// How long a follower should wait before looking for more.
pub fn follow_poll() -> Duration {
    FOLLOW_POLL
}

/// Called once at startup
pub fn sweep_abandoned() {
    let abandoned: Vec<String> = ids_in(journal_dir())
        .into_iter()
        .filter_map(|id| parse(&id))
        .filter(|parsed| !parsed.closed)
        .map(|parsed| format!("{} ({})", parsed.job_id, parsed.subject))
        .collect();
    if !abandoned.is_empty() {
        tracing::warn!(
            "runs left unfinished by a previous agent process: {}",
            abandoned.join(", ")
        );
    }
}

// ─────────────────────────── the two verbs ───────────────────────────

pub async fn run_watch_job(codec: Codec, req: pb::WatchJobRequest) -> Resp {
    if !is_valid_job_id(&req.job_id) || job(&req.job_id).is_none() {
        return connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("this host has no record of job {}", req.job_id),
        );
    }
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        follow(req.job_id, req.from_sequence, codec, tx).await;
    });
    stream_response(json, rx)
}

async fn follow(job_id: String, from_sequence: u64, codec: Codec, tx: Sender<Bytes>) {
    let Some(mut tail) = Tail::open(&job_id) else { return };
    loop {
        let Some(events) = tail.read_new() else {
            return;
        };
        for event in events.into_iter().filter(|e| e.sequence >= from_sequence) {
            let payload = codec.encode_payload(&event);
            if tx.send(envelope(0x00, &payload)).await.is_err() {
                return;
            }
        }
        if tail.parsed.closed {
            if !tail.parsed.failure.is_empty() {
                let _ = tx.send(error_trailer("internal", &tail.parsed.failure)).await;
            }
            return;
        }
        if !is_running(&job_id) && !crate::install::journal::is_running(&job_id) {
            if tail.has_unread() {
                continue;
            }
            let _ = tx.send(error_trailer("aborted", ABANDONED_NOTE)).await;
            return;
        }
        tokio::time::sleep(follow_poll()).await;
    }
}

const ABANDONED_NOTE: &str = "the agent stopped while this run was going; nothing is known about what it left behind. What to do about that depends on the operation, so the client is told rather than guessed for";

/// `Jobs/ListJobs` — what this host has run lately, newest first
pub async fn run_list_jobs(codec: Codec, req: pb::ListJobsRequest) -> Resp {
    let kind = pb::JobKind::try_from(req.kind).unwrap_or(pb::JobKind::Unspecified);
    let list = pb::JobList {
        jobs: list(kind, req.running_only),
    };
    codec.encode(&list).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

// ───────────────────────────── Stopping one ─────────────────────────────

fn switches() -> &'static Mutex<HashMap<String, tokio::sync::watch::Sender<bool>>> {
    static SWITCHES: OnceLock<Mutex<HashMap<String, tokio::sync::watch::Sender<bool>>>> =
        OnceLock::new();
    SWITCHES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn switches_guard() -> std::sync::MutexGuard<'static, HashMap<String, tokio::sync::watch::Sender<bool>>>
{
    switches().lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct CancelSwitch {
    job_id: String,
    rx: tokio::sync::watch::Receiver<bool>,
}

impl CancelSwitch {
    #[allow(dead_code)]
    pub fn asked(&self) -> bool {
        *self.rx.borrow()
    }

    pub async fn wait(&self) {
        let mut rx = self.rx.clone();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

impl Drop for CancelSwitch {
    fn drop(&mut self) {
        switches_guard().remove(&self.job_id);
    }
}

/// Register a run as stoppable
pub fn cancellable(journal: &Option<Journal>) -> Option<CancelSwitch> {
    let job_id = journal.as_ref()?.job_id().to_string();
    let (tx, rx) = tokio::sync::watch::channel(false);
    switches_guard().insert(job_id.clone(), tx);
    Some(CancelSwitch { job_id, rx })
}

/// Ask a run to stop
pub fn ask_to_stop(job_id: &str) -> bool {
    match switches_guard().get(job_id) {
        Some(tx) => tx.send(true).is_ok(),
        None => false,
    }
}

/// `Jobs/CancelJob` — stop a run that is still going
pub async fn run_cancel_job(codec: Codec, req: pb::CancelJobRequest) -> Resp {
    if !is_valid_job_id(&req.job_id) {
        return connect_error(StatusCode::NOT_FOUND, "not_found", "no run with that id on this host");
    }
    let Some(current) = job(&req.job_id) else {
        return connect_error(StatusCode::NOT_FOUND, "not_found", "no run with that id on this host");
    };
    if current.outcome != pb::JobOutcome::Running as i32 {
        return codec.encode(&current).unwrap_or_else(|err| {
            connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
        });
    }
    if !ask_to_stop(&req.job_id) {
        return connect_error(
            StatusCode::FAILED_DEPENDENCY,
            "failed_precondition",
            "this run cannot be stopped once it has started",
        );
    }
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !is_running(&req.job_id) {
            break;
        }
    }
    let answer = job(&req.job_id).unwrap_or(current);
    codec.encode(&answer).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events_after(job_id: &str, from_sequence: u64) -> Option<(Vec<pb::JobEvent>, bool, String)> {
        let mut tail = Tail::open(job_id)?;
        let events = tail.read_new()?.into_iter().filter(|e| e.sequence >= from_sequence).collect();
        Some((events, tail.parsed.closed, tail.parsed.failure))
    }

    fn with_dir<T>(name: &str, body: impl FnOnce() -> T) -> T {
        let _guard = crate::util::STATE_DIR_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-jobs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var(STATE_DIR_ENV, &dir);
        running_guard().clear();
        let out = body();
        std::env::remove_var(STATE_DIR_ENV);
        let _ = fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn a_watched_job_moves_its_island_and_the_end_lets_go() {
        with_dir("live", || {
            let journal = Journal::open(pb::JobKind::Update, "nextcloud").unwrap();
            let id = journal.job_id().to_string();
            crate::live::watch(&id, "token", "Updating Nextcloud");
            journal.append(pb::JobPhase::Progress, "stdout", "GRYONIXNEXUS_STEP 2/4\nPulling images\n");
            assert_eq!(crate::live::shown(&id), Some(("Pulling images".to_string(), Some(0.5))));
            journal.finish(None);
            assert_eq!(crate::live::shown(&id), None);
        });
    }

    #[test]
    fn a_stopped_run_reads_back_as_cancelled_and_not_as_a_failure() {
        with_dir("cancelled", || {
            let journal = Journal::open(pb::JobKind::ModelPull, "llama3.2:3b").unwrap();
            let id = journal.job_id().to_string();
            journal.append(pb::JobPhase::Progress, "agent", "pulling manifest");
            journal.cancelled("stopped; 12.0 GB of partly fetched layers removed");

            let job = super::job(&id).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Cancelled as i32);
            assert!(job.failure.is_empty(), "a cancel is not a failure: {}", job.failure);
            let (events, closed, failure) = events_after(&id, 0).unwrap();
            assert!(closed);
            assert!(failure.is_empty());
            assert!(
                events.last().unwrap().text.contains("partly fetched layers removed"),
                "the run does not say what it left behind: {events:?}"
            );
        });
    }

    #[test]
    fn an_older_journal_still_reads_as_it_did() {
        with_dir("older", || {
            let journal = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
            let id = journal.job_id().to_string();
            journal.append(pb::JobPhase::Progress, "agent", "archiving");
            drop(journal);
            // The end line an older agent wrote: no `cancelled` key.
            let path = path_for(&id);
            let text = fs::read_to_string(&path).unwrap();
            let stripped: String = text
                .lines()
                .map(|line| line.replace(",\"cancelled\":false", "").replace(",\"cancelled\":true", ""))
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(&path, format!("{stripped}\n")).unwrap();

            let job = super::job(&id).unwrap();
            assert_ne!(job.outcome, pb::JobOutcome::Cancelled as i32);
        });
    }

    #[test]
    fn only_a_run_that_registered_a_switch_can_be_stopped() {
        with_dir("switches", || {
            let journal = Some(Journal::open(pb::JobKind::ModelPull, "llama3.2:3b").unwrap());
            let id = crate::jobs::id_of(&journal);
            assert!(!ask_to_stop(&id), "a run with no switch accepted a cancel");

            let switch = cancellable(&journal).unwrap();
            assert!(!switch.asked());
            assert!(ask_to_stop(&id), "a registered run refused a cancel");
            assert!(switch.asked(), "the switch did not see the request");

            drop(switch);
            assert!(!ask_to_stop(&id), "a finished run still accepts a cancel");
        });
    }

    #[test]
    fn a_run_of_a_kind_that_cannot_stop_is_refused() {
        with_dir("uncancellable", || {
            let journal = Journal::open(pb::JobKind::Install, "mailcow").unwrap();
            assert!(!ask_to_stop(journal.job_id()));
        });
    }

    #[test]
    fn a_finished_run_reads_back_line_for_line() {
        with_dir("readback", || {
            let journal = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
            let job = journal.job_id().to_string();
            for text in ["stopping", "archiving", "done"] {
                journal.append(pb::JobPhase::Progress, "agent", text);
            }
            journal.finish(None);

            let (events, closed, failure) = events_after(&job, 0).unwrap();
            assert_eq!(events.len(), 3);
            assert_eq!(events[1].text, "archiving");
            assert_eq!(events[1].sequence, 1, "sequences are dense and start at 0");
            assert_eq!(events[1].job_id, job);
            assert_eq!(events[1].kind, pb::JobKind::Backup as i32);
            assert_eq!(events[1].subject, "nextcloud");
            assert!(closed);
            assert!(failure.is_empty());
            let job = super::job(&job).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Succeeded as i32);
            assert_eq!(job.kind, pb::JobKind::Backup as i32);
            assert_eq!(job.subject, "nextcloud");
        });
    }

    #[test]
    fn reattaching_asks_for_what_it_has_not_seen() {
        with_dir("resume", || {
            let journal = Journal::open(pb::JobKind::Update, "immich").unwrap();
            let job = journal.job_id().to_string();
            for text in ["a", "b", "c", "d"] {
                journal.append(pb::JobPhase::Progress, "agent", text);
            }
            let (events, closed, _) = events_after(&job, 2).unwrap();
            assert_eq!(events.iter().map(|e| e.text.as_str()).collect::<Vec<_>>(), ["c", "d"]);
            assert!(!closed, "an unfinished run is not closed");
            assert_eq!(super::job(&job).unwrap().outcome, pb::JobOutcome::Running as i32,
                       "a journal this process is holding is RUNNING, not abandoned");
        });
    }

    #[test]
    fn a_failed_run_says_so_and_says_why() {
        with_dir("failed", || {
            let journal = Journal::open(pb::JobKind::ContainerUpdate, "immich-stack").unwrap();
            let job = journal.job_id().to_string();
            journal.append(pb::JobPhase::Progress, "stderr", "no space left on device");
            journal.finish(Some("the update failed and was rolled back"));

            let (_, closed, failure) = events_after(&job, 0).unwrap();
            assert!(closed);
            assert_eq!(failure, "the update failed and was rolled back");
            assert_eq!(super::job(&job).unwrap().outcome, pb::JobOutcome::Failed as i32);
        });
    }

    #[test]
    fn a_run_that_completed_reads_back_as_a_success() {
        with_dir("completed", || {
            let job = {
                let journal = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
                let id = journal.job_id().to_string();
                journal.append(pb::JobPhase::Progress, "agent", "archiving");
                journal.append(pb::JobPhase::Completed, "agent", "");
                id
            };
            let job = super::job(&job).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Succeeded as i32);
            assert!(job.failure.is_empty());
        });
    }

    #[test]
    fn dropping_the_handle_ends_the_run() {
        with_dir("dropped", || {
            let job = {
                let journal = Journal::open(pb::JobKind::Restore, "vaultwarden").unwrap();
                let id = journal.job_id().to_string();
                journal.append(pb::JobPhase::Progress, "agent", "unpacking");
                id
            };
            let job = super::job(&job).unwrap();
            assert_eq!(job.outcome, pb::JobOutcome::Failed as i32,
                       "an outcome nobody reported is not a success");
            assert!(!job.failure.is_empty(), "and it says that much out loud");
            assert!(!is_running(&job.job_id), "nor is it still running");
        });
    }

    #[test]
    fn the_listing_answers_by_kind_and_by_what_is_still_going() {
        with_dir("listing", || {
            let done = Journal::open(pb::JobKind::Backup, "nextcloud").unwrap();
            done.append(pb::JobPhase::Progress, "agent", "x");
            done.finish(None);
            let going = Journal::open(pb::JobKind::Update, "immich").unwrap();
            going.append(pb::JobPhase::Progress, "agent", "y");

            let all = list(pb::JobKind::Unspecified, false);
            assert_eq!(all.len(), 2, "every kind, because a returning client does not know");
            let updates = list(pb::JobKind::Update, false);
            assert_eq!(updates.len(), 1);
            assert_eq!(updates[0].subject, "immich");
            let running = list(pb::JobKind::Unspecified, true);
            assert_eq!(running.len(), 1, "only the one nobody has closed");
            assert_eq!(running[0].job_id, going.job_id());
            assert!(list(pb::JobKind::Backup, true).is_empty());
        });
    }

    #[tokio::test]
    async fn a_path_shaped_job_id_is_rejected_before_it_reaches_the_filesystem() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-jobs-traversal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var(STATE_DIR_ENV, &dir);
        running_guard().clear();
        let secret = dir.parent().unwrap().join("gryonixnexusd-jobs-traversal-secret.jsonl");
        fs::write(&secret, r#"{"kind":"meta","job":"secret","service":"root-only","started":1}"#).unwrap();
        let traversal_id = format!("../{}", secret.file_stem().unwrap().to_str().unwrap());

        let watch =
            run_watch_job(Codec::Json, pb::WatchJobRequest { job_id: traversal_id.clone(), from_sequence: 0 }).await;
        assert_eq!(watch.status(), StatusCode::NOT_FOUND);

        let cancel = run_cancel_job(Codec::Json, pb::CancelJobRequest { job_id: traversal_id }).await;
        assert_eq!(cancel.status(), StatusCode::NOT_FOUND);

        let _ = fs::remove_file(&secret);
        std::env::remove_var(STATE_DIR_ENV);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn installs_written_by_the_older_slice_are_listed_as_installs() {
        with_dir("legacy", || {
            let dir = legacy_install_dir();
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("legacy-job.jsonl");
            let mut file = fs::File::create(&path).unwrap();
            writeln!(file, r#"{{"kind":"meta","job":"legacy-job","service":"adguard","started":10}}"#).unwrap();
            writeln!(file, r#"{{"kind":"event","seq":0,"phase":2,"stream":"agent","text":"pulling"}}"#).unwrap();
            writeln!(file, r#"{{"kind":"end","finished":20,"failure":""}}"#).unwrap();

            let jobs = list(pb::JobKind::Unspecified, false);
            assert_eq!(jobs.len(), 1);
            assert_eq!(jobs[0].kind, pb::JobKind::Install as i32);
            assert_eq!(jobs[0].subject, "adguard");
            assert_eq!(jobs[0].outcome, pb::JobOutcome::Succeeded as i32);
            let (events, closed, _) = events_after("legacy-job", 0).unwrap();
            assert_eq!(events[0].text, "pulling");
            assert!(closed);
        });
    }

    #[test]
    fn runs_the_install_slice_wrote_are_listed_and_each_names_its_service() {
        with_dir("install-writer", || {
            let first = crate::install::journal::Journal::open("adguard").unwrap();
            first.append(0, 2, "agent", "one", "adguard");
            first.finish(None);
            let second = crate::install::journal::Journal::open("pihole").unwrap();
            second.append(0, 2, "agent", "two", "pihole");
            second.finish(None);

            let jobs = list(pb::JobKind::Unspecified, false);
            assert_eq!(jobs.len(), 2);
            let subjects: Vec<&str> = jobs.iter().map(|j| j.subject.as_str()).collect();
            assert!(subjects.contains(&"adguard"));
            assert!(subjects.contains(&"pihole"));
            assert!(jobs.iter().all(|j| j.events == 1));
            assert!(jobs.iter().all(|j| j.kind == pb::JobKind::Install as i32));
        });
    }

    #[test]
    fn an_unfinished_install_is_abandoned_once_nothing_is_holding_it() {
        with_dir("legacy-abandoned", || {
            let dir = legacy_install_dir();
            fs::create_dir_all(&dir).unwrap();
            let mut file = fs::File::create(dir.join("stuck.jsonl")).unwrap();
            writeln!(file, r#"{{"kind":"meta","job":"stuck","service":"forgejo","started":10}}"#).unwrap();
            writeln!(file, r#"{{"kind":"event","seq":0,"phase":1,"stream":"agent","text":"started"}}"#).unwrap();
            drop(file);

            crate::install::journal::hold_for_test("stuck", "forgejo");
            let held = list(pb::JobKind::Unspecified, false);
            assert_eq!(held.len(), 1);
            assert_eq!(held[0].outcome, pb::JobOutcome::Running as i32);

            crate::install::journal::release_all_for_test();
            let dropped = list(pb::JobKind::Unspecified, false);
            assert_eq!(
                dropped[0].outcome,
                pb::JobOutcome::Abandoned as i32,
                "an unfinished journal no process is writing to must not read as still running"
            );
        });
    }

    #[test]
    fn phases_map_to_what_the_verbs_already_say() {
        assert_eq!(phase_of(pb::ServiceOperationPhase::Started as i32), pb::JobPhase::Started);
        assert_eq!(phase_of(pb::ServiceOperationPhase::Progress as i32), pb::JobPhase::Progress);
        assert_eq!(phase_of(pb::ServiceOperationPhase::Completed as i32), pb::JobPhase::Completed);
        assert_eq!(phase_of(99), pb::JobPhase::Progress);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn same_subject_is_exclusive_and_release_allows_retry() {
        let first = OperationClaim::acquire("service", "admission-exclusive").ok().unwrap();
        assert!(OperationClaim::acquire("service", "admission-exclusive").is_err());
        assert!(OperationClaim::acquire("service", "admission-other").is_ok());
        drop(first);
        assert!(OperationClaim::acquire("service", "admission-exclusive").is_ok());
    }

    #[test]
    fn simultaneous_requests_admit_exactly_one() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8).map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let claim = OperationClaim::acquire("service", "admission-race");
                barrier.wait();
                claim.is_ok()
            })
        }).collect();
        assert_eq!(threads.into_iter().map(|t| t.join().unwrap() as usize).sum::<usize>(), 1);
    }

    #[tokio::test]
    async fn backup_refuses_before_starting_a_second_stream() {
        let _claim = OperationClaim::acquire("service", "admission-rpc").ok().unwrap();
        let response = crate::backup::run_backup(Codec::Json,
            pb::RunBackupRequest { service_id: "admission-rpc".into(), ..Default::default() }).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = crate::update::run_update(Codec::Json,
            pb::RunUpdateRequest { service_id: "admission-rpc".into(), ..Default::default() }).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn aborting_task_releases_its_reservation() {
        let claim = OperationClaim::acquire("service", "admission-abort").ok().unwrap();
        let task = tokio::spawn(async move {
            let _claim = claim;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert!(OperationClaim::acquire("service", "admission-abort").is_ok());
    }
}
