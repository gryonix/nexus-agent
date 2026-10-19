//! The record an install leaves behind, so the phone does not have to stay

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb;

const STATE_DIR_ENV: &str = "GRYONIXNEXUSD_STATE_DIR";
const STATE_DIR_FALLBACK: &str = "/var/lib/gryonixnexus/agent";

/// How many runs are kept
const KEEP_JOBS: usize = 40;

const FOLLOW_POLL: Duration = Duration::from_millis(250);

fn journal_dir() -> PathBuf {
    let base = std::env::var(STATE_DIR_ENV).unwrap_or_else(|_| STATE_DIR_FALLBACK.to_string());
    PathBuf::from(base).join("installs")
}

fn path_for(job_id: &str) -> PathBuf {
    journal_dir().join(format!("{job_id}.jsonl"))
}

fn running() -> &'static Mutex<HashMap<String, String>> {
    static RUNNING: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    RUNNING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn running_guard() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
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

/// One line of the file
fn write_line(path: &PathBuf, line: &serde_json::Value) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}

/// The handle a running install writes through.
pub struct Journal {
    job_id: String,
    service_id: String,
    path: PathBuf,
    started: i64,
}

impl Journal {
    #[cfg(test)]
    pub fn open(service_id: &str) -> Option<Journal> {
        Self::open_checked(service_id, false).ok().flatten()
    }

    pub fn open_unique(service_id: &str) -> Result<Option<Journal>, String> {
        Self::open_checked(service_id, true)
    }

    fn open_checked(service_id: &str, unique: bool) -> Result<Option<Journal>, String> {
        let mut held = running_guard();
        if unique {
            if let Some((job, _)) = held.iter().find(|(_, service)| service.as_str() == service_id) {
                return Err(job.clone());
            }
        }
        let dir = journal_dir();
        if let Err(err) = fs::create_dir_all(&dir) {
            tracing::warn!("install journal unavailable ({err}); this run cannot be reattached to");
            return Ok(None);
        }
        let job_id = mint_job_id();
        let path = path_for(&job_id);
        let meta = serde_json::json!({
            "kind": "meta",
            "job": job_id,
            "service": service_id,
            "started": now_unix(),
        });
        if let Err(err) = write_line(&path, &meta) {
            tracing::warn!("install journal unavailable ({err}); this run cannot be reattached to");
            return Ok(None);
        }
        held.insert(job_id.clone(), service_id.to_string());
        drop(held);
        prune(&dir);
        if super::plan::card_of(service_id).is_none() {
            crate::notify::job_started(crate::pb::JobKind::Install as i32, service_id, &job_id);
        }
        Ok(Some(Journal {
            job_id,
            service_id: service_id.to_string(),
            path,
            started: now_unix(),
        }))
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Record one narrated line
    pub fn append(&self, sequence: u64, phase: i32, stream: &str, text: &str, project: &str) {
        self.append_quiet(sequence, phase, stream, text, project);
        let card = super::plan::card_of(&self.service_id).unwrap_or_else(|| self.job_id.clone());
        crate::live::line(&card, text);
    }

    /// Record one line without showing it on the lock screen.
    pub fn append_quiet(&self, sequence: u64, phase: i32, stream: &str, text: &str, project: &str) {
        let line = serde_json::json!({
            "kind": "event",
            "seq": sequence,
            "phase": phase,
            "stream": stream,
            "text": text,
            "project": project,
        });
        if let Err(err) = write_line(&self.path, &line) {
            tracing::warn!("could not append to the install journal: {err}");
        }
    }

    /// Close the journal
    pub fn finish(&self, failure: Option<&str>) {
        let line = serde_json::json!({
            "kind": "end",
            "finished": now_unix(),
            "failure": failure.unwrap_or(""),
        });
        if let Err(err) = write_line(&self.path, &line) {
            tracing::warn!("could not close the install journal: {err}");
        }
        running_guard().remove(&self.job_id);
        if super::plan::card_of(&self.service_id).is_none() && !crate::live::finished(&self.job_id, failure) {
            let seconds = now_unix() - self.started;
            crate::notify::job_ended(crate::pb::JobKind::Install as i32, &self.service_id, seconds, failure);
        }
    }
}

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
    service_id: String,
    started: i64,
    finished: i64,
    failure: String,
    closed: bool,
    events: Vec<pb::InstallServiceEvent>,
}

fn parse(job_id: &str) -> Option<Parsed> {
    let file = File::open(path_for(job_id)).ok()?;
    let mut parsed = Parsed {
        job_id: job_id.to_string(),
        service_id: String::new(),
        started: 0,
        finished: 0,
        failure: String::new(),
        closed: false,
        events: Vec::new(),
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        match value.get("kind").and_then(|k| k.as_str()) {
            Some("meta") => {
                parsed.service_id = value
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                parsed.started = value.get("started").and_then(|v| v.as_i64()).unwrap_or(0);
            }
            Some("event") => parsed.events.push(pb::InstallServiceEvent {
                phase: value.get("phase").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                service_id: parsed.service_id.clone(),
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
                project: value
                    .get("project")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                service: None,
                job_id: job_id.to_string(),
                sequence: value.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            }),
            Some("end") => {
                parsed.closed = true;
                parsed.finished = value.get("finished").and_then(|v| v.as_i64()).unwrap_or(0);
                parsed.failure = value
                    .get("failure")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
            }
            _ => {}
        }
    }
    if parsed.service_id.is_empty() && parsed.events.is_empty() {
        return None;
    }
    Some(parsed)
}

fn job_ids() -> Vec<String> {
    let Ok(entries) = fs::read_dir(journal_dir()) else {
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

pub fn exists(job_id: &str) -> bool {
    parse(job_id).is_some()
}

pub fn events_after(job_id: &str, from_sequence: u64) -> Option<(Vec<pb::InstallServiceEvent>, bool, String)> {
    let parsed = parse(job_id)?;
    let closed = parsed.closed;
    let failure = parsed.failure.clone();
    let events = parsed
        .events
        .into_iter()
        .filter(|e| e.sequence >= from_sequence)
        .collect();
    Some((events, closed, failure))
}

#[cfg(test)]
pub fn running_job_for(service_id: &str) -> Option<String> {
    running_guard()
        .iter()
        .find(|(_, service)| service.as_str() == service_id)
        .map(|(job, _)| job.clone())
}

/// Whether any run is still going on this host
pub fn any_running() -> bool {
    !running_guard().is_empty()
}

pub fn is_running(job_id: &str) -> bool {
    running_guard().contains_key(job_id)
}

#[cfg(test)]
pub(crate) fn hold_for_test(job_id: &str, service_id: &str) {
    running_guard().insert(job_id.to_string(), service_id.to_string());
}

#[cfg(test)]
pub(crate) fn release_all_for_test() {
    running_guard().clear();
}

/// How long a follower should wait before looking for more.
pub fn follow_poll() -> Duration {
    FOLLOW_POLL
}

/// Called once at startup
pub fn sweep_abandoned() {
    let abandoned: Vec<String> = job_ids()
        .iter()
        .filter_map(|id| parse(id))
        .filter(|parsed| !parsed.closed)
        .map(|parsed| format!("{} ({})", parsed.job_id, parsed.service_id))
        .collect();
    if !abandoned.is_empty() {
        tracing::warn!(
            "install runs left unfinished by a previous agent process: {}",
            abandoned.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_dir<T>(name: &str, body: impl FnOnce() -> T) -> T {
        let _guard = crate::util::STATE_DIR_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-journal-{name}-{}", std::process::id()));
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
    fn an_install_moves_its_island_and_the_end_lets_go() {
        with_dir("island", || {
            let journal = Journal::open("immich").unwrap();
            let job = journal.job_id().to_string();
            crate::live::watch(&job, "token", "Installing Immich");
            journal.append(0, 2, "agent", "GRYONIXNEXUS_STEP 2/4\npulling images", "immich");
            assert_eq!(crate::live::shown(&job), Some(("pulling images".to_string(), Some(0.5))));
            journal.finish(None);
            assert_eq!(crate::live::shown(&job), None, "the end hands the island over");
        });
    }

    #[test]
    fn a_finished_run_reads_back_line_for_line() {
        with_dir("readback", || {
            let journal = Journal::open("adguard").unwrap();
            let job = journal.job_id().to_string();
            for (i, text) in ["pulling", "starting", "up"].iter().enumerate() {
                journal.append(i as u64, 2, "agent", text, "adguard");
            }
            journal.finish(None);

            let (events, closed, failure) = events_after(&job, 0).unwrap();
            assert_eq!(events.len(), 3);
            assert_eq!(events[1].text, "starting");
            assert_eq!(events[1].sequence, 1);
            assert_eq!(events[1].job_id, job);
            assert!(closed);
            assert!(failure.is_empty());
            assert!(exists(&job));
            assert!(!exists("no-such-run"), "and a run this host never had is not one");
        });
    }

    #[test]
    fn reattaching_asks_for_what_it_has_not_seen() {
        with_dir("resume", || {
            let journal = Journal::open("nextcloud").unwrap();
            let job = journal.job_id().to_string();
            for i in 0..5u64 {
                journal.append(i, 2, "stdout", &format!("line {i}"), "nextcloud");
            }
            journal.finish(None);

            let (events, _, _) = events_after(&job, 3).unwrap();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].text, "line 3");
            assert_eq!(events[1].text, "line 4");
        });
    }

    #[test]
    fn a_failed_run_carries_its_reason() {
        with_dir("failed", || {
            let journal = Journal::open("mailcow").unwrap();
            let job = journal.job_id().to_string();
            journal.append(0, 2, "stderr", "port 25 is taken", "mailcowdockerized");
            journal.finish(Some("port 25 is taken"));

            let (_, closed, failure) = events_after(&job, 0).unwrap();
            assert!(closed);
            assert_eq!(failure, "port 25 is taken");
        });
    }

    #[test]
    fn a_second_install_of_the_same_service_can_be_seen_coming() {
        with_dir("guard", || {
            let journal = Journal::open("jellyfin").unwrap();
            assert_eq!(
                running_job_for("jellyfin").as_deref(),
                Some(journal.job_id())
            );
            assert_eq!(running_job_for("adguard"), None);
            journal.finish(None);
            assert_eq!(
                running_job_for("jellyfin"),
                None,
                "a finished run must not keep refusing the next one"
            );
        });
    }

    #[test]
    fn a_torn_final_line_does_not_lose_the_run() {
        with_dir("torn", || {
            let journal = Journal::open("seafile").unwrap();
            let job = journal.job_id().to_string();
            journal.append(0, 2, "agent", "creating directories", "seafile");
            let mut file = OpenOptions::new().append(true).open(path_for(&job)).unwrap();
            file.write_all(b"{\"kind\":\"eve").unwrap();
            drop(file);

            let (events, closed, _) = events_after(&job, 0).unwrap();
            assert_eq!(events.len(), 1, "the intact lines before the tear still count");
            assert!(!closed);
        });
    }
}
