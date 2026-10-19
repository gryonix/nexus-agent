//! Moves an iPhone Live Activity with a job while the app is asleep

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::notify;
use crate::notify_send::{self, Sent};
use crate::pb;
use crate::state::Store;

const SPACING: Duration = Duration::from_secs(15);
/// How often a step may spend the urgent budget
const URGENT_SPACING: Duration = Duration::from_secs(60);
const STALE_AFTER: i64 = 300;
const LINGER: i64 = 30;
const FAILED_LINGER: i64 = 120;

struct Watch {
    /// The card the app started itself, if any
    token: String,
    /// Cards the relay started for this job on every iPhone
    job_cards: bool,
    title: String,
    text: String,
    progress: Option<f64>,
    /// The script's own step counter, done and total
    step: Option<(u32, u32)>,
    last_sent: Option<Instant>,
    flush_planned: bool,
    last_urgent: Option<Instant>,
}

fn watches() -> &'static Mutex<HashMap<String, Watch>> {
    static WATCHES: OnceLock<Mutex<HashMap<String, Watch>>> = OnceLock::new();
    WATCHES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn store() -> &'static OnceLock<Arc<Mutex<Store>>> {
    static STORE: OnceLock<Arc<Mutex<Store>>> = OnceLock::new();
    &STORE
}

pub fn init(shared: Arc<Mutex<Store>>) {
    let _ = store().set(shared);
}

// MARK: reading the journal

/// A journal line's readable text and step fraction
pub fn read_line(text: &str) -> (Option<String>, Option<f64>) {
    let mut readable = None;
    let mut progress = None;
    for raw in text.lines() {
        let line = strip_ansi(raw).trim().to_string();
        if let Some(step) = line.strip_prefix("GRYONIXNEXUS_STEP ") {
            progress = step_fraction(step);
        } else if !line.is_empty() && !line.starts_with("GRYONIXNEXUS_") {
            readable = Some(line.chars().take(80).collect());
        }
    }
    (readable, progress)
}

/// The last `GRYONIXNEXUS_STEP done/total` counter in a chunk
pub fn read_step(text: &str) -> Option<(u32, u32)> {
    text.lines().rev().find_map(|raw| {
        let first = strip_ansi(raw).trim().strip_prefix("GRYONIXNEXUS_STEP ")?.split_whitespace().next()?.to_string();
        let (done, total) = first.split_once('/')?;
        let (done, total) = (done.parse::<u32>().ok()?, total.parse::<u32>().ok()?);
        (total > 0 && done <= total).then_some((done, total))
    })
}

fn step_fraction(step: &str) -> Option<f64> {
    let first = step.split_whitespace().next()?;
    let (done, total) = first.split_once('/')?;
    let (done, total) = (done.parse::<f64>().ok()?, total.parse::<f64>().ok()?);
    (total > 0.0).then(|| (done / total).clamp(0.0, 1.0))
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// The app's ContentState, key for key
pub fn content_state(text: &str, progress: Option<f64>, finished: bool, failure: Option<&str>) -> Value {
    let mut state = json!({ "progressText": text, "isFinished": finished });
    if let Some(progress) = progress.filter(|_| !finished) {
        state["progress"] = json!(progress);
    }
    if let Some(failure) = failure {
        state["errorMessage"] = json!(failure);
    }
    state
}

fn headline(failed: bool, russian: bool) -> &'static str {
    match (failed, russian) {
        (false, false) => "Completed successfully",
        (false, true) => "Успешно завершено",
        (true, false) => "Failed",
        (true, true) => "Ошибка",
    }
}

// MARK: hooks from the journal

pub fn watch(job_id: &str, token: &str, title: &str) {
    let mut all = watches().lock().unwrap();
    if let Some(cards) = all.get_mut(job_id).filter(|w| w.job_cards) {
        cards.token = token.to_string();
        return;
    }
    all.insert(job_id.to_string(), Watch::new(token, false, title, String::new()));
}

impl Watch {
    fn new(token: &str, job_cards: bool, title: &str, text: String) -> Watch {
        Watch { token: token.to_string(), job_cards, title: title.to_string(), text, progress: None, step: None, last_sent: None, flush_planned: false, last_urgent: None }
    }

    /// One body per destination: the job's cards, the app's own
    fn addressed(&self, job_id: &str, body: &Value) -> Vec<Value> {
        let mut bodies = Vec::new();
        if self.job_cards {
            let mut cards = body.clone();
            cards["token"] = json!("");
            cards["job"] = json!(job_id);
            bodies.push(cards);
        }
        if !self.token.is_empty() {
            bodies.push(body.clone());
        }
        bodies
    }
}

/// Starts the job's card on every iPhone of the server
pub fn job_began(kind: i32, subject: &str, job_id: &str) {
    let Some(config) = config().filter(relay_ready) else { return };
    let russian = config.russian();
    let title = format!("{} · {}", notify::run_name(kind, russian), subject);
    let text = if russian { "Запуск…" } else { "Starting…" }.to_string();
    let body = start_body(job_id, kind, &title, &text, &config);
    let mut watch = Watch::new("", true, &title, text);
    watch.last_sent = Some(Instant::now());
    watches().lock().unwrap().insert(job_id.to_string(), watch);
    send_to(START_PATH, body);
}

/// Unix seconds at Apple's reference date
const APPLE_EPOCH: i64 = 978_307_200;

/// The relay's start request, with the app's attributes
pub fn start_body(job_id: &str, kind: i32, title: &str, text: &str, config: &notify::Config) -> Value {
    json!({
        "job": job_id,
        "kind": kind_word(kind),
        "attributes": {
            "title": title,
            "serverName": notify::host(),
            "startedAt": notify::now() - APPLE_EPOCH,
            "canStop": true,
            "jobID": job_id,
            "serverID": config.server_id,
        },
        "state": content_state(text, None, false, None),
        "alert": { "title": title, "body": notify::host() },
        "stale_at": notify::now() + STALE_AFTER,
    })
}

/// The kind name a phone may switch off
pub fn kind_word(kind: i32) -> &'static str {
    use pb::JobKind::*;
    match pb::JobKind::try_from(kind).unwrap_or(Unspecified) {
        Install | Repair | Reinstall => "install",
        Update | ContainerUpdate | AgentUpdate => "update",
        Backup | ContainerBackup => "backup",
        Restore => "restore",
        Move => "move",
        Uninstall | ContainerRemoval => "removal",
        _ => "other",
    }
}

pub fn line(job_id: &str, text: &str) {
    let (readable, progress) = read_line(text);
    let mut all = watches().lock().unwrap();
    let Some(watch) = all.get_mut(job_id) else { return };
    if let Some(readable) = readable {
        watch.text = readable;
    }
    if progress.is_some() {
        watch.progress = progress;
    }
    if let Some(step) = read_step(text) {
        watch.step = Some(step);
    }
    let due = watch.last_sent.map_or(true, |at| at.elapsed() >= SPACING);
    if due {
        watch.last_sent = Some(Instant::now());
        let body = update_body(watch);
        let bodies = watch.addressed(job_id, &body);
        drop(all);
        bodies.into_iter().for_each(send);
    } else if !watch.flush_planned {
        watch.flush_planned = true;
        let wait = SPACING.saturating_sub(watch.last_sent.map(|at| at.elapsed()).unwrap_or_default());
        drop(all);
        flush_later(job_id.to_string(), wait);
    }
}

/// The job ended: the island opens with the outcome
pub fn finished(job_id: &str, failure: Option<&str>) -> bool {
    let Some(watch) = watches().lock().unwrap().remove(job_id) else { return false };
    let russian = config().is_some_and(|c| c.language.starts_with("ru"));
    let (shown, closing) = ending_bodies(&watch, failure, russian, notify::now());
    watch.addressed(job_id, &shown).into_iter().for_each(send);
    let wait = Duration::from_secs(linger_of(failure) as u64);
    for body in watch.addressed(job_id, &closing) {
        send_later(body, wait, failure.is_none());
    }
    true
}

/// Steps of the sample card, and the pause between them
const CHECK_STEPS: u32 = 6;
const CHECK_PAUSE: Duration = Duration::from_secs(5);

/// The sample card's line for one step
fn check_step(number: u32, russian: bool) -> String {
    if russian { format!("Шаг {number} из {CHECK_STEPS}") } else { format!("Step {number} of {CHECK_STEPS}") }
}

/// Walks a sample card through its steps from here
pub fn run_check(token: &str, title: &str) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    let job = format!("island-check-{}", notify::now());
    watch(&job, token, title);
    let russian = config().is_some_and(|c| c.language.starts_with("ru"));
    runtime.spawn(async move {
        for number in 1..=CHECK_STEPS {
            let bodies = {
                let mut all = watches().lock().unwrap();
                let Some(watch) = all.get_mut(&job) else { return };
                watch.text = check_step(number, russian);
                watch.progress = Some(f64::from(number) / f64::from(CHECK_STEPS));
                watch.last_sent = Some(Instant::now());
                let body = update_body(watch);
                watch.addressed(&job, &body)
            };
            bodies.into_iter().for_each(send);
            tokio::time::sleep(CHECK_PAUSE).await;
        }
        finished(&job, None);
    });
}

/// How long an outcome stays in the island
fn linger_of(failure: Option<&str>) -> i64 {
    if failure.is_some() { FAILED_LINGER } else { LINGER }
}

/// The outcome shown with an alert, then the card's end
fn ending_bodies(watch: &Watch, failure: Option<&str>, russian: bool, now: i64) -> (Value, Value) {
    let state = content_state(&watch.text, None, true, failure);
    let shown = json!({
        "token": watch.token,
        "state": state,
        "stale_at": now + linger_of(failure) + STALE_AFTER,
        "alert": { "title": headline(failure.is_some(), russian), "body": watch.title },
    });
    let closing = json!({ "token": watch.token, "end": true, "state": state });
    (shown, closing)
}

fn send_later(mut body: Value, wait: Duration, dismiss: bool) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    runtime.spawn(async move {
        tokio::time::sleep(wait).await;
        if dismiss {
            body["dismiss_at"] = json!(notify::now());
        }
        send(body);
    });
}

/// What the island would show now for a watched job
#[cfg(test)]
pub fn shown(job_id: &str) -> Option<(String, Option<f64>)> {
    watches().lock().unwrap().get(job_id).map(|w| (w.text.clone(), w.progress))
}

fn update_body(watch: &mut Watch) -> Value {
    let urgent = watch.last_urgent.map_or(true, |at| at.elapsed() >= URGENT_SPACING);
    if urgent {
        watch.last_urgent = Some(Instant::now());
    }
    let mut state = content_state(&watch.text, watch.progress, false, None);
    if let Some((done, total)) = watch.step {
        state["step"] = json!(done);
        state["steps"] = json!(total);
    }
    json!({
        "token": watch.token,
        "state": state,
        "stale_at": notify::now() + STALE_AFTER,
        "urgent": urgent,
    })
}

fn flush_later(job_id: String, wait: Duration) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    runtime.spawn(async move {
        tokio::time::sleep(wait).await;
        let body = {
            let mut all = watches().lock().unwrap();
            let Some(watch) = all.get_mut(&job_id) else { return };
            watch.flush_planned = false;
            watch.last_sent = Some(Instant::now());
            let body = update_body(watch);
            watch.addressed(&job_id, &body)
        };
        body.into_iter().for_each(send);
    });
}

// MARK: sending

pub fn config() -> Option<notify::Config> {
    store().get().map(notify::load)
}

/// The shared state, for alerts sent outside the check loop
pub fn shared_store() -> Option<Arc<Mutex<Store>>> {
    store().get().cloned()
}

/// Whether this server reaches phones through a relay
pub fn relay_ready(config: &notify::Config) -> bool {
    config.channel == pb::NotifyChannel::Relay as i32 && !config.relay_url.is_empty()
        && config.registered_at == config.relay_url
}

const MOVE_PATH: &str = "live";
const START_PATH: &str = "live/start";

pub fn send(body: Value) {
    send_to(MOVE_PATH, body);
}

/// Queues one relay request, in order
fn send_to(path: &'static str, body: Value) {
    static QUEUE: OnceLock<tokio::sync::mpsc::UnboundedSender<(&'static str, Value)>> = OnceLock::new();
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    let queue = QUEUE.get_or_init(|| {
        let (queue, mut inbox) = tokio::sync::mpsc::unbounded_channel::<(&'static str, Value)>();
        runtime.spawn(async move {
            while let Some((path, body)) = inbox.recv().await {
                deliver_now(path, body).await;
            }
        });
        queue
    });
    let _ = queue.send((path, body));
}

/// Now, or one second past the last one sent
fn rising(last: i64, now: i64) -> i64 {
    now.max(last + 1)
}

fn next_timestamp(now: i64) -> i64 {
    static LAST: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let mut taken = now;
    let _ = LAST.fetch_update(std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst, |last| {
        taken = rising(last, now);
        Some(taken)
    });
    taken
}

async fn deliver_now(suffix: &str, mut body: Value) {
    let Some(config) = config().filter(relay_ready) else { return };
    let Some(seed) = config.seed_bytes() else { return };
    body["timestamp"] = json!(next_timestamp(notify::now()));
    let path = format!("/v1/servers/{}/{suffix}", config.server_id);
    let body = body.to_string();
    let mut sent = notify_send::relay(&config.relay_url, &seed, "POST", &path, body.as_bytes(), notify::now()).await;
    if notify::forgot_server(&sent) {
        if let Some(store) = shared_store() {
            if notify::register_again(&store).await == Sent::Ok {
                sent = notify_send::relay(&config.relay_url, &seed, "POST", &path, body.as_bytes(), notify::now()).await;
            }
        }
    }
    if let Sent::Failed(why) = sent {
        tracing::warn!("live activity update not sent: {why}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_lines_become_island_text() {
        assert_eq!(read_line("GRYONIXNEXUS_STEP 3/12\n"), (None, Some(0.25)));
        assert_eq!(read_line("\u{1b}[32mPulling images\u{1b}[0m\r\n").0.as_deref(), Some("Pulling images"));
        assert_eq!(read_line("GRYONIXNEXUS_UPDATE_DONE\n").0, None);
        assert_eq!(read_line("one\ntwo\n").0.as_deref(), Some("two"));
        assert_eq!(read_line("GRYONIXNEXUS_STEP 3/0").1, None);
    }

    #[test]
    fn the_state_matches_the_app() {
        let running = content_state("Pulling", Some(0.5), false, None);
        assert_eq!(running, json!({ "progressText": "Pulling", "isFinished": false, "progress": 0.5 }));
        let failed = content_state("Pulling", Some(0.5), true, Some("disk full"));
        assert_eq!(failed, json!({ "progressText": "Pulling", "isFinished": true, "errorMessage": "disk full" }));
    }

    #[test]
    fn only_watched_jobs_are_kept_and_the_end_forgets_them() {
        watch("job-live-test", "token", "Updating Nextcloud");
        line("job-live-test", "GRYONIXNEXUS_STEP 1/4\nStarting\n");
        {
            let all = watches().lock().unwrap();
            let kept = all.get("job-live-test").unwrap();
            assert_eq!((kept.text.as_str(), kept.progress), ("Starting", Some(0.25)));
        }
        line("other-job", "ignored");
        finished("job-live-test", None);
        assert!(watches().lock().unwrap().get("job-live-test").is_none());
    }

    #[test]
    fn the_outcome_is_shown_before_the_card_ends() {
        let watch = Watch::new("t", false, "Updating Nextcloud", "done".into());
        let (shown, closing) = ending_bodies(&watch, None, false, 1000);
        assert!(shown.get("end").is_none(), "the outcome must not end the card at once");
        assert_eq!(shown["alert"]["title"], "Completed successfully");
        assert_eq!(closing["end"], true);
        assert_eq!(shown["stale_at"], 1000 + LINGER + STALE_AFTER);
        let (failed_shown, failed) = ending_bodies(&watch, Some("disk full"), false, 1000);
        assert!(failed.get("dismiss_at").is_none(), "a failure stays on the lock screen");
        assert_eq!(failed_shown["stale_at"], 1000 + FAILED_LINGER + STALE_AFTER);
    }

    #[test]
    fn the_alert_speaks_the_owners_language() {
        assert_eq!(headline(false, true), "Успешно завершено");
        assert_eq!(headline(true, false), "Failed");
    }

    #[test]
    fn a_jobs_cards_and_the_apps_own_card_each_get_a_body() {
        let body = json!({ "token": "app-card", "state": {} });
        let mut watch = Watch::new("app-card", true, "Updating · immich", String::new());
        let bodies = watch.addressed("6ac-1", &body);
        assert_eq!(bodies.len(), 2);
        assert_eq!((bodies[0]["job"].as_str(), bodies[0]["token"].as_str()), (Some("6ac-1"), Some("")));
        assert_eq!(bodies[1]["token"], "app-card");
        watch.token.clear();
        assert_eq!(watch.addressed("6ac-1", &body).len(), 1);
        assert!(Watch::new("", false, "", String::new()).addressed("6ac-1", &body).is_empty());
    }

    #[test]
    fn the_start_carries_the_apps_attributes_and_a_kind_a_phone_can_switch_off() {
        let config = notify::Config { server_id: "srv-1".into(), ..Default::default() };
        let body = start_body("6ac-1", pb::JobKind::ContainerUpdate as i32, "Update · immich", "Starting…", &config);
        assert_eq!(body["kind"], "update");
        assert_eq!(body["attributes"]["jobID"], "6ac-1");
        assert_eq!(body["attributes"]["serverID"], "srv-1");
        assert_eq!(body["attributes"]["canStop"], true);
        assert!(body["attributes"]["startedAt"].as_i64().unwrap() > 700_000_000, "seconds since 2001, as Swift decodes a Date");
        assert_eq!(body["state"]["progressText"], "Starting…");
        assert_eq!(body["alert"]["title"], "Update · immich");
        assert_eq!(kind_word(pb::JobKind::ContainerRemoval as i32), "removal");
        assert_eq!(kind_word(pb::JobKind::SecurityControl as i32), "other");
    }

    #[test]
    fn the_scripts_step_counter_reaches_the_card() {
        assert_eq!(read_step("GRYONIXNEXUS_STEP 3/7 pulling\n"), Some((3, 7)));
        assert_eq!(read_step("GRYONIXNEXUS_STEP 1/4\nGRYONIXNEXUS_STEP 2/4\n"), Some((2, 4)));
        assert_eq!(read_step("GRYONIXNEXUS_STEP 9/4\n"), None);
        assert_eq!(read_step("plain output"), None);
        let mut watch = Watch::new("t", false, "Update", "Pulling".into());
        watch.step = Some((3, 7));
        let body = update_body(&mut watch);
        assert_eq!((body["state"]["step"].as_u64(), body["state"]["steps"].as_u64()), (Some(3), Some(7)));
    }

    #[test]
    fn a_step_spends_the_urgent_budget_at_most_once_a_minute() {
        let mut watch = Watch::new("t", false, "Update", "Pulling".into());
        assert_eq!(update_body(&mut watch)["urgent"], true, "the first step shows at once");
        assert_eq!(update_body(&mut watch)["urgent"], false, "the next one leaves the budget for the outcome");
        watch.last_urgent = Some(Instant::now() - URGENT_SPACING);
        assert_eq!(update_body(&mut watch)["urgent"], true);
    }

    #[test]
    fn the_sample_card_counts_in_the_owners_language() {
        assert_eq!(check_step(2, true), "Шаг 2 из 6");
        assert_eq!(check_step(6, false), "Step 6 of 6");
    }

    #[test]
    fn every_change_carries_a_newer_timestamp() {
        assert_eq!(rising(0, 1000), 1000);
        assert_eq!(rising(1000, 1000), 1001, "two changes in one second keep their order");
        assert_eq!(rising(1001, 1000), 1002);
    }
}
