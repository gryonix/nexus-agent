//! Moves the island card of an agent build from the build's log

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The job id of a handed-over agent build
pub const JOB: &str = "agent-build";
const LOG_NAME: &str = ".gryonixnexus-agent-build.log";
const EXIT_MARK: &str = "GRYONIXNEXUS_AGENT_BUILD_EXIT=";
const CARD_FILE: &str = "agent-build-card.json";
const EVERY: Duration = Duration::from_secs(3);
const LONGEST: Duration = Duration::from_secs(3 * 3600);

static FOLLOWING: AtomicBool = AtomicBool::new(false);

/// The card a restart must not lose
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Card {
    token: String,
    title: String,
    since: u64,
}

fn card_path() -> PathBuf {
    crate::util::state_dir().join(CARD_FILE)
}

fn homes() -> Vec<PathBuf> {
    let root = std::env::var("GRYONIXNEXUSD_BUILD_HOMES").unwrap_or_else(|_| "/root:/home/*".to_string());
    root.split(':').flat_map(expand).collect()
}

/// A home pattern, `*` standing for every directory
fn expand(pattern: &str) -> Vec<PathBuf> {
    let Some(parent) = pattern.strip_suffix("/*") else { return vec![PathBuf::from(pattern)] };
    std::fs::read_dir(parent)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default()
}

/// The newest build log in any home
fn newest_log(homes: &[PathBuf]) -> Option<(PathBuf, SystemTime)> {
    homes
        .iter()
        .map(|home| home.join(LOG_NAME))
        .filter_map(|path| Some((path.clone(), std::fs::metadata(&path).ok()?.modified().ok()?)))
        .max_by_key(|(_, modified)| *modified)
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The app handed the card over: keep it, then follow
pub fn follow(token: &str, title: &str) {
    let since = unix(SystemTime::now()).saturating_sub(2);
    let card = Card { token: token.to_string(), title: title.to_string(), since };
    if let Ok(text) = serde_json::to_string(&card) {
        let _ = crate::util::write_file_atomic(&card_path(), text.as_bytes(), 0o600);
    }
    start(since);
}

/// Takes over the kept card when the agent starts
pub fn resume() {
    let Some(card) = std::fs::read_to_string(card_path()).ok().and_then(|t| serde_json::from_str::<Card>(&t).ok())
    else {
        return;
    };
    if unix(SystemTime::now()).saturating_sub(card.since) > LONGEST.as_secs() {
        let _ = std::fs::remove_file(card_path());
        return;
    }
    crate::live::watch(JOB, &card.token, &card.title);
    start(card.since);
}

fn start(since: u64) {
    if FOLLOWING.swap(true, Ordering::SeqCst) {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        FOLLOWING.store(false, Ordering::SeqCst);
        return;
    };
    runtime.spawn(async move {
        read_until_done(UNIX_EPOCH + Duration::from_secs(since)).await;
        let _ = std::fs::remove_file(card_path());
        FOLLOWING.store(false, Ordering::SeqCst);
    });
}

async fn read_until_done(since: SystemTime) {
    let deadline = Instant::now() + LONGEST;
    let mut shown = String::new();
    while Instant::now() < deadline {
        tokio::time::sleep(EVERY).await;
        let Some(text) = fresh_log(&homes(), since) else { continue };
        if let Some(code) = exit_code(&text) {
            crate::live::finished(JOB, failure(code).as_deref());
            return;
        }
        if let Some(line) = last_line(&text).filter(|line| *line != shown) {
            crate::live::line(JOB, &line);
            shown = line;
        }
    }
}

/// This build's log, once it has written it
fn fresh_log(homes: &[PathBuf], since: SystemTime) -> Option<String> {
    let (path, modified) = newest_log(homes)?;
    (modified >= since).then(|| read(&path)).flatten()
}

fn read(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| crate::util::strip_ansi(&String::from_utf8_lossy(&bytes)))
}

/// The build's exit code, once it wrote one
pub fn exit_code(text: &str) -> Option<i32> {
    text.lines().rev().find_map(|line| line.trim().strip_prefix(EXIT_MARK)?.trim().parse().ok())
}

/// The newest readable line of the log
pub fn last_line(text: &str) -> Option<String> {
    text.lines()
        .rev()
        .map(|line| line.trim().to_string())
        .find(|line| !line.is_empty() && !line.starts_with(EXIT_MARK))
}

fn failure(code: i32) -> Option<String> {
    if code == 0 {
        return None;
    }
    let russian = crate::live::config().is_some_and(|c| c.russian());
    Some(if russian {
        format!("Сборка агента завершилась с кодом {code}")
    } else {
        format!("The agent build ended with code {code}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("live-build-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_exit_mark_ends_the_card() {
        assert_eq!(exit_code("Compiling tokio v1\nGRYONIXNEXUS_AGENT_BUILD_EXIT=0\n"), Some(0));
        assert_eq!(exit_code("error: could not compile\nGRYONIXNEXUS_AGENT_BUILD_EXIT=101\n"), Some(101));
        assert_eq!(exit_code("Compiling tokio v1\n"), None);
    }

    #[test]
    fn the_card_shows_the_newest_line() {
        assert_eq!(last_line("Compiling hyper v1\n\n").as_deref(), Some("Compiling hyper v1"));
        assert_eq!(last_line("restarting the agent\nGRYONIXNEXUS_AGENT_BUILD_EXIT=0\n").as_deref(), Some("restarting the agent"));
        assert_eq!(last_line(""), None);
    }

    #[test]
    fn the_newest_log_of_any_home_is_read() {
        let base = scratch("homes");
        let (old, new) = (base.join("orion"), base.join("draco"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join(LOG_NAME), "old run\n").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(new.join(LOG_NAME), "\u{1b}[1mCompiling serde\u{1b}[0m\n").unwrap();
        let homes = expand(&format!("{}/*", base.display()));
        let text = fresh_log(&homes, UNIX_EPOCH).unwrap();
        assert_eq!(last_line(&text).as_deref(), Some("Compiling serde"));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn a_log_older_than_the_hand_over_is_the_previous_run() {
        let base = scratch("old");
        std::fs::write(base.join(LOG_NAME), "GRYONIXNEXUS_AGENT_BUILD_EXIT=0\n").unwrap();
        let later = SystemTime::now() + Duration::from_secs(60);
        assert!(fresh_log(&[base.clone()], later).is_none());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn the_kept_card_reads_back() {
        let card = Card { token: "t".into(), title: "Installing the agent".into(), since: 42 };
        let text = serde_json::to_string(&card).unwrap();
        assert_eq!(serde_json::from_str::<Card>(&text).unwrap(), card);
    }

    #[test]
    fn a_failure_names_the_code_and_success_names_nothing() {
        assert!(failure(0).is_none());
        assert!(failure(101).unwrap().contains("101"));
    }
}
