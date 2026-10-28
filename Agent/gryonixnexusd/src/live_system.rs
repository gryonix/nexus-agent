//! Moves a system update's island card from the updater's own log

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// The job id of a handed-over system update
pub const JOB: &str = "system-update";
const LOG: &str = "/var/log/gryonixnexus-system-update.log";
const EXIT_MARK: &str = "GRYONIXNEXUS_SYSTEM_EXIT:";
const EVERY: Duration = Duration::from_secs(3);
const LONGEST: Duration = Duration::from_secs(3 * 3600);
/// A log this fresh belongs to the run being watched
const RECENT: Duration = Duration::from_secs(15 * 60);

static FOLLOWING: AtomicBool = AtomicBool::new(false);

fn log_path() -> String {
    std::env::var("GRYONIXNEXUSD_SYSTEM_UPDATE_LOG").unwrap_or_else(|_| LOG.to_string())
}

/// Starts reading the log, once at a time
pub fn follow() {
    if FOLLOWING.swap(true, Ordering::SeqCst) {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        FOLLOWING.store(false, Ordering::SeqCst);
        return;
    };
    // A run ended before the hand-over still closes its card
    let since = SystemTime::now() - RECENT;
    runtime.spawn(async move {
        read_until_done(&log_path(), since).await;
        FOLLOWING.store(false, Ordering::SeqCst);
    });
}

async fn read_until_done(path: &str, since: SystemTime) {
    let deadline = Instant::now() + LONGEST;
    let mut shown = String::new();
    let mut first = true;
    while Instant::now() < deadline {
        if !std::mem::take(&mut first) {
            tokio::time::sleep(EVERY).await;
        }
        let Some(text) = fresh_log(path, since) else { continue };
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

/// The log, once this run has written it
fn fresh_log(path: &str, since: SystemTime) -> Option<String> {
    let modified = std::fs::metadata(path).and_then(|meta| meta.modified()).ok()?;
    (modified >= since).then(|| std::fs::read_to_string(path).ok()).flatten()
}

/// The updater's exit code, once it wrote one
pub fn exit_code(text: &str) -> Option<i32> {
    text.lines().rev().find_map(|line| line.trim().strip_prefix(EXIT_MARK)?.trim().parse().ok())
}

/// The newest readable line of the log
pub fn last_line(text: &str) -> Option<String> {
    text.lines()
        .rev()
        .map(|line| line.trim().trim_start_matches("## ").to_string())
        .find(|line| !line.is_empty() && !line.starts_with(EXIT_MARK))
}

fn failure(code: i32) -> Option<String> {
    if code == 0 {
        return None;
    }
    let russian = crate::live::config().is_some_and(|c| c.russian());
    Some(if russian { format!("Обновление завершилось с кодом {code}") } else { format!("The update ended with code {code}") })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_mark_ends_the_card() {
        assert_eq!(exit_code("## apt-get update\nok\nGRYONIXNEXUS_SYSTEM_EXIT:0\n"), Some(0));
        assert_eq!(exit_code("## apt-get upgrade\nGRYONIXNEXUS_SYSTEM_EXIT:100\n"), Some(100));
        assert_eq!(exit_code("## apt-get update\nGet:1 http://deb.example.org stable\n"), None);
    }

    #[test]
    fn the_card_shows_the_newest_line_without_markers() {
        assert_eq!(last_line("## apt-get update\n\n").as_deref(), Some("apt-get update"));
        assert_eq!(last_line("Setting up curl\nGRYONIXNEXUS_SYSTEM_EXIT:0\n").as_deref(), Some("Setting up curl"));
        assert_eq!(last_line(""), None);
    }

    #[test]
    fn a_log_older_than_the_hand_over_is_the_previous_run() {
        let path = std::env::temp_dir().join(format!("system-update-{}.log", std::process::id()));
        std::fs::write(&path, "GRYONIXNEXUS_SYSTEM_EXIT:0\n").unwrap();
        let later = SystemTime::now() + Duration::from_secs(60);
        assert!(fresh_log(path.to_str().unwrap(), later).is_none());
        assert!(fresh_log(path.to_str().unwrap(), SystemTime::UNIX_EPOCH).is_some());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_failure_names_the_code_and_success_names_nothing() {
        assert!(failure(0).is_none());
        assert!(failure(100).unwrap().contains("100"));
    }
}
