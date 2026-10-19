//! The agent's own backup timer for stranger's container groups

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::pb;
use crate::state::Store;

/// How often the scheduler looks
const TICK_SECS: u64 = 15 * 60;

pub const DAILY: &str = "daily";
pub const WEEKLY: &str = "weekly";
pub const MONTHLY: &str = "monthly";

/// The three the UI offers
pub fn is_valid(schedule: &str) -> bool {
    matches!(schedule, DAILY | WEEKLY | MONTHLY)
}

fn window_secs(schedule: &str) -> Option<i64> {
    match schedule {
        DAILY => Some(24 * 60 * 60),
        WEEKLY => Some(7 * 24 * 60 * 60),
        MONTHLY => Some(30 * 24 * 60 * 60),
        _ => None,
    }
}

/// Is this group due, given when it last ran?
pub fn is_due(schedule: &str, last_run: i64, now: i64) -> bool {
    let Some(window) = window_secs(schedule) else { return false };
    if last_run <= 0 {
        return true;
    }
    now.saturating_sub(last_run) >= window
}

/// Start the scheduler
pub fn spawn(store: Arc<Mutex<Store>>) {
    tokio::spawn(async move {
        loop {
            run_due(&store).await;
            tokio::time::sleep(Duration::from_secs(TICK_SECS)).await;
        }
    });
}

/// One pass: back up everything whose turn has come.
pub async fn run_due(store: &Arc<Mutex<Store>>) {
    let now = now_secs();
    let due: Vec<String> = {
        let guard = match store.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        match guard.container_backup_schedules() {
            Ok(rows) => rows
                .into_iter()
                .filter(|(_, schedule, last_run)| is_due(schedule, *last_run, now))
                .map(|(key, _, _)| key)
                .collect(),
            Err(err) => {
                tracing::warn!("container backup schedule could not be read: {err}");
                return;
            }
        }
    };

    for key in due {
        let outcome = run_one(store, &key).await;
        let text = match &outcome {
            Ok(archive) => format!("ok {archive}"),
            Err(err) => format!("failed: {err}"),
        };
        if let Ok(guard) = store.lock() {
            let _ = guard.record_container_backup_run(&key, now_secs(), &text);
        }
        match outcome {
            Ok(archive) => tracing::info!("scheduled backup of {key} wrote {archive}"),
            Err(err) => tracing::warn!("scheduled backup of {key} failed: {err}"),
        }
    }
}

async fn run_one(store: &Arc<Mutex<Store>>, key: &str) -> Result<String, String> {
    let names = store
        .lock()
        .map_err(|_| "the agent's state is locked".to_string())?
        .container_names()
        .map_err(|err| err.to_string())?;
    let stored = store
        .lock()
        .map_err(|_| "the agent's state is locked".to_string())?
        .container_backup_plan(key)
        .map_err(|err| err.to_string())?;

    let (group, details) = crate::containers::details_of_group(key, &names)
        .await
        .map_err(|refusal| refusal.reason())?;
    let plan = crate::container_backup::effective(key, &details, stored);
    let kind = crate::containers::kind_of_group(&group);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let encode = |_: &'static str, _: String| bytes::Bytes::new();
    let archive =
        crate::container_backup_run::run_for_update(key, kind, &plan, &details, &tx, &encode).await;
    drop(tx);
    let _ = drain.await;
    archive.map(|a| a.path)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn schedule_of(store: &Mutex<Store>, key: &str) -> pb::ContainerBackupSchedule {
    let stored = store.lock().ok().and_then(|guard| guard.container_backup_schedule(key).ok().flatten());
    stored.unwrap_or(pb::ContainerBackupSchedule {
        key: key.to_string(),
        schedule: String::new(),
        enabled: false,
        last_outcome: String::new(),
        last_run: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60;

    #[test]
    fn only_the_three_offered_schedules_are_accepted() {
        assert!(is_valid(DAILY) && is_valid(WEEKLY) && is_valid(MONTHLY));
        assert!(!is_valid("Mon *-*-* 03:00:00"));
        assert!(!is_valid("hourly"));
        assert!(!is_valid(""));
    }

    #[test]
    fn a_group_that_never_ran_is_due_at_once() {
        assert!(is_due(DAILY, 0, 1_000_000));
        assert!(is_due(MONTHLY, 0, 1_000_000));
    }

    #[test]
    fn a_group_is_due_once_its_window_has_passed() {
        let now = 100 * DAY;
        assert!(!is_due(DAILY, now - DAY / 2, now));
        assert!(is_due(DAILY, now - DAY, now));

        assert!(!is_due(WEEKLY, now - 6 * DAY, now));
        assert!(is_due(WEEKLY, now - 7 * DAY, now));

        assert!(!is_due(MONTHLY, now - 29 * DAY, now));
        assert!(is_due(MONTHLY, now - 30 * DAY, now));

        assert!(!is_due("fortnightly", 0, now));
    }

    #[test]
    fn a_backwards_clock_does_not_make_everything_due() {
        let now = 10 * DAY;
        assert!(!is_due(DAILY, now + 5 * DAY, now));
    }
}
