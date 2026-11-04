//! Stopping a wrapper's backup work so the wrapper cleans up after itself.

use std::collections::HashMap;
use std::time::Duration;

use crate::jobs::CancelSwitch;

/// Programs that only copy, pack, dump or download
const STOPPABLE: [&str; 11] = ["tar", "gzip", "pigz", "zstd", "xz", "gpg", "rclone", "rsync", "ssh", "scp", "sftp"];

/// What a `docker` command may be doing to be stopped
const STOPPABLE_DOCKER: [&str; 5] = ["pg_dump", "pg_dumpall", "mysqldump", "mariadb-dump", "pull"];

/// Whether a stop may end this command line
pub fn is_stoppable(args: &[String]) -> bool {
    let Some(program) = args.first().map(|first| first.rsplit('/').next().unwrap_or(first)) else {
        return false;
    };
    if STOPPABLE.contains(&program) {
        return true;
    }
    program == "docker" && args.iter().skip(1).any(|arg| STOPPABLE_DOCKER.contains(&arg.as_str()))
}

/// Waits for the stop, then ends backup work every second
pub async fn watch(switch: Option<&CancelSwitch>, leader: Option<u32>, said: impl std::future::Future<Output = ()>) {
    let (Some(switch), Some(leader)) = (switch, leader) else {
        return std::future::pending().await;
    };
    switch.wait().await;
    said.await;
    loop {
        end_backup_work(leader);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Sends SIGTERM to the leader's stoppable descendants
pub fn end_backup_work(leader: u32) -> usize {
    let parents = parents();
    let mut ended = 0;
    for (&pid, _) in parents.iter().filter(|(&pid, _)| descends_from(pid, leader, &parents)) {
        if is_stoppable(&command_line(pid)) {
            // SAFETY: kill(2) takes plain integers.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            ended += 1;
        }
    }
    ended
}

fn descends_from(pid: u32, leader: u32, parents: &HashMap<u32, u32>) -> bool {
    let mut current = pid;
    for _ in 0..64 {
        match parents.get(&current) {
            Some(&parent) if parent == leader => return true,
            Some(&parent) if parent > 1 => current = parent,
            _ => return false,
        }
    }
    false
}

/// Every process's parent, read from /proc
fn parents() -> HashMap<u32, u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return HashMap::new() };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            Some((pid, parent_in_stat(&stat)?))
        })
        .collect()
}

/// The fourth field, after the parenthesised name
fn parent_in_stat(stat: &str) -> Option<u32> {
    stat[stat.rfind(')')? + 1..].split_whitespace().nth(1)?.parse().ok()
}

fn command_line(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn packing_dumping_and_pulling_may_be_stopped() {
        assert!(is_stoppable(&args("tar --numeric-owner -czf /opt/backups/x.tar.gz data")));
        assert!(is_stoppable(&args("/usr/bin/gpg --batch --symmetric")));
        assert!(is_stoppable(&args("docker compose -p nextcloud exec -T db mysqldump nextcloud")));
        assert!(is_stoppable(&args("docker exec immich-database-1 pg_dumpall -U postgres")));
        assert!(is_stoppable(&args("docker compose -p immich pull -q")));
    }

    #[test]
    fn recreating_and_the_wrapper_itself_are_left_alone() {
        assert!(!is_stoppable(&args("docker compose -p immich up -d")));
        assert!(!is_stoppable(&args("bash /opt/gryonixnexus-update-ctl.sh run immich")));
        assert!(!is_stoppable(&args("cp -a a b")));
        assert!(!is_stoppable(&[]));
    }

    #[test]
    fn the_parent_is_read_past_a_name_with_spaces() {
        assert_eq!(parent_in_stat("1234 (tar (x) y) S 1200 1234 1200 0"), Some(1200));
        assert_eq!(parent_in_stat("garbage"), None);
    }

    #[test]
    fn only_descendants_of_the_leader_count() {
        let parents = HashMap::from([(10, 1), (20, 10), (30, 20), (40, 1)]);
        assert!(descends_from(20, 10, &parents));
        assert!(descends_from(30, 10, &parents));
        assert!(!descends_from(40, 10, &parents));
        assert!(!descends_from(10, 10, &parents));
    }
}
