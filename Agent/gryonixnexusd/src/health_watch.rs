//! Scheduled health checks: RAID, SMART and free space.
//!
//! Each check yields problems with stable ids such as `raid:md0`, so
//! `notify.rs` can send only what appeared or cleared since the last run.
//! A missing tool means nothing to check.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Raid,
    Smart,
    Space,
    Service,
    Backup,
    AgentUpdate,
    DriveStale,
    DriveReadOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    pub id: String,
    pub kind: Kind,
    /// The affected array, disk or mount
    pub subject: String,
    /// A short state word, or the fullness
    pub detail: String,
    /// What the service itself last said went wrong
    #[serde(default)]
    pub reason: String,
}

/// Arrays whose member map shows a missing disk, from /proc/mdstat
pub fn mdstat_problems(text: &str) -> Vec<Problem> {
    let mut found = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some((name, _)) = line.split_once(" : ") {
            let name = name.trim();
            current = name.starts_with("md").then(|| name.to_string());
            continue;
        }
        let Some(array) = &current else { continue };
        let Some(start) = line.rfind('[') else { continue };
        let map = &line[start + 1..];
        let Some(end) = map.find(']') else { continue };
        let map = &map[..end];
        if !map.is_empty() && map.chars().all(|c| c == 'U' || c == '_') {
            if map.contains('_') {
                found.push(Problem {
                    id: format!("raid:{array}"),
                    kind: Kind::Raid,
                    subject: array.clone(),
                    detail: "DEGRADED".into(),
        reason: String::new(),
                });
            }
            current = None;
        }
    }
    found
}

/// Pools that are not ONLINE, from `zpool list`
pub fn zpool_problems(text: &str) -> Vec<Problem> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let name = parts.next()?.trim();
            let health = parts.next()?.trim();
            (!name.is_empty() && health != "ONLINE").then(|| Problem {
                id: format!("raid:{name}"),
                kind: Kind::Raid,
                subject: name.to_string(),
                detail: health.to_string(),
        reason: String::new(),
            })
        })
        .collect()
}

/// Device paths from `smartctl --scan`
pub fn smart_devices(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|device| device.starts_with("/dev/"))
        .map(String::from)
        .collect()
}

/// A failed overall assessment in `smartctl -H --json=c` output
pub fn smart_problem(device: &str, json: &str) -> Option<Problem> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let passed = value.get("smart_status")?.get("passed")?.as_bool()?;
    (!passed).then(|| Problem {
        id: format!("smart:{device}"),
        kind: Kind::Smart,
        subject: device.to_string(),
        detail: "FAILED".into(),
        reason: String::new(),
    })
}

const REAL_FILESYSTEMS: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3"];

/// Mounts worth watching from /proc/mounts: real filesystems, each once
pub fn watched_mounts(text: &str) -> Vec<String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 || !REAL_FILESYSTEMS.contains(&fields[2]) {
            continue;
        }
        let (device, mount) = (fields[0], fields[1].replace("\\040", " "));
        if mount.starts_with("/boot") || mount.starts_with("/snap") {
            continue;
        }
        // Bind mounts repeat a device; keep the shortest path.
        match seen.get(device) {
            Some(existing) if existing.len() <= mount.len() => {}
            _ => {
                seen.insert(device.to_string(), mount);
            }
        }
    }
    let mut mounts: Vec<String> = seen.into_values().collect();
    mounts.sort();
    mounts
}

pub fn space_problem(mount: &str, size: i64, used: i64, limit_percent: u32) -> Option<Problem> {
    if size <= 0 {
        return None;
    }
    let percent = (used as f64 * 100.0 / size as f64).round() as i64;
    (percent >= limit_percent as i64).then(|| Problem {
        id: format!("space:{mount}"),
        kind: Kind::Space,
        subject: mount.to_string(),
        detail: percent.to_string(),
        reason: String::new(),
    })
}

/// Problems that appeared, and ones that cleared, since `before`
pub fn changes(before: &[Problem], now: &[Problem]) -> (Vec<Problem>, Vec<Problem>) {
    let appeared = now.iter().filter(|p| !before.iter().any(|b| b.id == p.id)).cloned().collect();
    let cleared = before.iter().filter(|b| !now.iter().any(|p| p.id == b.id)).cloned().collect();
    (appeared, cleared)
}

pub struct Checks {
    pub raid: bool,
    pub smart: bool,
    pub space: bool,
    pub space_percent: u32,
    pub services: bool,
    pub backups: bool,
    pub agent_update: bool,
}

/// Exit codes of a container someone stopped on purpose
const STOPPED_ON_PURPOSE: &[i32] = &[0, 137, 143];

pub fn service_problems(text: &str) -> Vec<Problem> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let (name, state, status) = (parts.next()?.trim(), parts.next()?.trim(), parts.next()?.trim());
            let detail = if state == "restarting" {
                "restarting"
            } else if status.contains("(unhealthy)") {
                "unhealthy"
            } else if state == "exited" && !STOPPED_ON_PURPOSE.contains(&exit_code(status)?) {
                "stopped"
            } else {
                return None;
            };
            Some(Problem {
                id: format!("service:{name}"),
                kind: Kind::Service,
                subject: name.to_string(),
                detail: detail.into(),
                reason: String::new(),
            })
        })
        .collect()
}

/// The newest log line that says what failed
pub fn error_line(log: &str) -> String {
    let lines: Vec<&str> = log.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let failing = lines.iter().rev().find(|l| {
        let lower = l.to_lowercase();
        lower.contains("fail") || lower.contains("error") || lower.contains("fatal") || lower.contains("panic")
    });
    let chosen = failing.or(lines.last()).copied().unwrap_or_default();
    let skip = chosen.chars().count().saturating_sub(160);
    chosen.chars().skip(skip).collect()
}

async fn last_error(container: &str) -> String {
    let run = tokio::process::Command::new("docker").args(["logs", "--tail", "30", container]).output();
    let Ok(Ok(out)) = tokio::time::timeout(std::time::Duration::from_secs(10), run).await else { return String::new() };
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    error_line(&text)
}

fn exit_code(status: &str) -> Option<i32> {
    status.strip_prefix("Exited (")?.split(')').next()?.parse().ok()
}

/// The backup timer's last result from `systemctl show`
pub fn backup_timer_problem(result: &str) -> Option<Problem> {
    let result = result.trim();
    (!result.is_empty() && result != "success").then(|| Problem {
        id: "backup:services".into(),
        kind: Kind::Backup,
        subject: "services".into(),
        detail: result.to_string(),
        reason: String::new(),
    })
}

/// A failed shipment in the destination status file
pub fn backup_destination_problem(status: &str) -> Option<Problem> {
    let value = |key: &str| status.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim_matches('\'').to_string());
    (value("OK=")? == "0").then(|| Problem {
        id: "backup:destination".into(),
        kind: Kind::Backup,
        subject: "destination".into(),
        detail: value("ERROR=").unwrap_or_default().chars().take(120).collect(),
        reason: String::new(),
    })
}

/// A drive copy that failed, from the drive status file
pub fn backup_drive_problem(status: &str) -> Option<Problem> {
    let value = |key: &str| status.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim_matches('\'').to_string());
    (value("DRIVE_OK=")? == "0").then(|| Problem {
        id: "backup:drives".into(),
        kind: Kind::Backup,
        subject: "USB drives".into(),
        detail: value("DRIVE_ERROR=").unwrap_or_default().chars().take(120).collect(),
        reason: String::new(),
    })
}

pub fn agent_update_problem(version: Option<String>) -> Option<Problem> {
    version.map(|v| Problem { id: format!("agent-update:{v}"), kind: Kind::AgentUpdate, subject: v, detail: String::new(), reason: String::new() })
}

async fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::process::Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .ok()?
    .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Runs the enabled checks on this host
pub async fn probe(checks: &Checks, failed_groups: &[(String, String)]) -> Vec<Problem> {
    let mut found = disk_problems(checks).await;
    if checks.services {
        let format = "{{.Names}}\t{{.State}}\t{{.Status}}";
        if let Some(text) = output("docker", &["ps", "-a", "--format", format]).await {
            for mut problem in service_problems(&text) {
                problem.reason = last_error(&problem.subject).await;
                found.push(problem);
            }
        }
    }
    if checks.backups {
        found.extend(backup_problems(failed_groups).await);
    }
    if checks.agent_update {
        found.extend(agent_update_problem(crate::agent_update::available_version()));
    }
    found
}

async fn backup_problems(failed_groups: &[(String, String)]) -> Vec<Problem> {
    let mut found = Vec::new();
    let args = ["show", "gryonixnexus-autobackup.service", "-p", "Result", "--value"];
    if let Some(result) = output("systemctl", &args).await {
        found.extend(backup_timer_problem(&result));
    }
    if let Ok(status) = tokio::fs::read_to_string("/etc/gryonixnexus/autobackup-dest.status").await {
        found.extend(backup_destination_problem(&status));
    }
    if let Ok(status) = tokio::fs::read_to_string("/etc/gryonixnexus/backup-drives.status").await {
        found.extend(backup_drive_problem(&status));
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    found.extend(crate::drive_watch::problems(now));
    found.extend(failed_groups.iter().map(|(key, outcome)| Problem {
        id: format!("backup:{key}"),
        kind: Kind::Backup,
        subject: key.clone(),
        detail: outcome.trim_start_matches("failed: ").chars().take(120).collect(),
        reason: String::new(),
    }));
    found
}

async fn disk_problems(checks: &Checks) -> Vec<Problem> {
    let mut found = Vec::new();
    if checks.raid {
        if let Ok(text) = tokio::fs::read_to_string("/proc/mdstat").await {
            found.extend(mdstat_problems(&text));
        }
        if let Some(text) = output("zpool", &["list", "-H", "-o", "name,health"]).await {
            found.extend(zpool_problems(&text));
        }
    }
    if checks.smart {
        if let Some(scan) = output("smartctl", &["--scan"]).await {
            for device in smart_devices(&scan) {
                if let Some(json) = output("smartctl", &["-n", "standby", "-H", "--json=c", &device]).await {
                    found.extend(smart_problem(&device, &json));
                }
            }
        }
    }
    if checks.space {
        if let Ok(text) = tokio::fs::read_to_string("/proc/mounts").await {
            for mount in watched_mounts(&text) {
                if let Some((size, used)) = crate::metrics::statvfs_usage(&mount) {
                    found.extend(space_problem(&mount, size, used, checks.space_percent));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDSTAT: &str = "Personalities : [raid1] [raid6] [raid5]
md1 : active raid1 sdb1[1] sda1[0]
      976630464 blocks super 1.2 [2/2] [UU]
      bitmap: 0/8 pages [0KB], 65536KB chunk

md2 : active raid5 sde1[3] sdd1[1] sdc1[0]
      1953260544 blocks super 1.2 level 5, 512k chunk, algorithm 2 [3/2] [UU_]

unused devices: <none>
";

    #[test]
    fn a_failed_drive_copy_is_a_backup_problem() {
        let problem = backup_drive_problem("DRIVE_AT=1\nDRIVE_OK=0\nDRIVE_ERROR='usb1: not connected;'\n").unwrap();
        assert_eq!(problem.id, "backup:drives");
        assert_eq!(problem.detail, "usb1: not connected;");
        assert!(backup_drive_problem("DRIVE_AT=1\nDRIVE_OK=1\nDRIVE_ERROR=''\n").is_none());
        assert!(backup_drive_problem("").is_none());
    }

    #[test]
    fn a_missing_member_marks_only_that_array() {
        let found = mdstat_problems(MDSTAT);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "raid:md2");
        assert_eq!(found[0].detail, "DEGRADED");
    }

    #[test]
    fn the_bitmap_line_is_not_a_member_map() {
        assert!(mdstat_problems("md0 : active raid1 sda1[0]\n      100 blocks [2/2] [UU]\n      bitmap: 0/8 pages [0KB]\n").is_empty());
    }

    #[test]
    fn pools_that_are_not_online() {
        let found = zpool_problems("tank\tONLINE\nbackup\tDEGRADED\n");
        assert_eq!(found, vec![Problem { id: "raid:backup".into(), kind: Kind::Raid, subject: "backup".into(), detail: "DEGRADED".into(), reason: String::new() }]);
    }

    #[test]
    fn smart_verdicts() {
        assert_eq!(smart_devices("/dev/sda -d sat # /dev/sda [SAT], ATA device\n/dev/nvme0 -d nvme # /dev/nvme0, NVMe device\n"), vec!["/dev/sda", "/dev/nvme0"]);
        assert!(smart_problem("/dev/sda", r#"{"smart_status":{"passed":true}}"#).is_none());
        assert_eq!(smart_problem("/dev/sda", r#"{"smart_status":{"passed":false}}"#).unwrap().id, "smart:/dev/sda");
        assert!(smart_problem("/dev/sda", r#"{"smartctl":{"exit_status":2}}"#).is_none());
    }

    #[test]
    fn mounts_skip_pseudo_filesystems_and_bind_repeats() {
        let mounts = "/dev/sda2 / ext4 rw 0 0
proc /proc proc rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda1 /boot/firmware vfat rw 0 0
/dev/sdb1 /srv/data ext4 rw 0 0
/dev/sdb1 /srv/data/nested ext4 rw 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0
tank/media /mnt/my\\040media zfs rw 0 0
";
        assert_eq!(watched_mounts(mounts), vec!["/", "/mnt/my media", "/srv/data"]);
    }

    #[test]
    fn space_over_the_limit() {
        assert!(space_problem("/", 100, 89, 90).is_none());
        assert_eq!(space_problem("/", 100, 93, 90).unwrap().detail, "93");
        assert!(space_problem("/", 0, 0, 90).is_none());
    }

    #[test]
    fn only_changes_are_reported() {
        let a = space_problem("/", 100, 95, 90).unwrap();
        let b = mdstat_problems(MDSTAT).remove(0);
        let (appeared, cleared) = changes(&[a.clone()], &[a.clone(), b.clone()]);
        assert_eq!((appeared, cleared), (vec![b.clone()], vec![]));
        let (appeared, cleared) = changes(&[a.clone(), b.clone()], &[b]);
        assert_eq!((appeared, cleared), (vec![], vec![a]));
    }

    #[test]
    fn containers_that_died_or_loop_are_problems() {
        let text = "nextcloud-app-1\trunning\tUp 2 hours (healthy)\n\
                    immich\texited\tExited (1) 5 minutes ago\n\
                    seafile\texited\tExited (0) 1 hour ago\n\
                    jellyfin\texited\tExited (137) 2 days ago\n\
                    ha\trestarting\tRestarting (1) 3 seconds ago\n\
                    db\trunning\tUp 1 minute (unhealthy)\n";
        let found: Vec<(String, String)> = service_problems(text).into_iter().map(|p| (p.subject, p.detail)).collect();
        assert_eq!(found, vec![
            ("immich".to_string(), "stopped".to_string()),
            ("ha".to_string(), "restarting".to_string()),
            ("db".to_string(), "unhealthy".to_string()),
        ]);
    }

    #[test]
    fn a_failed_backup_timer_or_shipment_is_a_problem() {
        assert!(backup_timer_problem("success\n").is_none());
        assert!(backup_timer_problem("").is_none());
        assert_eq!(backup_timer_problem("exit-code").unwrap().detail, "exit-code");
        assert!(backup_destination_problem("OK=1\nERROR=''\n").is_none());
        let failed = backup_destination_problem("OK=0\nERROR='connection refused'\n").unwrap();
        assert_eq!((failed.id.as_str(), failed.detail.as_str()), ("backup:destination", "connection refused"));
    }

    #[test]
    fn a_published_agent_is_one_problem_per_version() {
        assert!(agent_update_problem(None).is_none());
        assert_eq!(agent_update_problem(Some("0.0.131".into())).unwrap().id, "agent-update:0.0.131");
    }

    #[test]
    fn the_reason_is_the_newest_failing_line() {
        let log = "Xray 26.7.11 started\n[Warning] REALITY: non-443\nFailed to start: User iPhone already exists.\nXray 26.7.11\n";
        assert_eq!(error_line(log), "Failed to start: User iPhone already exists.");
        assert_eq!(error_line("booting\nlistening on :80\n"), "listening on :80");
        assert_eq!(error_line(""), "");
    }
}
