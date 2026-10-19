//! Health of the chosen backup drives: copies too old, read-only mounts.

use crate::backup_drive::{fstab_target, parse_settings};
use crate::health_watch::{Kind, Problem};
use crate::pb;

const CONFIG_DIR: &str = "/etc/gryonixnexus";

/// Seconds between runs of an `every:<n><h|d>@HH:MM` schedule
pub fn schedule_seconds(schedule: &str) -> Option<i64> {
    let every = schedule.strip_prefix("every:")?.split('@').next()?;
    let unit = every.chars().last()?;
    let count: i64 = every[..every.len() - unit.len_utf8()].parse().ok()?;
    match unit {
        'h' => Some(count * 3_600),
        'd' => Some(count * 86_400),
        _ => None,
    }
}

/// Drives in use, or none when copies stay local
fn chosen(config: &str) -> Vec<String> {
    let drives = parse_settings(config, "");
    if drives.mode == pb::BackupDriveMode::Local as i32 {
        return Vec::new();
    }
    drives.uuids
}

fn drive_label(fstab: &str, uuid: &str) -> String {
    fstab_target(fstab, uuid)
        .and_then(|target| target.rsplit('/').next().map(str::to_string))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| uuid.to_string())
}

/// When a drive last took a copy
fn last_copy(last: &str, uuid: &str) -> Option<i64> {
    last.lines().find_map(|line| {
        let (id, at) = line.split_once(' ')?;
        (id == uuid).then(|| at.trim().parse().ok()).flatten()
    })
}

/// Drives without a copy for two runs and a day
pub fn stale_problems(config: &str, last: &str, schedule: &str, fstab: &str, now: i64) -> Vec<Problem> {
    let Some(interval) = schedule_seconds(schedule) else { return Vec::new() };
    let limit = 2 * interval + 86_400;
    chosen(config)
        .into_iter()
        .filter_map(|uuid| {
            let age = now - last_copy(last, &uuid)?;
            (age > limit).then(|| Problem {
                id: format!("backup:drive-stale:{uuid}"),
                kind: Kind::DriveStale,
                subject: drive_label(fstab, &uuid),
                detail: (age / 86_400).to_string(),
                reason: String::new(),
            })
        })
        .collect()
}

fn mounted_read_only(mounts: &str, target: &str) -> bool {
    mounts.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() > 3 && fields[1] == target && fields[3].split(',').any(|option| option == "ro")
    })
}

/// Drives the kernel remounted read-only
pub fn read_only_problems(config: &str, fstab: &str, mounts: &str) -> Vec<Problem> {
    chosen(config)
        .into_iter()
        .filter_map(|uuid| {
            let target = fstab_target(fstab, &uuid)?;
            mounted_read_only(mounts, &target).then(|| Problem {
                id: format!("backup:drive-ro:{uuid}"),
                kind: Kind::DriveReadOnly,
                subject: drive_label(fstab, &uuid),
                detail: String::new(),
                reason: String::new(),
            })
        })
        .collect()
}

/// Both drive checks, read off this host
pub fn problems(now: i64) -> Vec<Problem> {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let config = read(&format!("{CONFIG_DIR}/backup-drives.conf"));
    if config.is_empty() {
        return Vec::new();
    }
    let fstab = read("/etc/fstab");
    let last = read(&format!("{CONFIG_DIR}/backup-drives.last"));
    let schedule = crate::backup::read_backup_schedule().schedule;
    let mut found = stale_problems(&config, &last, &schedule, &fstab, now);
    found.extend(read_only_problems(&config, &fstab, &read("/proc/mounts")));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "0d3e5f7a-1b2c-4d5e-8f90-a1b2c3d4e5f6";
    const FSTAB: &str = "UUID=0d3e5f7a-1b2c-4d5e-8f90-a1b2c3d4e5f6 /srv/gryonix-backup/usb1 ext4 nofail 0 2\n";
    const CONFIG: &str = "DRIVE_MODE=both\nDRIVE_ENCRYPT=1\nDRIVES='0d3e5f7a-1b2c-4d5e-8f90-a1b2c3d4e5f6'\n";
    const DAY: i64 = 86_400;

    fn last(at: i64) -> String {
        format!("{UUID} {at}\n")
    }

    #[test]
    fn schedules_turn_into_seconds() {
        assert_eq!(schedule_seconds("every:1d@03:30"), Some(DAY));
        assert_eq!(schedule_seconds("every:6h@00:15"), Some(6 * 3_600));
        assert_eq!(schedule_seconds("off"), None);
        assert_eq!(schedule_seconds("every:xd@03:30"), None);
    }

    #[test]
    fn a_drive_without_copies_for_too_long_is_stale() {
        let now = 100 * DAY;
        let problems = stale_problems(CONFIG, &last(now - 4 * DAY), "every:1d@03:30", FSTAB, now);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].id, format!("backup:drive-stale:{UUID}"));
        assert_eq!(problems[0].subject, "usb1");
        assert_eq!(problems[0].detail, "4");
        assert!(stale_problems(CONFIG, &last(now - 2 * DAY), "every:1d@03:30", FSTAB, now).is_empty());
    }

    #[test]
    fn no_stale_alert_without_schedule_history_or_drive_use() {
        let now = 100 * DAY;
        let old = last(now - 30 * DAY);
        assert!(stale_problems(CONFIG, &old, "off", FSTAB, now).is_empty());
        assert!(stale_problems(CONFIG, "", "every:1d@03:30", FSTAB, now).is_empty());
        let local = CONFIG.replace("DRIVE_MODE=both", "DRIVE_MODE=local");
        assert!(stale_problems(&local, &old, "every:1d@03:30", FSTAB, now).is_empty());
    }

    #[test]
    fn a_read_only_drive_is_a_problem() {
        let mounts = "/dev/sdb1 /srv/gryonix-backup/usb1 ext4 ro,noatime 0 0\n";
        let problems = read_only_problems(CONFIG, FSTAB, mounts);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].id, format!("backup:drive-ro:{UUID}"));
        assert_eq!(problems[0].subject, "usb1");
        let writable = "/dev/sdb1 /srv/gryonix-backup/usb1 ext4 rw,noatime,errors=remount-ro 0 0\n";
        assert!(read_only_problems(CONFIG, FSTAB, writable).is_empty());
        assert!(read_only_problems(CONFIG, FSTAB, "").is_empty());
    }
}
