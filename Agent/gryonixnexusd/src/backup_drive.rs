//! USB drives that hold a second copy of every backup.
//!
//! The backup wrapper writes the copies; this module prepares the
//! drives (scripts matching the app's byte for byte), stores which are
//! used, lists the copies on them and stages one for a restore.

use std::path::{Path, PathBuf};

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::backup;
use crate::pb;
use crate::storage_array::disk_guard;
use crate::storage_task::{field, is_block_device, quote, safe_path};

pub(crate) const DRIVE_ROOT: &str = "/srv/gryonix-backup";
const MARKER_FILE: &str = ".gryonix-backup-drive";
const LABEL_PREFIX: &str = "gnxb-";
const FORMAT_DONE: &str = "GRYONIXNEXUS_DRIVE_FORMAT_DONE";
const ATTACH_DONE: &str = "GRYONIXNEXUS_DRIVE_ATTACH_DONE";
const CHECK_DONE: &str = "GRYONIXNEXUS_DRIVE_CHECK_DONE";
const EJECT_DONE: &str = "GRYONIXNEXUS_DRIVE_EJECT_DONE";
const FORGET_DONE: &str = "GRYONIXNEXUS_DRIVE_FORGET_DONE";
const STAGING_DIRECTORY: &str = "incoming";

fn lines(items: &[&str]) -> Vec<String> {
    items.iter().map(|l| l.to_string()).collect()
}

fn join(all: Vec<String>) -> String {
    all.join("\n") + "\n"
}

fn mount_point(name: &str) -> String {
    format!("{DRIVE_ROOT}/{name}")
}

// MARK: checks

pub(crate) fn safe_drive_name(name: &str) -> bool {
    (1..=11).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub(crate) fn safe_drive_uuid(uuid: &str) -> bool {
    (1..=64).contains(&uuid.len()) && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Whether a mount is one of our backup drives
fn own_mount(mount: &str) -> bool {
    mount.starts_with(&format!("{DRIVE_ROOT}/")) && !mount.contains("..")
}

/// Refuses a disk with system mounts, arrays or volumes
pub(crate) fn drive_free(path: &str, lsblk: &str) -> Result<(), String> {
    let start = path.trim_start_matches("/dev/");
    let mut pending = vec![start.to_string()];
    let mut seen = std::collections::HashSet::new();
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        for row in lsblk.lines() {
            if field(row, "PKNAME") == name {
                pending.push(field(row, "NAME").to_string());
            }
            if field(row, "NAME") != name {
                continue;
            }
            let kind = field(row, "TYPE");
            let mounts = field(row, "MOUNTPOINTS");
            let foreign = mounts.split("\\x0a").any(|m| !m.is_empty() && !own_mount(m));
            if foreign || kind.starts_with("raid") || kind == "lvm" || kind == "crypt" {
                return Err(format!("{path} is in use"));
            }
        }
    }
    Ok(())
}

fn check_format(task: &pb::DriveFormatTask, lsblk: &str) -> Result<(), String> {
    if !safe_drive_name(&task.name) {
        return Err("a drive name is up to 11 lowercase letters, digits or dashes".into());
    }
    if !safe_path(&task.disk) || !is_block_device(&task.disk) {
        return Err(format!("{} is not a disk on this server", task.disk));
    }
    drive_free(&task.disk, lsblk)
}

fn check_drive(task: &pb::DriveTask) -> Result<(), String> {
    if safe_drive_uuid(&task.uuid) && safe_drive_name(&task.name) {
        Ok(())
    } else {
        Err("the drive is not described correctly".into())
    }
}

// MARK: scripts

fn removable_guard() -> Vec<String> {
    lines(&[
        "removable=\"$(lsblk -dno TRAN,RM,HOTPLUG \"$DISK\" | tr -s ' ')\"",
        "case \" $removable \" in",
        "  *\" usb \"*|*\" 1 \"*) ;;",
        "  *) echo \"$DISK is not a removable drive. Nothing was erased.\"; exit 3 ;;",
        "esac",
    ])
}

/// Writes fstab, mounts the drive and marks it as ours
fn attach_lines() -> Vec<String> {
    lines(&[
        "install -d -m 700 \"$MOUNT\"",
        "awk -v m=\"$MOUNT\" -v u=\"UUID=$uuid\" '$1 != u && $2 != m' /etc/fstab > /etc/fstab.gryonixnexus",
        "cat /etc/fstab.gryonixnexus > /etc/fstab",
        "rm -f /etc/fstab.gryonixnexus",
        "device=\"$(systemd-escape -p --suffix=device \"/dev/disk/by-uuid/$uuid\")\"",
        "echo \"UUID=$uuid $MOUNT ext4 nofail,noatime,x-systemd.device-timeout=5s,x-systemd.wanted-by=$device 0 2\" >> /etc/fstab",
        "systemctl daemon-reload >/dev/null 2>&1 || true",
        "mountpoint -q \"$MOUNT\" || mount \"$MOUNT\"",
        "chmod 700 \"$MOUNT\"",
        "printf '%s\\n' \"$uuid\" > \"$MOUNT/.gryonix-backup-drive\"",
        "echo \"GRYONIXNEXUS_DRIVE_UUID $uuid\"",
    ])
}

fn drive_header(task: &pb::DriveTask, strict: bool) -> Vec<String> {
    let mut out = lines(&["#!/bin/bash", if strict { "set -euo pipefail" } else { "set -uo pipefail" }]);
    out.push(format!("DRIVE={}", quote(&task.uuid)));
    out.push(format!("MOUNT={}", quote(&mount_point(&task.name))));
    out
}

fn plugged_in() -> Vec<String> {
    lines(&[
        "part=\"/dev/disk/by-uuid/$DRIVE\"",
        "if [ ! -b \"$part\" ]; then",
        "  echo \"The drive is not plugged in.\"",
        "  exit 3",
        "fi",
    ])
}

fn unmount_or_refuse() -> Vec<String> {
    lines(&[
        "if mountpoint -q \"$MOUNT\" && ! umount \"$MOUNT\"; then",
        "  echo \"The drive is busy. A backup may be writing to it.\"",
        "  exit 3",
        "fi",
    ])
}

pub fn format_script(task: &pb::DriveFormatTask) -> String {
    let mut out = lines(&["#!/bin/bash", "set -euo pipefail"]);
    out.push(format!("DISK={}", quote(&task.disk)));
    out.push(format!("LABEL={}", quote(&format!("{LABEL_PREFIX}{}", task.name))));
    out.push(format!("MOUNT={}", quote(&mount_point(&task.name))));
    out.extend(disk_guard(&task.identity));
    out.extend(removable_guard());
    out.extend(lines(&[
        "for held in $(lsblk -rno MOUNTPOINT \"$DISK\" | grep '^/srv/gryonix-backup/' || true); do",
        "  umount \"$held\"",
        "done",
        "gnx_free \"$DISK\"",
        "for old in $(lsblk -rnpo NAME,TYPE \"$DISK\" | awk '$2 == \"part\" {print $1}'); do",
        "  wipefs -a -q \"$old\" || true",
        "done",
        "wipefs -a -q \"$DISK\"",
        "printf 'label: gpt\\n,,L\\n' | sfdisk -q \"$DISK\"",
        "udevadm settle",
        "part=\"$(lsblk -rnpo NAME,TYPE \"$DISK\" | awk '$2 == \"part\" {print $1; exit}')\"",
        "mkfs.ext4 -q -F -L \"$LABEL\" \"$part\"",
        "udevadm settle",
        "uuid=\"$(blkid -s UUID -o value \"$part\")\"",
    ]));
    out.extend(attach_lines());
    out.push(format!("echo {FORMAT_DONE}"));
    join(out)
}

pub fn attach_script(task: &pb::DriveTask) -> String {
    let mut out = drive_header(task, true);
    out.extend(plugged_in());
    out.extend(lines(&[
        "if [ \"$(blkid -s TYPE -o value \"$part\")\" != ext4 ]; then",
        "  echo \"The drive is not prepared for backups. Format it first.\"",
        "  exit 3",
        "fi",
        "uuid=\"$DRIVE\"",
    ]));
    out.extend(attach_lines());
    out.push(format!("echo {ATTACH_DONE}"));
    join(out)
}

fn smart_and_fsck() -> Vec<String> {
    lines(&[
        "disk=\"/dev/$(lsblk -no PKNAME \"$part\" | head -n 1)\"",
        "case \"$(smartctl -d sat -H \"$disk\" 2>/dev/null || true)\" in",
        "  *PASSED*) echo \"GRYONIXNEXUS_DRIVE_SMART passed\" ;;",
        "  *FAILED*) echo \"GRYONIXNEXUS_DRIVE_SMART failed\" ;;",
        "  *) echo \"GRYONIXNEXUS_DRIVE_SMART none\" ;;",
        "esac",
        "remount=0",
        "if mountpoint -q \"$MOUNT\"; then",
        "  sync",
        "  if umount \"$MOUNT\" 2>/dev/null; then remount=1; fi",
        "fi",
        "if mountpoint -q \"$MOUNT\"; then",
        "  echo \"GRYONIXNEXUS_DRIVE_FSCK busy\"",
        "elif e2fsck -fn \"$part\" >/dev/null 2>&1; then",
        "  echo \"GRYONIXNEXUS_DRIVE_FSCK clean\"",
        "else",
        "  echo \"GRYONIXNEXUS_DRIVE_FSCK errors\"",
        "fi",
        "if [ \"$remount\" -eq 1 ]; then mount \"$MOUNT\" || true; fi",
    ])
}

fn speed_lines() -> Vec<String> {
    lines(&[
        "if mountpoint -q \"$MOUNT\"; then",
        "  probe=\"$MOUNT/.gnx-speed\"",
        "  start=\"$(date +%s%N)\"",
        "  if dd if=/dev/zero of=\"$probe\" bs=1M count=64 oflag=direct status=none 2>/dev/null; then",
        "    mid=\"$(date +%s%N)\"",
        "    dd if=\"$probe\" of=/dev/null bs=1M iflag=direct status=none 2>/dev/null || true",
        "    end=\"$(date +%s%N)\"",
        "    echo \"GRYONIXNEXUS_DRIVE_SPEED $((67108864 * 1000000000 / (mid - start + 1))) $((67108864 * 1000000000 / (end - mid + 1)))\"",
        "  else",
        "    echo \"GRYONIXNEXUS_DRIVE_SPEED 0 0\"",
        "  fi",
        "  rm -f \"$probe\"",
        "fi",
    ])
}

pub fn check_script(task: &pb::DriveTask) -> String {
    let mut out = drive_header(task, false);
    out.extend(plugged_in());
    out.extend(smart_and_fsck());
    out.extend(speed_lines());
    out.push(format!("echo {CHECK_DONE}"));
    join(out)
}

pub fn eject_script(task: &pb::DriveTask) -> String {
    let mut out = drive_header(task, true);
    out.push("sync".into());
    out.extend(unmount_or_refuse());
    out.extend(lines(&[
        "part=\"/dev/disk/by-uuid/$DRIVE\"",
        "if [ -b \"$part\" ] && command -v udisksctl >/dev/null 2>&1; then",
        "  udisksctl power-off -b \"/dev/$(lsblk -no PKNAME \"$part\" | head -n 1)\" >/dev/null 2>&1 || true",
        "fi",
    ]));
    out.push(format!("echo {EJECT_DONE}"));
    join(out)
}

pub fn forget_script(task: &pb::DriveTask) -> String {
    let mut out = drive_header(task, true);
    out.extend(unmount_or_refuse());
    out.extend(lines(&[
        "awk -v m=\"$MOUNT\" -v u=\"UUID=$DRIVE\" '$1 != u && $2 != m' /etc/fstab > /etc/fstab.gryonixnexus",
        "cat /etc/fstab.gryonixnexus > /etc/fstab",
        "rm -f /etc/fstab.gryonixnexus",
        "systemctl daemon-reload >/dev/null 2>&1 || true",
        "rmdir \"$MOUNT\" 2>/dev/null || true",
    ]));
    out.push(format!("echo {FORGET_DONE}"));
    join(out)
}

/// The drive task's script, or why it is refused
pub fn script(req: &pb::StorageTaskRequest, kind: pb::StorageTaskKind, lsblk: &str) -> Result<String, String> {
    let missing = || "the task has no details".to_string();
    if kind == pb::StorageTaskKind::DriveFormat {
        let task = req.drive_format.as_ref().ok_or_else(missing)?;
        return check_format(task, lsblk).map(|_| format_script(task));
    }
    let task = req.drive.as_ref().ok_or_else(missing)?;
    check_drive(task)?;
    Ok(match kind {
        pb::StorageTaskKind::DriveAttach => attach_script(task),
        pb::StorageTaskKind::DriveCheck => check_script(task),
        pb::StorageTaskKind::DriveEject => eject_script(task),
        _ => forget_script(task),
    })
}

// MARK: settings

fn shell_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim().strip_prefix(key)?.strip_prefix('=')?.trim();
    Some(rest.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')).unwrap_or(rest))
}

fn mode_of(word: &str) -> pb::BackupDriveMode {
    match word {
        "local" => pb::BackupDriveMode::Local,
        "drive" => pb::BackupDriveMode::Drive,
        _ => pb::BackupDriveMode::Both,
    }
}

fn mode_word(mode: i32) -> &'static str {
    match pb::BackupDriveMode::try_from(mode).unwrap_or(pb::BackupDriveMode::Both) {
        pb::BackupDriveMode::Local => "local",
        pb::BackupDriveMode::Drive => "drive",
        _ => "both",
    }
}

/// The wrapper's drive settings and last result
pub fn parse_settings(config: &str, status: &str) -> pb::BackupDrives {
    let mut drives = pb::BackupDrives { mode: pb::BackupDriveMode::Both as i32, encrypt: true, ..Default::default() };
    for line in config.lines() {
        if let Some(value) = shell_value(line, "DRIVE_MODE") {
            drives.mode = mode_of(value) as i32;
        } else if let Some(value) = shell_value(line, "DRIVE_ENCRYPT") {
            drives.encrypt = value != "0";
        } else if let Some(value) = shell_value(line, "DRIVES") {
            drives.uuids = value.split_whitespace().map(str::to_string).collect();
        }
    }
    for line in status.lines() {
        if let Some(value) = shell_value(line, "DRIVE_AT") {
            drives.last_copy_at = value.parse().unwrap_or(0);
        } else if let Some(value) = shell_value(line, "DRIVE_OK") {
            drives.last_copy_ok = value == "1";
        } else if let Some(value) = shell_value(line, "DRIVE_ERROR") {
            drives.last_copy_error = value.to_string();
        }
    }
    drives
}

/// Where fstab mounts a drive, from /etc/fstab
pub fn fstab_target(fstab: &str, uuid: &str) -> Option<String> {
    let source = format!("UUID={uuid}");
    fstab.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some(source.as_str())).then(|| fields.next().map(str::to_string)).flatten()
    })
}

/// A mounted backup drive carrying this drive's marker
fn marked(target: &str, uuid: &str, mounts: &str) -> bool {
    let mounted = mounts.lines().any(|line| line.split_whitespace().nth(1) == Some(target));
    let marker = std::fs::read_to_string(Path::new(target).join(MARKER_FILE)).unwrap_or_default();
    own_mount(target) && mounted && marker.trim() == uuid
}

fn drive_status(uuid: &str, fstab: &str, mounts: &str) -> pb::BackupDriveStatus {
    let target = fstab_target(fstab, uuid).unwrap_or_default();
    let mut status = pb::BackupDriveStatus { uuid: uuid.to_string(), mount_point: target.clone(), ..Default::default() };
    if !target.is_empty() && marked(&target, uuid, mounts) {
        status.mounted = true;
        if let Some((size, used)) = crate::metrics::statvfs_usage(&target) {
            status.size_bytes = size.max(0) as u64;
            status.free_bytes = (size - used).max(0) as u64;
        }
    }
    status
}

/// The drive half of the backup policy, read off disk
pub fn read_drives(config_dir: &Path) -> pb::BackupDrives {
    let read = |name: &str| std::fs::read_to_string(config_dir.join(name)).unwrap_or_default();
    let mut drives = parse_settings(&read("backup-drives.conf"), &read("backup-drives.status"));
    let fstab = std::fs::read_to_string("/etc/fstab").unwrap_or_default();
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    drives.drives = drives.uuids.iter().map(|uuid| drive_status(uuid, &fstab, &mounts)).collect();
    drives.passphrase_stored = std::fs::metadata(config_dir.join("autobackup.pass")).map(|m| m.len() > 0).unwrap_or(false);
    drives
}

pub async fn set_backup_drives(codec: Codec, req: pb::SetBackupDrivesRequest) -> Resp {
    let drives = req.drives.unwrap_or_default();
    if !drives.uuids.iter().all(|uuid| safe_drive_uuid(uuid)) {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", "a drive id is not valid");
    }
    let encrypt = if drives.encrypt { "1" } else { "0" };
    let mut args = vec!["set-drives", mode_word(drives.mode), encrypt];
    args.extend(drives.uuids.iter().map(String::as_str));
    backup::run_quick(&args, codec).await
}

// MARK: mounting on plug-in

const HOTPLUG_OPTION: &str = "x-systemd.wanted-by=";

/// The systemd device unit of a filesystem UUID
fn device_unit(uuid: &str) -> String {
    format!("dev-disk-by\\x2duuid-{}.device", uuid.replace('-', "\\x2d"))
}

/// One of our fstab lines, made to mount on plug-in
fn hotplug_line(line: &str) -> Option<String> {
    let mut fields: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    let uuid = fields.first()?.strip_prefix("UUID=")?.to_string();
    let ours = fields.len() >= 4 && own_mount(&fields[1]) && safe_drive_uuid(&uuid);
    if !ours || fields[3].contains(HOTPLUG_OPTION) {
        return None;
    }
    fields[3] = format!("{},{HOTPLUG_OPTION}{}", fields[3], device_unit(&uuid));
    Some(fields.join(" "))
}

/// Our drives' fstab lines mounting on plug-in, when that changes
pub fn with_hotplug(fstab: &str) -> Option<String> {
    let mut changed = false;
    let lines: Vec<String> = fstab
        .lines()
        .map(|line| match hotplug_line(line) {
            Some(new) => {
                changed = true;
                new
            }
            None => line.to_string(),
        })
        .collect();
    changed.then(|| lines.join("\n") + "\n")
}

/// Upgrades fstab lines written before mounting on plug-in
pub fn upgrade_fstab() {
    let Ok(fstab) = std::fs::read_to_string("/etc/fstab") else { return };
    let Some(upgraded) = with_hotplug(&fstab) else { return };
    if let Err(err) = std::fs::write("/etc/fstab", upgraded) {
        tracing::warn!(%err, "could not upgrade the backup drives in fstab");
        return;
    }
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
    tracing::info!("backup drives now mount when plugged in");
}

// MARK: copies on the drives

/// The drives' mount points that carry their marker
fn marked_drives(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else { return Vec::new() };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join(MARKER_FILE).is_file())
        .collect();
    found.sort();
    found
}

/// Every copy of one service on the plugged-in drives
pub fn drive_archives(label: &str) -> Vec<pb::BackupArchive> {
    let mut found = Vec::new();
    for drive in marked_drives(Path::new(DRIVE_ROOT)) {
        let name = drive.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let Ok(archives) = backup::read_directory(&drive.join(label)) else { continue };
        found.extend(archives.into_iter().map(|archive| pb::BackupArchive { drive: name.clone(), ..archive }));
    }
    found
}

/// The drive a path lies on, empty when local
pub fn drive_name(path: &str) -> String {
    path.strip_prefix(DRIVE_ROOT)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default()
        .to_string()
}

/// The drive holding this service's copy at a path
pub fn drive_of(path: &str, label: &str) -> Option<String> {
    let rest = path.strip_prefix(DRIVE_ROOT)?.strip_prefix('/')?;
    let parts: Vec<&str> = rest.split('/').collect();
    let well_formed = parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && *p != "." && *p != "..");
    (well_formed && parts[1] == label && !parts[2].starts_with('.')).then(|| parts[0].to_string())
}

pub async fn fetch_drive_backup(codec: Codec, req: pb::FetchDriveBackupRequest) -> Resp {
    let target = match backup::resolve(&req.service_id) {
        Ok(target) => target,
        Err(rejection) => return rejection.response(),
    };
    if drive_of(&req.path, target.label).is_none() || !Path::new(&req.path).is_file() {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", "the copy is not on a backup drive");
    }
    match stage(&req.path, &target.directory).await {
        Ok(archive) => codec
            .encode(&archive)
            .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())),
        Err(err) => connect_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &format!("could not copy from the drive: {err}")),
    }
}

/// Copies a drive archive into the service's staging folder
async fn stage(path: &str, directory: &Path) -> std::io::Result<pb::BackupArchive> {
    use std::os::unix::fs::PermissionsExt;
    let staging = directory.join(STAGING_DIRECTORY);
    tokio::fs::create_dir_all(&staging).await?;
    let name = Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let dest = staging.join(&name);
    let size = tokio::fs::copy(path, &dest).await?;
    tokio::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(pb::BackupArchive {
        name,
        path: dest.to_string_lossy().to_string(),
        size_bytes: size as i64,
        modified_at: crate::util::now_millis(),
        directory: false,
        drive: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Android/catalog/src/test/resources/storage").join(name);
        std::fs::read_to_string(path).unwrap()
    }

    fn drive() -> pb::DriveTask {
        pb::DriveTask { uuid: "3f2a7c1e-5b8d-4e6f-9a0b-1c2d3e4f5a6b".into(), name: "usb1".into() }
    }

    #[test]
    fn scripts_match_the_app() {
        let format = pb::DriveFormatTask {
            disk: "/dev/sdf".into(),
            name: "usb1".into(),
            identity: Some(pb::DiskIdentity { path: "/dev/sdf".into(), serial: "4C530001".into(), size_bytes: 61_530_439_680 }),
        };
        assert_eq!(format_script(&format), golden("drive-format.sh"));
        assert_eq!(attach_script(&drive()), golden("drive-attach.sh"));
        assert_eq!(check_script(&drive()), golden("drive-check.sh"));
        assert_eq!(eject_script(&drive()), golden("drive-eject.sh"));
        assert_eq!(forget_script(&drive()), golden("drive-forget.sh"));
    }

    #[test]
    fn names_and_ids_are_checked() {
        assert!(safe_drive_name("usb1"));
        assert!(safe_drive_name("backup-2"));
        assert!(!safe_drive_name("USB"));
        assert!(!safe_drive_name("-x"));
        assert!(!safe_drive_name("a/../b"));
        assert!(!safe_drive_name("twelve-chars"));
        assert!(safe_drive_uuid("3f2a7c1e-5b8d-4e6f-9a0b-1c2d3e4f5a6b"));
        assert!(!safe_drive_uuid("3f2a; rm -rf /"));
        assert!(check_drive(&pb::DriveTask { uuid: "x y".into(), name: "usb1".into() }).is_err());
    }

    #[test]
    fn a_disk_with_system_mounts_is_refused() {
        let lsblk = [
            r#"NAME="sda" PKNAME="" TYPE="disk" MOUNTPOINTS="""#,
            r#"NAME="sda1" PKNAME="sda" TYPE="part" MOUNTPOINTS="/""#,
            r#"NAME="sdb" PKNAME="" TYPE="disk" MOUNTPOINTS="""#,
            r#"NAME="sdc" PKNAME="" TYPE="disk" MOUNTPOINTS="""#,
            r#"NAME="sdc1" PKNAME="sdc" TYPE="part" MOUNTPOINTS="/srv/gryonix-backup/usb1""#,
            r#"NAME="sdd" PKNAME="" TYPE="disk" MOUNTPOINTS="""#,
            r#"NAME="md0" PKNAME="sdd" TYPE="raid1" MOUNTPOINTS="""#,
            r#"NAME="sde" PKNAME="" TYPE="disk" MOUNTPOINTS="""#,
            r#"NAME="sde1" PKNAME="sde" TYPE="part" MOUNTPOINTS="/media/stick""#,
        ]
        .join("\n");
        assert!(drive_free("/dev/sda", &lsblk).is_err(), "the system disk");
        assert!(drive_free("/dev/sdb", &lsblk).is_ok(), "a blank stick");
        assert!(drive_free("/dev/sdc", &lsblk).is_ok(), "our own drive is unmounted first");
        assert!(drive_free("/dev/sdd", &lsblk).is_err(), "an array member");
        assert!(drive_free("/dev/sde", &lsblk).is_err(), "mounted somewhere else");
    }

    #[test]
    fn settings_and_status_are_read() {
        let config = "DRIVE_MODE=drive\nDRIVE_ENCRYPT=0\nDRIVES='aa-bb cc-dd'\n";
        let status = "DRIVE_AT=1700000000\nDRIVE_OK=0\nDRIVE_ERROR='usb2: not connected;'\n";
        let drives = parse_settings(config, status);
        assert_eq!(drives.mode, pb::BackupDriveMode::Drive as i32);
        assert!(!drives.encrypt);
        assert_eq!(drives.uuids, vec!["aa-bb", "cc-dd"]);
        assert_eq!(drives.last_copy_at, 1_700_000_000);
        assert!(!drives.last_copy_ok);
        assert_eq!(drives.last_copy_error, "usb2: not connected;");
        let fresh = parse_settings("", "");
        assert_eq!(fresh.mode, pb::BackupDriveMode::Both as i32);
        assert!(fresh.encrypt, "copies on a drive are encrypted unless switched off");
    }

    #[test]
    fn fstab_names_the_mount_point() {
        let fstab = "# comment\nUUID=aa-bb /srv/gryonix-backup/usb1 ext4 nofail 0 2\nUUID=ff / ext4 defaults 0 1\n";
        assert_eq!(fstab_target(fstab, "aa-bb").as_deref(), Some("/srv/gryonix-backup/usb1"));
        assert_eq!(fstab_target(fstab, "cc"), None);
    }

    #[test]
    fn old_drive_lines_learn_to_mount_on_plug_in() {
        let fstab = "# comment\nUUID=ff / ext4 defaults 0 1\n\
                     UUID=aa-bb /srv/gryonix-backup/usb1 ext4 nofail,noatime 0 2\n\
                     UUID=cc /media/stick ext4 nofail 0 2\n";
        let upgraded = with_hotplug(fstab).expect("our line changes");
        assert!(upgraded.contains(
            "UUID=aa-bb /srv/gryonix-backup/usb1 ext4 nofail,noatime,x-systemd.wanted-by=dev-disk-by\\x2duuid-aa\\x2dbb.device 0 2"
        ));
        assert!(upgraded.contains("UUID=ff / ext4 defaults 0 1"));
        assert!(upgraded.contains("UUID=cc /media/stick ext4 nofail 0 2"));
        assert!(upgraded.starts_with("# comment\n"));
        assert_eq!(with_hotplug(&upgraded), None, "an upgraded line stays as it is");
        assert_eq!(with_hotplug("UUID=x;y /srv/gryonix-backup/usb1 ext4 nofail 0 2\n"), None);
    }

    #[test]
    fn only_a_copy_of_this_service_on_a_drive_is_accepted() {
        let copy = "/srv/gryonix-backup/usb1/nextcloud/nextcloud-20260101.tar.gz.gpg";
        assert_eq!(drive_of(copy, "nextcloud").as_deref(), Some("usb1"));
        assert_eq!(drive_of(copy, "vaultwarden"), None);
        assert_eq!(drive_of("/srv/gryonix-backup/usb1/../etc/x", "etc"), None);
        assert_eq!(drive_of("/srv/gryonix-backup/usb1/nextcloud/.partial-x", "nextcloud"), None);
        assert_eq!(drive_of("/opt/backups/nextcloud/x.tar.gz", "nextcloud"), None);
    }

    #[test]
    fn an_unmarked_folder_is_not_a_drive() {
        let dir = std::env::temp_dir().join(format!("gnx-drive-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("usb1/nextcloud")).unwrap();
        std::fs::create_dir_all(dir.join("bare/nextcloud")).unwrap();
        std::fs::write(dir.join("usb1").join(MARKER_FILE), "aa\n").unwrap();
        let found = marked_drives(&dir);
        assert_eq!(found, vec![dir.join("usb1")]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
