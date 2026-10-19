//! Disk work that needs root: SMART reads and RAID arrays.
//!
//! The app sends a typed task; this module checks its disks and names,
//! writes the script and runs it. The scripts match the app's own
//! generators byte for byte, pinned by the shared golden files.

use std::os::unix::fs::FileTypeExt;
use std::time::Duration;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::install::packages::{apt_quiet, drop_retired_sources};
use crate::pb;
use crate::storage_array;
use crate::storage_cache;

const TIMEOUT: Duration = Duration::from_secs(900);
const SMART_DONE: &str = "GRYONIXNEXUS_SMART_DONE";
const RAID_DONE: &str = "GRYONIXNEXUS_RAID_DONE";
const IMPORT_DONE: &str = "GRYONIXNEXUS_RAID_IMPORT_DONE";
const REPAIR_DONE: &str = "GRYONIXNEXUS_RAID_REPAIR_DONE";

pub(crate) fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn join(lines: &[String]) -> String {
    lines.join("\n") + "\n"
}

fn owned(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|l| l.to_string()).collect()
}

// MARK: checks

pub(crate) fn safe_path(path: &str) -> bool {
    path.starts_with("/dev/")
        && !path.contains("..")
        && path.len() < 128
        && path[5..].chars().all(|c| c.is_ascii_alphanumeric() || "/_.-:".contains(c))
}

pub(crate) fn safe_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

pub(crate) fn safe_mount(mount: &str) -> bool {
    (mount.starts_with("/srv/") || mount.starts_with("/mnt/"))
        && !mount.contains("..")
        && mount.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c))
}

pub(crate) fn safe_uuid(uuid: &str) -> bool {
    (1..=64).contains(&uuid.len()) && uuid.chars().all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '-')
}

pub(crate) fn is_block_device(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.file_type().is_block_device()).unwrap_or(false)
}

pub(crate) fn wipeable(path: &str, lsblk: &str) -> Result<(), String> {
    if !safe_path(path) || !is_block_device(path) {
        return Err(format!("{path} is not a disk on this server"));
    }
    let real = std::fs::canonicalize(path).map(|p| p.display().to_string()).unwrap_or_else(|_| path.to_string());
    if mounted_under(&real, lsblk) {
        return Err(format!("{path} is in use"));
    }
    Ok(())
}

/// One `lsblk -Pno NAME,PKNAME,TYPE,MOUNTPOINTS` row
pub(crate) fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let marker = format!("{key}=\"");
    line.find(&marker)
        .map(|start| &line[start + marker.len()..])
        .and_then(|rest| rest.find('"').map(|end| &rest[..end]))
        .unwrap_or("")
}

pub fn mounted_under(path: &str, lsblk: &str) -> bool {
    let held = |l: &str| !field(l, "MOUNTPOINTS").is_empty() || field(l, "TYPE").starts_with("raid") || field(l, "TYPE") == "lvm";
    let rows: Vec<(&str, &str, bool)> = lsblk.lines().map(|l| (field(l, "NAME"), field(l, "PKNAME"), held(l))).collect();
    let start = path.trim_start_matches("/dev/").to_string();
    let own_mount = lsblk.lines().any(|l| field(l, "NAME") == start && !field(l, "MOUNTPOINTS").is_empty());
    let mut pending = vec![start.clone()];
    let mut seen = std::collections::HashSet::new();
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        for (row, parent, held) in &rows {
            if *row == name && (*held && name != start || own_mount) {
                return true;
            }
            if *parent == name {
                pending.push(row.to_string());
            }
        }
    }
    false
}

pub(crate) async fn lsblk() -> String {
    let out = tokio::process::Command::new("lsblk").args(["-Pno", "NAME,PKNAME,TYPE,MOUNTPOINTS"]).output().await;
    out.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

// MARK: scripts

pub fn disk_health_script(disks: &[String]) -> String {
    let install = format!(
        "  {} install -y -qq --no-install-recommends smartmontools >/dev/null 2>&1 \\",
        apt_quiet()
    );
    let mut lines = owned(&[
        "#!/bin/bash",
        "set -uo pipefail",
        "if ! command -v smartctl >/dev/null 2>&1; then",
        "  export DEBIAN_FRONTEND=noninteractive",
        install.as_str(),
        "    || { echo \"smartmontools could not be installed\"; exit 3; }",
        "fi",
    ]);
    for disk in disks {
        let quoted = quote(disk);
        lines.push(format!("echo \"### \"{quoted}; smartctl --json=c -H -A -i {quoted}; echo"));
    }
    lines.push(format!("echo {SMART_DONE}"));
    join(&lines)
}

/// Installs ZFS tools, failing quietly into the caller's message
pub(crate) fn zfs_fetch_line() -> String {
    let apt = apt_quiet();
    format!(
        "  if ! {{ {}; {apt} update -qq && {apt} install -y -qq zfsutils-linux; }} >/dev/null 2>&1; then",
        drop_retired_sources()
    )
}

fn mdadm_install() -> Vec<String> {
    let install = format!("  {} install -y -q mdadm", apt_quiet());
    owned(&["if ! command -v mdadm >/dev/null 2>&1; then", install.as_str(), "fi"])
}

fn mount_lines() -> Vec<String> {
    owned(&[
        "install -d \"$MOUNT\"",
        "uuid=\"$(blkid -s UUID -o value \"$ARRAY\")\"",
        "grep -q \"UUID=$uuid $MOUNT \" /etc/fstab || echo \"UUID=$uuid $MOUNT ext4 defaults,nofail 0 2\" >> /etc/fstab",
        "mountpoint -q \"$MOUNT\" || mount \"$MOUNT\"",
    ])
}

pub fn raid_create_script(task: &pb::RaidCreateTask) -> String {
    let members = task.disks.iter().map(|d| quote(d)).collect::<Vec<_>>().join(" ");
    let mount = (!task.mount_point.is_empty()).then_some(task.mount_point.as_str());
    let mut lines = owned(&["#!/bin/bash", "set -euo pipefail"]);
    lines.push(format!("ARRAY={}", quote(&format!("/dev/md/{}", task.name))));
    if let Some(mount) = mount {
        lines.push(format!("MOUNT={}", quote(mount)));
    }
    lines.extend(storage_array::disk_guard(&task.identities));
    lines.extend(mdadm_install());
    lines.push("if [ ! -e \"$ARRAY\" ]; then".into());
    lines.extend(storage_array::check_all(&members));
    lines.push(format!("  for disk in {members}; do"));
    lines.extend(owned(&["    wipefs -a -q \"$disk\"", "  done"]));
    lines.push(format!(
        "  mdadm --create \"$ARRAY\" --name={} --metadata=1.2 --run --level={} --raid-devices={} {members}",
        task.name, task.level, task.disks.len()
    ));
    lines.push("  wipefs -a -q \"$ARRAY\"".into());
    if mount.is_some() {
        lines.push("  mkfs.ext4 -q -L gnx-storage \"$ARRAY\"".into());
    }
    lines.extend(owned(&[
        "  install -d /etc/mdadm",
        "  mdadm --detail --brief \"$ARRAY\" >> /etc/mdadm/mdadm.conf",
        "  update-initramfs -u >/dev/null 2>&1 || true",
        "fi",
    ]));
    if mount.is_some() {
        lines.extend(mount_lines());
    }
    lines.push(format!("echo {RAID_DONE}"));
    join(&lines)
}

/// mdadm, ZFS or btrfs, as the task names
pub fn create_script(task: &pb::RaidCreateTask) -> String {
    match pb::StorageArrayKind::try_from(task.kind).unwrap_or(pb::StorageArrayKind::Md) {
        pb::StorageArrayKind::Zfs => storage_array::zfs_create_script(task),
        pb::StorageArrayKind::Btrfs => storage_array::btrfs_create_script(task),
        _ => raid_create_script(task),
    }
}

fn zfs_install() -> Vec<String> {
    let zfs_fetch = zfs_fetch_line();
    owned(&[
        "if ! command -v zpool >/dev/null 2>&1; then",
        "  export DEBIAN_FRONTEND=noninteractive",
        zfs_fetch.as_str(),
        "    echo \"ZFS tools could not be installed here. On Debian they come from the contrib section.\"",
        "    exit 3",
        "  fi",
        "fi",
    ])
}

pub fn raid_import_script(task: &pb::RaidImportTask) -> String {
    if task.kind == pb::StorageArrayKind::Zfs as i32 {
        return zfs_import_script(task);
    }
    let uuid = quote(&task.uuid);
    let mount = (!task.mount_point.is_empty()).then_some(task.mount_point.as_str());
    let mut lines = owned(&["#!/bin/bash", "set -euo pipefail"]);
    lines.push(format!("ARRAY={}", quote(&task.address)));
    if let Some(mount) = mount {
        lines.push(format!("MOUNT={}", quote(mount)));
    }
    lines.extend(mdadm_install());
    lines.push("if ! mdadm --detail \"$ARRAY\" >/dev/null 2>&1; then".into());
    lines.push(format!("  mdadm --assemble \"$ARRAY\" --uuid={uuid} --run"));
    lines.extend(owned(&["fi", "install -d /etc/mdadm"]));
    lines.push(format!(
        "grep -q {uuid} /etc/mdadm/mdadm.conf 2>/dev/null || mdadm --detail --brief \"$ARRAY\" >> /etc/mdadm/mdadm.conf"
    ));
    lines.push("update-initramfs -u >/dev/null 2>&1 || true".into());
    if mount.is_some() {
        lines.extend(owned(&[
            "if [ -z \"$(blkid -s TYPE -o value \"$ARRAY\" || true)\" ]; then",
            "  echo \"The array holds no filesystem; nothing was formatted.\"",
            "  exit 3",
            "fi",
        ]));
        lines.extend(mount_lines());
    }
    lines.push(format!("echo {IMPORT_DONE}"));
    join(&lines)
}

fn zfs_import_script(task: &pb::RaidImportTask) -> String {
    let id = if task.uuid.is_empty() { &task.name } else { &task.uuid };
    let mut lines = owned(&["#!/bin/bash", "set -euo pipefail"]);
    lines.push(format!("POOL={}", quote(&task.name)));
    lines.push(format!("ID={}", quote(id)));
    lines.extend(zfs_install());
    lines.extend(owned(&[
        "if ! zpool list -H \"$POOL\" >/dev/null 2>&1; then",
        "  zpool import -f \"$ID\"",
        "fi",
        "zpool set cachefile=/etc/zfs/zpool.cache \"$POOL\" || true",
    ]));
    lines.push(format!("echo {IMPORT_DONE}"));
    join(&lines)
}

pub fn raid_repair_script(task: &pb::RaidRepairTask) -> String {
    let mut lines = owned(&["#!/bin/bash", "set -euo pipefail"]);
    if task.kind == pb::StorageArrayKind::Zfs as i32 {
        lines.push(format!("POOL={}", quote(&task.name)));
        lines.push(format!("OLD={}", quote(&task.failed)));
        lines.push(format!("NEW={}", quote(&task.replacement)));
        lines.extend(storage_array::disk_guard(&task.identities));
        lines.extend(owned(&[
            "if ! zpool status -LP \"$POOL\" | grep -q \"$NEW\"; then",
            "  gnx_free \"$NEW\"",
            "  wipefs -a -q \"$NEW\"",
            "  zpool replace -f \"$POOL\" \"$OLD\" \"$NEW\"",
            "fi",
        ]));
    } else {
        lines.push(format!("ARRAY={}", quote(&task.address)));
        lines.push(format!("NEW={}", quote(&task.replacement)));
        lines.extend(storage_array::disk_guard(&task.identities));
        lines.extend(owned(&[
            "mdadm \"$ARRAY\" --remove failed >/dev/null 2>&1 || true",
            "mdadm \"$ARRAY\" --remove detached >/dev/null 2>&1 || true",
            "if ! mdadm --detail \"$ARRAY\" | grep -q \"$NEW\"; then",
            "  gnx_free \"$NEW\"",
            "  wipefs -a -q \"$NEW\"",
            "  mdadm \"$ARRAY\" --add \"$NEW\"",
            "fi",
        ]));
    }
    lines.push(format!("echo {REPAIR_DONE}"));
    join(&lines)
}

// MARK: validation

pub(crate) fn check_create(task: &pb::RaidCreateTask, lsblk: &str) -> Result<(), String> {
    if task.kind == pb::StorageArrayKind::Btrfs as i32 && ![0, 1, 10].contains(&task.level) {
        return Err("btrfs arrays are RAID 0, 1 or 10".into());
    }
    let minimum = match task.level {
        0 | 1 => 2,
        5 => 3,
        6 | 10 => 4,
        _ => return Err("RAID level must be 0, 1, 5, 6 or 10".into()),
    };
    if task.disks.len() < minimum || (task.level == 10 && task.disks.len() % 2 != 0) {
        return Err(format!("RAID {} needs at least {minimum} disks", task.level));
    }
    if !safe_name(&task.name) || !(task.mount_point.is_empty() || safe_mount(&task.mount_point)) {
        return Err("the array name or mount point is not allowed".into());
    }
    task.disks.iter().try_for_each(|disk| wipeable(disk, lsblk))
}

fn check_import(task: &pb::RaidImportTask) -> Result<(), String> {
    let zfs = task.kind == pb::StorageArrayKind::Zfs as i32;
    let address_ok = if zfs { true } else { safe_path(&task.address) && task.address.starts_with("/dev/md") };
    let uuid_ok = if zfs { task.uuid.is_empty() || safe_uuid(&task.uuid) } else { safe_uuid(&task.uuid) };
    let mount_ok = task.mount_point.is_empty() || safe_mount(&task.mount_point);
    if safe_name(&task.name) && address_ok && uuid_ok && mount_ok {
        Ok(())
    } else {
        Err("the array to bring back is not described correctly".into())
    }
}

fn check_repair(task: &pb::RaidRepairTask, lsblk: &str) -> Result<(), String> {
    let zfs = task.kind == pb::StorageArrayKind::Zfs as i32;
    let target_ok = if zfs {
        safe_name(&task.name) && !task.failed.is_empty() && safe_uuid(task.failed.trim_start_matches("/dev/").replace('/', "-").as_str())
    } else {
        safe_path(&task.address) && task.address.starts_with("/dev/md")
    };
    if !target_ok {
        return Err("the array to repair is not described correctly".into());
    }
    wipeable(&task.replacement, lsblk)
}

/// The script for a task, or why it is refused
pub async fn script(req: &pb::StorageTaskRequest) -> Result<String, String> {
    let missing = || "the task has no details".to_string();
    match pb::StorageTaskKind::try_from(req.kind).unwrap_or(pb::StorageTaskKind::Unspecified) {
        pb::StorageTaskKind::DiskHealth => {
            let disks = &req.disk_health.as_ref().ok_or_else(missing)?.disks;
            if disks.is_empty() || !disks.iter().all(|d| safe_path(d) && is_block_device(d)) {
                return Err("name the disks to read".into());
            }
            Ok(disk_health_script(disks))
        }
        pb::StorageTaskKind::RaidCreate => {
            let create = req.raid_create.as_ref().ok_or_else(missing)?;
            check_create(create, &lsblk().await).map(|_| create_script(create))
        }
        pb::StorageTaskKind::RaidImport => {
            let import = req.raid_import.as_ref().ok_or_else(missing)?;
            check_import(import).map(|_| raid_import_script(import))
        }
        pb::StorageTaskKind::RaidRepair => {
            let repair = req.raid_repair.as_ref().ok_or_else(missing)?;
            check_repair(repair, &lsblk().await).map(|_| raid_repair_script(repair))
        }
        pb::StorageTaskKind::CacheProbe => Ok(storage_cache::probe_script()),
        pb::StorageTaskKind::CacheMove => {
            let task = req.cache_move.as_ref().ok_or_else(missing)?;
            let lsblk = lsblk().await;
            storage_cache::check_move(task, &lsblk, storage_cache::fast_source(&lsblk).as_deref())
                .map(|_| storage_cache::move_script(task))
        }
        pb::StorageTaskKind::CacheRestore => {
            let task = req.cache_restore.as_ref().ok_or_else(missing)?;
            storage_cache::check_restore(task).map(|_| storage_cache::restore_script(task))
        }
        pb::StorageTaskKind::CacheCleanup => {
            let task = req.cache_cleanup.as_ref().ok_or_else(missing)?;
            let fstab = std::fs::read_to_string("/etc/fstab").unwrap_or_default();
            storage_cache::check_cleanup(task, &fstab).map(|_| storage_cache::cleanup_script(task))
        }
        pb::StorageTaskKind::ArrayChange => {
            let task = req.array_change.as_ref().ok_or_else(missing)?;
            storage_array::check_change(task, &lsblk().await).map(|_| storage_array::array_change_script(task))
        }
        pb::StorageTaskKind::DiskFormat => {
            let task = req.disk_format.as_ref().ok_or_else(missing)?;
            storage_array::check_format(task, &lsblk().await).map(|_| storage_array::disk_format_script(task))
        }
        pb::StorageTaskKind::DiskRelease => {
            let task = req.disk_release.as_ref().ok_or_else(missing)?;
            storage_array::check_release(task).map(|_| storage_array::disk_release_script(task))
        }
        pb::StorageTaskKind::DiskBlink => {
            let task = req.disk_blink.as_ref().ok_or_else(missing)?;
            storage_array::check_blink(task).map(|_| storage_array::disk_blink_script(task))
        }
        kind @ (pb::StorageTaskKind::DriveFormat
        | pb::StorageTaskKind::DriveAttach
        | pb::StorageTaskKind::DriveCheck
        | pb::StorageTaskKind::DriveEject
        | pb::StorageTaskKind::DriveForget) => crate::backup_drive::script(req, kind, &lsblk().await),
        pb::StorageTaskKind::Unspecified => Err("choose a disk task".into()),
    }
}

fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_STORAGE_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

/// Runs outside the agent's sandbox, where /etc is writable
async fn run_script(script: &str) -> pb::StorageTaskResult {
    use std::os::unix::fs::PermissionsExt;
    let path = format!("/run/gryonixnexusd-storage-{}-{}.sh", std::process::id(), crate::notify::stamp());
    let staged = std::fs::write(&path, format!("exec 2>&1\n{script}"))
        .and_then(|_| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)));
    if let Err(err) = staged {
        return pb::StorageTaskResult { exit_code: -1, output: format!("could not stage the disk task: {err}") };
    }
    let child = tokio::process::Command::new(systemd_run_bin())
        .args(["--quiet", "--collect", "--wait", "--pipe", "--service-type=oneshot", "/bin/bash", &path])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let result = match tokio::time::timeout(TIMEOUT, child).await {
        Ok(Ok(out)) => pb::StorageTaskResult {
            exit_code: out.status.code().unwrap_or(-1),
            output: String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
        },
        Ok(Err(err)) => pb::StorageTaskResult { exit_code: -1, output: err.to_string() },
        Err(_) => pb::StorageTaskResult { exit_code: -1, output: "the disk task took too long".into() },
    };
    let _ = std::fs::remove_file(&path);
    result
}

pub async fn run(codec: Codec, req: pb::StorageTaskRequest) -> Resp {
    let script = match script(&req).await {
        Ok(script) => script,
        Err(why) => return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &why),
    };
    let result = run_script(&script).await;
    codec.encode(&result).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../Android/catalog/src/test/resources/storage")
            .join(name);
        std::fs::read_to_string(path).unwrap()
    }

    fn disks(list: &[&str]) -> Vec<String> {
        list.iter().map(|d| d.to_string()).collect()
    }

    fn identity(path: &str, serial: &str, size_bytes: u64) -> pb::DiskIdentity {
        pb::DiskIdentity { path: path.into(), serial: serial.into(), size_bytes }
    }

    #[test]
    fn smart_matches_the_app() {
        assert_eq!(disk_health_script(&disks(&["/dev/sda", "/dev/sdb"])), golden("smart.sh"));
    }

    #[test]
    fn raid_creation_matches_the_app() {
        let storage = pb::RaidCreateTask {
            level: 1,
            disks: disks(&["/dev/sdb", "/dev/sdc"]),
            name: "gryonixnexus".into(),
            mount_point: "/srv/gryonixnexus-storage".into(),
            kind: 0,
            identities: vec![identity("/dev/sdb", "", 4_000_787_030_016), identity("/dev/sdc", "", 4_000_787_030_016)],
        };
        assert_eq!(raid_create_script(&storage), golden("raid1.sh"));
        let named = pb::RaidCreateTask {
            identities: vec![identity("/dev/sdb", "WDWCC4E177", 4_000_787_030_016), identity("/dev/sdc", "", 4_000_787_030_016)],
            ..storage.clone()
        };
        assert_eq!(raid_create_script(&named), golden("raid1-serials.sh"));
        let mirror = pb::RaidCreateTask {
            level: 1,
            disks: disks(&["/dev/nvme0n1", "/dev/sdd"]),
            name: "gnx-fast".into(),
            mount_point: String::new(),
            kind: 0,
            identities: vec![identity("/dev/nvme0n1", "", 256_060_514_304), identity("/dev/sdd", "", 1_000_204_886_016)],
        };
        assert_eq!(raid_create_script(&mirror), golden("cache-mirror.sh"));
    }

    #[test]
    fn imports_match_the_app() {
        let md = pb::RaidImportTask {
            kind: pb::StorageArrayKind::Md as i32,
            address: "/dev/md/gryonixnexus".into(),
            name: "gryonixnexus".into(),
            uuid: "dd96909c:ae315ffe:3a59f52c:051376ba".into(),
            mount_point: "/srv/gryonixnexus-storage".into(),
        };
        assert_eq!(raid_import_script(&md), golden("raid-import.sh"));
        let zfs = pb::RaidImportTask {
            kind: pb::StorageArrayKind::Zfs as i32,
            address: "tank".into(),
            name: "tank".into(),
            uuid: "15437563216592283341".into(),
            mount_point: String::new(),
        };
        assert_eq!(raid_import_script(&zfs), golden("zfs-import.sh"));
    }

    #[test]
    fn repairs_match_the_app() {
        let md = pb::RaidRepairTask {
            kind: pb::StorageArrayKind::Md as i32,
            address: "/dev/md127".into(),
            name: "md127".into(),
            failed: String::new(),
            replacement: "/dev/vde".into(),
            identities: vec![identity("/dev/vde", "", 1_073_741_824)],
        };
        assert_eq!(raid_repair_script(&md), golden("raid-repair.sh"));
        let zfs = pb::RaidRepairTask {
            kind: pb::StorageArrayKind::Zfs as i32,
            address: "tank".into(),
            name: "tank".into(),
            failed: "9147389209417539263".into(),
            replacement: "/dev/sdj".into(),
            identities: vec![identity("/dev/sdj", "", 1_000_204_886_016)],
        };
        assert_eq!(raid_repair_script(&zfs), golden("zfs-replace.sh"));
    }

    #[test]
    fn a_disk_without_a_size_is_not_pinned() {
        let unpinned = storage_array::disk_guard(&[identity("/dev/sdz", "X", 0)]);
        assert_eq!(unpinned, storage_array::disk_guard(&[]));
        assert!(!unpinned.join("\n").contains("gnx_expect"));
    }

    #[test]
    fn unsafe_input_is_refused() {
        assert!(!safe_path("/dev/../proc/cpuinfo"));
        assert!(!safe_path("/proc/cpuinfo"));
        assert!(!safe_path("/dev/sda; rm -rf /"));
        assert!(!safe_name("a b"));
        assert!(!safe_mount("/etc"));
        assert!(!safe_mount("/srv/../etc"));
        let bad_level = pb::RaidCreateTask { level: 4, disks: disks(&["/dev/sda", "/dev/sdb"]), name: "x".into(), mount_point: String::new(), kind: 0, ..Default::default() };
        assert!(check_create(&bad_level, "").is_err());
        let too_few = pb::RaidCreateTask { level: 5, disks: disks(&["/dev/sda", "/dev/sdb"]), name: "x".into(), mount_point: String::new(), kind: 0, ..Default::default() };
        assert!(check_create(&too_few, "").is_err());
    }

    #[test]
    fn a_mounted_disk_is_in_use() {
        let lsblk = [
            r#"NAME="sda" PKNAME="" MOUNTPOINTS="""#,
            r#"NAME="sda1" PKNAME="sda" MOUNTPOINTS="/boot/firmware""#,
            r#"NAME="sdb" PKNAME="" MOUNTPOINTS="""#,
            r#"NAME="sdc" PKNAME="" MOUNTPOINTS="""#,
            r#"NAME="sdc1" PKNAME="sdc" MOUNTPOINTS="""#,
            r#"NAME="md127" PKNAME="sdc1" MOUNTPOINTS="/srv/data""#,
            r#"NAME="sdd" PKNAME="" MOUNTPOINTS="""#,
            r#"NAME="sde" PKNAME="" TYPE="disk" MOUNTPOINTS="""#,
            r#"NAME="md126" PKNAME="sde" TYPE="raid1" MOUNTPOINTS="""#,
        ]
        .join("\n");
        let lsblk = lsblk.as_str();
        assert!(mounted_under("/dev/sda", lsblk));
        assert!(!mounted_under("/dev/sdb", lsblk));
        assert!(mounted_under("/dev/sdc", lsblk), "an array on it is mounted");
        assert!(!mounted_under("/dev/sdd", lsblk));
        assert!(mounted_under("/dev/sde", lsblk), "a member of an unmounted array");
    }
}
