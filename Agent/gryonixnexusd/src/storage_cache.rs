//! Cache-disk tasks: find busy folders, move them, bring them back.
//!
//! Scripts match the app's generators byte for byte. Every folder is
//! checked here first; cleanup only touches folders bound in fstab.

use crate::install::packages::apt_quiet;
use crate::pb;
use crate::storage_task::{field, is_block_device, mounted_under, quote, safe_path};

pub const MOUNT_POINT: &str = "/srv/gryonixnexus-fast";
const PROBE_DONE: &str = "GRYONIXNEXUS_FAST_PROBE_DONE";
const MOVE_DONE: &str = "GRYONIXNEXUS_FAST_MOVE_DONE";
const RESTORE_DONE: &str = "GRYONIXNEXUS_FAST_RESTORE_DONE";
const CLEANUP_DONE: &str = "GRYONIXNEXUS_FAST_CLEANUP_DONE";

fn join(lines: Vec<String>) -> String {
    lines.join("\n") + "\n"
}

fn owned(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|l| l.to_string()).collect()
}

// MARK: scripts

pub fn probe_script() -> String {
    let probe = format!(
        "for f in $(ls -d /opt/*/docker-compose.y*ml /opt/*/compose.y*ml /srv/*/docker-compose.y*ml 2>/dev/null); \
         do echo \"### $f\"; cat \"$f\"; echo; done; \
         mountpoint -q {MOUNT_POINT} && echo \"GRYONIXNEXUS_FAST_MOUNTED\" || true; \
         awk '$3 == \"none\" && $1 ~ /gryonixnexus-fast\\/binds/ {{print \"GRYONIXNEXUS_FAST_BOUND \" $2}}' /etc/fstab"
    );
    format!("#!/bin/bash\n{probe}\necho {PROBE_DONE}\n")
}

fn root(task: &pb::CacheMoveTask) -> String {
    if task.device.is_empty() {
        format!("{}/gryonixnexus-fast", task.folder_on)
    } else {
        MOUNT_POINT.to_string()
    }
}

fn format_lines(device: &str) -> Vec<String> {
    let mut lines = vec![format!("DISK={}", quote(device))];
    lines.extend(owned(&[
        "if ! mountpoint -q \"$FAST\"; then",
        "  if [ -z \"$(lsblk -nro FSTYPE \"$DISK\" | tr -d '[:space:]')\" ] && [ \"$(lsblk -nro NAME \"$DISK\" | wc -l)\" -eq 1 ]; then",
        "    mkfs.ext4 -q -L gnx-fast \"$DISK\"",
        "  fi",
        "  install -d \"$FAST\"",
        "  uuid=\"$(blkid -s UUID -o value \"$DISK\")\"",
        "  grep -q \"UUID=$uuid $FAST \" /etc/fstab || echo \"UUID=$uuid $FAST ext4 defaults,noatime,nofail 0 2\" >> /etc/fstab",
        "  mount \"$FAST\"",
        "fi",
    ]));
    lines
}

fn rsync_lines() -> Vec<String> {
    let install = format!("  {} install -y -qq rsync >/dev/null", apt_quiet());
    owned(&[
        "if ! command -v rsync >/dev/null 2>&1; then",
        "  export DEBIAN_FRONTEND=noninteractive",
        install.as_str(),
        "fi",
    ])
}

fn move_functions() -> Vec<String> {
    owned(&[
        "move_dir() {",
        "  local target=\"$1\" source=\"$FAST/binds$1\" old=\"$1.before-cache\"",
        "  if mountpoint -q \"$target\"; then echo \"$target is already on the fast disk\"; return 0; fi",
        "  if [ ! -d \"$target\" ]; then echo \"$target does not exist, skipped\"; return 0; fi",
        "  echo \"Moving $target\"",
        "  install -d \"$source\" || return 1",
        "  rsync -aHAX --delete \"$target/\" \"$source/\" || return 1",
        "  if [ -e \"$old\" ]; then old=\"$old.$(date +%s)\"; fi",
        "  mv \"$target\" \"$old\" || return 1",
        "  install -d \"$target\" || return 1",
        "  grep -qF \" $target none bind\" /etc/fstab || echo \"$source $target none bind,nofail,x-systemd.requires-mounts-for=$FAST 0 0\" >> /etc/fstab || return 1",
        "  mount \"$target\" || return 1",
        "}",
        "move_project() {",
        "  local project=\"$1\" rc=0 todo=0",
        "  shift",
        "  for dir in \"$@\"; do mountpoint -q \"$dir\" || todo=1; done",
        "  if [ \"$todo\" = 0 ]; then echo \"$project is already on the fast disk\"; return 0; fi",
        "  (cd \"$project\" && docker compose stop) || return 1",
        "  for dir in \"$@\"; do move_dir \"$dir\" || rc=1; done",
        "  (cd \"$project\" && docker compose start) || rc=1",
        "  return $rc",
        "}",
    ])
}

fn project_calls(verb: &str, projects: &[pb::CacheProject]) -> Vec<String> {
    projects
        .iter()
        .map(|p| {
            let dirs = p.hot_paths.iter().map(|d| quote(d)).collect::<Vec<_>>().join(" ");
            format!("{verb} {} {dirs} || FAILED=1", quote(&p.directory))
        })
        .collect()
}

pub fn move_script(task: &pb::CacheMoveTask) -> String {
    let mut lines = owned(&["#!/bin/bash", "set -euo pipefail"]);
    lines.push(format!("FAST={}", quote(&root(task))));
    if task.device.is_empty() {
        lines.push("install -d \"$FAST\"".into());
    } else {
        lines.extend(format_lines(&task.device));
    }
    lines.extend(rsync_lines());
    lines.extend(move_functions());
    lines.extend(project_calls("move_project", &task.projects));
    lines.push("[ \"${FAILED:-0}\" = 0 ] || exit 4".into());
    lines.push(format!("echo {MOVE_DONE}"));
    join(lines)
}

fn restore_functions() -> Vec<String> {
    owned(&[
        "bound_source() {",
        "  awk -v t=\"$1\" '$2 == t && $3 == \"none\" {print $1; exit}' /etc/fstab",
        "}",
        "restore_dir() {",
        "  local target=\"$1\" source",
        "  source=\"$(bound_source \"$target\")\"",
        "  if [ -z \"$source\" ]; then echo \"$target is not on the fast disk\"; return 0; fi",
        "  echo \"Bringing back $target\"",
        "  if mountpoint -q \"$target\"; then umount \"$target\" || return 1; fi",
        "  rsync -aHAX --delete \"$source/\" \"$target/\" || return 1",
        "  awk -v t=\"$target\" '!($2 == t && $3 == \"none\")' /etc/fstab > /etc/fstab.gryonixnexus || return 1",
        "  cat /etc/fstab.gryonixnexus > /etc/fstab && rm -f /etc/fstab.gryonixnexus || return 1",
        "}",
        "restore_project() {",
        "  local project=\"$1\" rc=0 todo=0",
        "  shift",
        "  for dir in \"$@\"; do [ -n \"$(bound_source \"$dir\")\" ] && todo=1; done",
        "  if [ \"$todo\" = 0 ]; then echo \"$project is on the system disk\"; return 0; fi",
        "  (cd \"$project\" && docker compose stop) || return 1",
        "  for dir in \"$@\"; do restore_dir \"$dir\" || rc=1; done",
        "  (cd \"$project\" && docker compose start) || rc=1",
        "  return $rc",
        "}",
    ])
}

pub fn restore_script(task: &pb::CacheRestoreTask) -> String {
    let mut lines = owned(&["#!/bin/bash", "set -euo pipefail"]);
    lines.extend(rsync_lines());
    lines.extend(restore_functions());
    lines.extend(project_calls("restore_project", &task.projects));
    lines.push("[ \"${FAILED:-0}\" = 0 ] || exit 4".into());
    lines.push(format!("echo {RESTORE_DONE}"));
    join(lines)
}

pub fn cleanup_script(task: &pb::CacheCleanupTask) -> String {
    let mut lines = owned(&["#!/bin/bash", "set -euo pipefail"]);
    for path in &task.paths {
        let old = quote(&format!("{path}.before-cache"));
        lines.push(format!(
            "for old in {old} {old}.*; do [ -d \"$old\" ] || continue; rm -rf -- \"$old\"; echo \"removed $old\"; done"
        ));
    }
    lines.push(format!("echo {CLEANUP_DONE}"));
    join(lines)
}

// MARK: checks

/// An absolute data folder: no traversal, not a system tree
pub fn safe_folder(path: &str) -> bool {
    let allowed_root = ["/opt/", "/srv/", "/mnt/", "/data/", "/media/"].iter().any(|r| path.starts_with(r));
    allowed_root
        && !path.contains("..")
        && !path.contains("//")
        && path.len() < 256
        && path.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-@+".contains(c))
}

fn check_projects(projects: &[pb::CacheProject]) -> Result<(), String> {
    if projects.is_empty() {
        return Err("no services to move".into());
    }
    for project in projects {
        let compose = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"];
        let has_compose = compose.iter().any(|f| std::path::Path::new(&project.directory).join(f).is_file());
        if !safe_folder(&project.directory) || !has_compose {
            return Err(format!("{} is not a service folder", project.directory));
        }
        if project.hot_paths.is_empty() || !project.hot_paths.iter().all(|p| safe_folder(p)) {
            return Err(format!("the folders of {} are not allowed", project.directory));
        }
    }
    Ok(())
}

pub fn check_move(task: &pb::CacheMoveTask, lsblk: &str, fast_source: Option<&str>) -> Result<(), String> {
    check_projects(&task.projects)?;
    if task.device.is_empty() {
        let mounted = std::path::Path::new(&task.folder_on).is_dir() && is_mount_point(&task.folder_on);
        return if safe_folder(&task.folder_on) && mounted { Ok(()) } else { Err("the data disk is not mounted".into()) };
    }
    let device = std::fs::canonicalize(&task.device).map(|p| p.display().to_string()).unwrap_or_default();
    if !safe_path(&task.device) || !is_block_device(&device) {
        return Err(format!("{} is not a disk on this server", task.device));
    }
    if fast_source == Some(device.as_str()) || !mounted_under(&device, lsblk) {
        Ok(())
    } else {
        Err(format!("{} is in use", task.device))
    }
}

fn is_mount_point(path: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|m| m.lines().any(|l| l.split_whitespace().nth(1) == Some(path)))
        .unwrap_or(false)
}

/// Folders bound onto the cache in fstab
pub fn bound_in(fstab: &str) -> Vec<String> {
    fstab
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 2 && f[2] == "none" && f[0].contains("gryonixnexus-fast/binds")).then(|| f[1].to_string())
        })
        .collect()
}

pub fn check_cleanup(task: &pb::CacheCleanupTask, fstab: &str) -> Result<(), String> {
    let bound = bound_in(fstab);
    if task.paths.is_empty() || !task.paths.iter().all(|p| safe_folder(p) && bound.contains(p)) {
        return Err("only folders on the cache disk have old copies to delete".into());
    }
    Ok(())
}

pub fn check_restore(task: &pb::CacheRestoreTask) -> Result<(), String> {
    check_projects(&task.projects)
}

/// The device mounted as the cache, if any
pub fn fast_source(lsblk_paths: &str) -> Option<String> {
    lsblk_paths
        .lines()
        .find(|l| field(l, "MOUNTPOINTS").split("\\x0a").any(|m| m == MOUNT_POINT))
        .map(|l| format!("/dev/{}", field(l, "NAME")))
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

    fn projects() -> Vec<pb::CacheProject> {
        vec![
            pb::CacheProject { directory: "/opt/immich".into(), hot_paths: vec!["/opt/immich/postgres".into()] },
            pb::CacheProject {
                directory: "/opt/nextcloud".into(),
                hot_paths: vec!["/opt/nextcloud/db".into(), "/opt/nextcloud/redis".into()],
            },
        ]
    }

    #[test]
    fn scripts_match_the_app() {
        let task = pb::CacheMoveTask { device: String::new(), folder_on: "/mnt/fast".into(), projects: projects() };
        assert_eq!(move_script(&task), golden("fast-move.sh"));
        assert_eq!(restore_script(&pb::CacheRestoreTask { projects: projects() }), golden("fast-restore.sh"));
        let cleanup = pb::CacheCleanupTask { paths: vec!["/opt/immich/postgres".into()] };
        assert_eq!(cleanup_script(&cleanup), golden("fast-cleanup.sh"));
    }

    #[test]
    fn the_disk_format_lines_match_the_app() {
        let blank = golden("fast-blank.sh");
        for line in format_lines("/dev/nvme0n1") {
            assert!(blank.contains(&line), "missing: {line}");
        }
    }

    #[test]
    fn folders_outside_data_trees_are_refused() {
        assert!(safe_folder("/opt/immich/postgres"));
        assert!(!safe_folder("/proc/1"));
        assert!(!safe_folder("/opt/../proc"));
        assert!(!safe_folder("/opt/a b"));
        assert!(!safe_folder("/"));
    }

    #[test]
    fn cleanup_needs_a_folder_on_the_cache() {
        let fstab = "/srv/gryonixnexus-fast/binds/opt/immich/postgres /opt/immich/postgres none bind,nofail 0 0\n";
        assert_eq!(bound_in(fstab), vec!["/opt/immich/postgres"]);
        assert!(check_cleanup(&pb::CacheCleanupTask { paths: vec!["/opt/immich/postgres".into()] }, fstab).is_ok());
        assert!(check_cleanup(&pb::CacheCleanupTask { paths: vec!["/opt/immich/upload".into()] }, fstab).is_err());
    }

    #[test]
    fn the_mounted_cache_is_found() {
        let lsblk = "NAME=\"sdb\" PKNAME=\"\" TYPE=\"disk\" MOUNTPOINTS=\"/srv/gryonixnexus-fast\"\nNAME=\"sda\" PKNAME=\"\" TYPE=\"disk\" MOUNTPOINTS=\"\"";
        assert_eq!(fast_source(lsblk).as_deref(), Some("/dev/sdb"));
    }
}
