//! Changes to running arrays, new ZFS and btrfs arrays, and single-disk work.
//!
//! Every script matches the app's generators byte for byte, pinned by the
//! shared golden files; long parts run as a background job unit.

use crate::install::packages::apt_quiet;
use crate::pb;
use crate::storage_task::{is_block_device, quote, safe_mount, safe_name, safe_path, wipeable, zfs_fetch_line};

pub(crate) const CHANGE_DONE: &str = "GRYONIXNEXUS_ARRAY_CHANGE_DONE";
pub(crate) const FORMAT_DONE: &str = "GRYONIXNEXUS_DISK_FORMAT_DONE";
pub(crate) const RELEASE_DONE: &str = "GRYONIXNEXUS_DISK_RELEASE_DONE";
pub(crate) const BLINK_DONE: &str = "GRYONIXNEXUS_DISK_BLINK_DONE";
const RAID_DONE: &str = "GRYONIXNEXUS_RAID_DONE";
const JOB_UNIT: &str = "gryonixnexus-disk-job";
const JOB_LOG: &str = "/var/log/gryonixnexus-disk-job.log";
const JOB_FILE: &str = "/var/lib/gryonixnexus-disk-job.sh";
const RESHAPE_BACKUP: &str = "/var/lib/gryonixnexus-md-reshape.backup";
const DEFAULT_MOUNT: &str = "/srv/gryonixnexus-storage";
const RAID_DEVICES: &str = "$(mdadm --detail \"$ARRAY\" | awk '/Raid Devices :/ {print $4}')";

fn lines(items: &[&str]) -> Vec<String> {
    items.iter().map(|l| l.to_string()).collect()
}

fn join(all: Vec<String>) -> String {
    all.join("\n") + "\n"
}

fn quoted_list(items: &[String]) -> String {
    items.iter().map(|i| quote(i)).collect::<Vec<_>>().join(" ")
}

/// Lines run now, and lines left to the background job
struct Steps {
    now: Vec<String>,
    later: Vec<String>,
}

fn now(now: Vec<String>) -> Steps {
    Steps { now, later: vec![] }
}

fn action_name(action: i32) -> &'static str {
    use pb::ArrayChangeAction as A;
    match A::try_from(action).unwrap_or(A::Unspecified) {
        A::AddSpare => "add-spare",
        A::Grow => "grow",
        A::Replace => "replace",
        A::Detach => "detach",
        A::Remove => "remove",
        A::ChangeLevel => "change-level",
        A::Check => "check",
        A::Delete => "delete",
        A::Unspecified => "",
    }
}

// MARK: shared pieces

fn services_guard() -> Vec<String> {
    lines(&[
        "if [ -n \"$MOUNT\" ] && command -v docker >/dev/null 2>&1; then",
        "  for c in $(docker ps -aq); do",
        "    if docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' \"$c\" | grep -qF -- \"$MOUNT\"; then",
        "      echo \"Services keep their data here. Move or remove them first.\"",
        "      exit 3",
        "    fi",
        "  done",
        "fi",
    ])
}

fn forget_mount() -> Vec<String> {
    lines(&[
        "awk -v m=\"$MOUNT\" '$2 != m' /etc/fstab > /etc/fstab.gryonixnexus",
        "cat /etc/fstab.gryonixnexus > /etc/fstab",
        "rm -f /etc/fstab.gryonixnexus",
    ])
}

/// Refuses a disk that is missing, changed or in use
pub(crate) fn disk_guard<'a>(identities: impl IntoIterator<Item = &'a pb::DiskIdentity>) -> Vec<String> {
    let known: Vec<&pb::DiskIdentity> = identities.into_iter().filter(|identity| identity.size_bytes > 0).collect();
    let mut out = expected_table(&known);
    out.extend(lines(&[
        "gnx_free() {",
        "  if [ ! -b \"$1\" ]; then",
        "    echo \"$1 is not a disk on this server.\"",
        "    exit 3",
        "  fi",
    ]));
    if !known.is_empty() {
        out.extend(lines(&IDENTITY_CHECK));
    }
    out.extend(lines(&[
        "  if [ -n \"$(lsblk -rno MOUNTPOINT \"$1\" | tr -d '[:space:]')\" ] || lsblk -rno TYPE \"$1\" | grep -E '^(raid|lvm|crypt)' >/dev/null; then",
        "    echo \"$1 is in use. Nothing was erased.\"",
        "    exit 3",
        "  fi",
        "}",
    ]));
    out
}

fn expected_table(identities: &[&pb::DiskIdentity]) -> Vec<String> {
    if identities.is_empty() {
        return vec![];
    }
    let mut out = lines(&["gnx_expect() {", "  case \"$1\" in"]);
    for identity in identities {
        let size_and_serial = format!("{}|{}", identity.size_bytes, identity.serial);
        out.push(format!("    {}) echo {} ;;", quote(&identity.path), quote(&size_and_serial)));
    }
    out.extend(lines(&["  esac", "}"]));
    out
}

const IDENTITY_CHECK: [&str; 10] = [
    "  local want size serial",
    "  want=\"$(gnx_expect \"$1\")\"",
    "  if [ -n \"$want\" ]; then",
    "    size=\"$(lsblk -dnbo SIZE \"$1\" | tr -d '[:space:]')\"",
    "    serial=\"$(lsblk -dno SERIAL \"$1\" | tr -d '[:space:]')\"",
    "    if [ \"${want%%|*}\" != \"$size\" ] || { [ -n \"${want#*|}\" ] && [ -n \"$serial\" ] && [ \"${want#*|}\" != \"$serial\" ]; }; then",
    "      echo \"$1 is not the disk the app listed. Nothing was erased.\"",
    "      exit 3",
    "    fi",
    "  fi",
];

/// Checks every disk before the first one is wiped
pub(crate) fn check_all(members: &str) -> Vec<String> {
    vec![format!("  for disk in {members}; do"), "    gnx_free \"$disk\"".into(), "  done".into()]
}

const ZFS_MEMBERS: &str = "zpool status -LP \"$POOL\" | awk '$1 ~ /^\\/dev\\// {print $1}'";
const BTRFS_MEMBERS: &str = "btrfs filesystem show \"$MOUNT\" | awk '$NF ~ /^\\/dev\\// {print $NF}'";

fn require_members(members: &[String], listing: &str, noun: &str) -> Vec<String> {
    vec![
        format!("REAL=\"$({listing})\""),
        format!("for disk in {}; do", quoted_list(members)),
        "  if ! printf '%s\\n' \"$REAL\" | grep -qxF -- \"$disk\"; then".into(),
        format!("    echo \"$disk is not in this {noun}.\""),
        "    exit 3".into(),
        "  fi".into(),
        "done".into(),
    ]
}

fn wipe(members: &[String], command: &str) -> Vec<String> {
    vec![
        format!("WIPE=({})", quoted_list(members)),
        "for disk in \"${WIPE[@]}\"; do".into(),
        format!("  {command}"),
        "done".into(),
    ]
}

fn busy_guard() -> Vec<String> {
    vec![
        format!("if systemctl is-active -q {JOB_UNIT}; then"),
        "  echo \"Another disk job is still running. Wait until it ends.\"".into(),
        "  exit 3".into(),
        "fi".into(),
    ]
}

fn job_lines(action: &str, target: &str, variables: &[String], body: Vec<String>) -> Vec<String> {
    let mut out = vec![
        format!("cat > {JOB_FILE} <<'GNX_JOB'"),
        "#!/bin/bash".into(),
        "set -eEuo pipefail".into(),
        format!("exec >> {JOB_LOG} 2>&1"),
        "trap 'echo \"GRYONIXNEXUS_DISK_JOB_FAILED $(date +%s)\"' ERR".into(),
        format!("echo \"GRYONIXNEXUS_DISK_JOB_START {action} {target} $(date +%s)\""),
    ];
    out.extend(variables.iter().cloned());
    out.extend(body);
    out.extend([
        "echo \"GRYONIXNEXUS_DISK_JOB_DONE $(date +%s)\"".to_string(),
        "GNX_JOB".into(),
        format!(": > {JOB_LOG}"),
        format!("chmod 644 {JOB_LOG}"),
        format!("systemctl reset-failed {JOB_UNIT} >/dev/null 2>&1 || true"),
        format!("systemd-run --quiet --collect --unit={JOB_UNIT} /bin/bash {JOB_FILE}"),
    ]);
    out
}

fn variables(task: &pb::ArrayChangeTask) -> Vec<String> {
    let head = match pb::StorageArrayKind::try_from(task.kind).unwrap_or(pb::StorageArrayKind::Md) {
        pb::StorageArrayKind::Zfs => "POOL=",
        pb::StorageArrayKind::Btrfs => "MOUNT=",
        _ => "ARRAY=",
    };
    let mut out = vec![format!("{head}{}", quote(&task.address))];
    if !task.member.is_empty() {
        out.push(format!("OLD={}", quote(&task.member)));
    }
    for (index, disk) in task.disks.iter().enumerate() {
        let suffix = if index == 0 { String::new() } else { (index + 1).to_string() };
        out.push(format!("NEW{suffix}={}", quote(disk)));
    }
    out
}

fn health_lines(disks: &[String]) -> Vec<String> {
    if disks.is_empty() {
        return vec![];
    }
    let mut out = vec![format!("CHECK=({})", quoted_list(disks))];
    out.extend(lines(&[
        "if command -v smartctl >/dev/null 2>&1; then",
        "  for disk in \"${CHECK[@]}\"; do",
        "    if smartctl -H \"$disk\" 2>/dev/null | grep -q FAILED; then",
        "      echo \"$disk reports that it is failing. Replace that disk first.\"",
        "      exit 3",
        "    fi",
        "  done",
        "fi",
    ]));
    out
}

pub fn array_change_script(task: &pb::ArrayChangeTask) -> String {
    let steps = match pb::StorageArrayKind::try_from(task.kind).unwrap_or(pb::StorageArrayKind::Md) {
        pb::StorageArrayKind::Zfs => zfs_steps(task),
        pb::StorageArrayKind::Btrfs => btrfs_steps(task),
        _ => md_steps(task),
    };
    let vars = variables(task);
    let mut out = lines(&["#!/bin/bash", "set -euo pipefail"]);
    out.extend(vars.iter().cloned());
    if !task.disks.is_empty() {
        out.extend(disk_guard(&task.identities));
    }
    if !steps.later.is_empty() {
        out.extend(busy_guard());
    }
    out.extend(health_lines(&task.check_disks));
    out.extend(steps.now);
    if !steps.later.is_empty() {
        out.extend(job_lines(action_name(task.action), &task.name, &vars, steps.later));
    }
    out.push(format!("echo {CHANGE_DONE}"));
    join(out)
}

// MARK: mdadm

fn md_present() -> Vec<String> {
    lines(&[
        "if ! mdadm --detail \"$ARRAY\" | grep -qw -- \"$OLD\"; then",
        "  echo \"$OLD is not in this array.\"",
        "  exit 3",
        "fi",
    ])
}

fn md_healthy() -> Vec<String> {
    lines(&[
        "if mdadm --detail \"$ARRAY\" | grep -Eq 'State : .*(degraded|recovering|resyncing|reshaping)'; then",
        "  echo \"The array is not healthy right now. Wait until it is, then try again.\"",
        "  exit 3",
        "fi",
    ])
}

fn md_add() -> Vec<String> {
    lines(&[
        "if ! mdadm --detail \"$ARRAY\" | grep -qw -- \"$NEW\"; then",
        "  gnx_free \"$NEW\"",
        "  wipefs -a -q \"$NEW\"",
        "  mdadm \"$ARRAY\" --add \"$NEW\"",
        "fi",
    ])
}

fn md_grow_to(devices: u32) -> Vec<String> {
    vec![
        format!("if [ \"{RAID_DEVICES}\" -lt {devices} ]; then"),
        format!("  mdadm --grow \"$ARRAY\" --raid-devices={devices}"),
        "fi".into(),
    ]
}

fn md_take_out() -> Vec<String> {
    lines(&[
        "if mdadm --detail \"$ARRAY\" | grep -qw -- \"$OLD\"; then",
        "  mdadm \"$ARRAY\" --fail \"$OLD\"",
        "  mdadm \"$ARRAY\" --remove \"$OLD\"",
        "fi",
    ])
}

fn md_forget() -> Vec<String> {
    lines(&["mdadm --zero-superblock \"$OLD\" >/dev/null 2>&1 || true"])
}

fn md_wait() -> Vec<String> {
    lines(&["mdadm --wait \"$ARRAY\" || true", "sleep 5"])
}

fn md_resize() -> Vec<String> {
    lines(&[
        "target=\"$(findmnt -no TARGET \"$ARRAY\" | head -n 1 || true)\"",
        "case \"$(blkid -s TYPE -o value \"$ARRAY\" || true)\" in",
        "  ext2|ext3|ext4) resize2fs \"$ARRAY\" ;;",
        "  xfs) xfs_growfs \"$target\" ;;",
        "  btrfs) btrfs filesystem resize max \"$target\" ;;",
        "esac",
    ])
}

fn md_shrink_mirror(devices: u32) -> Vec<String> {
    let force = if devices == 1 { " --force" } else { "" };
    vec![
        format!("if [ \"{RAID_DEVICES}\" -gt {devices} ]; then"),
        format!("  mdadm --grow \"$ARRAY\" --raid-devices={devices}{force}"),
        "fi".into(),
    ]
}

fn md_steps(task: &pb::ArrayChangeTask) -> Steps {
    use pb::ArrayChangeAction as A;
    let chain = |parts: Vec<Vec<String>>| parts.concat();
    match A::try_from(task.action).unwrap_or(A::Unspecified) {
        A::AddSpare => now(md_add()),
        A::Grow => Steps {
            now: chain(vec![md_healthy(), md_add(), md_grow_to(task.devices)]),
            later: if task.level == "raid1" { vec![] } else { chain(vec![md_wait(), md_resize()]) },
        },
        A::Replace => Steps {
            now: chain(vec![md_present(), md_healthy(), md_add(), lines(&["mdadm \"$ARRAY\" --replace \"$OLD\" --with \"$NEW\""])]),
            later: chain(vec![md_wait(), lines(&["mdadm \"$ARRAY\" --remove \"$OLD\""]), md_forget()]),
        },
        A::Detach => now(chain(vec![md_healthy(), md_take_out(), md_forget()])),
        A::Remove if task.level == "raid1" => {
            now(chain(vec![md_healthy(), md_take_out(), md_shrink_mirror(task.devices), md_forget()]))
        }
        A::Remove => Steps { now: chain(vec![md_present(), md_healthy(), md_shrink_check(task)]), later: md_shrink_job(task) },
        A::ChangeLevel => md_change_level(task),
        A::Check => now(lines(&[
            "md=\"$(basename \"$(readlink -f \"$ARRAY\")\")\"",
            "echo check > \"/sys/block/$md/md/sync_action\"",
        ])),
        A::Delete => now(md_delete()),
        A::Unspecified => now(vec![]),
    }
}

fn md_change_level(task: &pb::ArrayChangeTask) -> Steps {
    if task.new_level == 5 {
        let mut first = md_healthy();
        first.extend(lines(&[
            "if mdadm --detail \"$ARRAY\" | grep -q 'Raid Level : raid1'; then",
            "  mdadm --grow \"$ARRAY\" --level=5",
            "fi",
        ]));
        return Steps { now: [first, md_add(), md_grow_to(task.devices)].concat(), later: [md_wait(), md_resize()].concat() };
    }
    let mut first = [md_healthy(), md_add()].concat();
    first.extend([
        "if mdadm --detail \"$ARRAY\" | grep -q 'Raid Level : raid5'; then".to_string(),
        format!("  mdadm --grow \"$ARRAY\" --level=6 --raid-devices={} --backup-file={RESHAPE_BACKUP}", task.devices),
        "fi".into(),
    ]);
    let mut later = md_wait();
    later.push(format!("rm -f {RESHAPE_BACKUP}"));
    Steps { now: first, later }
}

fn md_delete() -> Vec<String> {
    let mut out = lines(&["MOUNT=\"$(findmnt -no TARGET \"$ARRAY\" | head -n 1 || true)\""]);
    out.extend(services_guard());
    out.extend(lines(&[
        "uuid=\"$(mdadm --detail \"$ARRAY\" | awk '/UUID :/ {print $3}')\"",
        "members=\"$(mdadm --detail \"$ARRAY\" | awk '$NF ~ /^\\/dev\\// && NF > 4 {print $NF}')\"",
        "if [ -n \"$MOUNT\" ]; then",
        "  umount \"$MOUNT\"",
    ]));
    out.extend(forget_mount().into_iter().map(|l| format!("  {l}")));
    out.extend(lines(&[
        "fi",
        "mdadm --stop \"$ARRAY\"",
        "for disk in $members; do",
        "  mdadm --zero-superblock \"$disk\" || true",
        "  wipefs -a -q \"$disk\" || true",
        "done",
        "if [ -f /etc/mdadm/mdadm.conf ]; then",
        "  sed -i \"/UUID=$uuid/d\" /etc/mdadm/mdadm.conf",
        "fi",
        "update-initramfs -u >/dev/null 2>&1 || true",
    ]));
    out
}

fn md_room(task: &pb::ArrayChangeTask) -> String {
    let parity = if task.level == "raid6" { 2 } else { 1 };
    let data = task.devices as i64 - parity;
    format!("room=$(( $(mdadm --detail \"$ARRAY\" | awk '/Used Dev Size :/ {{print $5}}') * {data} ))")
}

fn md_shrink_check(task: &pb::ArrayChangeTask) -> Vec<String> {
    let mut out = lines(&[
        "if [ \"$(blkid -s TYPE -o value \"$ARRAY\" || true)\" != ext4 ]; then",
        "  echo \"Only an array with ext4 on it can give a disk back.\"",
        "  exit 3",
        "fi",
    ]);
    out.push(md_room(task));
    out.extend(lines(&[
        "MOUNT=\"$(findmnt -no TARGET \"$ARRAY\" | head -n 1 || true)\"",
        "if [ -n \"$MOUNT\" ] && [ \"$(df -k --output=used \"$MOUNT\" | tail -n 1 | tr -d ' ')\" -gt $((room * 9 / 10)) ]; then",
        "  echo \"The data does not fit on the disks that stay. Free some space first.\"",
        "  exit 3",
        "fi",
    ]));
    out
}

fn md_pause() -> Vec<String> {
    lines(&[
        "MOUNT=\"$(findmnt -no TARGET \"$ARRAY\" | head -n 1 || true)\"",
        "stopped=\"\"",
        "restore() {",
        "  if [ -n \"$MOUNT\" ] && ! mountpoint -q \"$MOUNT\"; then mount \"$MOUNT\" || true; fi",
        "  if [ -n \"$stopped\" ]; then docker start $stopped >/dev/null || true; fi",
        "}",
        "trap restore EXIT",
        "if [ -n \"$MOUNT\" ]; then",
        "  if command -v docker >/dev/null 2>&1; then",
        "    for c in $(docker ps -q); do",
        "      if docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' \"$c\" | grep -qF -- \"$MOUNT\"; then",
        "        stopped=\"$stopped $c\"",
        "      fi",
        "    done",
        "    if [ -n \"$stopped\" ]; then docker stop $stopped >/dev/null; fi",
        "  fi",
        "  umount \"$MOUNT\"",
        "fi",
    ])
}

fn md_shrink_job(task: &pb::ArrayChangeTask) -> Vec<String> {
    let mut out = vec![md_room(task)];
    out.extend(md_pause());
    out.extend(lines(&[
        "e2fsck -f -y \"$ARRAY\" || [ $? -le 1 ]",
        "resize2fs \"$ARRAY\" \"${room}K\"",
        "mdadm --grow \"$ARRAY\" --array-size=\"$room\"",
        "restore",
    ]));
    out.push(format!("mdadm --grow \"$ARRAY\" --raid-devices={} --backup-file={RESHAPE_BACKUP}", task.devices));
    out.extend(lines(&[
        "mdadm --wait \"$ARRAY\" || true",
        "sleep 5",
        "spare=\"$(mdadm --detail \"$ARRAY\" | awk '/spare/ && $NF ~ /^\\/dev\\// {print $NF}' | head -n 1)\"",
        "if [ -n \"$spare\" ] && [ \"$spare\" != \"$OLD\" ]; then",
        "  mdadm \"$ARRAY\" --replace \"$OLD\" --with \"$spare\"",
        "  mdadm --wait \"$ARRAY\" || true",
        "  sleep 5",
        "fi",
        "mdadm \"$ARRAY\" --remove \"$OLD\"",
        "mdadm --zero-superblock \"$OLD\" >/dev/null 2>&1 || true",
    ]));
    out.push(format!("rm -f {RESHAPE_BACKUP}"));
    out
}

// MARK: ZFS

fn zfs_unless_new(body: &[&str]) -> Vec<String> {
    let mut out = lines(&["if ! zpool status -LP \"$POOL\" | grep -qw -- \"$NEW\"; then"]);
    out.extend(body.iter().map(|l| format!("  {l}")));
    out.push("fi".into());
    out
}

fn zfs_healthy() -> Vec<String> {
    lines(&[
        "if ! zpool status -x \"$POOL\" | grep -q 'is healthy'; then",
        "  echo \"The pool is not healthy right now. Wait until it is, then try again.\"",
        "  exit 3",
        "fi",
    ])
}

fn zfs_grow(task: &pb::ArrayChangeTask) -> Vec<&'static str> {
    match task.level.as_str() {
        "mirror" if task.disks.len() == 2 => vec!["gnx_free \"$NEW2\"", "wipefs -a -q \"$NEW2\"", "zpool add -f \"$POOL\" mirror \"$NEW\" \"$NEW2\""],
        "mirror" => vec!["zpool attach -f \"$POOL\" \"$OLD\" \"$NEW\""],
        "stripe" => vec!["zpool add -f \"$POOL\" \"$NEW\""],
        _ => vec![
            "vdev=\"$(zpool status -P \"$POOL\" | awk '$1 ~ /^raidz[123]-[0-9]+$/ {print $1; exit}')\"",
            "zpool attach -f \"$POOL\" \"$vdev\" \"$NEW\"",
        ],
    }
}

fn zfs_steps(task: &pb::ArrayChangeTask) -> Steps {
    use pb::ArrayChangeAction as A;
    let clear_old = "zpool labelclear -f \"$OLD\" >/dev/null 2>&1 || true";
    match A::try_from(task.action).unwrap_or(A::Unspecified) {
        A::AddSpare => now(zfs_unless_new(&["gnx_free \"$NEW\"", "wipefs -a -q \"$NEW\"", "zpool add -f \"$POOL\" spare \"$NEW\""])),
        A::Grow => now(zfs_unless_new(&[vec!["gnx_free \"$NEW\"", "wipefs -a -q \"$NEW\""], zfs_grow(task)].concat())),
        A::Replace => now(zfs_unless_new(&["gnx_free \"$NEW\"", "wipefs -a -q \"$NEW\"", "zpool replace -f \"$POOL\" \"$OLD\" \"$NEW\""])),
        A::Detach => now([zfs_healthy(), lines(&["zpool offline \"$POOL\" \"$OLD\""])].concat()),
        A::Remove if task.level == "mirror" => {
            now([zfs_healthy(), lines(&["zpool detach \"$POOL\" \"$OLD\"", clear_old])].concat())
        }
        A::Remove => Steps {
            now: [zfs_healthy(), lines(&["zpool remove \"$POOL\" \"$OLD\""])].concat(),
            later: lines(&["zpool wait -t remove \"$POOL\"", clear_old]),
        },
        A::Check => now(lines(&["zpool scrub \"$POOL\""])),
        A::ChangeLevel => now(lines(&["echo \"ZFS cannot change the level of a pool.\"", "exit 3"])),
        A::Delete => {
            let mut out = lines(&["MOUNT=\"$(zfs get -H -o value mountpoint \"$POOL\" 2>/dev/null | grep '^/' || true)\""]);
            out.extend(services_guard());
            out.extend(require_members(&task.members, ZFS_MEMBERS, "pool"));
            out.push("zpool destroy -f \"$POOL\"".into());
            out.extend(wipe(&task.members, "zpool labelclear -f \"$disk\" >/dev/null 2>&1 || true; wipefs -a -q \"$disk\" || true"));
            now(out)
        }
        A::Unspecified => now(vec![]),
    }
}

// MARK: btrfs

fn btrfs_present() -> Vec<String> {
    lines(&[
        "if ! btrfs filesystem show \"$MOUNT\" | grep -qw -- \"$OLD\"; then",
        "  echo \"$OLD is not in this filesystem.\"",
        "  exit 3",
        "fi",
    ])
}

fn btrfs_profiles(level: u32) -> &'static str {
    match level {
        0 => "-dconvert=raid0 -mconvert=raid1",
        10 => "-dconvert=raid10 -mconvert=raid10",
        _ => "-dconvert=raid1 -mconvert=raid1",
    }
}

fn btrfs_steps(task: &pb::ArrayChangeTask) -> Steps {
    let mut steps = btrfs_action_steps(task);
    let mut mounted = lines(&["if ! mountpoint -q \"$MOUNT\"; then", "  echo \"$MOUNT is not mounted.\"", "  exit 3", "fi"]);
    mounted.extend(steps.now);
    steps.now = mounted;
    steps
}

fn btrfs_action_steps(task: &pb::ArrayChangeTask) -> Steps {
    use pb::ArrayChangeAction as A;
    match A::try_from(task.action).unwrap_or(A::Unspecified) {
        A::Grow => Steps {
            now: lines(&[
                "if ! btrfs filesystem show \"$MOUNT\" | grep -qw -- \"$NEW\"; then",
                "  gnx_free \"$NEW\"",
                "  wipefs -a -q \"$NEW\"",
                "  btrfs device add -f \"$NEW\" \"$MOUNT\"",
                "fi",
            ]),
            later: lines(&["btrfs balance start --full-balance \"$MOUNT\""]),
        },
        A::Replace => Steps {
            now: [btrfs_present(), lines(&["gnx_free \"$NEW\"", "wipefs -a -q \"$NEW\""])].concat(),
            later: lines(&[
                "btrfs replace start -B -f \"$OLD\" \"$NEW\" \"$MOUNT\"",
                "devid=\"$(btrfs filesystem show \"$MOUNT\" | awk -v d=\"$NEW\" '$NF == d {print $2}')\"",
                "btrfs filesystem resize \"$devid:max\" \"$MOUNT\"",
            ]),
        },
        A::Remove => Steps {
            now: btrfs_present(),
            later: lines(&["btrfs device remove \"$OLD\" \"$MOUNT\"", "wipefs -a -q \"$OLD\" || true"]),
        },
        A::ChangeLevel => Steps {
            now: vec![],
            later: vec![format!("btrfs balance start {} \"$MOUNT\"", btrfs_profiles(task.new_level))],
        },
        A::Check => now(lines(&["btrfs scrub start \"$MOUNT\" >/dev/null"])),
        A::Delete => {
            let mut out = services_guard();
            out.extend(require_members(&task.members, BTRFS_MEMBERS, "filesystem"));
            out.push("umount \"$MOUNT\"".into());
            out.extend(forget_mount());
            out.extend(wipe(&task.members, "wipefs -a -q \"$disk\" || true"));
            now(out)
        }
        A::AddSpare | A::Detach => now(lines(&["echo \"btrfs has no spare or offline disks.\"", "exit 3"])),
        A::Unspecified => now(vec![]),
    }
}

// MARK: new ZFS pools and btrfs arrays

fn zfs_tools() -> Vec<String> {
    let zfs_fetch = zfs_fetch_line();
    lines(&[
        "if ! command -v zpool >/dev/null 2>&1; then",
        "  export DEBIAN_FRONTEND=noninteractive",
        zfs_fetch.as_str(),
        "    echo \"ZFS tools could not be installed here. On Debian they come from the contrib section.\"",
        "    exit 3",
        "  fi",
        "fi",
    ])
}

fn btrfs_tools() -> Vec<String> {
    tool_install("mkfs.btrfs", "btrfs-progs")
}

/// Installs one package when its command is missing
fn tool_install(command: &str, package: &str) -> Vec<String> {
    vec![
        format!("if ! command -v {command} >/dev/null 2>&1; then"),
        format!("  {} install -y -q {package}", apt_quiet()),
        "fi".to_string(),
    ]
}

fn create_mount(task: &pb::RaidCreateTask) -> &str {
    if task.mount_point.is_empty() {
        DEFAULT_MOUNT
    } else {
        &task.mount_point
    }
}

fn zfs_layout(task: &pb::RaidCreateTask) -> String {
    let paths: Vec<String> = task.disks.iter().map(|d| quote(d)).collect();
    match task.level {
        0 => paths.join(" "),
        1 => format!("mirror {}", paths.join(" ")),
        5 => format!("raidz1 {}", paths.join(" ")),
        6 => format!("raidz2 {}", paths.join(" ")),
        _ => paths.chunks(2).filter(|p| p.len() == 2).map(|p| format!("mirror {} {}", p[0], p[1])).collect::<Vec<_>>().join(" "),
    }
}

pub fn zfs_create_script(task: &pb::RaidCreateTask) -> String {
    let members = quoted_list(&task.disks);
    let mut out = lines(&["#!/bin/bash", "set -euo pipefail"]);
    out.push(format!("POOL={}", quote(&task.name)));
    out.push(format!("MOUNT={}", quote(create_mount(task))));
    out.extend(disk_guard(&task.identities));
    out.extend(zfs_tools());
    out.extend(lines(&[
        "if ! modprobe zfs >/dev/null 2>&1; then",
        "  echo \"This kernel has no ZFS module. Install zfs-dkms, or pick another kind of array.\"",
        "  exit 3",
        "fi",
        "if ! zpool list -H \"$POOL\" >/dev/null 2>&1; then",
    ]));
    out.extend(check_all(&members));
    out.push(format!("  for disk in {members}; do"));
    out.extend(lines(&["    wipefs -a -q \"$disk\"", "  done"]));
    out.push(format!(
        "  zpool create -f -o ashift=12 -O compression=lz4 -O atime=off -m \"$MOUNT\" \"$POOL\" {}",
        zfs_layout(task)
    ));
    out.extend(lines(&["fi", "zpool set cachefile=/etc/zfs/zpool.cache \"$POOL\" || true"]));
    out.push(format!("echo {RAID_DONE}"));
    join(out)
}

pub fn btrfs_create_script(task: &pb::RaidCreateTask) -> String {
    let members = quoted_list(&task.disks);
    let profiles = match task.level {
        10 => "-d raid10 -m raid10",
        0 => "-d raid0 -m raid1",
        _ => "-d raid1 -m raid1",
    };
    let mut out = lines(&["#!/bin/bash", "set -euo pipefail"]);
    out.push(format!("NAME={}", quote(&task.name)));
    out.push(format!("MOUNT={}", quote(create_mount(task))));
    out.push(format!("FIRST={}", quote(task.disks.first().map(String::as_str).unwrap_or(""))));
    out.extend(disk_guard(&task.identities));
    out.extend(btrfs_tools());
    out.push("if [ \"$(blkid -s LABEL -o value \"$FIRST\" || true)\" != \"$NAME\" ]; then".into());
    out.extend(check_all(&members));
    out.push(format!("  for disk in {members}; do"));
    out.extend(lines(&["    wipefs -a -q \"$disk\"", "  done"]));
    out.push(format!("  mkfs.btrfs -q -f -L \"$NAME\" {profiles} {members}"));
    out.extend(lines(&[
        "  udevadm settle",
        "fi",
        "btrfs device scan >/dev/null",
        "install -d \"$MOUNT\"",
        "uuid=\"$(blkid -s UUID -o value \"$FIRST\")\"",
        "grep -q \"UUID=$uuid $MOUNT \" /etc/fstab || echo \"UUID=$uuid $MOUNT btrfs defaults,nofail 0 0\" >> /etc/fstab",
        "mountpoint -q \"$MOUNT\" || mount \"$MOUNT\"",
    ]));
    out.push(format!("echo {RAID_DONE}"));
    join(out)
}

// MARK: single disks

pub fn disk_format_script(task: &pb::DiskFormatTask) -> String {
    let (tools, make, pass) = match task.filesystem.as_str() {
        "xfs" => (
            tool_install("mkfs.xfs", "xfsprogs"),
            "mkfs.xfs -f -q -L \"$LABEL\" \"$part\"",
            "0",
        ),
        "btrfs" => (btrfs_tools(), "mkfs.btrfs -f -q -L \"$LABEL\" \"$part\"", "0"),
        _ => (vec![], "mkfs.ext4 -q -L \"$LABEL\" \"$part\"", "2"),
    };
    let mut out = lines(&["#!/bin/bash", "set -euo pipefail"]);
    out.push(format!("DISK={}", quote(&task.disk)));
    out.push(format!("LABEL={}", quote(&task.label)));
    out.push(format!("MOUNT={}", quote(&task.mount_point)));
    out.extend(disk_guard(&task.identity));
    out.extend(tools);
    out.extend(lines(&[
        "if ! lsblk -rno LABEL \"$DISK\" | grep -qx -- \"$LABEL\"; then",
        "  gnx_free \"$DISK\"",
        "  for old in $(lsblk -rnpo NAME,TYPE \"$DISK\" | awk '$2 == \"part\" {print $1}'); do",
        "    zpool labelclear -f \"$old\" >/dev/null 2>&1 || true",
        "    wipefs -a -q \"$old\" || true",
        "  done",
        "  zpool labelclear -f \"$DISK\" >/dev/null 2>&1 || true",
        "  wipefs -a -q \"$DISK\"",
        "  size=\"$(blockdev --getsz \"$DISK\")\"",
        "  dd if=/dev/zero of=\"$DISK\" bs=512 seek=\"$((size - 8192))\" count=8192 conv=fsync status=none",
        "  printf 'label: gpt\\n,,L\\n' | sfdisk -q \"$DISK\"",
        "  udevadm settle",
        "  part=\"$(lsblk -rnpo NAME,TYPE \"$DISK\" | awk '$2 == \"part\" {print $1; exit}')\"",
    ]));
    out.push(format!("  {make}"));
    out.extend(lines(&[
        "  udevadm settle",
        "fi",
        "part=\"$(lsblk -rnpo NAME,LABEL \"$DISK\" | awk -v l=\"$LABEL\" '$2 == l {print $1; exit}')\"",
        "install -d \"$MOUNT\"",
        "uuid=\"$(blkid -s UUID -o value \"$part\")\"",
    ]));
    let fs = if task.filesystem.is_empty() { "ext4" } else { task.filesystem.as_str() };
    out.push(format!(
        "grep -q \"UUID=$uuid $MOUNT \" /etc/fstab || echo \"UUID=$uuid $MOUNT {fs} defaults,nofail 0 {pass}\" >> /etc/fstab"
    ));
    out.push("mountpoint -q \"$MOUNT\" || mount \"$MOUNT\"".into());
    out.push(format!("echo {FORMAT_DONE}"));
    join(out)
}

pub fn disk_release_script(task: &pb::DiskReleaseTask) -> String {
    let mut out = lines(&["#!/bin/bash", "set -euo pipefail"]);
    out.push(format!("MOUNT={}", quote(&task.mount_point)));
    out.extend(services_guard());
    out.extend(lines(&["if mountpoint -q \"$MOUNT\"; then", "  umount \"$MOUNT\"", "fi"]));
    out.extend(forget_mount());
    out.push(format!("echo {RELEASE_DONE}"));
    join(out)
}

pub fn disk_blink_script(task: &pb::DiskBlinkTask) -> String {
    let mut out = lines(&["#!/bin/bash", "set -uo pipefail"]);
    out.push(format!("DISK={}", quote(&task.disk)));
    out.extend(lines(&[
        "if command -v ledctl >/dev/null 2>&1; then",
        "  ledctl locate=\"$DISK\" >/dev/null 2>&1 || true",
        "fi",
        "timeout 30 dd if=\"$DISK\" of=/dev/null bs=1M iflag=direct status=none || true",
        "if command -v ledctl >/dev/null 2>&1; then",
        "  ledctl locate_off=\"$DISK\" >/dev/null 2>&1 || true",
        "fi",
    ]));
    out.push(format!("echo {BLINK_DONE}"));
    join(out)
}

// MARK: validation

fn safe_member(member: &str) -> bool {
    safe_path(member) || (!member.is_empty() && member.len() < 32 && member.chars().all(|c| c.is_ascii_digit()))
}

fn safe_btrfs_mount(mount: &str) -> bool {
    mount.starts_with('/') && mount.len() > 1 && !mount.contains("..")
        && mount.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c))
}

fn change_target_ok(task: &pb::ArrayChangeTask) -> bool {
    match pb::StorageArrayKind::try_from(task.kind).unwrap_or(pb::StorageArrayKind::Unspecified) {
        pb::StorageArrayKind::Md => safe_path(&task.address) && task.address.starts_with("/dev/md"),
        pb::StorageArrayKind::Zfs => safe_name(&task.address),
        pb::StorageArrayKind::Btrfs => safe_btrfs_mount(&task.address),
        pb::StorageArrayKind::Unspecified => false,
    }
}

/// What each action needs, beyond safe names
fn change_shape_ok(task: &pb::ArrayChangeTask) -> bool {
    use pb::ArrayChangeAction as A;
    let member = !task.member.is_empty();
    match A::try_from(task.action).unwrap_or(A::Unspecified) {
        A::AddSpare => task.disks.len() == 1,
        A::Grow => (1..=2).contains(&task.disks.len()),
        A::Replace => member && task.disks.len() == 1,
        A::Detach | A::Remove => member && task.disks.is_empty(),
        A::ChangeLevel => [0, 1, 5, 6, 10].contains(&task.new_level) && task.disks.len() <= 1,
        A::Check | A::Delete => task.disks.is_empty(),
        A::Unspecified => false,
    }
}

pub fn check_change(task: &pb::ArrayChangeTask, lsblk: &str) -> Result<(), String> {
    let names_ok = safe_name(&task.name)
        && (task.level.is_empty() || safe_name(&task.level))
        && (task.member.is_empty() || safe_member(&task.member))
        && task.members.iter().all(|m| safe_member(m))
        && task.check_disks.iter().all(|d| safe_path(d))
        && task.devices <= 64;
    if !change_target_ok(task) || !names_ok || !change_shape_ok(task) {
        return Err("the array change is not described correctly".into());
    }
    task.disks.iter().try_for_each(|disk| wipeable(disk, lsblk))
}

pub fn check_format(task: &pb::DiskFormatTask, lsblk: &str) -> Result<(), String> {
    let ok = ["ext4", "xfs", "btrfs"].contains(&task.filesystem.as_str())
        && safe_name(&task.label)
        && task.label.len() <= 12
        && safe_mount(&task.mount_point);
    if !ok {
        return Err("the disk to format is not described correctly".into());
    }
    wipeable(&task.disk, lsblk)
}

pub fn check_release(task: &pb::DiskReleaseTask) -> Result<(), String> {
    let mount = &task.mount_point;
    let under = ["/srv/", "/mnt/", "/media/"].iter().any(|p| mount.starts_with(p));
    if under && safe_btrfs_mount(mount) {
        Ok(())
    } else {
        Err("only a disk under /srv, /mnt or /media is released here".into())
    }
}

pub fn check_blink(task: &pb::DiskBlinkTask) -> Result<(), String> {
    if safe_path(&task.disk) && is_block_device(&task.disk) {
        Ok(())
    } else {
        Err(format!("{} is not a disk on this server", task.disk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../Android/catalog/src/test/resources/storage")
            .join(name);
        std::fs::read_to_string(path).unwrap()
    }

    fn strings(value: &serde_json::Value) -> Vec<String> {
        value.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
    }

    fn identity(path: &str, serial: &str, size_bytes: u64) -> pb::DiskIdentity {
        pb::DiskIdentity { path: path.into(), serial: serial.into(), size_bytes }
    }

    fn identities(value: &serde_json::Value) -> Vec<pb::DiskIdentity> {
        let text = |item: &serde_json::Value, key: &str| item[key].as_str().unwrap().to_string();
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| identity(&text(item, "path"), &text(item, "serial"), item["sizeBytes"].as_u64().unwrap()))
            .collect()
    }

    fn action(raw: &str) -> i32 {
        use pb::ArrayChangeAction as A;
        let action = match raw {
            "add-spare" => A::AddSpare,
            "grow" => A::Grow,
            "replace" => A::Replace,
            "detach" => A::Detach,
            "remove" => A::Remove,
            "change-level" => A::ChangeLevel,
            "check" => A::Check,
            "delete" => A::Delete,
            _ => A::Unspecified,
        };
        action as i32
    }

    fn kind(raw: &str) -> i32 {
        match raw {
            "zfs" => pb::StorageArrayKind::Zfs as i32,
            "btrfs" => pb::StorageArrayKind::Btrfs as i32,
            _ => pb::StorageArrayKind::Md as i32,
        }
    }

    fn cases() -> Vec<(String, pb::ArrayChangeTask)> {
        let all: serde_json::Value = serde_json::from_str(&fixture("array-change-cases.json")).unwrap();
        all.as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let text = |key: &str| c[key].as_str().unwrap().to_string();
                let task = pb::ArrayChangeTask {
                    action: action(&text("action")),
                    kind: kind(&text("kind")),
                    address: text("address"),
                    name: text("name"),
                    level: text("level"),
                    member: text("member"),
                    disks: strings(&c["disks"]),
                    devices: c["devices"].as_u64().unwrap() as u32,
                    new_level: c["newLevel"].as_u64().unwrap() as u32,
                    members: strings(&c["members"]),
                    check_disks: strings(&c["checkDisks"]),
                    identities: identities(&c["identities"]),
                };
                (text("golden"), task)
            })
            .collect()
    }

    #[test]
    fn every_change_matches_the_app() {
        let all = cases();
        assert_eq!(all.len(), 28);
        for (golden, task) in all {
            assert_eq!(array_change_script(&task), fixture(&golden), "{golden}");
            assert!(change_target_ok(&task) && change_shape_ok(&task), "{golden} is a valid shape");
        }
    }

    fn serial_of(disk: &str) -> &'static str {
        match disk {
            "/dev/sdi" => "WD-WCC4E1FREE1",
            "/dev/sdj" => "WD-WCC4E1FREE2",
            "/dev/sdb" => "WD-WCC4E1AAAAA1",
            "/dev/sdc" => "WD-WCC4E1AAAAA2",
            _ => "",
        }
    }

    fn create(level: u32, disks: &[&str], name: &str, kind: pb::StorageArrayKind) -> pb::RaidCreateTask {
        pb::RaidCreateTask {
            level,
            disks: disks.iter().map(|d| d.to_string()).collect(),
            name: name.into(),
            mount_point: "/srv/gryonixnexus-storage2".into(),
            kind: kind as i32,
            identities: disks.iter().map(|d| identity(d, serial_of(d), 4_000_787_030_016)).collect(),
        }
    }

    #[test]
    fn new_arrays_and_disk_work_match_the_app() {
        let zfs = create(1, &["/dev/sdi", "/dev/sdj"], "gryonixnexus2", pb::StorageArrayKind::Zfs);
        assert_eq!(crate::storage_task::create_script(&zfs), fixture("zfs-create.sh"));
        let pairs = create(10, &["/dev/sdb", "/dev/sdc", "/dev/sdi", "/dev/sdj"], "gryonixnexus2", pb::StorageArrayKind::Zfs);
        assert_eq!(crate::storage_task::create_script(&pairs), fixture("zfs-create-pairs.sh"));
        let btrfs = create(1, &["/dev/sdi", "/dev/sdj"], "gryonixnexus2", pb::StorageArrayKind::Btrfs);
        assert_eq!(crate::storage_task::create_script(&btrfs), fixture("btrfs-create.sh"));
        let format = |disk: &str, fs: &str, label: &str, mount: &str| pb::DiskFormatTask {
            disk: disk.into(),
            filesystem: fs.into(),
            label: label.into(),
            mount_point: mount.into(),
            identity: None,
        };
        let pinned = pb::DiskFormatTask {
            identity: Some(identity("/dev/sdi", "WD-WCC4E1FREE1", 4_000_787_030_016)),
            ..format("/dev/sdi", "ext4", "gnx-sdi", "/srv/disk-sdi")
        };
        assert_eq!(disk_format_script(&pinned), fixture("disk-format.sh"));
        assert_eq!(disk_format_script(&format("/dev/sdj", "xfs", "gnx-sdj", "/srv/disk-sdj")), fixture("disk-format-xfs.sh"));
        let release = pb::DiskReleaseTask { mount_point: "/srv/disk-sdi".into() };
        assert_eq!(disk_release_script(&release), fixture("disk-release.sh"));
        assert_eq!(disk_blink_script(&pb::DiskBlinkTask { disk: "/dev/sdi".into() }), fixture("disk-blink.sh"));
    }

    #[test]
    fn unsafe_changes_are_refused() {
        let mut task = cases().into_iter().find(|(g, _)| g == "change-md-detach.sh").unwrap().1;
        assert!(check_change(&task, "").is_ok());
        task.address = "/dev/sda".into();
        assert!(check_change(&task, "").is_err(), "md arrays live under /dev/md");
        task.address = "/dev/md127".into();
        task.member = "/dev/sdc; reboot".into();
        assert!(check_change(&task, "").is_err());
        task.member = String::new();
        assert!(check_change(&task, "").is_err(), "detach names the member");
        let release = pb::DiskReleaseTask { mount_point: "/home".into() };
        assert!(check_release(&release).is_err());
        let bad_fs = pb::DiskFormatTask { disk: "/dev/sdi".into(), filesystem: "ntfs".into(), label: "x".into(), mount_point: "/srv/x".into(), identity: None };
        assert!(check_format(&bad_fs, "").is_err());
        let btrfs5 = create(5, &["/dev/a", "/dev/b", "/dev/c"], "x", pb::StorageArrayKind::Btrfs);
        assert!(crate::storage_task::check_create(&btrfs5, "").is_err());
    }
}
