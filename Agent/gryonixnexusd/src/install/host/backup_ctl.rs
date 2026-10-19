//! Port of `BackupControlSections` — `/opt/gryonixnexus-backup-ctl.sh`

use crate::install::host::{lock, HostInput};
use crate::install::{authelia, headscale, homepage, pihole};

/// Where the wrapper lives on disk.
pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-backup-ctl.sh";
pub const DONE_MARKER: &str = "GRYONIXNEXUS_BACKUP_CTL_DONE";
/// Printed by a finished backup: `<marker> <bytes> <path>`
pub const BACKUP_DONE_MARKER: &str = "GRYONIXNEXUS_BACKUP_DONE";
/// Printed by `estimate`: `<marker> <data bytes> <free bytes>`.
pub const ESTIMATE_MARKER: &str = "GRYONIXNEXUS_BACKUP_ESTIMATE";
pub const CONFIG_DIRECTORY: &str = "/etc/gryonixnexus";
pub const CONFIG_PATH: &str = "/etc/gryonixnexus/autobackup.conf";
pub const PASSPHRASE_PATH: &str = "/etc/gryonixnexus/autobackup.pass";
pub const TIMER_NAME: &str = "gryonixnexus-autobackup.timer";
pub const SERVICE_NAME: &str = "gryonixnexus-autobackup.service";

/// `DashboardAccessInput.backupRetention`'s default
const DEFAULT_RETENTION: u32 = 7;

const DUMP_DIRECTORY_NAME: &str = "gryonixnexus-db";

#[derive(Clone, Copy)]
enum Engine {
    Postgres,
    Mysql,
}

struct Database {
    engine: Engine,
    service: &'static str,
    file_name: &'static str,
    database_name: Option<&'static str>,
}

struct Target {
    /// The `case` label — `BackupWrapperSpec.wrapperTarget`
    id: String,
    backup_dir: String,
    encrypts_by_default: bool,
    size_paths: Vec<String>,
    body: String,
}

/// Bash function name for a service label (`vpn-panel` → `vpn_panel`).
fn function_name(id: &str) -> String {
    id.replace('-', "_")
}

fn quoted_path(path: &str) -> String {
    path.split('*')
        .map(|part| if part.is_empty() { String::new() } else { format!("'{part}'") })
        .collect::<Vec<_>>()
        .join("*")
}

fn last_component(path: &str) -> String {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or(path).to_string()
}

fn split_data_path(data_path: &str) -> (String, String) {
    let trimmed = data_path.trim_end_matches('/');
    let parent = match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => trimmed[..idx].to_string(),
        None => "/".to_string(),
    };
    let slot = trimmed.rsplit('/').next().unwrap_or(trimmed).to_string();
    (parent, slot)
}

fn archive_body(
    id: &str,
    backup_dir: &str,
    compose_project: &str,
    data_path: &str,
    databases: &[Database],
    quiesce: &[&str],
    excludes: &[String],
) -> String {
    let mut lines: Vec<String> = vec![
        "  local stamp work plain rc=0".to_string(),
        format!("  install -d -m 750 '{backup_dir}'"),
        "  stamp=\"$(date +%Y%m%d-%H%M%S)\"".to_string(),
        format!("  work=\"$(mktemp -d '{backup_dir}/.work-XXXXXX')\""),
        format!("  plain=\"$work/{id}-$stamp.tar.gz\""),
        format!("  install -d -m 700 \"$work/{DUMP_DIRECTORY_NAME}\""),
        format!("  if [ ! -d '{data_path}' ]; then"),
        "    rm -rf \"$work\"".to_string(),
        format!("    echo \"{id} has no data at {data_path}\" >&2"),
        "    return 1".to_string(),
        "  fi".to_string(),
    ];

    if !quiesce.is_empty() {
        let quoted = quiesce.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(" ");
        lines.push("  # Stopped for the archive only, and started again on EVERY path".to_string());
        lines.push("  # below — a backup that leaves the service down is an outage.".to_string());
        lines.push(format!("  gd_compose_stop '{compose_project}' {quoted}"));
    }

    for db in databases {
        let helper = match db.engine {
            Engine::Postgres => "gd_dump_postgres",
            Engine::Mysql => "gd_dump_mysql",
        };
        let named = db.database_name.map(|n| format!(" '{n}'")).unwrap_or_default();
        let service = db.service;
        let file_name = db.file_name;
        lines.push(format!(
            "  {helper} '{compose_project}' '{service}' \"$work/{DUMP_DIRECTORY_NAME}/{file_name}\"{named} || rc=1"
        ));
    }

    let excludes_str: String = excludes.iter().map(|e| format!(" --exclude '{e}'")).collect();
    let (data_parent, data_slot) = split_data_path(data_path);
    lines.push("  if [ \"$rc\" -eq 0 ]; then".to_string());
    lines.push(format!("    tar --numeric-owner -czf \"$plain\"{excludes_str} \\"));
    lines.push(format!("        -C '{data_parent}' '{data_slot}' \\"));
    lines.push(format!("        -C \"$work\" '{DUMP_DIRECTORY_NAME}' || rc=1"));
    lines.push("  fi".to_string());

    if !quiesce.is_empty() {
        let quoted = quiesce.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(" ");
        lines.push(format!("  gd_compose_start '{compose_project}' {quoted}"));
    }

    lines.push("  if [ \"$rc\" -ne 0 ]; then".to_string());
    lines.push("    rm -rf \"$work\"".to_string());
    lines.push(format!("    echo \"{id} backup failed\" >&2"));
    lines.push("    return 1".to_string());
    lines.push("  fi".to_string());
    lines.push(format!("  gd_finish '{id}' '{backup_dir}' \"$plain\" \"$work\""));

    lines.join("\n")
}

fn vaultwarden_body(container: &str, data_path: &str, backup_dir: &str) -> String {
    let mut s = String::new();
    s.push_str("  local stamp plain\n");
    s.push_str("  stamp=\"$(date +%Y%m%d-%H%M%S)\"\n");
    s.push_str("  plain='");
    s.push_str(backup_dir);
    s.push_str("/vaultwarden-backup.tar.gz'\n");
    s.push_str("  docker stop '");
    s.push_str(container);
    s.push_str("' >/dev/null 2>&1 || true\n");
    s.push_str("  local archived=0\n");
    s.push_str("  tar -czf \"$plain\" '");
    s.push_str(data_path);
    s.push_str("' 2>/dev/null && archived=1\n");
    s.push_str("  # The container comes back up no matter what the archive did.\n");
    s.push_str("  docker start '");
    s.push_str(container);
    s.push_str("' >/dev/null 2>&1 || true\n");
    s.push_str("  if [ \"$archived\" -ne 1 ] || [ ! -s \"$plain\" ]; then\n");
    s.push_str("    rm -f \"$plain\"\n");
    s.push_str("    echo \"the vaultwarden archive could not be written\" >&2\n");
    s.push_str("    return 1\n");
    s.push_str("  fi\n");
    s.push_str("  if ! printf '%s' \"$GD_PASS\" | gpg --batch --quiet --yes --symmetric \\\n");
    s.push_str("       --cipher-algo AES256 --passphrase-fd 0 --pinentry-mode loopback \\\n");
    s.push_str("       --output \"$plain.$stamp.gpg\" \"$plain\"; then\n");
    s.push_str("    rm -f \"$plain\"\n");
    s.push_str("    echo \"could not encrypt the vaultwarden backup\" >&2\n");
    s.push_str("    return 1\n");
    s.push_str("  fi\n");
    s.push_str("  # The plain archive never outlives the encrypted one.\n");
    s.push_str("  rm -f \"$plain\"\n");
    s.push_str("  chmod 600 \"$plain.$stamp.gpg\"\n");
    s.push_str("  chown \"$OWNER\" \"$plain.$stamp.gpg\" 2>/dev/null || true\n");
    s.push_str("  # Rotation: keep the newest RETENTION encrypted archives. The\n");
    s.push_str("  # pipeline is guarded — with fewer archives than RETENTION,\n");
    s.push_str("  # `ls` finds nothing to list and would fail the whole run\n");
    s.push_str("  # under pipefail (which is every first run).\n");
    s.push_str("  { ls -1t '");
    s.push_str(backup_dir);
    s.push_str("'/*.gpg 2>/dev/null || true; } \\\n");
    s.push_str("    | tail -n +$((RETENTION + 1)) | xargs -r rm -f\n");
    s.push_str("  printf '%s %s %s\\n' '");
    s.push_str(BACKUP_DONE_MARKER);
    s.push_str("' \\\n");
    s.push_str("    \"$(stat -c %s \"$plain.$stamp.gpg\" 2>/dev/null || echo 0)\" \"$plain.$stamp.gpg\"\n");
    s.push_str("  gd_drive_copy \"$plain.$stamp.gpg\" 'vaultwarden'");
    s
}

pub const BACKUP_CAPABLE_SERVICE_IDS: &[&str] = &[
    "mailcow",
    "mailu",
    "docker-mailserver",
    "vaultwarden",
    "psono",
    "passbolt",
    "nextcloud",
    "seafile",
    "immich",
    "photoprism",
    "forgejo",
    "gitlab",
    "jellyfin",
    "minecraft-java",
    "minecraft-bedrock",
    "crafty-controller",
    "adguard-home",
    "pihole",
    "homepage",
    "authelia",
    "headscale",
    "vpn-panel",
    "open-webui",
    "anythingllm",
    "litellm",
    "qdrant",
    "openclaw",
    "n8n",
    "home-assistant",
    "mosquitto",
    "zigbee2mqtt",
];

fn build_targets(input: &HostInput) -> Vec<Target> {
    let mut result = Vec::new();
    build_targets_1(input, &mut result);
    build_targets_2(input, &mut result);
    build_targets_3(input, &mut result);
    build_targets_4(input, &mut result);
    build_targets_5(input, &mut result);
    build_targets_6(input, &mut result);
    build_targets_7(input, &mut result);
    build_targets_8(input, &mut result);
    build_targets_9(input, &mut result);
    build_targets_10(input, &mut result);
    build_targets_11(input, &mut result);

    result
}

fn build_targets_1(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);
    if has("mailcow") {
        let path = p.mailcow_path.clone();
        result.push(Target {
            id: "mailcow".to_string(),
            backup_dir: "/opt/backups/mailcow".to_string(),
            encrypts_by_default: false,
            size_paths: vec![path.clone(), "/var/lib/docker/volumes/mailcowdockerized_*".to_string()],
            body: format!("  '{path}/bot-backup.sh'\n  gd_drive_copy_newest '/opt/backups/mailcow' 'mailcow'"),
        });
    }

    if has("mailu") {
        let path = p.mailu_path.clone();
        let backup_dir = "/opt/backups/mailu".to_string();
        let slot = last_component(&path);
        let quiesce = ["front", "admin", "imap", "smtp", "antispam", "webmail", "redis", "resolver"];
        let excludes = vec![format!("{slot}/filter"), format!("{slot}/mailqueue")];
        let body = archive_body("mailu", &backup_dir, "mailu", &path, &[], &quiesce, &excludes);
        result.push(Target {
            id: "mailu".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![format!("{path}/mail"), format!("{path}/data"), format!("{path}/webmail")],
            body,
        });
    }

    if has("docker-mailserver") {
        let path = p.docker_mailserver_path.clone();
        let backup_dir = "/opt/backups/docker-mailserver".to_string();
        let slot = last_component(&path);
        let quiesce = ["mailserver", "webmail"];
        let excludes = vec![format!("{slot}/mail-logs")];
        let body = archive_body("docker-mailserver", &backup_dir, "dockermailserver", &path, &[], &quiesce, &excludes);
        result.push(Target {
            id: "docker-mailserver".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![format!("{path}/mail-data"), format!("{path}/config")],
            body,
        });
    }

    if has("vaultwarden") {
        let container = p.vaultwarden_container.clone();
        let data_path = p.vaultwarden_data_path.clone();
        let backup_dir = "/opt/backups/vaultwarden".to_string();
        let body = vaultwarden_body(&container, &data_path, &backup_dir);
        result.push(Target {
            id: "vaultwarden".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }
}

fn build_targets_2(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("psono") {
        let path = p.psono_path.clone();
        let backup_dir = "/opt/backups/psono".to_string();
        let data_path = format!("{path}/config");
        let databases =
            [Database { engine: Engine::Postgres, service: "db", file_name: "psono.sql", database_name: None }];
        let body = archive_body("psono", &backup_dir, "psono", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "psono".to_string(),
            backup_dir,
            // This is the password store's own asymmetric keypair.
            encrypts_by_default: true,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("passbolt") {
        let path = p.passbolt_path.clone();
        let backup_dir = "/opt/backups/passbolt".to_string();
        let data_path = format!("{path}/secrets");
        let databases =
            [Database { engine: Engine::Mysql, service: "db", file_name: "passbolt.sql", database_name: None }];
        let body = archive_body("passbolt", &backup_dir, "passbolt", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "passbolt".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("nextcloud") {
        let path = p.nextcloud_path.clone();
        let backup_dir = "/opt/backups/nextcloud".to_string();
        let data_path = format!("{path}/data");
        let databases =
            [Database { engine: Engine::Mysql, service: "db", file_name: "nextcloud.sql", database_name: None }];
        let quiesce = ["app"];
        let body = archive_body("nextcloud", &backup_dir, "nextcloud", &data_path, &databases, &quiesce, &[]);
        result.push(Target {
            id: "nextcloud".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }
}

fn build_targets_3(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("seafile") {
        let path = p.seafile_path.clone();
        let backup_dir = "/opt/backups/seafile".to_string();
        let data_path = format!("{path}/data");
        let databases = [
            Database { engine: Engine::Mysql, service: "db", file_name: "ccnet_db.sql", database_name: Some("ccnet_db") },
            Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "seafile_db.sql",
                database_name: Some("seafile_db"),
            },
            Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "seahub_db.sql",
                database_name: Some("seahub_db"),
            },
        ];
        let quiesce = ["seafile"];
        let excludes = vec!["data/logs".to_string()];
        let body = archive_body("seafile", &backup_dir, "seafile", &data_path, &databases, &quiesce, &excludes);
        result.push(Target {
            id: "seafile".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("immich") {
        let path = p.immich_path.clone();
        let backup_dir = "/opt/backups/immich".to_string();
        let data_path = format!("{path}/library");
        let databases =
            [Database { engine: Engine::Postgres, service: "database", file_name: "immich.sql", database_name: None }];
        let body = archive_body("immich", &backup_dir, "immich", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "immich".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/postgres")],
            body,
        });
    }
}

fn build_targets_4(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("photoprism") {
        let path = p.photoprism_path.clone();
        let backup_dir = "/opt/backups/photoprism".to_string();
        let data_path = format!("{path}/originals");
        let databases = [Database {
            engine: Engine::Mysql,
            service: "mariadb",
            file_name: "photoprism.sql",
            database_name: None,
        }];
        let body = archive_body("photoprism", &backup_dir, "photoprism", &data_path, &databases, &[], &[]);
        result.push(Target {
            id: "photoprism".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/storage"), format!("{path}/db")],
            body,
        });
    }

    if has("forgejo") {
        let path = p.forgejo_path.clone();
        let backup_dir = "/opt/backups/forgejo".to_string();
        let data_path = format!("{path}/data");
        let databases =
            [Database { engine: Engine::Postgres, service: "db", file_name: "forgejo.sql", database_name: None }];
        let quiesce = ["server"];
        let body = archive_body("forgejo", &backup_dir, "forgejo", &data_path, &databases, &quiesce, &[]);
        result.push(Target {
            id: "forgejo".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path, format!("{path}/db")],
            body,
        });
    }

    if has("gitlab") {
        let path = p.gitlab_path.clone();
        let backup_dir = "/opt/backups/gitlab".to_string();
        let slot = last_component(&path);
        let quiesce = ["gitlab"];
        let excludes = vec![format!("{slot}/logs")];
        let body = archive_body("gitlab", &backup_dir, "gitlab", &path, &[], &quiesce, &excludes);
        result.push(Target {
            id: "gitlab".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![format!("{path}/config"), format!("{path}/data")],
            body,
        });
    }
}

fn build_targets_5(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("jellyfin") {
        let path = p.jellyfin_path.clone();
        let backup_dir = "/opt/backups/jellyfin".to_string();
        let data_path = format!("{path}/config");
        let quiesce = ["jellyfin"];
        let body = archive_body("jellyfin", &backup_dir, "jellyfin", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "jellyfin".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("minecraft-java") {
        let path = p.minecraft_java_path.clone();
        let backup_dir = "/opt/backups/minecraft-java".to_string();
        let data_path = format!("{path}/data");
        let quiesce = ["minecraft-java"];
        let body = archive_body("minecraft-java", &backup_dir, "minecraft-java", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "minecraft-java".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("minecraft-bedrock") {
        let path = p.minecraft_bedrock_path.clone();
        let backup_dir = "/opt/backups/minecraft-bedrock".to_string();
        let data_path = format!("{path}/data");
        let quiesce = ["minecraft-bedrock"];
        let body =
            archive_body("minecraft-bedrock", &backup_dir, "minecraft-bedrock", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "minecraft-bedrock".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }
}

fn build_targets_6(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("crafty-controller") {
        let path = p.crafty_path.clone();
        let backup_dir = "/opt/backups/crafty-controller".to_string();
        let data_path = format!("{path}/config");
        let quiesce = ["crafty"];
        let body = archive_body("crafty-controller", &backup_dir, "crafty", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "crafty-controller".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("adguard-home") {
        let path = p.adguard_path.clone();
        let backup_dir = "/opt/backups/adguard-home".to_string();
        let data_path = format!("{path}/conf");
        let body = archive_body("adguard-home", &backup_dir, "adguardhome", &data_path, &[], &[], &[]);
        result.push(Target {
            id: "adguard-home".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("pihole") {
        let path = p.pihole_path.clone();
        let backup_dir = "/opt/backups/pihole".to_string();
        let data_path = format!("{path}/etc-pihole");
        let body = archive_body("pihole", &backup_dir, pihole::COMPOSE_PROJECT, &data_path, &[], &[], &[]);
        result.push(Target {
            id: "pihole".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }
}

fn build_targets_7(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("headscale") {
        let path = p.headscale_path.clone();
        let backup_dir = "/opt/backups/headscale".to_string();
        let data_path = format!("{path}/data");
        let quiesce = ["headscale"];
        let body = archive_body("headscale", &backup_dir, headscale::COMPOSE_PROJECT, &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "headscale".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("homepage") {
        let path = p.homepage_path.clone();
        let backup_dir = "/opt/backups/homepage".to_string();
        let data_path = format!("{path}/config");
        let body = archive_body("homepage", &backup_dir, homepage::COMPOSE_PROJECT, &data_path, &[], &[], &[]);
        result.push(Target {
            id: "homepage".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("authelia") {
        let path = p.authelia_path.clone();
        let backup_dir = "/opt/backups/authelia".to_string();
        let data_path = format!("{path}/config");
        let quiesce = ["authelia"];
        let body = archive_body("authelia", &backup_dir, authelia::COMPOSE_PROJECT, &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "authelia".to_string(),
            backup_dir,
            // The user database with its password hashes.
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }
}

fn build_targets_8(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if super::has_vpn(&input.services) {
        let backup_dir = "/opt/backups/vpn-panel".to_string();
        let data_path = "/opt/gryonix-vpn-panel/data".to_string();
        let quiesce = ["vpnpanel"];
        let body = archive_body("vpn-panel", &backup_dir, "vpnpanel", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "vpn-panel".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("open-webui") {
        let path = p.open_webui_path.clone();
        let backup_dir = "/opt/backups/open-webui".to_string();
        let data_path = format!("{path}/data");
        let quiesce = ["open-webui"];
        let body = archive_body("open-webui", &backup_dir, "open-webui", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "open-webui".to_string(),
            backup_dir,
            encrypts_by_default: false,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("anythingllm") {
        let path = p.anythingllm_path.clone();
        let backup_dir = "/opt/backups/anythingllm".to_string();
        let data_path = path;
        // SQLite and a vector index, both written continuously.
        let quiesce = ["anythingllm"];
        let body = archive_body("anythingllm", &backup_dir, "anythingllm", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "anythingllm".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }
}

fn build_targets_9(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("litellm") {
        let path = p.litellm_path.clone();
        let backup_dir = "/opt/backups/litellm".to_string();
        let data_path = path;
        let body = archive_body("litellm", &backup_dir, "litellm", &data_path, &[], &[], &[]);
        result.push(Target {
            id: "litellm".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("qdrant") {
        let path = p.qdrant_path.clone();
        let backup_dir = "/opt/backups/qdrant".to_string();
        let data_path = format!("{path}/storage");
        let quiesce = ["qdrant"];
        let body = archive_body("qdrant", &backup_dir, "qdrant", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "qdrant".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }

    if has("openclaw") {
        let path = p.openclaw_path.clone();
        let backup_dir = "/opt/backups/openclaw".to_string();
        let data_path = format!("{path}/state");
        let quiesce = ["openclaw"];
        let body = archive_body("openclaw", &backup_dir, "openclaw", &data_path, &[], &quiesce, &[]);
        result.push(Target {
            id: "openclaw".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }
}

fn build_targets_10(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("n8n") {
        let path = p.n8n_path.clone();
        let backup_dir = "/opt/backups/n8n".to_string();
        let data_path = format!("{path}/data");
        let databases =
            [Database { engine: Engine::Postgres, service: "database", file_name: "n8n.sql", database_name: None }];
        let quiesce = ["n8n"];
        let body = archive_body("n8n", &backup_dir, "n8n", &data_path, &databases, &quiesce, &[]);
        result.push(Target {
            id: "n8n".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path, format!("{path}/postgres")],
            body,
        });
    }

    if has("home-assistant") {
        let path = p.home_assistant_path.clone();
        let backup_dir = "/opt/backups/home-assistant".to_string();
        let data_path = format!("{path}/config");
        let quiesce = [crate::install::home_assistant::CONTAINER];
        let body = archive_body(
            "home-assistant",
            &backup_dir,
            crate::install::home_assistant::COMPOSE_PROJECT,
            &data_path,
            &[],
            &quiesce,
            &[],
        );
        result.push(Target {
            id: "home-assistant".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }
}

fn build_targets_11(input: &HostInput, result: &mut Vec<Target>) {
    let p = &input.install;
    let has = |id: &str| input.services.iter().any(|s| s == id);

    if has("mosquitto") {
        let path = p.mosquitto_path.clone();
        let backup_dir = "/opt/backups/mosquitto".to_string();
        let data_path = format!("{path}/config");
        let quiesce = [crate::install::mosquitto::CONTAINER];
        let body = archive_body(
            "mosquitto",
            &backup_dir,
            crate::install::mosquitto::COMPOSE_PROJECT,
            &data_path,
            &[],
            &quiesce,
            &[],
        );
        result.push(Target {
            id: "mosquitto".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path, format!("{path}/data")],
            body,
        });
    }

    if has("zigbee2mqtt") {
        let path = p.zigbee2mqtt_path.clone();
        let backup_dir = "/opt/backups/zigbee2mqtt".to_string();
        let data_path = format!("{path}/data");
        let quiesce = [crate::install::zigbee2mqtt::CONTAINER];
        let body = archive_body(
            "zigbee2mqtt",
            &backup_dir,
            crate::install::zigbee2mqtt::COMPOSE_PROJECT,
            &data_path,
            &[],
            &quiesce,
            &[],
        );
        result.push(Target {
            id: "zigbee2mqtt".to_string(),
            backup_dir,
            encrypts_by_default: true,
            size_paths: vec![data_path],
            body,
        });
    }
}

pub fn backup_dirs(input: &HostInput) -> Vec<(String, String)> {
    build_targets(input).into_iter().map(|t| (t.id, t.backup_dir)).collect()
}

pub fn needs_stored_passphrase(input: &HostInput) -> bool {
    build_targets(input).iter().any(|t| t.encrypts_by_default)
}

pub fn script(input: &HostInput) -> String {
    let targets = build_targets(input);

    let owner = input.ssh_user.clone().unwrap_or_else(|| "root".to_string());

    let ids: Vec<&str> = targets.iter().map(|t| t.id.as_str()).collect();
    let all_ids = ids.join(" ");
    let forloop_ids = if ids.is_empty() { "''".to_string() } else { all_ids.clone() };

    let functions = if targets.is_empty() {
        ": # no backup-capable service is installed".to_string()
    } else {
        targets
            .iter()
            .map(|t| format!("backup_{}() {{\n{}\n}}", function_name(&t.id), t.body))
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    let dispatch_arms = targets
        .iter()
        .map(|t| format!("    {}) gd_with_lock 'backup-{}' backup_{} ;;", t.id, t.id, function_name(&t.id)))
        .collect::<Vec<_>>()
        .join("\n");

    let encrypt_arms = targets
        .iter()
        .map(|t| format!("    {}) echo {} ;;", t.id, i32::from(t.encrypts_by_default)))
        .collect::<Vec<_>>()
        .join("\n");

    let estimate_arms = targets
        .iter()
        .map(|t| {
            let paths = t.size_paths.iter().map(|p| quoted_path(p)).collect::<Vec<_>>().join(" ");
            format!("    {}) dir='{}'; paths=({}) ;;", t.id, t.backup_dir, paths)
        })
        .collect::<Vec<_>>()
        .join("\n");

    let dir_cases = if targets.is_empty() {
        "\"\"".to_string()
    } else {
        targets.iter().map(|t| format!("\"{}\"/*", t.backup_dir)).collect::<Vec<_>>().join("|")
    };

    let template = r#####"#!/bin/bash
# Managed by gryonixNexus — backup housekeeping for the Server Dashboard.
# Usage: gryonixnexus-backup-ctl.sh delete <path>
#        gryonixnexus-backup-ctl.sh set-schedule <off|every:<n><h|d>@<HH:MM>> <retention> [services...]
#        gryonixnexus-backup-ctl.sh set-passphrase   (passphrase on stdin)
#        gryonixnexus-backup-ctl.sh run
#        gryonixnexus-backup-ctl.sh backup <service> [--encrypt|--no-encrypt]
#                                       (GPG passphrase on stdin when encrypting)
#        gryonixnexus-backup-ctl.sh estimate <service>
#        gryonixnexus-backup-ctl.sh set-destination <kind> <host> <port> <user> <path> <bucket> <keep>
#                                       (credential on stdin, optional)
#        gryonixnexus-backup-ctl.sh show-destination
#        gryonixnexus-backup-ctl.sh test-destination
#        gryonixnexus-backup-ctl.sh set-drives <both|local|drive> <1|0> [uuids...]
#        gryonixnexus-backup-ctl.sh show-drives
set -euo pipefail

ACTION="${1:-}"
CONFIG='/etc/gryonixnexus/autobackup.conf'
PASSFILE='/etc/gryonixnexus/autobackup.pass'
DESTCONF='/etc/gryonixnexus/autobackup-dest.conf'
DESTKEY='/etc/gryonixnexus/autobackup-dest.key'
DESTPUB='/etc/gryonixnexus/autobackup-dest.key.pub'
DESTSTATUS='/etc/gryonixnexus/autobackup-dest.status'
RETENTION=@@GD_RETENTION@@
SERVICES='@@GD_SERVICES@@'
SCHEDULE=off
# The control user. Finished archives are chowned to it: the app
# downloads and shares them, and what keeps other accounts away is the
# 0750 on the enclosing backup root, not the file's owner.
OWNER='@@GD_OWNER@@'
# Encryption state of the CURRENT run. The passphrase lives in a shell
# variable and reaches gpg down a pipe — never in argv, which is
# world-readable through /proc.
GD_ENCRYPT=0
GD_PASS=""

load_config() {
  # shellcheck disable=SC1090
  [ -f "$CONFIG" ] && . "$CONFIG"
  # A config from an older build may not set every value.
  : "${SCHEDULE:=off}" "${RETENTION:=@@GD_RETENTION@@}" "${SERVICES:=@@GD_SERVICES@@}"
  case "$RETENTION" in ''|*[!0-9]*|0) RETENTION=1 ;; esac
}

# Where finished archives are sent, if anywhere. Its own file and its
# own loader: a host that never chose a destination keeps every default
# below, which together mean "leave the archive where it is".
DEST_KIND=none
DEST_HOST=""
DEST_PORT=22
DEST_USER=""
DEST_PATH=""
DEST_BUCKET=""
DEST_KEEP=0
load_destination() {
  # shellcheck disable=SC1090
  [ -f "$DESTCONF" ] && . "$DESTCONF"
  : "${DEST_KIND:=none}" "${DEST_PORT:=22}" "${DEST_KEEP:=0}"
}

# **Where a copy of this machine's archives lands so they survive the
# machine.** Called after every archive this wrapper finishes, by the
# timer and by the app's own button alike — one body, both callers, the
# rule this whole file is built on.
#
# Failure NEVER fails the backup: the archive on this disk is real and
# already written, and refusing it because a bucket was unreachable
# would turn a bad night into no backup at all. What a failure does is
# get RECORDED, because a copy that silently never leaves is the exact
# defect this exists to end.
gd_ship() {
  local out="$1" service="${2:-check}" error="" ok=0
  load_destination
  [ "$DEST_KIND" = "none" ] && return 0
  # One folder per machine and service, so rotation stays inside it.
  local machine
  machine="$(hostname -s 2>/dev/null || echo server)-$(cut -c1-8 /etc/machine-id 2>/dev/null || echo 0)"
  local folder="${DEST_PATH%/}/$machine/$service"
  case "$DEST_KIND" in
    ssh)
      if [ -z "$DEST_HOST" ] || [ -z "$DEST_USER" ] || [ ! -s "$DESTKEY" ]; then
        error="the destination is incomplete (host, user or key missing)"
      else
        # **A known_hosts this machine can actually write.** Run from the agent's unit,
        # ssh cannot create /root/.ssh — ProtectHome=yes and
        # ProtectSystem=full — so `accept-new` pinned nothing and every
        # shipment carried "Could not create directory /root/.ssh" into
        # the status file, where it reads as the failure. This path is
        # inside the agent's ReadWritePaths and is root-owned, so the
        # timer and the app's button pin the same key in the same file.
        local known="${DESTCONF%/*}/autobackup-dest.known_hosts"
        [ -e "$known" ] || ( umask 077 && : > "$known" )
        # `accept-new`, not `no`: the first sight of the far side is
        # pinned, and a CHANGED key after that stops the copy — which
        # is the one moment somebody must be told rather than obeyed.
        error="$(ssh -i "$DESTKEY" -p "$DEST_PORT" \
                  -o StrictHostKeyChecking=accept-new \
                  -o UserKnownHostsFile="$known" \
                  -o BatchMode=yes -o ConnectTimeout=20 \
                  "$DEST_USER@$DEST_HOST" "mkdir -p '$folder'" 2>&1)" \
          && error="$(scp -i "$DESTKEY" -P "$DEST_PORT" \
                  -o StrictHostKeyChecking=accept-new \
                  -o UserKnownHostsFile="$known" \
                  -o BatchMode=yes -o ConnectTimeout=20 \
                  "$out" "$DEST_USER@$DEST_HOST:$folder/" 2>&1)" \
          && ok=1
        # **A warning is not a failure.** ssh writes advice to stderr on
        # runs that worked, and this field is what the app shows as the
        # reason the copy did not leave; keeping it would report a
        # successful shipment as a broken one.
        [ "$ok" -eq 1 ] && error=""
        if [ "$ok" -eq 1 ] && [ "$DEST_KEEP" -gt 0 ]; then
          # Rotation on the FAR side, and only there: what this machine
          # keeps is RETENTION, and the two are different numbers on
          # purpose — a phone-sized disk here, a big one there.
          ssh -i "$DESTKEY" -p "$DEST_PORT" -o StrictHostKeyChecking=accept-new \
              -o UserKnownHostsFile="$known" \
              -o BatchMode=yes "$DEST_USER@$DEST_HOST" \
              "ls -1t '$folder' 2>/dev/null | tail -n +$((DEST_KEEP + 1)) | while read -r old; do rm -rf -- '$folder'/\"\$old\"; done" \
              >/dev/null 2>&1 || true
        fi
      fi
      ;;
    s3)
      if ! command -v rclone >/dev/null 2>&1; then
        error="rclone is not installed on this server"
      elif [ ! -s "$DESTKEY" ]; then
        error="no credentials stored for the bucket"
      else
        # The credentials reach rclone as ENVIRONMENT, never argv:
        # /proc/<pid>/cmdline is world-readable and an access key in it
        # is an access key given away.
        error="$(
          AWS_ACCESS_KEY_ID="$(cut -d: -f1 "$DESTKEY")" \
          AWS_SECRET_ACCESS_KEY="$(cut -d: -f2- "$DESTKEY")" \
          RCLONE_CONFIG_GD_TYPE=s3 \
          RCLONE_CONFIG_GD_PROVIDER=Other \
          RCLONE_CONFIG_GD_ENV_AUTH=true \
          RCLONE_CONFIG_GD_ENDPOINT="$DEST_HOST" \
          rclone copy "$out" "gd:$DEST_BUCKET/$folder/" 2>&1
        )" && ok=1
      fi
      ;;
    *) error="unknown destination kind: $DEST_KIND" ;;
  esac
  {
    echo "AT=$(date +%s)"
    echo "OK=$ok"
    # One line, and the far side's own words: three different repairs
    # hide behind "it failed". QUOTED, and with quotes of its own
    # removed — see `do_test_destination` on what reading this file
    # as shell used to cost.
    # **Carriage returns too, not just newlines.** ssh ends its own
    # warnings with CR, and a reader that renders them the way a
    # terminal does — the agent's does, for progress bars — keeps only
    # what follows the last one and throws the rest away. The marker line vanished and the app was told the
    # copy failed, with no reason, while the file had landed.
    echo "ERROR='$(printf '%s' "$error" | tr '\r\n\t' '   ' | tr -d "'" | cut -c1-400)'"
  } > "$DESTSTATUS"
  chmod 644 "$DESTSTATUS"
  return 0
}

# The key this server ships WITH, made once and never replaced: the
# public half is already authorized on the far side, and a new pair
# would silently stop every copy.
gd_ensure_dest_key() {
  [ -s "$DESTKEY" ] && return 0
  # **The folder first.** A server that never had the agent installed
  # has no /etc/gryonixnexus, and ssh-keygen into a folder that is not
  # there failed with its output thrown away: `set-destination` stopped
  # on the chmod that followed and answered rc 1 with not one word.
  # The app's own screen showed
  # "could not save" and nothing else.
  install -d -m 755 "$(dirname "$DESTKEY")"
  rm -f "$DESTKEY" "$DESTPUB"
  if ! ssh-keygen -t ed25519 -N '' -C 'gryonixnexus-backup' -f "$DESTKEY" >/dev/null 2>&1; then
    echo "could not create the key this server ships backups with" >&2
    exit 2
  fi
  chmod 600 "$DESTKEY"
  chmod 644 "$DESTPUB" 2>/dev/null || true
}

do_set_destination() {
  local kind="${1:-none}" host="${2:-}" port="${3:-22}" user="${4:-}"
  local path="${5:-}" bucket="${6:-}" keep="${7:-0}"
  case "$kind" in
    none|ssh|s3) ;;
    *) echo "unsupported destination: ${kind}" >&2; exit 2 ;;
  esac
  case "$port$keep" in
    ''|*[!0-9]*) echo "invalid port or keep count" >&2; exit 2 ;;
  esac
  case "$host$user$path$bucket" in
    *[\'\"\\\`\$]*|*$'\n'*|*$'\r'*)
      echo "the destination may not contain quotes, backslashes, \$, backticks or line breaks" >&2
      exit 2 ;;
  esac
  # A secret on stdin, never argv — the same rule the passphrase
  # follows one function down.
  if [ ! -t 0 ]; then
    local secret
    secret="$(cat)"
    if [ -n "$secret" ]; then
      install -d -m 755 "$(dirname "$DESTKEY")"
      ( umask 077 && printf '%s' "$secret" > "$DESTKEY" )
      chmod 600 "$DESTKEY"
    fi
  fi
  [ "$kind" = "ssh" ] && gd_ensure_dest_key
  install -d -m 755 "$(dirname "$DESTCONF")"
  cat > "$DESTCONF" <<EOF_DEST
DEST_KIND=$kind
DEST_HOST='$host'
DEST_PORT=$port
DEST_USER='$user'
DEST_PATH='$path'
DEST_BUCKET='$bucket'
DEST_KEEP=$keep
EOF_DEST
  # 0640 and owned by root: it names a host and an account, which is
  # the owner's business and not every account's on this machine. The
  # app reads it through this wrapper, which runs as root.
  chmod 640 "$DESTCONF"
  # Printed so the app can authorize it on the far side without a
  # second call — a public key, and nothing else, is safe on stdout.
  [ -s "$DESTPUB" ] && printf 'GRYONIXNEXUS_DEST_PUBKEY %s\n' "$(cat "$DESTPUB")"
}

# Everything `show-destination` answers, in one read: the app draws the
# destination, the public key to authorize and what the last shipment
# did on a single screen.
do_show_destination() {
  load_destination
  printf 'DEST_KIND=%s\nDEST_HOST=%s\nDEST_PORT=%s\nDEST_USER=%s\nDEST_PATH=%s\nDEST_BUCKET=%s\nDEST_KEEP=%s\n' \
    "$DEST_KIND" "$DEST_HOST" "$DEST_PORT" "$DEST_USER" "$DEST_PATH" "$DEST_BUCKET" "$DEST_KEEP"
  [ -s "$DESTPUB" ] && printf 'DEST_PUBKEY=%s\n' "$(cat "$DESTPUB")"
  [ -s "$DESTSTATUS" ] && cat "$DESTSTATUS"
  return 0
}

# One small file, sent the same way a real archive is. The only way to
# learn a destination is wrong BEFORE the nightly run trusts it.
do_test_destination() {
  load_destination
  if [ "$DEST_KIND" = "none" ]; then
    echo "GRYONIXNEXUS_DEST_TEST 0 no destination is set"
    return 0
  fi
  local probe
  probe="$(mktemp /tmp/gryonixnexus-dest-XXXXXX.txt)"
  date -u +'gryonixNexus destination check %Y-%m-%dT%H:%M:%SZ' > "$probe"
  gd_ship "$probe" check
  rm -f "$probe"
  # Read back out of the status file rather than kept in a variable:
  # what the app will see later is exactly what it is told now.
  local ok="0" error=""
  # **Parsed, never sourced.** This file carries the FAR SIDE's own
  # words, and reading it with `.` made them shell: a message with
  # "(ED25519)" in it broke the read outright, and one carrying $(…)
  # would have run here as root.
  if [ -f "$DESTSTATUS" ]; then
    ok="$(sed -n 's/^OK=//p' "$DESTSTATUS" | head -1)"
    error="$(sed -n "s/^ERROR='\(.*\)'\$/\1/p" "$DESTSTATUS" | head -1)"
  fi
  ok="${ok:-0}"
  echo "GRYONIXNEXUS_DEST_TEST $ok $error"
}

# USB drives that take a copy of every archive. A host that never
# chose one keeps every archive here, exactly as before.
DRIVECONF='/etc/gryonixnexus/backup-drives.conf'
DRIVESTATUS='/etc/gryonixnexus/backup-drives.status'
DRIVELAST='/etc/gryonixnexus/backup-drives.last'
DRIVEROOT='/srv/gryonix-backup'
DRIVE_MODE=both
DRIVE_ENCRYPT=1
DRIVES=""
GD_DRIVE_ERROR=""
load_drives() {
  # shellcheck disable=SC1090
  [ -f "$DRIVECONF" ] && . "$DRIVECONF"
  : "${DRIVE_MODE:=both}" "${DRIVE_ENCRYPT:=1}"
}

# Where fstab mounts one drive, whether or not it is plugged in.
gd_drive_fstab() {
  findmnt --fstab -rno TARGET -S "UUID=$1" 2>/dev/null | head -n 1
}

# The drive's mount point, only when it is mounted and marked.
gd_drive_target() {
  local target
  target="$(gd_drive_fstab "$1")"
  case "$target" in "$DRIVEROOT"/*) ;; *) return 0 ;; esac
  # Never a bare folder: writing there fills the system disk.
  mountpoint -q "$target" || return 0
  grep -qx "$1" "$target/.gryonix-backup-drive" 2>/dev/null || return 0
  printf '%s\n' "$target"
}

# Mounts a drive plugged in after boot, through systemd.
gd_drive_ready() {
  local target
  target="$(gd_drive_target "$1")"
  if [ -z "$target" ] && [ -b "/dev/disk/by-uuid/$1" ]; then
    target="$(gd_drive_fstab "$1")"
    case "$target" in
      "$DRIVEROOT"/*)
        systemctl start "$(systemd-escape -p --suffix=mount "$target")" >/dev/null 2>&1 || true ;;
    esac
    target="$(gd_drive_target "$1")"
  fi
  printf '%s' "$target"
}

# The drive's name: the last part of its mount point.
gd_drive_name() {
  local target
  target="$(gd_drive_fstab "$1")"
  if [ -n "$target" ]; then printf '%s' "${target##*/}"; else printf '%s' "$1"; fi
}

# Why a write to a drive failed.
gd_drive_why() {
  local avail
  case ",$(findmnt -no OPTIONS --target "$1" 2>/dev/null || true)," in
    *,ro,*) echo "the drive went read-only; check it"; return 0 ;;
  esac
  avail="$(df -B1 --output=avail "$1" 2>/dev/null | tail -n 1 | tr -cd '0-9')"
  if [ "${avail:-0}" -lt 1048576 ]; then
    echo "the drive is full"
  else
    echo "the drive could not be written"
  fi
}

# Copies one archive to a drive, encrypting it when asked.
gd_drive_write() {
  local src="$1" dest="$2" pass=""
  GD_DRIVE_ERROR=""
  if [ "${dest%.gpg}" = "$dest" ] || [ "${src%.gpg}" != "$src" ]; then
    cp "$src" "$dest" 2>/dev/null && return 0
    GD_DRIVE_ERROR="$(gd_drive_why "${dest%/*}")"
    return 1
  fi
  pass="$GD_PASS"
  [ -n "$pass" ] || pass="$(cat "$PASSFILE" 2>/dev/null || true)"
  if [ -z "$pass" ]; then
    GD_DRIVE_ERROR="no backup passphrase is stored for encrypted copies"
    return 1
  fi
  printf '%s' "$pass" | gpg --batch --quiet --yes --symmetric \
       --cipher-algo AES256 --passphrase-fd 0 --pinentry-mode loopback \
       --output "$dest" "$src" 2>/dev/null && return 0
  GD_DRIVE_ERROR="$(gd_drive_why "${dest%/*}")"
  return 1
}

# Keeps the newest RETENTION copies in one folder.
gd_drive_rotate() {
  { ls -1t "$1" 2>/dev/null || true; } | tail -n +$((RETENTION + 1)) \
    | while IFS= read -r old; do rm -rf -- "${1:?}/$old"; done || true
}

# What the last drive copy did, read by show-drives.
gd_drive_status() {
  install -d -m 755 "${DRIVESTATUS%/*}" 2>/dev/null || true
  {
    echo "DRIVE_AT=$(date +%s)"
    if [ -z "$1" ]; then echo "DRIVE_OK=1"; else echo "DRIVE_OK=0"; fi
    echo "DRIVE_ERROR='$(printf '%s' "$1" | tr '\r\n\t' '   ' | tr -d "'" | sed 's/^ *//' | cut -c1-400)'"
  } > "$DRIVESTATUS" 2>/dev/null || true
  chmod 644 "$DRIVESTATUS" 2>/dev/null || true
}

# Records when a drive last took a copy.
gd_drive_seen() {
  if { grep -v "^$1 " "$DRIVELAST" 2>/dev/null || true; echo "$1 $(date +%s)"; } \
       > "$DRIVELAST.new" 2>/dev/null; then
    mv -f "$DRIVELAST.new" "$DRIVELAST" 2>/dev/null || true
    chmod 644 "$DRIVELAST" 2>/dev/null || true
  fi
}

# Writes one copy to one drive; prints where it landed, or why not.
gd_drive_put() {
  local out="$1" folder="$2/$3" name="$4"
  if ! install -d -m 700 "$folder" 2>/dev/null; then
    echo "the drive could not be written"
    return 1
  fi
  # Leftovers of a copy cut short when the drive was pulled.
  rm -f "$folder"/.partial-* 2>/dev/null || true
  if gd_drive_write "$out" "$folder/.partial-$name" \
     && mv -f "$folder/.partial-$name" "$folder/$name" 2>/dev/null; then
    sync -f "$folder/$name" 2>/dev/null || true
    chmod 600 "$folder/$name" 2>/dev/null || true
    gd_drive_rotate "$folder"
    printf '%s\n' "$folder/$name"
    return 0
  fi
  rm -f "$folder/.partial-$name" 2>/dev/null || true
  printf '%s\n' "${GD_DRIVE_ERROR:-the drive could not be written}"
  return 1
}

# **A copy of each archive on every chosen USB drive.** A missing
# or full drive never fails the backup; it is recorded instead.
gd_drive_copy() {
  local out="$1" service="$2" name uuid target landed first="" failed=""
  load_drives
  if [ -z "$DRIVES" ] || [ "$DRIVE_MODE" = "local" ]; then return 0; fi
  name="$(basename "$out")"
  if [ "$DRIVE_ENCRYPT" -eq 1 ] && [ "${name%.gpg}" = "$name" ]; then name="$name.gpg"; fi
  for uuid in $DRIVES; do
    target="$(gd_drive_ready "$uuid")"
    if [ -z "$target" ]; then
      failed="$failed $(gd_drive_name "$uuid"): not connected;"
      continue
    fi
    if landed="$(gd_drive_put "$out" "$target" "$service" "$name")"; then
      printf '%s %s %s\n' 'GRYONIXNEXUS_DRIVE_COPY' "$uuid" "$landed"
      [ -n "$first" ] || first="$landed"
      gd_drive_seen "$uuid"
    else
      failed="$failed ${target##*/}: $landed;"
    fi
  done
  gd_drive_status "$failed"
  # Drives only: the local archive goes once a drive holds it.
  if [ "$DRIVE_MODE" = "drive" ] && [ -n "$first" ]; then
    rm -f "$out"
    printf '%s %s %s\n' 'GRYONIXNEXUS_BACKUP_DONE' \
      "$(stat -c %s "$first" 2>/dev/null || echo 0)" "$first"
  fi
  return 0
}

# Copies the newest archive an external tool wrote.
gd_drive_copy_newest() {
  local newest
  newest="$({ ls -1t "$1/$2"-*.tar.gz 2>/dev/null || true; } | head -n 1)"
  [ -n "$newest" ] || return 0
  gd_drive_copy "$newest" "$2"
  # Drives only: the unpacked folder leaves with its archive.
  if [ ! -e "$newest" ] && [ -d "${newest%.tar.gz}" ]; then rm -rf "${newest%.tar.gz}"; fi
}

do_set_drives() {
  local mode="${1:-both}" encrypt="${2:-1}" checked="" uuid
  shift 2 || true
  case "$mode" in
    both|local|drive) ;;
    *) echo "unsupported drive mode: ${mode}" >&2; exit 2 ;;
  esac
  case "$encrypt" in
    0|1) ;;
    *) echo "invalid encryption flag: ${encrypt}" >&2; exit 2 ;;
  esac
  for uuid in "$@"; do
    case "$uuid" in
      ''|*[!0-9A-Fa-f-]*) echo "invalid drive id: ${uuid}" >&2; exit 2 ;;
    esac
    checked="$checked $uuid"
  done
  install -d -m 755 "$(dirname "$DRIVECONF")"
  cat > "$DRIVECONF" <<EOF_DRIVES
DRIVE_MODE=$mode
DRIVE_ENCRYPT=$encrypt
DRIVES='${checked# }'
EOF_DRIVES
  chmod 644 "$DRIVECONF"
  # A newly chosen drive counts from now.
  for uuid in $checked; do
    grep -q "^$uuid " "$DRIVELAST" 2>/dev/null || gd_drive_seen "$uuid"
  done
}

# Settings, each drive's state and the last copy, in one read.
do_show_drives() {
  local uuid target size avail
  load_drives
  printf 'DRIVE_MODE=%s\nDRIVE_ENCRYPT=%s\nDRIVES=%s\n' "$DRIVE_MODE" "$DRIVE_ENCRYPT" "$DRIVES"
  if [ -s "$PASSFILE" ]; then echo 'DRIVE_PASS=1'; else echo 'DRIVE_PASS=0'; fi
  for uuid in $DRIVES; do
    target="$(gd_drive_target "$uuid")"
    size=0
    avail=0
    if [ -n "$target" ]; then
      read -r size avail < <(df -B1 --output=size,avail "$target" 2>/dev/null | tail -n 1) || true
      printf 'DRIVE=%s 1 %s %s %s\n' "$uuid" "${size:-0}" "${avail:-0}" "$target"
    else
      printf 'DRIVE=%s 0 0 0 %s\n' "$uuid" "$(gd_drive_fstab "$uuid")"
    fi
  done
  [ -s "$DRIVESTATUS" ] && cat "$DRIVESTATUS"
  return 0
}

# --- per-service locking (see LockSections) --------------------------

@@GD_LOCK_HELPER@@

# --- helpers shared by every generated service body -----------------

gd_compose_stop() {
  local project="$1"
  shift
  docker compose -p "$project" stop "$@" >/dev/null 2>&1 || true
}

gd_compose_start() {
  local project="$1"
  shift
  docker compose -p "$project" start "$@" >/dev/null 2>&1 || true
}

# Container id of one compose service; empty when it is not running.
gd_container() {
  docker compose -p "$1" ps -q "$2" 2>/dev/null | head -n 1
}

# A tar of a live database directory is a corrupt backup, so the
# database is dumped through its own client instead. The credentials
# come from the container's OWN environment — compose already put them
# there — because passing them from here would place the password in
# the argv of `docker exec`, readable by every account on the host.
gd_dump_postgres() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then
    echo "the $1 database container is not running" >&2
    return 1
  fi
  if ! docker exec "$cid" sh -c \
       'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_dump --clean --if-exists -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
       > "$3"; then
    echo "the $1 database dump failed" >&2
    return 1
  fi
  [ -s "$3" ] || { echo "the $1 database dump is empty" >&2; return 1; }
}

# --single-transaction is what makes a dump of a RUNNING InnoDB
# database trustworthy: one consistent snapshot, no instance-wide lock.
# mariadb-dump on current images, mysqldump on older ones.
#
# A fourth argument names the database explicitly, for a service that
# keeps several in one engine and whose container therefore sets no
# MYSQL_DATABASE at all; without it the container's own variable is
# used, as it always was. Only the NAME travels here — the password is
# still read inside the container, never put in the argv of docker exec
# where /proc hands it to every account on the host.
gd_dump_mysql() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then
    echo "the $1 database container is not running" >&2
    return 1
  fi
  if ! docker exec "$cid" sh -c \
       'if command -v mariadb-dump >/dev/null 2>&1; then D=mariadb-dump; else D=mysqldump; fi; MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$D" --single-transaction --quick -u root "${1:-$MYSQL_DATABASE}"' \
       sh "${4:-}" > "$3"; then
    echo "the $1 database dump failed" >&2
    return 1
  fi
  [ -s "$3" ] || { echo "the $1 database dump is empty" >&2; return 1; }
}

# Keeps the newest RETENTION archives of one service — encrypted and
# plain together, they are one series. The pipeline is guarded: with
# fewer archives than RETENTION `ls` finds nothing to list and would
# fail the whole run under pipefail, which is every first run.
gd_rotate() {
  { ls -1t "$1/$2"-*.tar.gz "$1/$2"-*.tar.gz.gpg 2>/dev/null || true; } \
    | tail -n +$((RETENTION + 1)) | xargs -r rm -f
}

# Encrypt (or not), put the archive in place, rotate, announce.
gd_finish() {
  local name="$1" dir="$2" plain="$3" work="$4" out=""
  if [ ! -s "$plain" ]; then
    rm -rf "$work"
    echo "the $name archive is empty" >&2
    return 1
  fi
  if [ "$GD_ENCRYPT" -eq 1 ]; then
    out="$dir/$(basename "$plain").gpg"
    if ! printf '%s' "$GD_PASS" | gpg --batch --quiet --yes --symmetric \
         --cipher-algo AES256 --passphrase-fd 0 --pinentry-mode loopback \
         --output "$out" "$plain"; then
      rm -rf "$work"
      echo "could not encrypt the $name backup" >&2
      return 1
    fi
  else
    out="$dir/$(basename "$plain")"
    mv "$plain" "$out"
  fi
  # The plain archive never outlives the encrypted one.
  rm -rf "$work"
  chmod 600 "$out"
  chown "$OWNER" "$out" 2>/dev/null || true
  gd_rotate "$dir" "$name"
  # A streamed command carries no exit status back to the app, so the
  # archive announces itself: marker, size in bytes, path.
  printf '%s %s %s\n' 'GRYONIXNEXUS_BACKUP_DONE' \
    "$(stat -c %s "$out" 2>/dev/null || echo 0)" "$out"
  # And then it leaves the machine, if a destination was chosen. After
  # the marker on purpose: the archive exists and is announced whatever
  # the far side does.
  gd_ship "$out" "$name"
  # A copy on each USB drive, after the far side.
  gd_drive_copy "$out" "$name"
}

# --- per-service bodies (generated from each service's BackupSpec) ---

@@GD_FUNCTIONS@@

# The ONE dispatch both callers go through: the timer's `run` and the
# app's `backup`. Two copies of these bodies is exactly the drift this
# wrapper exists to prevent.
gd_run_service() {
  case "$1" in
@@GD_DISPATCH_ARMS@@
    *) echo "unsupported service: $1" >&2; return 2 ;;
  esac
}

# Whether a run of this service encrypts unless the caller says
# otherwise. Secret stores yes; bulk media no — GPG over a photo
# library costs hours of CPU on a Raspberry Pi.
gd_default_encrypt() {
  case "$1" in
@@GD_ENCRYPT_ARMS@@
    *) echo 0 ;;
  esac
}

do_delete() {
  local path="${1:-}"
  # The path must sit inside a backup directory this deployment owns.
  # Without the check a whitelisted wrapper would delete ANY file.
  case "$path" in
    *..*) echo "invalid path: ${path}" >&2; exit 2 ;;
  esac
  case "$path" in
    @@GD_DIR_CASES@@) ;;
    "$DRIVEROOT"/*/*/*) ;;
    *) echo "path outside the backup directories: ${path}" >&2; exit 2 ;;
  esac
  [ -e "$path" ] || { echo "no such backup: ${path}" >&2; exit 2; }
  rm -rf "$path"
}

do_run() {
  load_config
  local failed=""
  for svc in $SERVICES; do
    # Each service runs in its own subshell, and the `||` keeps errexit
    # from firing on a failure: an unattended run must not let one
    # broken service cancel the backups of every service after it.
    (
      GD_ENCRYPT="$(gd_default_encrypt "$svc")"
      GD_PASS=""
      if [ "$GD_ENCRYPT" -eq 1 ]; then
        # Unattended, so there is nobody to ask: the stored passphrase
        # is the only source. Without it the service refuses rather
        # than quietly writing its secrets out in the clear.
        if [ ! -s "$PASSFILE" ]; then
          echo "no backup passphrase stored for $svc" >&2
          exit 1
        fi
        GD_PASS="$(cat "$PASSFILE")"
      fi
      gd_run_service "$svc"
    ) || failed="$failed $svc"
  done
  if [ -n "$failed" ]; then
    echo "backup failed for:$failed" >&2
    exit 1
  fi
}

# One service, on demand. Same bodies the timer runs; the only
# difference is where the passphrase comes from.
do_backup() {
  local svc="${1:-}"
  shift || true
  load_config
  GD_ENCRYPT="$(gd_default_encrypt "$svc")"
  for arg in "$@"; do
    case "$arg" in
      --encrypt) GD_ENCRYPT=1 ;;
      --no-encrypt) GD_ENCRYPT=0 ;;
      *) echo "unsupported option: ${arg}" >&2; exit 2 ;;
    esac
  done
  if [ "$GD_ENCRYPT" -eq 1 ]; then
    # On stdin, never argv. A terminal means nobody piped anything in,
    # and reading would hang forever.
    if [ ! -t 0 ]; then GD_PASS="$(cat)"; fi
    # No passphrase given: fall back to the stored one, so an
    # encrypted run is possible without re-typing it.
    if [ -z "$GD_PASS" ] && [ -s "$PASSFILE" ]; then GD_PASS="$(cat "$PASSFILE")"; fi
    if [ -z "$GD_PASS" ]; then
      echo "an encrypted backup needs a passphrase on stdin" >&2
      exit 2
    fi
  fi
  gd_run_service "$svc"
}

# What a backup of this service would cost, in bytes, and what the
# backup filesystem still has free. Read-only, and the only reason the
# app can warn BEFORE starting an hours-long run.
do_estimate() {
  local svc="${1:-}" dir="" total=0 free="" sz=""
  local -a paths=()
  case "$svc" in
@@GD_ESTIMATE_ARMS@@
    *) echo "unsupported service: ${svc}" >&2; exit 2 ;;
  esac
  install -d -m 750 "$dir"
  local p
  for p in "${paths[@]}"; do
    [ -e "$p" ] || continue
    sz="$(du -sb "$p" 2>/dev/null | cut -f1)" || sz=""
    total=$((total + ${sz:-0}))
  done
  free="$(df -B1 --output=avail "$dir" 2>/dev/null | tail -n 1 | tr -cd '0-9')"
  printf '%s %s %s\n' 'GRYONIXNEXUS_BACKUP_ESTIMATE' "$total" "${free:-0}"
}

do_set_schedule() {
  # <schedule> is `off` or `every:<n><unit>@<HH:MM>` — the interval and
  # the time of day the user picked. Parsed here rather than taking a
  # raw OnCalendar expression: the wrapper is whitelisted in sudoers,
  # so it must not accept arbitrary systemd input from the client.
  local schedule="${1:-off}" retention="${2:-@@GD_RETENTION@@}"
  shift 2 || true
  local services="$*"
  local oncal=""
  case "$schedule" in
    off) ;;
    every:*)
      local spec="${schedule#every:}"
      local every="${spec%@*}" at="${spec#*@}"
      local n="${every%[hd]}" unit="${every##*[0-9]}"
      case "$n" in
        ''|*[!0-9]*) echo "invalid interval: ${every}" >&2; exit 2 ;;
      esac
      [ "$n" -ge 1 ] || { echo "invalid interval: ${every}" >&2; exit 2; }
      case "$at" in
        [0-2][0-9]:[0-5][0-9]) ;;
        *) echo "invalid time: ${at}" >&2; exit 2 ;;
      esac
      [ "${at%%:*}" -le 23 ] || { echo "invalid time: ${at}" >&2; exit 2; }
      case "$unit" in
        h)
          # Every n hours, aligned to the chosen minute.
          if [ "$n" -ge 24 ]; then
            oncal="*-*-* ${at}:00"
          else
            oncal="*-*-* 00/${n}:${at#*:}:00"
          fi
          ;;
        d)
          # Every n days at the chosen time. systemd has no "every n
          # days" for n > 1, so those run daily-aligned on a day step.
          if [ "$n" -le 1 ]; then
            oncal="*-*-* ${at}:00"
          else
            oncal="*-*-01/${n} ${at}:00"
          fi
          ;;
        *) echo "invalid interval unit: ${every}" >&2; exit 2 ;;
      esac
      ;;
    *) echo "unsupported schedule: ${schedule}" >&2; exit 2 ;;
  esac
  case "$retention" in
    ''|*[!0-9]*) echo "invalid retention: ${retention}" >&2; exit 2 ;;
  esac
  [ "$retention" -ge 1 ] || { echo "invalid retention: ${retention}" >&2; exit 2; }
  # Only services this wrapper knows about may end up in the config.
  local checked=""
  for svc in $services; do
    for known in @@GD_FORLOOP_IDS@@; do
      if [ "$svc" = "$known" ]; then checked="$checked $svc"; fi
    done
  done
  install -d -m 755 "$(dirname "$CONFIG")"
  cat > "$CONFIG" <<EOF_CONF
SCHEDULE=$schedule
RETENTION=$retention
SERVICES='${checked# }'
EOF_CONF
  # World-readable on purpose: it holds no secrets (the passphrase is
  # a separate 0600 file) and the app reads it without sudo.
  chmod 644 "$CONFIG"
  if [ "$schedule" = "off" ]; then
    systemctl disable --now 'gryonixnexus-autobackup.timer' >/dev/null 2>&1 || true
  else
    mkdir -p /etc/systemd/system
    cat > /etc/systemd/system/gryonixnexus-autobackup.timer <<EOF_TIMER
[Unit]
Description=gryonixNexus scheduled backups
[Timer]
OnCalendar=$oncal
# Servers are not up 24/7 — a missed window must still run.
Persistent=true
# Small jitter only: the user picked a specific time, so the run must
# not wander an hour away from it.
RandomizedDelaySec=5m
[Install]
WantedBy=timers.target
EOF_TIMER
    systemctl daemon-reload
    # A bad OnCalendar would leave the timer permanently inactive —
    # catch it here, while the app is still listening. Only when the
    # tool is actually present: its ABSENCE must not reject a schedule
    # that is fine (minimal images ship without systemd-analyze).
    if command -v systemd-analyze >/dev/null 2>&1; then
      if ! systemd-analyze calendar "$oncal" >/dev/null 2>&1; then
        echo "invalid schedule expression: ${oncal}" >&2; exit 2
      fi
    fi
    systemctl enable --now 'gryonixnexus-autobackup.timer' >/dev/null 2>&1 || true
  fi
}

do_set_passphrase() {
  install -d -m 755 "$(dirname '/etc/gryonixnexus/autobackup.pass')"
  # From stdin, never argv: argv is world-readable in /proc.
  local pass
  pass="$(cat)"
  if [ -z "$pass" ]; then echo "an empty passphrase is refused" >&2; exit 2; fi
  ( umask 077 && printf '%s' "$pass" > '/etc/gryonixnexus/autobackup.pass' )
  chmod 600 '/etc/gryonixnexus/autobackup.pass'
}

case "$ACTION" in
  delete) do_delete "${2:-}" ;;
  run) do_run ;;
  backup) shift; do_backup "$@" ;;
  estimate) do_estimate "${2:-}" ;;
  set-schedule) shift; do_set_schedule "$@" ;;
  set-passphrase) do_set_passphrase ;;
  set-destination) shift; do_set_destination "$@" ;;
  show-destination) do_show_destination ;;
  test-destination) do_test_destination ;;
  set-drives) shift; do_set_drives "$@" ;;
  show-drives) do_show_drives ;;
  *) echo "unsupported action: ${ACTION}" >&2; exit 2 ;;
esac
echo 'GRYONIXNEXUS_BACKUP_CTL_DONE'"#####;

    template
        .replace("@@GD_RETENTION@@", &DEFAULT_RETENTION.to_string())
        .replace("@@GD_SERVICES@@", &all_ids)
        .replace("@@GD_OWNER@@", &owner)
        .replace("@@GD_LOCK_HELPER@@", &lock::helper())
        .replace("@@GD_FUNCTIONS@@", &functions)
        .replace("@@GD_DISPATCH_ARMS@@", &dispatch_arms)
        .replace("@@GD_ENCRYPT_ARMS@@", &encrypt_arms)
        .replace("@@GD_DIR_CASES@@", &dir_cases)
        .replace("@@GD_ESTIMATE_ARMS@@", &estimate_arms)
        .replace("@@GD_FORLOOP_IDS@@", &forloop_ids)
}

pub fn unit() -> String {
    format!("[Unit]\nDescription=gryonixNexus scheduled backup run\nAfter=docker.service\n[Service]\nType=oneshot\nExecStart={SCRIPT_PATH} run")
}

#[allow(dead_code)]
pub fn uninstall_lines(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}# Scheduled backups: the timer is armed by set-schedule, not by"),
        format!("{indent}# setup, so it outlives the services unless it is stopped here."),
        format!("{indent}systemctl disable --now '{TIMER_NAME}' >/dev/null 2>&1 || true"),
        format!("{indent}rm -f /etc/systemd/system/{TIMER_NAME} /etc/systemd/system/{SERVICE_NAME}"),
        format!("{indent}rm -f '{SCRIPT_PATH}'"),
        format!("{indent}rm -rf '{CONFIG_DIRECTORY}'"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;
    use crate::install::context::Input;
    use crate::install::host::HostRole;

    fn host_input(services: &[&str]) -> HostInput {
        let mut services: Vec<String> = services.iter().map(|s| s.to_string()).collect();
        services.sort();
        HostInput {
            services,
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    #[test]
    fn only_a_host_with_a_secret_store_needs_a_stored_passphrase() {
        assert!(needs_stored_passphrase(&host_input(&["vaultwarden"])));
        assert!(needs_stored_passphrase(&host_input(&["psono"])));
        assert!(needs_stored_passphrase(&host_input(&["passbolt"])));
        assert!(
            needs_stored_passphrase(&host_input(&["jellyfin", "vaultwarden"])),
            "one service that encrypts is enough for the host to need one"
        );
        assert!(
            !needs_stored_passphrase(&host_input(&["jellyfin"])),
            "bulk media is not encrypted by default — GPG over a photo library costs hours"
        );
        assert!(!needs_stored_passphrase(&host_input(&[])));
    }

    #[test]
    fn every_encrypting_target_makes_its_host_need_a_passphrase() {
        for id in ["vaultwarden", "psono", "passbolt", "nextcloud", "jellyfin", "seafile"] {
            let input = host_input(&[id]);
            let encrypts = build_targets(&input).iter().any(|t| t.encrypts_by_default);
            assert_eq!(
                encrypts,
                needs_stored_passphrase(&input),
                "{id}: the wrapper's own table and the passphrase decision disagree"
            );
        }
    }

    #[test]
    fn quoted_path_keeps_a_glob_outside_the_quotes() {
        assert_eq!(quoted_path("/opt/mailcow-dockerized"), "'/opt/mailcow-dockerized'");
        assert_eq!(
            quoted_path("/var/lib/docker/volumes/mailcowdockerized_*"),
            "'/var/lib/docker/volumes/mailcowdockerized_'*"
        );
    }

    #[test]
    fn split_data_path_matches_archive_backup_plan() {
        assert_eq!(split_data_path("/opt/gitlab-ce"), ("/opt".to_string(), "gitlab-ce".to_string()));
        assert_eq!(split_data_path("/opt/nextcloud/data"), ("/opt/nextcloud".to_string(), "data".to_string()));
        assert_eq!(split_data_path("/opt"), ("/".to_string(), "opt".to_string()));
    }

    #[test]
    fn an_empty_service_set_uses_the_documented_fallbacks() {
        let input = host_input(&[]);
        let rendered = script(&input);
        assert!(rendered.contains("SERVICES=''"));
        assert!(rendered.contains(": # no backup-capable service is installed"));
        assert!(rendered.contains("    \"\") ;;"));
        assert!(rendered.contains("for known in ''; do"));
    }

    #[test]
    fn falls_back_to_root_when_no_ssh_control_user_exists() {
        let mut input = host_input(&["adguard-home"]);
        input.ssh_user = None;
        assert!(script(&input).contains("OWNER='root'\n"));
    }

    #[test]
    fn unit_matches_the_real_generated_timer_service() {
        let path = format!(
            "{}/tests/fixtures/install/host/autobackup_unit/A-adguard-access-en.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected = std::fs::read_to_string(&path).expect("fixture");
        assert_eq!(unit(), expected.trim_end_matches('\n'));
    }

    #[test]
    fn backup_dirs_names_exactly_the_directories_the_wrapper_dispatches_into() {
        let input = host_input(&["vaultwarden", "nextcloud", "wireguard-vpn", "vpn-panel"]);
        let dirs = backup_dirs(&input);
        assert_eq!(
            dirs,
            vec![
                ("vaultwarden".to_string(), "/opt/backups/vaultwarden".to_string()),
                ("nextcloud".to_string(), "/opt/backups/nextcloud".to_string()),
                ("vpn-panel".to_string(), "/opt/backups/vpn-panel".to_string()),
            ]
        );
        assert!(!dirs.iter().any(|(id, _)| id == "wireguard-vpn"));
    }
}

#[cfg(test)]
mod arm_coverage {
    use super::*;
    use crate::install::context::Input;
    use crate::install::host::HostRole;

    fn host(services: &[&str]) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: crate::language::Language::En,
            ssh_user: Some("server-user".to_string()),
            role: HostRole::SingleHost,
        }
    }

    #[test]
    fn every_backup_capable_service_has_an_arm() {
        for id in BACKUP_CAPABLE_SERVICE_IDS {
            let targets = build_targets(&host(&[id]));
            assert!(
                targets.iter().any(|t| t.id == *id),
                "`{id}` declares a backup but this wrapper renders no arm for it — \
                 a host set up by the agent refuses to back it up"
            );
        }
    }

    #[test]
    fn a_full_host_carries_every_arm() {
        let script = script(&host(BACKUP_CAPABLE_SERVICE_IDS));
        for id in BACKUP_CAPABLE_SERVICE_IDS {
            assert!(
                script.contains(&format!("    {id}) dir='")),
                "the rendered wrapper has no estimate arm for `{id}` — this is \
                 the exact line `backup::resolve` reads to answer at all"
            );
        }
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::context::Input;
    use crate::install::host::HostRole;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/backup_ctl/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"));
        raw.trim_end_matches('\n').to_string()
    }

    fn host_input(services: &[&str]) -> HostInput {
        let mut services: Vec<String> = services.iter().map(|s| s.to_string()).collect();
        services.sort();
        HostInput {
            services,
            install: Input { domain: "example.com".to_string(), ..Input::default() },
            language: crate::language::Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    #[test]
    fn dump_wrapper_for_a_live_host() {
        let (Ok(dir), Ok(services)) = (
            std::env::var("GRYONIXNEXUS_DUMP_DIR"),
            std::env::var("GRYONIXNEXUS_DUMP_SERVICES"),
        ) else {
            return;
        };
        let list: Vec<&str> = services.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let mut input = host_input(&list);
        if let Ok(user) = std::env::var("GRYONIXNEXUS_DUMP_SSH_USER") {
            input.ssh_user = Some(user);
        }
        std::fs::create_dir_all(&dir).expect("dump directory");
        std::fs::write(std::path::Path::new(&dir).join("backup-ctl.sh"), script(&input))
            .expect("write the wrapper");
    }

    fn assert_parity(services: &[&str], fixture_name: &str) {
        assert_eq!(script(&host_input(services)), fixture(fixture_name), "{fixture_name}");
    }

    #[test]
    fn pihole() {
        assert_parity(&["pihole"], "A-pihole-access-en");
    }

    #[test]
    fn homepage() {
        assert_parity(&["homepage"], "A-homepage-access-en");
    }

    #[test]
    fn authelia() {
        assert_parity(&["authelia"], "A-authelia-access-en");
    }

    #[test]
    fn headscale() {
        assert_parity(&["headscale", "tailscale-node"], "A-mesh-access-en");
    }

    #[test]
    fn adguard() {
        assert_parity(&["adguard-home"], "A-adguard-access-en");
    }

    #[test]
    fn adguard_full() {
        assert_parity(&["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn", "vpn-panel"], "A-adguard-full-access-en");
    }

    #[test]
    fn dms() {
        assert_parity(&["docker-mailserver"], "A-dms-access-en");
    }

    #[test]
    fn dms_full() {
        assert_parity(&["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn", "vpn-panel"], "A-dms-full-access-en");
    }

    #[test]
    fn jellyfin() {
        assert_parity(&["jellyfin"], "A-jellyfin-access-en");
    }

    #[test]
    fn jellyfin_full() {
        assert_parity(&["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn", "vpn-panel"], "A-jellyfin-full-access-en");
    }

    #[test]
    fn mailcow() {
        assert_parity(&["mailcow"], "A-mailcow-access-en");
    }

    #[test]
    fn mailcow_awg() {
        assert_parity(&["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn", "vpn-panel"], "A-mailcow-awg-access-en");
    }

    #[test]
    fn mailcow_wg() {
        assert_parity(&["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn", "vpn-panel"], "A-mailcow-wg-access-en");
    }

    #[test]
    fn mailcow_xray() {
        assert_parity(&["mailcow", "vaultwarden", "wireguard-vpn", "vpn-panel"], "A-mailcow-xray-access-en");
    }

    #[test]
    fn mailu() {
        assert_parity(&["mailu"], "A-mailu-access-en");
    }

    #[test]
    fn mailu_full() {
        assert_parity(&["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn", "vpn-panel"], "A-mailu-full-access-en");
    }

    #[test]
    fn multidomain() {
        assert_parity(
            &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "wireguard-vpn", "vpn-panel"],
            "A-multidomain",
        );
    }

    #[test]
    fn nomail() {
        assert_parity(&["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"], "A-nomail-access-en");
    }

    #[test]
    fn nomail_ovpn() {
        assert_parity(&["vaultwarden", "wireguard-vpn", "vpn-panel"], "A-nomail-ovpn-access-en");
    }

    #[test]
    fn passbolt() {
        assert_parity(&["passbolt"], "A-passbolt-access-en");
    }

    #[test]
    fn passwords_shelf() {
        assert_parity(&["passbolt", "psono", "vaultwarden"], "A-passwords-shelf-access-en");
    }

    #[test]
    fn photoprism() {
        assert_parity(&["photoprism"], "A-photoprism-access-en");
    }

    #[test]
    fn photoprism_immich() {
        assert_parity(&["photoprism", "immich", "vaultwarden"], "A-photoprism-immich-access-en");
    }

    #[test]
    fn psono() {
        assert_parity(&["psono"], "A-psono-access-en");
    }

    #[test]
    fn psono_vaultwarden() {
        assert_parity(&["psono", "vaultwarden"], "A-psono-vaultwarden-access-en");
    }

    #[test]
    fn seafile() {
        assert_parity(&["seafile"], "A-seafile-access-en");
    }

    #[test]
    fn seafile_nextcloud() {
        assert_parity(&["seafile", "nextcloud", "vaultwarden"], "A-seafile-nextcloud-access-en");
    }
}
