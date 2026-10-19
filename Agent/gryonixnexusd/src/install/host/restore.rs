//! Port of `DashboardAccessSections.restoreWrapper` — `/opt/gryonixnexus-restore.sh`

use crate::install::context::Input;
use crate::install::host::uninstall::BackupPaths;
use crate::install::host::HostInput;

// MARK: - Catalog order for the services this wrapper restores

pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-restore.sh";

const RESTORABLE_ORDER: &[&str] = &[
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
    "headscale",
    "homepage",
    "authelia",
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

const VPN_PROTOCOLS: &[&str] =
    &["wireguard-vpn", "amnezia-wg", "shadowsocks", "xray-reality", "openvpn"];

fn restorable_services(input: &HostInput) -> Vec<&'static str> {
    let has_protocol = VPN_PROTOCOLS.iter().any(|p| input.services.iter().any(|s| s == p));
    RESTORABLE_ORDER
        .iter()
        .copied()
        .filter(|id| {
            let present = input.services.iter().any(|s| s == id);
            present || (*id == "vpn-panel" && has_protocol)
        })
        .collect()
}

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

struct ArchivePlan {
    compose_project: &'static str,
    data_path: String,
    databases: Vec<Database>,
    quiesce_services: Vec<&'static str>,
}

impl ArchivePlan {
    /// A port of `ArchiveBackupPlan.dataSlot`: the archive member name.
    fn data_slot(&self) -> &str {
        self.data_path.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or(&self.data_path)
    }

    fn data_parent(&self) -> String {
        let trimmed = self.data_path.strip_suffix('/').unwrap_or(&self.data_path);
        match trimmed.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => trimmed[..i].to_string(),
        }
    }
}

/// A port of every non-mailcow, non-vaultwarden service's `actions(_:).backup?.wrapper?.plan.archive`
fn archive_plan_for(id: &str, input: &Input) -> ArchivePlan {
    archive_plan_for_1(id, input)
        .or_else(|| archive_plan_for_2(id, input))
        .or_else(|| archive_plan_for_3(id, input))
        .or_else(|| archive_plan_for_4(id, input))
        .or_else(|| archive_plan_for_5(id, input))
        .unwrap_or_else(|| unreachable!("archive_plan_for called with an id outside RESTORABLE_ORDER: {id}"))
}

fn archive_plan_for_1(id: &str, input: &Input) -> Option<ArchivePlan> {
    use crate::install::mail::dockermailserver as dms;
    match id {
        "adguard-home" => Some(ArchivePlan {
            compose_project: crate::install::adguard::COMPOSE_PROJECT,
            data_path: format!("{}/conf", input.adguard_path),
            databases: Vec::new(),
            quiesce_services: Vec::new(),
        }),
        "forgejo" => Some(ArchivePlan {
            compose_project: crate::install::forgejo::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.forgejo_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: "db",
                file_name: "forgejo.sql",
                database_name: None,
            }],
            quiesce_services: vec!["server"],
        }),
        "docker-mailserver" => Some(ArchivePlan {
            compose_project: dms::COMPOSE_PROJECT,
            data_path: input.docker_mailserver_path.clone(),
            databases: Vec::new(),
            quiesce_services: vec!["mailserver", "webmail"],
        }),
        "immich" => Some(ArchivePlan {
            compose_project: crate::install::immich::COMPOSE_PROJECT,
            data_path: format!("{}/library", input.immich_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: "database",
                file_name: "immich.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        }),
        "gitlab" => Some(ArchivePlan {
            compose_project: crate::install::gitlab::COMPOSE_PROJECT,
            data_path: input.gitlab_path.clone(),
            databases: Vec::new(),
            quiesce_services: vec!["gitlab"],
        }),
        "jellyfin" => Some(ArchivePlan {
            compose_project: crate::install::jellyfin::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.jellyfin_path),
            databases: Vec::new(),
            quiesce_services: vec!["jellyfin"],
        }),
        "mosquitto" => Some(ArchivePlan {
            compose_project: crate::install::mosquitto::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.mosquitto_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::mosquitto::CONTAINER],
        }),
        _ => None,
    }
}

fn archive_plan_for_2(id: &str, input: &Input) -> Option<ArchivePlan> {
    match id {
        "zigbee2mqtt" => Some(ArchivePlan {
            compose_project: crate::install::zigbee2mqtt::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.zigbee2mqtt_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::zigbee2mqtt::CONTAINER],
        }),
        "home-assistant" => Some(ArchivePlan {
            compose_project: crate::install::home_assistant::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.home_assistant_path),
            databases: Vec::new(),
            // The container name, which differs from the project's.
            quiesce_services: vec![crate::install::home_assistant::CONTAINER],
        }),
        "minecraft-java" => Some(ArchivePlan {
            compose_project: crate::install::minecraft::JAVA_COMPOSE_PROJECT,
            data_path: format!("{}/data", input.minecraft_java_path),
            databases: Vec::new(),
            quiesce_services: vec!["minecraft-java"],
        }),
        "minecraft-bedrock" => Some(ArchivePlan {
            compose_project: crate::install::minecraft::BEDROCK_COMPOSE_PROJECT,
            data_path: format!("{}/data", input.minecraft_bedrock_path),
            databases: Vec::new(),
            quiesce_services: vec!["minecraft-bedrock"],
        }),
        "litellm" => Some(ArchivePlan {
            compose_project: crate::install::litellm::COMPOSE_PROJECT,
            data_path: input.litellm_path.clone(),
            databases: Vec::new(),
            quiesce_services: Vec::new(),
        }),
        "anythingllm" => Some(ArchivePlan {
            compose_project: crate::install::anythingllm::COMPOSE_PROJECT,
            data_path: input.anythingllm_path.clone(),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::anythingllm::CONTAINER],
        }),
        "qdrant" => Some(ArchivePlan {
            compose_project: crate::install::qdrant::COMPOSE_PROJECT,
            data_path: format!("{}/storage", input.qdrant_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::qdrant::CONTAINER],
        }),
        "openclaw" => Some(ArchivePlan {
            compose_project: crate::install::openclaw::COMPOSE_PROJECT,
            data_path: format!("{}/state", input.openclaw_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::openclaw::CONTAINER],
        }),
        _ => None,
    }
}

fn archive_plan_for_3(id: &str, input: &Input) -> Option<ArchivePlan> {
    use crate::install::mail::mailu;
    match id {
        "n8n" => Some(ArchivePlan {
            compose_project: crate::install::n8n::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.n8n_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: crate::install::n8n::DATABASE_SERVICE,
                file_name: "n8n.sql",
                database_name: None,
            }],
            quiesce_services: vec![crate::install::n8n::CONTAINER],
        }),
        "open-webui" => Some(ArchivePlan {
            compose_project: crate::install::open_webui::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.open_webui_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::open_webui::CONTAINER],
        }),
        "crafty-controller" => Some(ArchivePlan {
            compose_project: crate::install::crafty::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.crafty_path),
            databases: Vec::new(),
            quiesce_services: vec!["crafty"],
        }),
        "nextcloud" => Some(ArchivePlan {
            compose_project: crate::install::nextcloud::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.nextcloud_path),
            databases: vec![Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "nextcloud.sql",
                database_name: None,
            }],
            quiesce_services: vec!["app"],
        }),
        "mailu" => Some(ArchivePlan {
            compose_project: mailu::COMPOSE_PROJECT,
            data_path: input.mailu_path.clone(),
            databases: Vec::new(),
            quiesce_services: vec![
                "front", "admin", "imap", "smtp", "antispam", "webmail", "redis", "resolver",
            ],
        }),
        "passbolt" => Some(ArchivePlan {
            compose_project: crate::install::passbolt::COMPOSE_PROJECT,
            // A port of `PassboltService.secretsPath(_:)`: `<passboltPath>/secrets`.
            data_path: format!("{}/secrets", input.passbolt_path),
            databases: vec![Database {
                engine: Engine::Mysql,
                service: "db",
                file_name: "passbolt.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        }),
        _ => None,
    }
}

fn archive_plan_for_4(id: &str, input: &Input) -> Option<ArchivePlan> {
    match id {
        "psono" => Some(ArchivePlan {
            compose_project: crate::install::psono::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.psono_path),
            databases: vec![Database {
                engine: Engine::Postgres,
                service: "db",
                file_name: "psono.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        }),
        "photoprism" => Some(ArchivePlan {
            compose_project: crate::install::photoprism::COMPOSE_PROJECT,
            data_path: format!("{}/originals", input.photoprism_path),
            databases: vec![Database {
                engine: Engine::Mysql,
                service: "mariadb",
                file_name: "photoprism.sql",
                database_name: None,
            }],
            quiesce_services: Vec::new(),
        }),
        "seafile" => Some(ArchivePlan {
            compose_project: crate::install::seafile::COMPOSE_PROJECT,
            // A port of `SeafileService.dataPath(_:)`: `<seafilePath>/data`.
            data_path: format!("{}/data", input.seafile_path),
            databases: vec![
                Database {
                    engine: Engine::Mysql,
                    service: "db",
                    file_name: "ccnet_db.sql",
                    database_name: Some("ccnet_db"),
                },
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
            ],
            quiesce_services: vec!["seafile"],
        }),
        "pihole" => Some(ArchivePlan {
            compose_project: crate::install::pihole::COMPOSE_PROJECT,
            data_path: format!("{}/etc-pihole", input.pihole_path),
            databases: Vec::new(),
            quiesce_services: Vec::new(),
        }),
        _ => None,
    }
}

fn archive_plan_for_5(id: &str, input: &Input) -> Option<ArchivePlan> {
    match id {
        "homepage" => Some(ArchivePlan {
            compose_project: crate::install::homepage::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.homepage_path),
            databases: Vec::new(),
            quiesce_services: Vec::new(),
        }),
        "authelia" => Some(ArchivePlan {
            compose_project: crate::install::authelia::COMPOSE_PROJECT,
            data_path: format!("{}/config", input.authelia_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::authelia::CONTAINER],
        }),
        "headscale" => Some(ArchivePlan {
            compose_project: crate::install::headscale::COMPOSE_PROJECT,
            data_path: format!("{}/data", input.headscale_path),
            databases: Vec::new(),
            quiesce_services: vec![crate::install::headscale::CONTAINER],
        }),
        "vpn-panel" => Some(ArchivePlan {
            compose_project: crate::install::vpn::panel::COMPOSE_PROJECT,
            data_path: format!("{}/data", crate::install::vpn::panel::PATH),
            databases: Vec::new(),
            quiesce_services: vec!["vpnpanel"],
        }),
        _ => None,
    }
}

/// A port of `DashboardAccessSections.restoreArchiveFunction(target:plan:)`.
fn restore_archive_function(target: &str, plan: &ArchivePlan) -> String {
    let mut lines = restore_prepare_lines(target, plan);
    lines.extend(restore_swap_lines(plan));
    lines.extend(restore_database_lines(target, plan));
    lines.join("\n")
}

fn restore_prepare_lines(target: &str, plan: &ArchivePlan) -> Vec<String> {
    let name = target.replace('-', "_");
    let slot = plan.data_slot();
    let parent = plan.data_parent();
    vec![
        format!("restore_{name}() {{"),
        "  local plain=\"$ARCHIVE\" tmp=\"\" stage=\"\" previous=\"\" saved=0 rc=0".to_string(),
        "  case \"$ARCHIVE\" in".to_string(),
        "    *.gpg)".to_string(),
        "      tmp=\"$(mktemp -d \"$(dirname \"$ARCHIVE\")/.gpg-XXXXXX\")\"".to_string(),
        "      plain=\"$tmp/restore.tar.gz\"".to_string(),
        "      # --passphrase-fd 0: the secret arrives on stdin, never in argv.".to_string(),
        "      if ! gpg --batch --quiet --yes --decrypt --passphrase-fd 0 \\".to_string(),
        "           --pinentry-mode loopback --output \"$plain\" \"$ARCHIVE\"; then".to_string(),
        "        rm -rf \"$tmp\"".to_string(),
        "        echo \"could not decrypt the backup (wrong passphrase?)\" >&2".to_string(),
        "        exit 1".to_string(),
        "      fi".to_string(),
        "      ;;".to_string(),
        "  esac".to_string(),
        "  # Verified BEFORE anything is stopped: a truncated upload must not".to_string(),
        "  # cost the user the data they still have.".to_string(),
        "  if ! tar -tzf \"$plain\" >/dev/null 2>&1; then".to_string(),
        "    rm -rf \"$tmp\"".to_string(),
        "    echo \"the backup archive is not readable\" >&2".to_string(),
        "    exit 1".to_string(),
        "  fi".to_string(),
        "  # Staged on the SERVICE's own filesystem, so putting the data back".to_string(),
        "  # is a rename rather than a second copy of the whole directory.".to_string(),
        format!("  stage=\"$(mktemp -d '{parent}/.restore-XXXXXX')\""),
        "  # shellcheck disable=SC2064".to_string(),
        "  trap \"rm -rf '$stage' '$tmp'\" EXIT".to_string(),
        "  tar --numeric-owner -xzf \"$plain\" -C \"$stage\"".to_string(),
        format!("  if [ ! -d \"$stage/{slot}\" ]; then"),
        format!("    echo \"the archive carries no {target} data\" >&2"),
        "    exit 1".to_string(),
        "  fi".to_string(),
    ]
}

fn restore_swap_lines(plan: &ArchivePlan) -> Vec<String> {
    let project = plan.compose_project;
    let data = &plan.data_path;
    let slot = plan.data_slot();
    let mut lines: Vec<String> = Vec::new();
    if !plan.quiesce_services.is_empty() {
        let quiesce = plan.quiesce_services.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(" ");
        lines.push(format!("  gd_compose_stop '{project}' {quiesce}"));
    }
    lines.extend([
        "  # The old data is moved aside, never deleted: if the move back".to_string(),
        "  # fails it is the only way home.".to_string(),
        format!("  previous='{data}'\".pre-restore-$STAMP\""),
        format!("  if [ -d '{data}' ]; then mv '{data}' \"$previous\"; saved=1; fi"),
        format!("  if mv \"$stage/{slot}\" '{data}'; then"),
        "    if [ \"$saved\" -eq 1 ]; then echo \"previous data kept at ${previous}\"; fi".to_string(),
        "  else".to_string(),
        "    echo \"restore failed, rolling back to the previous data\" >&2".to_string(),
        format!("    rm -rf '{data}'"),
        "    if [ \"$saved\" -eq 1 ]; then mv \"$previous\" '".to_string() + data + "'; fi",
        format!("    gd_compose_start_all '{project}'"),
        "    exit 1".to_string(),
        "  fi".to_string(),
    ]);
    lines
}

fn restore_database_lines(target: &str, plan: &ArchivePlan) -> Vec<String> {
    let project = plan.compose_project;
    let mut lines: Vec<String> = Vec::new();
    for db in &plan.databases {
        let helper = match db.engine {
            Engine::Postgres => "gd_load_postgres",
            Engine::Mysql => "gd_load_mysql",
        };
        let db_name_arg = db.database_name.map(|n| format!(" '{n}'")).unwrap_or_default();
        lines.extend([
            "  # The database container has to be up to take its dump back;".to_string(),
            "  # the rest of the project stays down until it is loaded.".to_string(),
            format!("  gd_compose_start '{project}' '{}'", db.service),
            format!(
                "  {helper} '{project}' '{}' \"$stage/gryonixnexus-db/{}\"{db_name_arg} || rc=1",
                db.service, db.file_name
            ),
        ]);
    }
    lines.extend([
        "  # Up again on every path, restored or not.".to_string(),
        format!("  gd_compose_start_all '{project}'"),
        "  if [ \"$rc\" -ne 0 ]; then".to_string(),
        format!("    echo \"the {target} database could not be restored\" >&2"),
        "    exit 1".to_string(),
        "  fi".to_string(),
        "}".to_string(),
    ]);
    lines
}

// MARK: - The two hardcoded arms

const RESTORE_MAILCOW_TEMPLATE: &str = r#"restore_mailcow() {
  [ -x "$MAILCOW_PATH/helper-scripts/backup_and_restore.sh" ] \
    || { echo "__MAILCOW_NOT_FOUND__" >&2; exit 1; }
  # mailcow's helper restores from a DIRECTORY inside its backup
  # location and picks it from a numbered menu. Stage the chosen backup
  # alone in a scratch location so that menu has exactly one entry.
  local stage="$MAILCOW_BACKUPS/.restore-$STAMP"
  mkdir -p "$stage"
  chmod 0777 "$stage"
  # shellcheck disable=SC2064
  trap "rm -rf '$stage'" EXIT
  local plain="$ARCHIVE"
  case "$ARCHIVE" in
    *.gpg)
      plain="$stage/.restore.tar.gz"
      gpg --batch --quiet --yes --decrypt --passphrase-fd 0 \
          --pinentry-mode loopback --output "$plain" "$ARCHIVE" \
        || { echo "could not decrypt the backup (wrong passphrase?)" >&2; exit 1; }
      ;;
  esac
  if [ -d "$ARCHIVE" ]; then
    cp -a "$ARCHIVE" "$stage/"
  else
    tar -xzf "$plain" -C "$stage"
    rm -f "$stage/.restore.tar.gz"
  fi
  export MAILCOW_BACKUP_LOCATION="$stage"
  # Bounded input, never `yes` (SIGPIPE under pipefail kills the pipeline).
  # The helper asks exactly two questions and then restores ONCE:
  # "Select a restore point" -> 1, the only staged backup; "Select a
  # dataset to restore" -> 0, the "[ 0 ] - all" entry, which expands to
  # every dataset in the backup (restore() loops over its arguments).
  # Feeding component indices one after another instead — as this did —
  # restores a SINGLE component and discards the rest of the input when
  # the helper exits, and which component index 1 refers to is whatever
  # `ls -f` returns first, so the survivor varied per run while the
  # wrapper still reported success.
  # The trailing "n" answers the vmail branch's "Force a resync now?";
  # extra input is harmless, a missing answer would depend on EOF.
  # Under `timeout` because an unrecognised prompt would otherwise wait
  # for a human that is never coming.
  printf '1\n0\nn\n' \
    | timeout 3600 "$MAILCOW_PATH/helper-scripts/backup_and_restore.sh" restore
}"#;

const RESTORE_VAULTWARDEN_BODY: &str = r#"restore_vaultwarden() {
  local plain="$ARCHIVE" tmp="" stage="" root="" previous="" saved=0
  case "$ARCHIVE" in
    *.gpg)
      tmp="$(mktemp -d)"
      # shellcheck disable=SC2064
      trap "rm -rf '$tmp'" EXIT
      plain="$tmp/restore.tar.gz"
      # --passphrase-fd 0: the secret arrives on stdin, never in argv.
      gpg --batch --quiet --yes --decrypt --passphrase-fd 0 \
          --pinentry-mode loopback --output "$plain" "$ARCHIVE" \
        || { echo "could not decrypt the backup (wrong passphrase?)" >&2; exit 1; }
      ;;
  esac
  # Verify BEFORE touching live data: a truncated upload must not cost
  # the user the data they still have.
  tar -tzf "$plain" >/dev/null 2>&1 \
    || { echo "the backup archive is not readable" >&2; exit 1; }
  # Unpacked aside; only the archived data directory is moved in.
  root="$(tar -tzf "$plain" | sed -n '1{s|^\./||;s|/*$||;p;}')"
  case "/$root/" in
    //|*/../*|*/./*) echo "the archive carries no vaultwarden data" >&2; exit 1 ;;
  esac
  mkdir -p "$(dirname "$VW_DATA")"
  stage="$(mktemp -d "$(dirname "$VW_DATA")/.restore-XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$stage' '$tmp'" EXIT
  tar --numeric-owner -xzf "$plain" -C "$stage" \
    || { echo "the backup archive is not readable" >&2; exit 1; }
  if [ ! -d "$stage/$root" ] || [ -L "$stage/$root" ]; then
    echo "the archive carries no vaultwarden data" >&2
    exit 1
  fi
  docker stop "$VW_CONTAINER" >/dev/null 2>&1 || true
  # The old data is moved aside, never deleted: if the move fails it is
  # the only way back, and the container must come up again either way.
  previous="${VW_DATA}.pre-restore-$STAMP"
  if [ -d "$VW_DATA" ]; then mv "$VW_DATA" "$previous"; saved=1; fi
  if mv "$stage/$root" "$VW_DATA"; then
    if [ "$saved" -eq 1 ]; then echo "previous data kept at ${previous}"; fi
  else
    echo "restore failed, rolling back to the previous data" >&2
    rm -rf "$VW_DATA"
    if [ "$saved" -eq 1 ]; then mv "$previous" "$VW_DATA"; fi
    docker start "$VW_CONTAINER" >/dev/null 2>&1 || true
    exit 1
  fi
  docker start "$VW_CONTAINER" >/dev/null 2>&1 || true
}"#;

const RESTORE_HELPERS: &str = r#"gd_compose_stop() {
  local project="$1"
  shift
  docker compose -p "$project" stop "$@" >/dev/null 2>&1 || true
}

gd_compose_start() {
  local project="$1"
  shift
  docker compose -p "$project" start "$@" >/dev/null 2>&1 || true
}

# Everything the project has, so the service is up again whatever the
# restore did — the same guarantee the vaultwarden arm gives.
gd_compose_start_all() {
  docker compose -p "$1" start >/dev/null 2>&1 || true
}

gd_container() {
  docker compose -p "$1" ps -q "$2" 2>/dev/null | head -n 1
}

# A container that has just been started reports "up" long before its
# engine accepts connections, and a dump loaded into it then fails with
# a connection error that reads exactly like a corrupt backup.
gd_db_wait() {
  local cid="$1" engine="$2" deadline
  deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    case "$engine" in
      postgres)
        if docker exec "$cid" sh -c 'exec pg_isready -q -U "$POSTGRES_USER"' >/dev/null 2>&1; then
          return 0
        fi
        ;;
      mysql)
        if docker exec "$cid" sh -c 'if command -v mariadb-admin >/dev/null 2>&1; then A=mariadb-admin; else A=mysqladmin; fi; MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$A" ping -u root' >/dev/null 2>&1; then
          return 0
        fi
        ;;
    esac
    sleep 3
  done
  return 1
}

# The credentials come from the container's OWN environment (compose
# put them there), never from the argv of docker exec — that is
# world-readable through /proc on the host.
gd_load_postgres() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then echo "the $1 database container is not running" >&2; return 1; fi
  if ! gd_db_wait "$cid" postgres; then echo "the $1 database never became ready" >&2; return 1; fi
  if [ ! -s "$3" ]; then echo "the archive carries no $1 database dump" >&2; return 1; fi
  # ON_ERROR_STOP: without it psql replays half a dump and still exits
  # 0, i.e. reports a restore that did not happen.
  if ! docker exec -i "$cid" sh -c \
       'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
       < "$3"; then
    echo "the $1 database could not be loaded" >&2
    return 1
  fi
}

# The fourth argument mirrors gd_dump_mysql: a service that keeps
# several databases in one engine names each one, and the load has to
# put each dump back where it came from.
gd_load_mysql() {
  local cid
  cid="$(gd_container "$1" "$2")"
  if [ -z "$cid" ]; then echo "the $1 database container is not running" >&2; return 1; fi
  if ! gd_db_wait "$cid" mysql; then echo "the $1 database never became ready" >&2; return 1; fi
  if [ ! -s "$3" ]; then echo "the archive carries no $1 database dump" >&2; return 1; fi
  if ! docker exec -i "$cid" sh -c \
       'if command -v mariadb >/dev/null 2>&1; then C=mariadb; else C=mysql; fi; MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$C" -u root "${1:-$MYSQL_DATABASE}"' \
       sh "${4:-}" < "$3"; then
    echo "the $1 database could not be loaded" >&2
    return 1
  fi
}"#;

/// A port of `L10nScripts.mailcowNotFound(_:path:)`.
fn mailcow_not_found(language: crate::language::Language, path: &str) -> String {
    use crate::language::Language::*;
    match language {
        En => format!("mailcow not found in {path}"),
        De => format!("mailcow nicht gefunden in {path}"),
        Fr => format!("mailcow introuvable dans {path}"),
        Es => format!("mailcow no encontrado en {path}"),
        Ru => format!("mailcow не найден в {path}"),
        Uk => format!("mailcow не знайдено в {path}"),
        It => format!("mailcow non trovato in {path}"),
        Ja => format!("{path} に mailcow が見つかりません"),
        Zh => format!("在 {path} 中未找到 mailcow"),
    }
}

/// A port of `L10nScripts.restoreDone(_:)`.
fn restore_done(language: crate::language::Language) -> &'static str {
    use crate::language::Language::*;
    match language {
        En => "Restore finished.",
        De => "Wiederherstellung abgeschlossen.",
        Fr => "Restauration terminée.",
        Es => "Restauración finalizada.",
        Ru => "Восстановление завершено.",
        Uk => "Відновлення завершено.",
        It => "Ripristino completato.",
        Ja => "復元が完了しました。",
        Zh => "恢复完成。",
    }
}

// MARK: - Assembly

fn script_head(input: &HostInput, backups: &BackupPaths, usage_targets: &str, dir_patterns: &str) -> String {
    let settings = &input.install;
    let mut out = String::new();
    out.push_str("#!/bin/bash\n");
    out.push_str("# Managed by gryonixNexus — restore a service from a backup.\n");
    out.push_str(&format!("# Usage: gryonixnexus-restore.sh <{usage_targets}> <archive>\n"));
    out.push_str("#        GPG passphrase (encrypted archives only) on stdin.\n");
    out.push_str("set -euo pipefail\n");
    out.push('\n');
    out.push_str("SERVICE=\"${1:-}\"\n");
    out.push_str("ARCHIVE=\"${2:-}\"\n");
    out.push('\n');
    out.push_str(&format!("MAILCOW_PATH='{}'\n", settings.mailcow_path));
    out.push_str(&format!("MAILCOW_BACKUPS='{}'\n", backups.mailcow));
    out.push_str(&format!("VW_CONTAINER='{}'\n", settings.vaultwarden_container));
    out.push_str(&format!("VW_DATA='{}'\n", settings.vaultwarden_data_path));
    out.push_str(&format!("VW_BACKUPS='{}'\n", backups.vaultwarden));
    out.push_str("STAMP=\"$(date +%Y%m%d-%H%M%S)\"\n");
    out.push('\n');
    out.push_str("# The archive must sit inside a backup directory this deployment owns.\n");
    out.push_str("# Without the check a whitelisted wrapper would happily unpack ANY\n");
    out.push_str("# root-readable file over a service's data directory.\n");
    out.push_str("case \"$ARCHIVE\" in\n");
    out.push_str("  *..*) echo \"invalid path: ${ARCHIVE}\" >&2; exit 2 ;;\n");
    out.push_str("esac\n");
    out.push_str("case \"$ARCHIVE\" in\n");
    out.push_str(&format!("  {dir_patterns}) ;;\n"));
    out.push_str("  *) echo \"path outside the backup directories: ${ARCHIVE}\" >&2; exit 2 ;;\n");
    out.push_str("esac\n");
    out.push_str("[ -e \"$ARCHIVE\" ] || { echo \"no such backup: ${ARCHIVE}\" >&2; exit 2; }\n");
    out
}

/// The final dispatch on the service, and the success marker
fn script_dispatch(input: &HostInput, generated_cases: &str) -> String {
    let mut out = String::new();
    out.push_str("case \"$SERVICE\" in\n");
    out.push_str("  mailcow) restore_mailcow ;;\n");
    out.push_str("  vaultwarden) restore_vaultwarden ;;\n");
    out.push_str(generated_cases);
    out.push('\n');
    out.push_str("  *) echo \"unsupported service: ${SERVICE}\" >&2; exit 2 ;;\n");
    out.push_str("esac\n");
    out.push_str("# A streamed command carries no exit status back to the app, so success\n");
    out.push_str("# is announced with a fixed ASCII marker (never the localized line —\n");
    out.push_str("# the app must not have to know which language the script was made in).\n");
    out.push_str(&format!("echo \"{}\"\n", restore_done(input.language)));
    out.push_str("echo 'GRYONIXNEXUS_RESTORE_DONE'");
    out
}

pub fn render(input: &HostInput, backups: &BackupPaths) -> String {
    let settings = &input.install;
    let restorable = restorable_services(input);
    let archive_ids: Vec<&str> =
        restorable.iter().copied().filter(|id| *id != "mailcow" && *id != "vaultwarden").collect();

    let usage_targets = restorable.join("|");

    let mut dir_patterns = vec!["\"$MAILCOW_BACKUPS\"/*".to_string(), "\"$VW_BACKUPS\"/*".to_string()];
    for id in &restorable {
        if *id == "mailcow" || *id == "vaultwarden" {
            continue;
        }
        dir_patterns.push(format!("\"{}\"/*", backups.for_id(id)));
    }
    let dir_patterns = dir_patterns.join("|");

    let generated_helpers =
        if archive_ids.is_empty() { String::new() } else { format!("\n{RESTORE_HELPERS}\n") };

    let generated_arms = archive_ids
        .iter()
        .map(|id| restore_archive_function(id, &archive_plan_for(id, settings)))
        .collect::<Vec<_>>()
        .join("\n\n");

    let generated_cases = archive_ids
        .iter()
        .map(|id| format!("  {id}) restore_{} ;;", id.replace('-', "_")))
        .collect::<Vec<_>>()
        .join("\n");

    let mailcow_body =
        RESTORE_MAILCOW_TEMPLATE.replace("__MAILCOW_NOT_FOUND__", &mailcow_not_found(input.language, &settings.mailcow_path));

    let mut out = script_head(input, backups, &usage_targets, &dir_patterns);
    out.push_str(&generated_helpers);
    out.push('\n');
    out.push_str(&mailcow_body);
    out.push_str("\n\n");
    out.push_str(RESTORE_VAULTWARDEN_BODY);
    out.push_str("\n\n");
    out.push_str(&generated_arms);
    out.push_str("\n\n");
    out.push_str(&script_dispatch(input, &generated_cases));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;
    use crate::install::host::HostRole;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/host/restore/{name}.txt", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn base_input() -> Input {
        Input {
            domain: "example.com".to_string(),
            wireguard_vpn_port: 51821,
            xray_reality_port: 8443,
            ..Input::default()
        }
    }

    fn multidomain_input() -> Input {
        Input {
            domain: "example.com".to_string(),
            additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
            wireguard_vpn_port: 51821,
            xray_reality_port: 8443,
            ..Input::default()
        }
    }

    fn host(services: &[&str], language: Language) -> HostInput {
        HostInput {
            services: services.iter().map(|s| s.to_string()).collect(),
            install: base_input(),
            language,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        }
    }

    #[test]
    fn fixture_parity() {
        let cases: &[(&str, &[&str])] = &[
            ("mailcow", &["mailcow"]),
            ("nomail", &["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"]),
            (
                "mailcow-wg",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn"],
            ),
            (
                "mailcow-awg",
                &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "amnezia-wg"],
            ),
            ("mailcow-xray", &["mailcow", "vaultwarden", "xray-reality"]),
            ("nomail-ovpn", &["vaultwarden", "openvpn"]),
            ("mailu", &["mailu"]),
            ("dms", &["docker-mailserver"]),
            (
                "dms-full",
                &["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn"],
            ),
            (
                "mailu-full",
                &["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn"],
            ),
            ("jellyfin", &["jellyfin"]),
            ("jellyfin-full", &["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn"]),
            ("adguard", &["adguard-home"]),
            ("pihole", &["pihole"]),
            ("homepage", &["homepage"]),
            ("authelia", &["authelia"]),
            ("adguard-full", &["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn"]),
            ("photoprism", &["photoprism"]),
            ("photoprism-immich", &["photoprism", "immich", "vaultwarden"]),
            ("seafile", &["seafile"]),
            ("seafile-nextcloud", &["seafile", "nextcloud", "vaultwarden"]),
            ("psono", &["psono"]),
            ("psono-vaultwarden", &["psono", "vaultwarden"]),
            ("passbolt", &["passbolt"]),
            ("passwords-shelf", &["passbolt", "psono", "vaultwarden"]),
        ];

        for (name, services) in cases {
            for (lang_suffix, language) in [("en", Language::En), ("ru", Language::Ru)] {
                let input = host(services, language);
                let backups = BackupPaths::default();
                let actual = render(&input, &backups);
                let fixture_name = format!("A-{name}-access-{lang_suffix}");
                let expected = fixture(&fixture_name);
                assert_eq!(actual, expected.trim_end_matches('\n'), "{fixture_name}");
            }
        }
    }

    #[test]
    fn fixture_parity_multidomain() {
        let input = HostInput {
            services: ["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "amnezia-wg"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            install: multidomain_input(),
            language: Language::En,
            ssh_user: Some("admin".to_string()),
            role: HostRole::SingleHost,
        };
        let backups = BackupPaths::default();
        let actual = render(&input, &backups);
        let expected = fixture("A-multidomain");
        assert_eq!(actual, expected.trim_end_matches('\n'));
    }

    #[test]
    fn render_is_the_same_regardless_of_host_role() {
        let mut input = host(&["adguard-home", "vaultwarden"], Language::En);
        let backups = BackupPaths::default();
        let single_host = render(&input, &backups);
        input.role = HostRole::HomeBackend;
        assert_eq!(render(&input, &backups), single_host);
    }

    #[test]
    fn no_archive_services_omits_the_shared_helpers() {
        let input = host(&["mailcow"], Language::En);
        let backups = BackupPaths::default();
        let script = render(&input, &backups);
        assert!(!script.contains("gd_compose_stop()"));
        assert!(!script.contains("gd_load_mysql()"));
        assert!(script.contains("restore_mailcow() {"));
        assert!(script.contains("restore_vaultwarden() {"));
    }

    #[test]
    fn the_two_hardcoded_arms_are_always_present() {
        let input = host(&["adguard-home"], Language::En);
        let backups = BackupPaths::default();
        let script = render(&input, &backups);
        assert!(script.contains("restore_mailcow() {"));
        assert!(script.contains("restore_vaultwarden() {"));
        assert!(script.contains("  mailcow) restore_mailcow ;;"));
        assert!(script.contains("  vaultwarden) restore_vaultwarden ;;"));
    }

    #[test]
    fn data_parent_and_slot_split_a_bare_opt_path_correctly() {
        let plan = ArchivePlan {
            compose_project: "gitlab",
            data_path: "/opt/gitlab-ce".to_string(),
            databases: Vec::new(),
            quiesce_services: vec!["gitlab"],
        };
        assert_eq!(plan.data_slot(), "gitlab-ce");
        assert_eq!(plan.data_parent(), "/opt");
    }
}
