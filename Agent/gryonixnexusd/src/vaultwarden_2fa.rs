//! Counts Vaultwarden accounts without two-factor login; reads its SQLite file, never writes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hyper::StatusCode;
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use tokio::process::Command;

use crate::api::{connect_error, Codec, Resp};
use crate::{discover, pb};

const SERVICE_ID: &str = "vaultwarden";
const DATA_MOUNT: &str = "/data";
const DATABASE_FILE: &str = "db.sqlite3";
const PROVIDER_TYPES: &str = "0, 1, 2, 3, 4, 6, 7";

#[derive(Deserialize)]
struct MountRow {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

pub async fn get(codec: Codec) -> Resp {
    let result = match read_counts().await {
        Ok(Some((users, without))) => {
            pb::VaultwardenTwoFactor { readable: true, users, users_without_two_factor: without }
        }
        Ok(None) | Err(_) => pb::VaultwardenTwoFactor::default(),
    };
    codec.encode(&result).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

async fn read_counts() -> Result<Option<(u32, u32)>> {
    let Some(dir) = data_directory().await? else { return Ok(None) };
    let database = dir.join(DATABASE_FILE);
    if !database.is_file() {
        return Ok(None);
    }
    let counts = tokio::task::spawn_blocking(move || count_accounts(&database)).await??;
    Ok(Some(counts))
}

async fn data_directory() -> Result<Option<PathBuf>> {
    for name in discover::containers_of_service(SERVICE_ID).await? {
        let output = Command::new("docker")
            .args(["inspect", "--format", "{{json .Mounts}}", &name])
            .output()
            .await
            .context("run `docker inspect`")?;
        if !output.status.success() {
            continue;
        }
        if let Some(dir) = data_source(&String::from_utf8_lossy(&output.stdout)) {
            return Ok(Some(dir));
        }
    }
    Ok(None)
}

fn data_source(mounts_json: &str) -> Option<PathBuf> {
    let rows: Vec<MountRow> = serde_json::from_str(mounts_json.trim()).ok()?;
    rows.into_iter()
        .find(|row| row.destination == DATA_MOUNT && row.source.starts_with('/'))
        .map(|row| PathBuf::from(row.source))
}

fn count_accounts(database: &Path) -> Result<(u32, u32)> {
    let connection = open_read_only(database)?;
    let enabled_only = has_enabled_column(&connection)?;
    let filter = if enabled_only { " WHERE enabled = 1" } else { "" };
    let users: u32 = connection.query_row(&format!("SELECT COUNT(*) FROM users{filter}"), [], |row| row.get(0))?;
    let and_enabled = if enabled_only { " AND u.enabled = 1" } else { "" };
    let without: u32 = connection.query_row(
        &format!(
            "SELECT COUNT(*) FROM users u WHERE 1 = 1{and_enabled} AND NOT EXISTS (\
             SELECT 1 FROM twofactor t WHERE t.user_uuid = u.uuid AND t.enabled = 1 \
             AND t.atype IN ({PROVIDER_TYPES}))"
        ),
        [],
        |row| row.get(0),
    )?;
    Ok((users, without))
}

fn has_enabled_column(connection: &Connection) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare("PRAGMA table_info(users)")?;
    let names = statement.query_map([], |row| row.get::<_, String>(1))?;
    for name in names {
        if name? == "enabled" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_read_only(database: &Path) -> rusqlite::Result<Connection> {
    if has_wal(database) {
        return Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY);
    }
    let uri = format!("file:{}?immutable=1", uri_path(database));
    Connection::open_with_flags(uri, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)
}

fn has_wal(database: &Path) -> bool {
    let mut wal = database.as_os_str().to_owned();
    wal.push("-wal");
    std::fs::metadata(wal).map(|meta| meta.len() > 0).unwrap_or(false)
}

fn uri_path(path: &Path) -> String {
    let mut out = String::new();
    for byte in path.to_string_lossy().bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gnx-vw2fa-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn seed(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE users (uuid TEXT PRIMARY KEY, email TEXT, enabled BOOLEAN NOT NULL DEFAULT 1);
                 CREATE TABLE twofactor (uuid TEXT PRIMARY KEY, user_uuid TEXT, atype INTEGER, enabled BOOLEAN);
                 INSERT INTO users (uuid, email, enabled) VALUES
                   ('a', 'a@x', 1), ('b', 'b@x', 1), ('c', 'c@x', 1), ('d', 'd@x', 1), ('e', 'e@x', 0);
                 INSERT INTO twofactor (uuid, user_uuid, atype, enabled) VALUES
                   ('1', 'a', 0, 1),
                   ('2', 'b', 0, 0),
                   ('3', 'c', 1003, 1),
                   ('4', 'c', 5, 1),
                   ('5', 'd', 7, 1),
                   ('6', 'd', 8, 1);",
            )
            .unwrap();
    }

    #[test]
    fn counts_enabled_accounts_and_those_without_a_real_second_factor() {
        let dir = scratch("counts");
        let database = dir.join(DATABASE_FILE);
        seed(&Connection::open(&database).unwrap());
        assert_eq!(count_accounts(&database).unwrap(), (4, 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reading_a_settled_database_leaves_the_directory_untouched() {
        let dir = scratch("untouched");
        let database = dir.join(DATABASE_FILE);
        seed(&Connection::open(&database).unwrap());
        let before = std::fs::read(&database).unwrap();
        count_accounts(&database).unwrap();
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from(DATABASE_FILE)]);
        assert_eq!(std::fs::read(&database).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_database_with_a_live_wal_is_read_including_the_wal() {
        let dir = scratch("wal");
        let database = dir.join(DATABASE_FILE);
        let writer = Connection::open(&database).unwrap();
        writer.pragma_update(None, "journal_mode", "WAL").unwrap();
        writer.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        seed(&writer);
        assert!(has_wal(&database));
        assert_eq!(count_accounts(&database).unwrap(), (4, 2));
        drop(writer);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_database_without_the_enabled_column_counts_every_account() {
        let dir = scratch("old");
        let database = dir.join(DATABASE_FILE);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE users (uuid TEXT PRIMARY KEY);
                 CREATE TABLE twofactor (uuid TEXT, user_uuid TEXT, atype INTEGER, enabled BOOLEAN);
                 INSERT INTO users VALUES ('a'), ('b');
                 INSERT INTO twofactor VALUES ('1', 'a', 1, 1);",
            )
            .unwrap();
        drop(connection);
        assert_eq!(count_accounts(&database).unwrap(), (2, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_with_odd_characters_still_opens() {
        let dir = scratch("odd name#1?");
        let database = dir.join(DATABASE_FILE);
        seed(&Connection::open(&database).unwrap());
        assert_eq!(count_accounts(&database).unwrap(), (4, 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_data_mount_is_found_by_its_destination() {
        let json = r#"[{"Type":"bind","Source":"/etc/localtime","Destination":"/etc/localtime"},
                       {"Type":"bind","Source":"/srv/vault/data","Destination":"/data"}]"#;
        assert_eq!(data_source(json), Some(PathBuf::from("/srv/vault/data")));
        assert_eq!(data_source("[]"), None);
        assert_eq!(data_source("not json"), None);
    }

    #[test]
    fn the_uri_escapes_what_sqlite_would_misread() {
        assert_eq!(uri_path(Path::new("/a b/c#d?e%f")), "/a%20b/c%23d%3Fe%25f");
    }
}
