use std::io::Read;
use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

use crate::pb;
use crate::util::now_millis;

pub struct Store {
    conn: Connection,
    /// Seals and opens the vault rows
    vault: crate::vault::VaultCipher,
}

impl Store {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let key_path = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("vault.key");
        let conn = Connection::open(path)?;
        Self::from_conn(conn, crate::vault::VaultCipher::open(&key_path)?)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::from_conn(
            Connection::open_in_memory()?,
            crate::vault::VaultCipher::ephemeral()?,
        )
    }

    fn from_conn(conn: Connection, vault: crate::vault::VaultCipher) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS services (
                 id           TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL,
                 status       INTEGER NOT NULL,
                 version      TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS devices (
                 id           TEXT PRIMARY KEY,
                 public_key   TEXT NOT NULL,
                 label        TEXT NOT NULL DEFAULT '',
                 scopes       TEXT NOT NULL DEFAULT 'read',
                 paired_at    INTEGER NOT NULL,
                 device_uid   TEXT NOT NULL DEFAULT '',
                 expires_at   INTEGER NOT NULL DEFAULT 0,
                 last_seen_at INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS vault (
                 id         TEXT PRIMARY KEY,
                 ciphertext BLOB NOT NULL,
                 nonce      BLOB NOT NULL,
                 updated_at INTEGER NOT NULL,
                 updated_by TEXT NOT NULL DEFAULT '',
                 deleted    INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS container_names (
                 group_key    TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS container_backup_plans (
                 group_key TEXT PRIMARY KEY,
                 plan_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS container_backup_schedules (
                 group_key    TEXT PRIMARY KEY,
                 schedule     TEXT NOT NULL,
                 last_run     INTEGER NOT NULL DEFAULT 0,
                 last_outcome TEXT NOT NULL DEFAULT ''
             );",
        )?;
        for (column, decl) in [
            ("device_uid", "TEXT NOT NULL DEFAULT ''"),
            ("expires_at", "INTEGER NOT NULL DEFAULT 0"),
            ("last_seen_at", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            add_column_if_missing(&conn, "devices", column, decl)?;
        }
        let stamp_existing = !column_exists(&conn, "services", "installed_by_agent")?;
        add_column_if_missing(&conn, "services", "installed_by_agent", "INTEGER NOT NULL DEFAULT 0")?;
        if stamp_existing {
            conn.execute("UPDATE services SET installed_by_agent = 1", [])?;
        }
        Ok(Self { conn, vault })
    }

    /// The authoritative snapshot the app renders
    pub fn snapshot(&self) -> Result<pb::State> {
        let mut stmt = self.conn.prepare(
            "SELECT id, display_name, status, version, installed_by_agent \
             FROM services ORDER BY id",
        )?;
        let services = stmt
            .query_map([], |row| {
                Ok(pb::Service {
                    installed_outside: row.get::<_, i64>(4)? == 0,
                    id: row.get(0)?,
                    display_name: row.get(1)?,
                    status: row.get(2)?,
                    version: row.get(3)?,
                    containers: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let discovered_at = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'discovered_at'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);

        Ok(pb::State {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            host: Some(host_info()),
            services,
            discovered_at,
            home_doors: Vec::new(),
            wake_on_lan: None,
            mesh_address: String::new(),
        })
    }

    pub fn record_discovery(&self, services: &[pb::Service]) -> Result<()> {
        for svc in services {
            self.put_service(svc)?;
        }
        for id in self.service_ids()? {
            if !services.iter().any(|svc| svc.id == id) {
                self.conn
                    .execute("DELETE FROM services WHERE id = ?1", [&id])?;
            }
        }
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('discovered_at', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [now_millis().to_string()],
        )?;
        Ok(())
    }

    fn service_ids(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT id FROM services")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    pub fn record_action(&self, id: &str, service: Option<&pb::Service>) -> Result<()> {
        match service {
            Some(svc) => {
                self.put_service(svc)?;
                self.conn.execute(
                    "UPDATE services SET installed_by_agent = 1 WHERE id = ?1",
                    [&svc.id],
                )?;
                Ok(())
            }
            None => {
                self.conn
                    .execute("DELETE FROM services WHERE id = ?1", [id])?;
                Ok(())
            }
        }
    }

    /// Upsert a service row
    pub fn put_service(&self, svc: &pb::Service) -> Result<()> {
        self.conn.execute(
            "INSERT INTO services (id, display_name, status, version)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                 display_name = excluded.display_name,
                 status       = excluded.status,
                 version      = excluded.version",
            rusqlite::params![svc.id, svc.display_name, svc.status, svc.version],
        )?;
        Ok(())
    }

    pub fn container_names(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_key, display_name FROM container_names")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Store one, or CLEAR it when the name is empty
    pub fn set_container_name(&self, key: &str, display_name: &str) -> Result<()> {
        if display_name.is_empty() {
            self.conn
                .execute("DELETE FROM container_names WHERE group_key = ?1", [key])?;
            return Ok(());
        }
        self.conn.execute(
            "INSERT INTO container_names (group_key, display_name) VALUES (?1, ?2)
             ON CONFLICT(group_key) DO UPDATE SET display_name = excluded.display_name",
            [key, display_name],
        )?;
        Ok(())
    }

    pub fn container_backup_plan(&self, key: &str) -> Result<Option<pb::ContainerBackupPlan>> {
        let mut stmt = self
            .conn
            .prepare("SELECT plan_json FROM container_backup_plans WHERE group_key = ?1")?;
        let mut rows = stmt.query([key])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let json: String = row.get(0)?;
        Ok(serde_json::from_str(&json).ok())
    }

    pub fn container_backup_schedule(&self, key: &str) -> Result<Option<pb::ContainerBackupSchedule>> {
        let mut stmt = self.conn.prepare(
            "SELECT schedule, last_run, last_outcome FROM container_backup_schedules WHERE group_key = ?1",
        )?;
        let mut rows = stmt.query([key])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => {
                let schedule: String = row.get(0)?;
                let last_run: i64 = row.get(1)?;
                let last_outcome: String = row.get(2)?;
                Ok(Some(pb::ContainerBackupSchedule {
                    key: key.to_string(),
                    enabled: !schedule.is_empty(),
                    schedule,
                    last_outcome,
                    last_run: if last_run == 0 { String::new() } else { last_run.to_string() },
                }))
            }
        }
    }

    /// Scheduled groups whose last backup failed, with the outcome
    pub fn failed_container_backups(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_key, last_outcome FROM container_backup_schedules \
             WHERE schedule <> '' AND last_outcome LIKE 'failed%'",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn container_backup_schedules(&self) -> Result<Vec<(String, String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_key, schedule, last_run FROM container_backup_schedules WHERE schedule <> ''")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Set or clear it
    pub fn set_container_backup_schedule(&self, key: &str, schedule: &str) -> Result<()> {
        if schedule.is_empty() {
            self.conn
                .execute("DELETE FROM container_backup_schedules WHERE group_key = ?1", [key])?;
        } else {
            self.conn.execute(
                "INSERT INTO container_backup_schedules (group_key, schedule) VALUES (?1, ?2)
                 ON CONFLICT(group_key) DO UPDATE SET schedule = excluded.schedule",
                [key, schedule],
            )?;
        }
        Ok(())
    }

    /// What the last scheduled run did
    pub fn record_container_backup_run(&self, key: &str, at: i64, outcome: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO container_backup_schedules (group_key, schedule, last_run, last_outcome)
             VALUES (?1, '', ?2, ?3)
             ON CONFLICT(group_key) DO UPDATE SET last_run = excluded.last_run,
                                                  last_outcome = excluded.last_outcome",
            rusqlite::params![key, at, outcome],
        )?;
        Ok(())
    }

    pub fn forget_container_backup_run(&self, key: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE container_backup_schedules SET last_run = 0, last_outcome = ''
             WHERE group_key = ?1",
            [key],
        )?;
        Ok(())
    }

    pub fn set_container_backup_plan(
        &self,
        key: &str,
        plan: Option<&pb::ContainerBackupPlan>,
    ) -> Result<()> {
        match plan {
            None => {
                self.conn.execute(
                    "DELETE FROM container_backup_plans WHERE group_key = ?1",
                    [key],
                )?;
            }
            Some(plan) => {
                let json = serde_json::to_string(plan)?;
                self.conn.execute(
                    "INSERT INTO container_backup_plans (group_key, plan_json) VALUES (?1, ?2)
                     ON CONFLICT(group_key) DO UPDATE SET plan_json = excluded.plan_json",
                    [key, &json],
                )?;
            }
        }
        Ok(())
    }

    /// Enroll, or re-enroll, one device
    pub fn pair(&self, public_key: &str, label: &str, device_uid: &str) -> Result<pb::Device> {
        let paired_at = now_millis();
        let expires_at = self.expiry_for(paired_at)?;
        let id = if device_uid.is_empty() {
            device_id(public_key)
        } else if let Some(existing) = self.device_id_for_uid(device_uid)? {
            existing
        } else if let Some(adoptable) = self.unclaimed_device_id_for_key(public_key)? {
            self.conn.execute(
                "UPDATE devices SET device_uid = ?1 WHERE id = ?2",
                rusqlite::params![device_uid, adoptable],
            )?;
            adoptable
        } else {
            device_id(device_uid)
        };
        self.conn.execute(
            "INSERT INTO devices (id, public_key, label, scopes, paired_at, device_uid, expires_at)
             VALUES (?1, ?2, ?3, 'read', ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET label = excluded.label,
                                           public_key = excluded.public_key,
                                           device_uid = excluded.device_uid,
                                           expires_at = excluded.expires_at",
            rusqlite::params![id, public_key, label, paired_at, device_uid, expires_at],
        )?;
        self.device(&id)
            .transpose()
            .expect("device exists right after upsert")
    }

    pub fn list_devices(&self) -> Result<Vec<pb::Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, public_key, label, scopes, paired_at, device_uid, expires_at, last_seen_at
             FROM devices ORDER BY paired_at",
        )?;
        let devices = stmt
            .query_map([], row_to_device)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(devices)
    }

    pub fn revoke(&self, device_id: &str) -> Result<bool> {
        let affected = self
            .conn
            .execute("DELETE FROM devices WHERE id = ?1", [device_id])?;
        Ok(affected > 0)
    }

    // ─────────────────────────── Session policy ───────────────────────────

    pub fn session_policy(&self) -> Result<pb::SessionPolicy> {
        let months = self
            .get_meta(AUTO_LOGOUT_KEY)?
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);
        let device_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?;
        Ok(pb::SessionPolicy {
            auto_logout_months: months,
            device_count: device_count as i32,
        })
    }

    pub fn set_session_policy(&self, months: i32) -> Result<pb::SessionPolicy> {
        if !ALLOWED_LOGOUT_MONTHS.contains(&months) {
            return Err(anyhow::anyhow!(
                "auto_logout_months must be one of {ALLOWED_LOGOUT_MONTHS:?}, got {months}"
            ));
        }
        self.set_meta(AUTO_LOGOUT_KEY, &months.to_string())?;
        if months == 0 {
            self.conn.execute("UPDATE devices SET expires_at = 0", [])?;
        } else {
            self.conn.execute(
                "UPDATE devices SET expires_at = paired_at + ?1",
                [months_in_millis(months)],
            )?;
        }
        self.session_policy()
    }

    pub fn device_session(&self, device_uid: &str) -> Result<DeviceSession> {
        if device_uid.is_empty() {
            return Ok(DeviceSession::Unidentified);
        }
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT id, expires_at FROM devices WHERE device_uid = ?1",
                [device_uid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        let Some((id, expires_at)) = row else {
            return Ok(DeviceSession::Unknown);
        };
        let now = now_millis();
        if expires_at != 0 && now >= expires_at {
            return Ok(DeviceSession::Expired);
        }
        self.conn.execute(
            "UPDATE devices SET last_seen_at = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )?;
        Ok(DeviceSession::Live)
    }

    /// Puts a device's window in the past
    #[cfg(test)]
    pub fn set_expiry_for_test(&self, device_uid: &str, expires_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE devices SET expires_at = ?1 WHERE device_uid = ?2",
            rusqlite::params![expires_at, device_uid],
        )?;
        Ok(())
    }

    fn expiry_for(&self, paired_at: i64) -> Result<i64> {
        let months = self.session_policy()?.auto_logout_months;
        Ok(if months == 0 {
            0
        } else {
            paired_at + months_in_millis(months)
        })
    }

    fn device_id_for_uid(&self, device_uid: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM devices WHERE device_uid = ?1",
                [device_uid],
                |row| row.get::<_, String>(0),
            )
            .ok())
    }

    fn unclaimed_device_id_for_key(&self, public_key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM devices WHERE public_key = ?1 AND device_uid = ''")?;
        let ids = stmt
            .query_map([public_key], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(if ids.len() == 1 { ids.into_iter().next() } else { None })
    }

    // ─────────────────────────── Vault ───────────────────────────

    pub fn vault_snapshot(&self) -> Result<pb::VaultSnapshot> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ciphertext, nonce, updated_at, updated_by, deleted FROM vault ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut entries = Vec::with_capacity(rows.len());
        for (id, ciphertext, nonce, updated_at, updated_by, deleted) in rows {
            let mut entry: pb::VaultEntry = if deleted != 0 {
                pb::VaultEntry::default()
            } else {
                match self.vault.unseal(&ciphertext, &nonce).map_err(anyhow::Error::from).and_then(|plain| {
                    serde_json::from_slice::<pb::VaultEntry>(&plain).map_err(anyhow::Error::from)
                }) {
                    Ok(entry) => entry,
                    Err(err) => {
                        eprintln!("vault: entry {id} cannot be opened and is left out: {err:#}");
                        continue;
                    }
                }
            };
            entry.id = id;
            entry.updated_at = updated_at;
            entry.updated_by = updated_by;
            entry.deleted = deleted != 0;
            entries.push(entry);
        }
        Ok(pb::VaultSnapshot {
            entries,
            revision: self.vault_revision()?,
        })
    }

    /// Upsert, LAST WRITE WINS PER ENTRY
    pub fn put_vault_entries(&self, entries: &[pb::VaultEntry]) -> Result<pb::VaultSnapshot> {
        self.in_transaction(|| self.put_vault_rows(entries))?;
        self.vault_snapshot()
    }

    fn in_transaction<T>(&self, work: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match work() {
            Ok(value) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    fn put_vault_rows(&self, entries: &[pb::VaultEntry]) -> Result<()> {
        for entry in entries {
            if entry.id.is_empty() {
                return Err(anyhow::anyhow!("a vault entry needs an id"));
            }
            let stored: Option<(i64, String)> = self
                .conn
                .query_row(
                    "SELECT updated_at, updated_by FROM vault WHERE id = ?1",
                    [&entry.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .ok();
            let updated_at = entry.updated_at;
            if let Some((stored_at, stored_by)) = &stored {
                let wins = entry.updated_at > *stored_at
                    || (entry.updated_at == *stored_at && entry.updated_by > *stored_by);
                if !wins {
                    continue;
                }
            }
            let mut to_seal = entry.clone();
            to_seal.updated_at = 0;
            to_seal.updated_by = String::new();
            to_seal.deleted = false;
            let (ciphertext, nonce) = self.vault.seal(&serde_json::to_vec(&to_seal)?)?;
            self.conn.execute(
                "INSERT INTO vault (id, ciphertext, nonce, updated_at, updated_by, deleted)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)
                 ON CONFLICT(id) DO UPDATE SET ciphertext = excluded.ciphertext,
                                               nonce = excluded.nonce,
                                               updated_at = excluded.updated_at,
                                               updated_by = excluded.updated_by,
                                               deleted = 0",
                rusqlite::params![entry.id, ciphertext, nonce, updated_at, entry.updated_by],
            )?;
        }
        self.bump_vault_revision()?;
        Ok(())
    }

    /// Tombstone
    pub fn delete_vault_entry(&self, id: &str, device_uid: &str, deleted_at: i64) -> Result<pb::VaultSnapshot> {
        let (ciphertext, nonce) = self.vault.seal(b"{}")?;
        let stamp = if deleted_at > 0 { deleted_at } else { now_millis() };
        self.in_transaction(|| {
            let newer_edit: Option<i64> = self
                .conn
                .query_row("SELECT updated_at FROM vault WHERE id = ?1 AND deleted = 0", [id], |row| row.get(0))
                .ok()
                .filter(|stored| *stored > stamp);
            if newer_edit.is_some() {
                return Ok(());
            }
            self.conn.execute(
                "INSERT INTO vault (id, ciphertext, nonce, updated_at, updated_by, deleted)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1)
                 ON CONFLICT(id) DO UPDATE SET ciphertext = excluded.ciphertext,
                                               nonce = excluded.nonce,
                                               updated_at = excluded.updated_at,
                                               updated_by = excluded.updated_by,
                                               deleted = 1",
                rusqlite::params![id, ciphertext, nonce, stamp, device_uid],
            )?;
            self.bump_vault_revision().map(|_| ())
        })?;
        self.vault_snapshot()
    }

    fn vault_revision(&self) -> Result<i64> {
        Ok(self
            .get_meta(VAULT_REVISION_KEY)?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0))
    }

    fn bump_vault_revision(&self) -> Result<i64> {
        let next = self.vault_revision()? + 1;
        self.set_meta(VAULT_REVISION_KEY, &next.to_string())?;
        Ok(next)
    }

    /// Issue a fresh one-time pairing code, valid for `ttl_secs`
    pub fn issue_pairing_code(&self, ttl_secs: i64) -> Result<String> {
        let code = generate_pairing_code()?;
        let expires = now_millis() + ttl_secs * 1000;
        self.set_meta("pairing_code", &code)?;
        self.set_meta("pairing_code_expires", &expires.to_string())?;
        Ok(code)
    }

    pub fn pairing_code_valid(&self, presented: &str) -> Result<bool> {
        let Some(stored) = self.get_meta("pairing_code")? else {
            return Ok(false);
        };
        let expires = self
            .get_meta("pairing_code_expires")?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        Ok(now_millis() < expires && ct_eq(&normalize_code(presented), &stored))
    }

    pub fn consume_pairing_code(&self, presented: &str) -> Result<bool> {
        let ok = self.pairing_code_valid(presented)?;
        if ok {
            self.conn.execute(
                "DELETE FROM meta WHERE key IN ('pairing_code', 'pairing_code_expires')",
                [],
            )?;
        }
        Ok(ok)
    }

    /// A named setting another module keeps here
    pub fn value(&self, key: &str) -> Result<Option<String>> {
        self.get_meta(key)
    }

    pub fn set_value(&self, key: &str, value: &str) -> Result<()> {
        self.set_meta(key, value)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get::<_, String>(0)
            })
            .ok())
    }

    pub fn device(&self, id: &str) -> Result<Option<pb::Device>> {
        let device = self
            .conn
            .query_row(
                "SELECT id, public_key, label, scopes, paired_at, device_uid, expires_at, last_seen_at
                 FROM devices WHERE id = ?1",
                [id],
                row_to_device,
            )
            .ok();
        Ok(device)
    }
}

fn row_to_device(row: &rusqlite::Row) -> rusqlite::Result<pb::Device> {
    let scopes: String = row.get(3)?;
    Ok(pb::Device {
        id: row.get(0)?,
        public_key: row.get(1)?,
        label: row.get(2)?,
        scopes: scopes.split(',').map(str::to_string).collect(),
        paired_at: row.get(4)?,
        device_uid: row.get(5)?,
        expires_at: row.get(6)?,
        last_seen_at: row.get(7)?,
    })
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DeviceSession {
    Unidentified,
    /// An id nobody paired under.
    Unknown,
    /// Paired, and its window has passed.
    Expired,
    /// Paired and current.
    Live,
}

const AUTO_LOGOUT_KEY: &str = "auto_logout_months";
const VAULT_REVISION_KEY: &str = "vault_revision";

/// The windows the screen offers
pub const ALLOWED_LOGOUT_MONTHS: [i32; 5] = [0, 1, 3, 6, 12];

fn months_in_millis(months: i32) -> i64 {
    let days = match months {
        12 => 365,
        m => i64::from(m) * 30,
    };
    days * 24 * 60 * 60 * 1000
}

fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    if !column_exists(conn, table, column)? {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), [])?;
    }
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let existing = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(existing.iter().any(|name| name == column))
}

const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile";

fn host_info() -> pb::Host {
    let (os_id, os_pretty_name) = std::fs::read_to_string("/etc/os-release")
        .map(|s| parse_os_release(&s))
        .unwrap_or_default();
    let served_hostnames = std::fs::read_to_string(CADDYFILE_PATH)
        .map(|text| crate::install::caddy::served_hostnames(&text))
        .unwrap_or_default();
    let domains = crate::install::caddy::domains(&served_hostnames);
    pb::Host {
        served_hostnames,
        domains,
        hostname: hostname(),
        os_id,
        os_pretty_name,
        arch: std::env::consts::ARCH.to_string(),
        topology: "single".to_string(),
    }
}

fn hostname() -> String {
    pick_hostname(
        std::fs::read_to_string("/proc/sys/kernel/hostname").ok().as_deref(),
        std::fs::read_to_string("/etc/hostname").ok().as_deref(),
    )
}

fn pick_hostname(kernel: Option<&str>, etc_hostname: Option<&str>) -> String {
    [kernel, etc_hostname]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|name| !name.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn parse_os_release(text: &str) -> (String, String) {
    let mut id = String::new();
    let mut pretty = String::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "ID" => id = value,
            "PRETTY_NAME" => pretty = value,
            _ => {}
        }
    }
    (id, pretty)
}

fn device_id(public_key: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in public_key.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("dev-{hash:016x}")
}

fn generate_pairing_code() -> Result<String> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut bytes = [0u8; 5];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut bits: u64 = 0;
    for b in bytes {
        bits = (bits << 8) | b as u64;
    }
    let code = (0..8)
        .map(|i| ALPHABET[((bits >> (35 - i * 5)) & 0x1f) as usize] as char)
        .collect();
    Ok(code)
}

fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(id: &str, status: pb::ServiceStatus) -> pb::Service {
        pb::Service {
            installed_outside: false,
            id: id.to_string(),
            display_name: id.to_string(),
            status: status as i32,
            version: "1.0".to_string(),
            containers: Vec::new(),
        }
    }

    #[test]
    fn a_service_this_agent_installed_is_in_the_state_without_a_discovery() {
        let store = Store::in_memory().unwrap();
        store
            .record_discovery(&[service("adguard", pb::ServiceStatus::Running)])
            .unwrap();

        store
            .record_action("minecraft", Some(&service("minecraft", pb::ServiceStatus::Running)))
            .unwrap();

        let ids: Vec<String> = store.snapshot().unwrap().services.iter().map(|s| s.id.clone()).collect();
        assert!(ids.contains(&"minecraft".to_string()), "the install never reached the state");
        assert!(ids.contains(&"adguard".to_string()), "recording one service pruned another");
    }

    #[test]
    fn a_service_this_agent_removed_leaves_the_state() {
        let store = Store::in_memory().unwrap();
        store
            .record_discovery(&[
                service("adguard", pb::ServiceStatus::Running),
                service("minecraft", pb::ServiceStatus::Running),
            ])
            .unwrap();

        store.record_action("minecraft", None).unwrap();

        let ids: Vec<String> = store.snapshot().unwrap().services.iter().map(|s| s.id.clone()).collect();
        assert_eq!(ids, vec!["adguard".to_string()],
                   "the removed service is still offered, or its neighbour went with it");
    }

    #[test]
    fn recording_one_service_does_not_claim_the_host_was_rescanned() {
        let store = Store::in_memory().unwrap();
        store.record_discovery(&[service("adguard", pb::ServiceStatus::Running)]).unwrap();
        let scanned = store.snapshot().unwrap().discovered_at;
        assert!(scanned > 0, "the discovery stamp was never written");

        while now_millis() == scanned {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        store
            .record_action("minecraft", Some(&service("minecraft", pb::ServiceStatus::Running)))
            .unwrap();

        assert_eq!(store.snapshot().unwrap().discovered_at, scanned,
                   "an install claimed the host had been rescanned");
    }

    #[test]
    fn recording_the_same_service_twice_updates_it_rather_than_doubling_it() {
        let store = Store::in_memory().unwrap();
        store
            .record_action("adguard", Some(&service("adguard", pb::ServiceStatus::Running)))
            .unwrap();
        store
            .record_action("adguard", Some(&service("adguard", pb::ServiceStatus::Stopped)))
            .unwrap();

        let services = store.snapshot().unwrap().services;
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].status, pb::ServiceStatus::Stopped as i32);
    }

    #[test]
    fn removing_a_group_forgets_its_last_run_but_keeps_its_schedule() {
        let store = Store::in_memory().unwrap();
        store.set_container_backup_schedule("shopdemo", "daily").unwrap();
        store.record_container_backup_run("shopdemo", 1_787_693_544, "ok /opt/backups/x.tar.gz").unwrap();

        let before = store.container_backup_schedule("shopdemo").unwrap().unwrap();
        assert_eq!(before.last_run, "1787693544");
        assert!(before.enabled);

        store.forget_container_backup_run("shopdemo").unwrap();

        let after = store.container_backup_schedule("shopdemo").unwrap().unwrap();
        assert_eq!(after.last_run, "", "the group still claims a run that was deleted with it");
        assert_eq!(after.last_outcome, "");
        assert_eq!(after.schedule, "daily", "the owner's schedule was thrown away too");
        assert!(after.enabled);

        store.forget_container_backup_run("never-seen").unwrap();
        assert!(store.container_backup_schedule("never-seen").unwrap().is_none());
    }

    #[test]
    fn snapshot_reports_persisted_services() {
        let store = Store::in_memory().unwrap();
        store
            .put_service(&pb::Service {
                installed_outside: false,
                id: "mailcow".into(),
                display_name: "Mailcow".into(),
                status: pb::ServiceStatus::Running as i32,
                version: "2024-11".into(),
                containers: Vec::new(),
            })
            .unwrap();

        let state = store.snapshot().unwrap();
        assert_eq!(state.services.len(), 1);
        assert_eq!(state.services[0].id, "mailcow");
        assert_eq!(state.services[0].status, pb::ServiceStatus::Running as i32);
        assert!(state.host.is_some());
    }

    #[test]
    fn a_discovery_pass_removes_services_that_are_no_longer_there() {
        let store = Store::in_memory().unwrap();
        let svc = |id: &str, status: pb::ServiceStatus| pb::Service {
            installed_outside: false,
            id: id.into(),
            display_name: id.into(),
            status: status as i32,
            version: "1".into(),
            containers: Vec::new(),
        };
        store
            .record_discovery(&[
                svc("vaultwarden", pb::ServiceStatus::Running),
                svc("forgejo", pb::ServiceStatus::Running),
            ])
            .unwrap();
        assert_eq!(store.snapshot().unwrap().services.len(), 2);

        store
            .record_discovery(&[svc("vaultwarden", pb::ServiceStatus::Stopped)])
            .unwrap();
        let state = store.snapshot().unwrap();
        assert_eq!(
            state.services.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["vaultwarden"]
        );
        assert_eq!(state.services[0].status, pb::ServiceStatus::Stopped as i32);

        store.record_discovery(&[]).unwrap();
        assert!(store.snapshot().unwrap().services.is_empty());
    }

    #[test]
    fn a_single_service_write_never_prunes_the_others() {
        let store = Store::in_memory().unwrap();
        let svc = |id: &str| pb::Service {
            installed_outside: false,
            id: id.into(),
            display_name: id.into(),
            status: pb::ServiceStatus::Running as i32,
            version: String::new(),
            containers: Vec::new(),
        };
        store.record_discovery(&[svc("vaultwarden"), svc("vpn")]).unwrap();
        store.put_service(&svc("vpn")).unwrap();
        assert_eq!(store.snapshot().unwrap().services.len(), 2);
    }

    #[test]
    fn pairing_is_idempotent_and_revocable() {
        let store = Store::in_memory().unwrap();
        let first = store.pair("ssh-ed25519 AAAA...", "iPhone", "").unwrap();
        let again = store.pair("ssh-ed25519 AAAA...", "iPhone (renamed)", "").unwrap();
        // Same key → same device row, not a duplicate.
        assert_eq!(first.id, again.id);
        assert_eq!(store.list_devices().unwrap().len(), 1);
        assert_eq!(again.label, "iPhone (renamed)");
        assert_eq!(again.scopes, vec!["read".to_string()]);

        assert!(store.revoke(&first.id).unwrap());
        assert!(store.list_devices().unwrap().is_empty());
        assert!(!store.revoke(&first.id).unwrap());
    }

    #[test]
    fn pairing_code_is_single_use_and_normalized() {
        let store = Store::in_memory().unwrap();
        let code = store.issue_pairing_code(600).unwrap();
        assert_eq!(code.len(), 8);
        assert!(!store.consume_pairing_code("WRONGONE").unwrap());
        let typed = format!("{}-{}", &code[..4], &code[4..].to_lowercase());
        assert!(store.consume_pairing_code(&typed).unwrap());
        // Consumed: it can't be reused.
        assert!(!store.consume_pairing_code(&code).unwrap());
    }

    #[test]
    fn expired_pairing_code_is_rejected() {
        let store = Store::in_memory().unwrap();
        let code = store.issue_pairing_code(-1).unwrap(); // already expired
        assert!(!store.consume_pairing_code(&code).unwrap());
    }

    #[test]
    fn consume_with_no_active_code_is_false() {
        let store = Store::in_memory().unwrap();
        assert!(!store.consume_pairing_code("ANYTHING").unwrap());
    }

    #[test]
    fn parses_os_release_id_and_pretty_name() {
        let text = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
HOME_URL="https://www.debian.org/"
"#;
        let (id, pretty) = parse_os_release(text);
        assert_eq!(id, "debian");
        assert_eq!(pretty, "Debian GNU/Linux 12 (bookworm)");
    }

    #[test]
    fn os_release_missing_fields_are_empty_not_fatal() {
        let (id, pretty) = parse_os_release("NAME=\"Something\"\n# comment\n");
        assert!(id.is_empty());
        assert!(pretty.is_empty());
    }

    #[test]
    fn an_empty_etc_hostname_does_not_make_the_host_nameless() {
        assert_eq!(pick_hostname(Some("my-vps\n"), Some("")), "my-vps");
        assert_eq!(pick_hostname(Some("my-vps\n"), None), "my-vps");
        assert_eq!(pick_hostname(None, Some("from-file\n")), "from-file");
        assert_eq!(pick_hostname(Some("   \n"), Some("from-file")), "from-file");
        // Neither source knows: honestly empty, never a placeholder.
        assert_eq!(pick_hostname(None, None), "");
        assert_eq!(pick_hostname(Some(""), Some("  ")), "");
    }

    // ───────────────── devices, sessions and the vault ─────────────────

    fn entry(id: &str, password: &str, at: i64) -> pb::VaultEntry {
        pb::VaultEntry {
            id: id.to_string(),
            host: "single".into(),
            title: "Vaultwarden".into(),
            website: "https://vault.example.com".into(),
            login: "admin@example.com".into(),
            password: password.to_string(),
            token: String::new(),
            updated_at: at,
            updated_by: "phone-a".into(),
            deleted: false,
            service_secret: String::new(),
        }
    }

    #[test]
    fn a_device_that_says_which_installation_it_is_keeps_one_row_across_re_pairings() {
        let store = Store::in_memory().unwrap();
        let first = store.pair("ssh-ed25519 AAAA", "iPhone", "uid-a").unwrap();
        let again = store.pair("ssh-ed25519 AAAA", "Morgan's iPhone", "uid-a").unwrap();
        assert_eq!(first.id, again.id);
        assert_eq!(again.label, "Morgan's iPhone");
        assert_eq!(store.list_devices().unwrap().len(), 1);
    }

    #[test]
    fn two_installations_sharing_one_deployment_key_are_two_rows() {
        let store = Store::in_memory().unwrap();
        store.pair("ssh-ed25519 AAAA", "iPhone", "uid-a").unwrap();
        store.pair("ssh-ed25519 AAAA", "iPad", "uid-b").unwrap();
        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 2, "the second phone did not get its own row");
        assert!(devices.iter().any(|d| d.device_uid == "uid-a"));
        assert!(devices.iter().any(|d| d.device_uid == "uid-b"));
    }

    #[test]
    fn an_old_row_is_adopted_by_the_first_installation_that_names_itself() {
        let store = Store::in_memory().unwrap();
        let old = store.pair("ssh-ed25519 AAAA", "iPhone", "").unwrap();
        assert_eq!(old.device_uid, "");
        let adopted = store.pair("ssh-ed25519 AAAA", "iPhone", "uid-a").unwrap();
        assert_eq!(adopted.id, old.id, "the old row was left behind");
        assert_eq!(adopted.device_uid, "uid-a");
        assert_eq!(store.list_devices().unwrap().len(), 1);
    }

    /// …but only when there is exactly one candidate
    #[test]
    fn an_ambiguous_old_row_is_never_adopted() {
        let store = Store::in_memory().unwrap();
        store.pair("ssh-ed25519 AAAA", "iPhone", "").unwrap();
        store
            .conn
            .execute(
                "INSERT INTO devices (id, public_key, label, scopes, paired_at)
                 VALUES ('other', 'ssh-ed25519 AAAA', 'iPad', 'read', 1)",
                [],
            )
            .unwrap();
        store.pair("ssh-ed25519 AAAA", "iPhone", "uid-a").unwrap();
        assert_eq!(store.list_devices().unwrap().len(), 3, "a row was adopted on a guess");
    }

    #[test]
    fn the_default_policy_is_never_and_dates_nothing() {
        let store = Store::in_memory().unwrap();
        assert_eq!(store.session_policy().unwrap().auto_logout_months, 0);
        let device = store.pair("k", "iPhone", "uid-a").unwrap();
        assert_eq!(device.expires_at, 0, "a fresh install started signing devices out");
    }

    #[test]
    fn setting_a_window_re_dates_the_devices_that_are_already_here() {
        let store = Store::in_memory().unwrap();
        let device = store.pair("k", "iPhone", "uid-a").unwrap();
        let policy = store.set_session_policy(3).unwrap();
        assert_eq!(policy.auto_logout_months, 3);
        assert_eq!(policy.device_count, 1);
        let listed = &store.list_devices().unwrap()[0];
        assert_eq!(listed.expires_at, device.paired_at + 90 * 24 * 60 * 60 * 1000);
        store.set_session_policy(0).unwrap();
        assert_eq!(store.list_devices().unwrap()[0].expires_at, 0);
    }

    #[test]
    fn an_unoffered_window_is_refused_rather_than_rounded() {
        let store = Store::in_memory().unwrap();
        assert!(store.set_session_policy(2).is_err());
        assert!(store.set_session_policy(-1).is_err());
        assert_eq!(store.session_policy().unwrap().auto_logout_months, 0);
    }

    #[test]
    fn the_session_of_a_device_is_live_unknown_unidentified_or_expired() {
        let store = Store::in_memory().unwrap();
        store.pair("k", "iPhone", "uid-a").unwrap();
        assert_eq!(store.device_session("uid-a").unwrap(), DeviceSession::Live);
        assert_eq!(store.device_session("uid-b").unwrap(), DeviceSession::Unknown);
        assert_eq!(store.device_session("").unwrap(), DeviceSession::Unidentified);

        store
            .conn
            .execute("UPDATE devices SET expires_at = 1 WHERE device_uid = 'uid-a'", [])
            .unwrap();
        assert_eq!(store.device_session("uid-a").unwrap(), DeviceSession::Expired);
    }

    #[test]
    fn a_live_call_records_that_the_device_was_seen() {
        let store = Store::in_memory().unwrap();
        store.pair("k", "iPhone", "uid-a").unwrap();
        assert_eq!(store.list_devices().unwrap()[0].last_seen_at, 0);
        store.device_session("uid-a").unwrap();
        assert!(store.list_devices().unwrap()[0].last_seen_at > 0);
    }

    #[test]
    fn an_expired_device_is_not_recorded_as_seen() {
        let store = Store::in_memory().unwrap();
        store.pair("k", "iPhone", "uid-a").unwrap();
        store
            .conn
            .execute("UPDATE devices SET expires_at = 1 WHERE device_uid = 'uid-a'", [])
            .unwrap();
        store.device_session("uid-a").unwrap();
        assert_eq!(store.list_devices().unwrap()[0].last_seen_at, 0);
    }

    #[test]
    fn the_vault_starts_empty_and_at_revision_zero() {
        let store = Store::in_memory().unwrap();
        let snapshot = store.vault_snapshot().unwrap();
        assert!(snapshot.entries.is_empty());
        assert_eq!(snapshot.revision, 0);
    }

    #[test]
    fn an_entry_comes_back_whole_and_the_revision_moves() {
        let store = Store::in_memory().unwrap();
        let snapshot = store.put_vault_entries(&[entry("single|Vaultwarden", "hunter2", 100)]).unwrap();
        assert_eq!(snapshot.revision, 1);
        let stored = &snapshot.entries[0];
        assert_eq!(stored.password, "hunter2");
        assert_eq!(stored.login, "admin@example.com");
        assert_eq!(stored.updated_at, 100);
        assert_eq!(stored.updated_by, "phone-a");
        assert!(!stored.deleted);
    }

    #[test]
    fn the_row_on_disk_does_not_contain_the_password() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("single|Vaultwarden", "correct-horse", 100)]).unwrap();
        let blob: Vec<u8> = store
            .conn
            .query_row("SELECT ciphertext FROM vault", [], |row| row.get(0))
            .unwrap();
        assert!(
            !blob.windows(13).any(|w| w == b"correct-horse"),
            "the vault row carries the password in the clear"
        );
        assert!(!blob.windows(5).any(|w| w == b"admin"));
    }

    #[test]
    fn one_unreadable_row_does_not_take_the_vault_down() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("good", "keep-me", 100), entry("bad", "lost", 100)]).unwrap();
        store
            .conn
            .execute("UPDATE vault SET ciphertext = x'0102030405' WHERE id = 'bad'", [])
            .unwrap();
        let snapshot = store.vault_snapshot().unwrap();
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].password, "keep-me");
    }

    #[test]
    fn a_write_that_fails_midway_leaves_nothing_behind() {
        let store = Store::in_memory().unwrap();
        let failing = [entry("first", "written", 100), entry("", "no id", 100)];
        assert!(store.put_vault_entries(&failing).is_err());
        let snapshot = store.vault_snapshot().unwrap();
        assert!(snapshot.entries.is_empty());
        assert_eq!(snapshot.revision, 0);
    }

    #[test]
    fn the_later_edit_wins_whichever_device_calls_last() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("id", "newer", 200)]).unwrap();
        let snapshot = store.put_vault_entries(&[entry("id", "older", 100)]).unwrap();
        assert_eq!(snapshot.entries[0].password, "newer");
        let snapshot = store.put_vault_entries(&[entry("id", "newest", 300)]).unwrap();
        assert_eq!(snapshot.entries[0].password, "newest");
    }

    #[test]
    fn an_entry_with_no_timestamp_never_beats_one_that_has_a_time() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("id", "typed-by-hand", 100)]).unwrap();
        let snapshot = store.put_vault_entries(&[entry("id", "from-the-report", 0)]).unwrap();
        assert_eq!(snapshot.entries[0].password, "typed-by-hand");
        assert_eq!(snapshot.entries[0].updated_at, 100);
    }

    #[test]
    fn an_entry_with_no_timestamp_is_stored_without_one() {
        let store = Store::in_memory().unwrap();
        let snapshot = store.put_vault_entries(&[entry("id", "from-the-report", 0)]).unwrap();
        assert_eq!(snapshot.entries[0].updated_at, 0);
    }

    #[test]
    fn re_pushing_an_untimed_entry_does_not_resurrect_a_deleted_one() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("id", "from-the-report", 0)]).unwrap();
        store.delete_vault_entry("id", "phone-b", 0).unwrap();
        let snapshot = store.put_vault_entries(&[entry("id", "from-the-report", 0)]).unwrap();
        assert!(
            snapshot.entries[0].deleted,
            "a re-pushed report value undid somebody's deletion"
        );
    }

    #[test]
    fn a_delete_older_than_the_latest_edit_leaves_the_entry_alone() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("id", "edited-later", 200)]).unwrap();
        let snapshot = store.delete_vault_entry("id", "phone-b", 100).unwrap();
        assert!(!snapshot.entries[0].deleted, "an older delete wiped a newer edit");
        let snapshot = store.delete_vault_entry("id", "phone-b", 300).unwrap();
        assert!(snapshot.entries[0].deleted);
        assert_eq!(snapshot.entries[0].updated_at, 300);
    }

    #[test]
    fn an_equal_timestamp_is_broken_by_the_device_id_not_by_arrival_order() {
        let store = Store::in_memory().unwrap();
        let mut from_a = entry("id", "from-a", 100);
        from_a.updated_by = "phone-a".into();
        let mut from_b = entry("id", "from-b", 100);
        from_b.updated_by = "phone-b".into();

        // b after a: b's id is higher, so b wins.
        let store_ab = Store::in_memory().unwrap();
        store_ab.put_vault_entries(&[from_a.clone()]).unwrap();
        let snapshot = store_ab.put_vault_entries(&[from_b.clone()]).unwrap();
        assert_eq!(snapshot.entries[0].password, "from-b");

        store.put_vault_entries(&[from_b]).unwrap();
        let snapshot = store.put_vault_entries(&[from_a]).unwrap();
        assert_eq!(
            snapshot.entries[0].password, "from-b",
            "the answer changed with the order the two phones reconnected in"
        );
    }

    #[test]
    fn a_delete_leaves_a_tombstone_that_carries_no_secret() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("id", "hunter2", 100)]).unwrap();
        let snapshot = store.delete_vault_entry("id", "phone-b", 0).unwrap();
        let stored = &snapshot.entries[0];
        assert!(stored.deleted);
        assert_eq!(stored.password, "", "a deleted entry still holds its password");
        assert_eq!(stored.updated_by, "phone-b");
        let blob: Vec<u8> = store
            .conn
            .query_row("SELECT ciphertext FROM vault", [], |row| row.get(0))
            .unwrap();
        assert!(!blob.windows(7).any(|w| w == b"hunter2"), "the deleted row is still on disk");
    }

    #[test]
    fn an_older_copy_does_not_resurrect_a_deleted_entry() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("id", "hunter2", 100)]).unwrap();
        store.delete_vault_entry("id", "phone-b", 0).unwrap();
        let snapshot = store.put_vault_entries(&[entry("id", "hunter2", 100)]).unwrap();
        assert!(snapshot.entries[0].deleted, "an old copy brought the entry back");
    }

    #[test]
    fn a_newer_edit_revives_a_deleted_entry() {
        let store = Store::in_memory().unwrap();
        store.put_vault_entries(&[entry("id", "hunter2", 100)]).unwrap();
        store.delete_vault_entry("id", "phone-b", 0).unwrap();
        let snapshot = store.put_vault_entries(&[entry("id", "fresh", now_millis() + 1000)]).unwrap();
        assert!(!snapshot.entries[0].deleted);
        assert_eq!(snapshot.entries[0].password, "fresh");
    }

    #[test]
    fn an_entry_without_an_id_is_refused() {
        let store = Store::in_memory().unwrap();
        assert!(store.put_vault_entries(&[entry("", "hunter2", 100)]).is_err());
    }

    #[test]
    fn a_database_from_an_older_agent_gains_the_new_columns_and_keeps_its_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE devices (
                 id          TEXT PRIMARY KEY,
                 public_key  TEXT NOT NULL,
                 label       TEXT NOT NULL DEFAULT '',
                 scopes      TEXT NOT NULL DEFAULT 'read',
                 paired_at   INTEGER NOT NULL
             );
             INSERT INTO devices (id, public_key, label, scopes, paired_at)
             VALUES ('old', 'ssh-ed25519 AAAA', 'iPhone', 'read', 42);",
        )
        .unwrap();
        let store = Store::from_conn(conn, crate::vault::VaultCipher::ephemeral().unwrap()).unwrap();
        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1, "the migration lost the rows it was migrating");
        assert_eq!(devices[0].label, "iPhone");
        assert_eq!(devices[0].paired_at, 42);
        assert_eq!(devices[0].device_uid, "");
        assert_eq!(devices[0].expires_at, 0);
    }

    #[test]
    fn a_scanned_service_reads_as_a_stranger_and_an_installed_one_does_not() {
        let store = Store::from_conn(
            Connection::open_in_memory().unwrap(),
            crate::vault::VaultCipher::ephemeral().unwrap(),
        )
        .unwrap();
        let found = pb::Service {
            id: "ollama".to_string(),
            display_name: "Ollama".to_string(),
            status: 0,
            version: String::new(),
            containers: Vec::new(),
            installed_outside: false,
        };
        store.put_service(&found).unwrap();
        let scanned = store.snapshot().unwrap();
        assert!(
            scanned.services.iter().any(|s| s.id == "ollama" && s.installed_outside),
            "a service nobody recorded installing must read as a stranger"
        );

        // What an install does.
        store.record_action("ollama", Some(&found)).unwrap();
        let ours = store.snapshot().unwrap();
        assert!(
            ours.services.iter().any(|s| s.id == "ollama" && !s.installed_outside),
            "a service this agent installed must stop reading as a stranger"
        );

        store.put_service(&found).unwrap();
        let rescanned = store.snapshot().unwrap();
        assert!(
            rescanned.services.iter().any(|s| s.id == "ollama" && !s.installed_outside),
            "a scan must not unlearn who installed a service"
        );
    }

    #[test]
    fn services_from_an_older_agent_are_not_called_strangers() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE services (
                 id           TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL,
                 status       INTEGER NOT NULL,
                 version      TEXT NOT NULL DEFAULT ''
             );
             INSERT INTO services (id, display_name, status, version)
             VALUES ('vaultwarden', 'Vaultwarden', 1, '1.32.0');",
        )
        .unwrap();
        let store = Store::from_conn(conn, crate::vault::VaultCipher::ephemeral().unwrap()).unwrap();
        let state = store.snapshot().unwrap();
        let service = state.services.iter().find(|s| s.id == "vaultwarden").expect("kept");
        assert!(!service.installed_outside, "the migration cried wolf on a service we manage");
        assert_eq!(service.version, "1.32.0", "the migration lost the row it was migrating");
    }
}
