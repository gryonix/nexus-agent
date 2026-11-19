//! Authelia sign-in accounts in its file backend

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::authelia::CONTAINER;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "authelia";
const USERS_FILE: &str = "/config/users_database.yml";
const ADMIN_GROUP: &str = "admins";
const ROLE_USER: &str = "user";
const BCRYPT_COST: u32 = 12;
const BCRYPT_LIMIT: usize = 72;

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_enabled: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        needs_email: true,
        ..Default::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    pub login: String,
    pub disabled: bool,
    pub display_name: String,
    pub password: String,
    pub email: String,
    pub groups: Vec<String>,
    pub extra: Vec<String>,
}

impl Entry {
    pub fn is_admin(&self) -> bool {
        self.groups.iter().any(|group| group == ADMIN_GROUP)
    }
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if let Some(inner) = value.strip_prefix('\'').and_then(|rest| rest.strip_suffix('\'')) {
        return inner.replace("''", "'");
    }
    if let Some(inner) = value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        return inner.replace("\\\"", "\"").replace("\\\\", "\\");
    }
    value.to_string()
}

fn single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn inline_groups(value: &str) -> Vec<String> {
    let inner = value.trim().trim_start_matches('[').trim_end_matches(']');
    inner.split(',').map(unquote).filter(|group| !group.is_empty()).collect()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The accounts of a users_database.yml in the layout Authelia documents
pub fn parse(text: &str) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut in_users = false;
    let mut in_groups = false;
    for line in text.lines().filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#')) {
        let indent = indent_of(line);
        let body = line.trim();
        if indent == 0 {
            in_users = body == "users:";
            continue;
        }
        if !in_users {
            continue;
        }
        if indent == 2 && body.ends_with(':') {
            entries.push(Entry { login: unquote(body.trim_end_matches(':')), ..Default::default() });
            in_groups = false;
        } else if indent >= 6 && in_groups {
            if let (Some(entry), Some(group)) = (entries.last_mut(), body.strip_prefix("- ")) {
                entry.groups.push(unquote(group));
            }
        } else if let (Some(entry), Some((key, value))) = (entries.last_mut(), body.split_once(':')) {
            in_groups = false;
            match key {
                "disabled" => entry.disabled = value.trim() == "true",
                "displayname" => entry.display_name = unquote(value),
                "password" => entry.password = unquote(value),
                "email" => entry.email = unquote(value),
                "groups" if value.trim().is_empty() => in_groups = true,
                "groups" => entry.groups = inline_groups(value),
                _ => entry.extra.push(line.to_string()),
            }
        }
    }
    entries
}

fn key_text(login: &str) -> String {
    if login.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) { login.to_string() } else { single_quoted(login) }
}

/// The file text for the accounts
pub fn render(entries: &[Entry]) -> String {
    let mut out = String::from("---\nusers:\n");
    for entry in entries {
        out.push_str(&format!("  {}:\n", key_text(&entry.login)));
        out.push_str(&format!("    disabled: {}\n", entry.disabled));
        out.push_str(&format!("    displayname: {}\n", single_quoted(&entry.display_name)));
        out.push_str(&format!("    password: {}\n", single_quoted(&entry.password)));
        out.push_str(&format!("    email: {}\n", single_quoted(&entry.email)));
        if entry.groups.is_empty() {
            out.push_str("    groups: []\n");
        } else {
            out.push_str("    groups:\n");
            for group in &entry.groups {
                out.push_str(&format!("      - {}\n", single_quoted(group)));
            }
        }
        for extra in &entry.extra {
            out.push_str(extra);
            out.push('\n');
        }
    }
    out
}

pub fn to_users(entries: &[Entry]) -> Vec<pb::ServiceUser> {
    let first_admin = entries.iter().position(Entry::is_admin);
    let mut users: Vec<pb::ServiceUser> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| pb::ServiceUser {
            id: entry.login.clone(),
            login: entry.login.clone(),
            display_name: entry.display_name.clone(),
            email: entry.email.clone(),
            role: if entry.is_admin() { ADMIN_ROLE } else { ROLE_USER }.to_string(),
            enabled: !entry.disabled,
            is_self: first_admin == Some(index),
            ..Default::default()
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    users
}

pub fn hash_password(password: &str) -> Result<String, Refusal> {
    if password.len() > BCRYPT_LIMIT {
        return Err(Refusal::InvalidPassword);
    }
    bcrypt::hash(password, BCRYPT_COST).map_err(|_| Refusal::Failed)
}

fn find_mut<'a>(entries: &'a mut [Entry], login: &str) -> Result<&'a mut Entry, Refusal> {
    entries.iter_mut().find(|entry| entry.login == login).ok_or(Refusal::UnknownUser)
}

pub fn add(entries: &mut Vec<Entry>, new: &NewUser, hash: String) -> Done {
    if entries.iter().any(|entry| entry.login.eq_ignore_ascii_case(&new.login)) {
        return Err(Refusal::InvalidLogin);
    }
    let name = if new.display_name.is_empty() { new.login.clone() } else { new.display_name.clone() };
    let groups = if new.role == ADMIN_ROLE { vec![ADMIN_GROUP.to_string()] } else { Vec::new() };
    entries.push(Entry { login: new.login.clone(), display_name: name, password: hash, email: new.email.clone(), groups, ..Default::default() });
    Ok(())
}

pub fn set_admin(entries: &mut [Entry], login: &str, admin: bool) -> Done {
    let entry = find_mut(entries, login)?;
    entry.groups.retain(|group| group != ADMIN_GROUP);
    if admin {
        entry.groups.push(ADMIN_GROUP.to_string());
    }
    Ok(())
}

pub fn remove(entries: &mut Vec<Entry>, login: &str) -> Done {
    find_mut(entries, login)?;
    entries.retain(|entry| entry.login != login);
    Ok(())
}

pub fn read_call() -> Call {
    Call::new(&["exec", CONTAINER, "cat", USERS_FILE])
}

pub fn write_call(text: String) -> Call {
    let script = format!("cat > {USERS_FILE}.new && chmod 600 {USERS_FILE}.new && mv {USERS_FILE}.new {USERS_FILE}");
    Call::new(&["exec", "-i", CONTAINER, "sh", "-c", &script]).with_stdin(text)
}

pub fn restart_call() -> Call {
    Call::new(&["restart", CONTAINER])
}

pub struct Authelia;

impl Authelia {
    pub async fn find() -> Result<Option<Authelia>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        Ok((!containers.is_empty()).then_some(Authelia))
    }

    async fn load(&self) -> Result<Vec<Entry>, Refusal> {
        Ok(parse(&docker::run(&read_call()).await?))
    }

    async fn save(&self, entries: &[Entry]) -> Done {
        docker::run(&write_call(render(entries))).await?;
        docker::run(&restart_call()).await.map(|_| ())
    }

    async fn edit(&self, change: impl FnOnce(&mut Vec<Entry>) -> Done) -> Done {
        let mut entries = self.load().await?;
        change(&mut entries)?;
        self.save(&entries).await
    }
}

impl UserBackend for Authelia {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        Ok(to_users(&self.load().await?))
    }

    async fn create(&self, new: &NewUser) -> Done {
        let password = new.password.clone();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password)).await.map_err(|_| Refusal::Failed)??;
        self.edit(|entries| add(entries, new, hash)).await
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.edit(|entries| remove(entries, user_id)).await
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        let password = password.to_string();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password)).await.map_err(|_| Refusal::Failed)??;
        self.edit(|entries| {
            find_mut(entries, user_id)?.password = hash;
            Ok(())
        })
        .await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.edit(|entries| set_admin(entries, user_id, role == ADMIN_ROLE)).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.edit(|entries| {
            find_mut(entries, user_id)?.disabled = !enabled;
            Ok(())
        })
        .await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = include_str!("../../tests/fixtures/service_users/authelia/users_database.yml");

    fn new_user() -> NewUser {
        NewUser {
            login: "clara".into(),
            display_name: String::new(),
            email: "clara@example.org".into(),
            password: "s3cr3t-pass-word".into(),
            role: "admin".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_installers_file_parses() {
        let entries = parse(FILE);
        let logins: Vec<&str> = entries.iter().map(|e| e.login.as_str()).collect();
        assert_eq!(logins, ["operator", "anna", "boris"]);
        assert_eq!(entries[0].groups, ["admins"]);
        assert_eq!(entries[1].display_name, "Anna \"A\" Example");
        assert_eq!(entries[1].email, "anna@example.org");
        assert!(entries[1].groups.is_empty());
        assert_eq!(entries[2].groups, ["family", "admins"]);
        assert!(entries[2].disabled);
        assert_eq!(entries[2].extra, ["    given_name: 'Boris'"]);
    }

    #[test]
    fn the_first_admin_is_the_app_sign_in() {
        let users = to_users(&parse(FILE));
        let marks: Vec<(&str, bool, &str)> = users.iter().map(|u| (u.login.as_str(), u.is_self, u.role.as_str())).collect();
        assert_eq!(marks, [("anna", false, "user"), ("boris", false, "admin"), ("operator", true, "admin")]);
        assert!(!users[1].enabled);
    }

    #[test]
    fn writing_and_reading_again_keeps_every_account() {
        let entries = parse(FILE);
        let text = render(&entries);
        assert_eq!(parse(&text), entries);
        assert!(text.starts_with("---\nusers:\n  operator:\n    disabled: false\n"));
    }

    #[test]
    fn changes_touch_only_the_asked_account() {
        let mut entries = parse(FILE);
        add(&mut entries, &new_user(), "$2b$12$hash".into()).unwrap();
        assert_eq!(entries.last().unwrap().groups, ["admins"]);
        assert_eq!(entries.last().unwrap().display_name, "clara");
        assert_eq!(add(&mut entries, &new_user(), String::new()), Err(Refusal::InvalidLogin));
        set_admin(&mut entries, "boris", false).unwrap();
        assert_eq!(entries[2].groups, ["family"]);
        remove(&mut entries, "anna").unwrap();
        assert_eq!(remove(&mut entries, "anna"), Err(Refusal::UnknownUser));
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn passwords_become_bcrypt_hashes_and_long_ones_are_refused() {
        let hash = hash_password("s3cr3t-pass-word").unwrap();
        assert!(hash.starts_with("$2b$12$"), "{hash}");
        assert!(bcrypt::verify("s3cr3t-pass-word", &hash).unwrap());
        assert_eq!(hash_password(&"x".repeat(73)), Err(Refusal::InvalidPassword));
    }

    #[test]
    fn the_file_travels_on_stdin_and_stays_private() {
        let call = write_call(render(&parse(FILE)));
        assert!(call.args.iter().all(|arg| !arg.contains("$2b$")));
        assert!(call.stdin.as_deref().is_some_and(|text| text.contains("$2b$12$")));
        let script = call.args.last().unwrap();
        assert!(script.contains("chmod 600") && script.contains("mv /config/users_database.yml.new /config/users_database.yml"));
        assert_eq!(restart_call().args, ["restart", "authelia"]);
    }

    #[test]
    fn quotes_in_values_are_doubled() {
        assert_eq!(single_quoted("O'Neil"), "'O''Neil'");
        assert_eq!(unquote("'O''Neil'"), "O'Neil");
    }
}
