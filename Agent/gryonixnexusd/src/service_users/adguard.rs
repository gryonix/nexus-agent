//! AdGuard Home web sign-ins in the users list of its configuration file

use std::path::PathBuf;

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend};
use crate::install::adguard::CONTAINER;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "adguard-home";
const CONFIG_FILE: &str = "conf/AdGuardHome.yaml";
const BCRYPT_COST: u32 = 10;
const BCRYPT_LIMIT: usize = 72;

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        ..Default::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub hash: String,
}

fn value_of(line: &str, key: &str) -> Option<String> {
    let rest = line.trim().trim_start_matches("- ").strip_prefix(key)?.strip_prefix(':')?;
    Some(rest.trim().trim_matches(|c| c == '\'' || c == '"').to_string())
}

/// The line range of the top-level `users:` block
fn block_of(lines: &[&str]) -> Option<(usize, usize)> {
    let start = lines.iter().position(|line| line.trim_end() == "users:" || line.trim_end() == "users: []")?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| !line.trim().is_empty() && !line.starts_with(' ') && !line.starts_with('-') && !line.starts_with('#'))
        .map_or(lines.len(), |offset| start + 1 + offset);
    Some((start, end))
}

pub fn parse(text: &str) -> Vec<Account> {
    let lines: Vec<&str> = text.lines().collect();
    let Some((start, end)) = block_of(&lines) else { return Vec::new() };
    let mut accounts: Vec<Account> = Vec::new();
    for line in &lines[start + 1..end] {
        if let Some(name) = value_of(line, "name").filter(|_| line.trim_start().starts_with("- ")) {
            accounts.push(Account { name, hash: String::new() });
        } else if let (Some(hash), Some(account)) = (value_of(line, "password"), accounts.last_mut()) {
            account.hash = hash;
        }
    }
    accounts
}

/// The configuration text with the users block replaced
pub fn render(text: &str, accounts: &[Account]) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let block = if accounts.is_empty() {
        "users: []\n".to_string()
    } else {
        let rows: String = accounts.iter().map(|a| format!("  - name: {}\n    password: {}\n", a.name, a.hash)).collect();
        format!("users:\n{rows}")
    };
    let Some((start, end)) = block_of(&lines) else { return format!("{}\n{block}", text.trim_end()) };
    let mut out: String = lines[..start].iter().map(|line| format!("{line}\n")).collect();
    out.push_str(&block);
    out.extend(lines[end..].iter().map(|line| format!("{line}\n")));
    out
}

pub fn to_users(accounts: &[Account]) -> Vec<pb::ServiceUser> {
    let mut users: Vec<pb::ServiceUser> = accounts
        .iter()
        .map(|a| pb::ServiceUser { id: a.name.clone(), login: a.name.clone(), enabled: true, ..Default::default() })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    users
}

fn hash_password(password: &str) -> Result<String, Refusal> {
    if password.len() > BCRYPT_LIMIT {
        return Err(Refusal::InvalidPassword);
    }
    bcrypt::hash(password, BCRYPT_COST).map_err(|_| Refusal::Failed)
}

pub fn add(accounts: &mut Vec<Account>, login: &str, hash: String) -> Done {
    let starts_plain = login.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    if !starts_plain || accounts.iter().any(|a| a.name.eq_ignore_ascii_case(login)) {
        return Err(Refusal::InvalidLogin);
    }
    accounts.push(Account { name: login.to_string(), hash });
    Ok(())
}

pub fn remove(accounts: &mut Vec<Account>, login: &str) -> Done {
    if !accounts.iter().any(|a| a.name == login) {
        return Err(Refusal::UnknownUser);
    }
    if accounts.len() == 1 {
        return Err(Refusal::CannotRemoveAdmin);
    }
    accounts.retain(|a| a.name != login);
    Ok(())
}

pub fn stop_call() -> Call {
    Call::new(&["stop", CONTAINER])
}

pub fn start_call() -> Call {
    Call::new(&["start", CONTAINER])
}

pub struct Adguard {
    path: PathBuf,
}

impl Adguard {
    pub async fn find() -> Result<Option<Adguard>, Refusal> {
        let directory = discover::directory_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        Ok(directory.map(|dir| Adguard { path: dir.join(CONFIG_FILE) }))
    }

    fn read(&self) -> Result<String, Refusal> {
        std::fs::read_to_string(&self.path).map_err(|_| Refusal::Failed)
    }

    fn write(&self, text: &str) -> Done {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&self.path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o600);
        crate::util::write_file_atomic(&self.path, text.as_bytes(), mode).map_err(|_| Refusal::Failed)
    }

    async fn edit(&self, change: impl FnOnce(&mut Vec<Account>) -> Done) -> Done {
        docker::run(&stop_call()).await?;
        let result = self.rewrite(change);
        let started = docker::run(&start_call()).await;
        result?;
        started.map(|_| ())
    }

    fn rewrite(&self, change: impl FnOnce(&mut Vec<Account>) -> Done) -> Done {
        let text = self.read()?;
        let mut accounts = parse(&text);
        change(&mut accounts)?;
        self.write(&render(&text, &accounts))
    }
}

impl UserBackend for Adguard {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        Ok(to_users(&parse(&self.read()?)))
    }

    async fn create(&self, new: &NewUser) -> Done {
        let password = new.password.clone();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password)).await.map_err(|_| Refusal::Failed)??;
        self.edit(|accounts| add(accounts, &new.login, hash)).await
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.edit(|accounts| remove(accounts, user_id)).await
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        let password = password.to_string();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password)).await.map_err(|_| Refusal::Failed)??;
        self.edit(|accounts| {
            accounts.iter_mut().find(|a| a.name == user_id).ok_or(Refusal::UnknownUser)?.hash = hash;
            Ok(())
        })
        .await
    }

    async fn set_role(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_enabled(&self, _: &str, _: bool) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = include_str!("../../tests/fixtures/service_users/adguard-home/AdGuardHome.yaml");

    #[test]
    fn the_users_block_parses() {
        let accounts = parse(CONFIG);
        let names: Vec<&str> = accounts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["operator", "anna"]);
        assert!(accounts[0].hash.starts_with("$2a$10$"));
        assert!(parse("http:\n  address: 0.0.0.0:3000\n").is_empty());
        assert!(parse("users: []\nlanguage: en\n").is_empty());
    }

    #[test]
    fn only_the_users_block_changes_when_the_file_is_written() {
        let mut accounts = parse(CONFIG);
        add(&mut accounts, "clara", "$2b$10$newhash".into()).unwrap();
        let text = render(CONFIG, &accounts);
        assert!(text.contains("  - name: clara\n    password: $2b$10$newhash\nauth_attempts: 5\n"));
        assert!(text.starts_with("http:\n  pprof:"));
        assert!(text.ends_with("language: \"\"\n"));
        assert_eq!(parse(&text).len(), 3);
        remove(&mut accounts, "anna").unwrap();
        let smaller = render(&text, &accounts);
        assert!(!smaller.contains("anna") && smaller.contains("block_auth_min: 15"));
    }

    #[test]
    fn the_last_user_cannot_be_removed_and_names_are_unique() {
        let mut one = vec![Account { name: "operator".into(), hash: "h".into() }];
        assert_eq!(remove(&mut one, "operator"), Err(Refusal::CannotRemoveAdmin));
        assert_eq!(remove(&mut one, "nobody"), Err(Refusal::UnknownUser));
        assert_eq!(add(&mut one, "Operator", "h".into()), Err(Refusal::InvalidLogin));
        assert_eq!(add(&mut one, "@odd", "h".into()), Err(Refusal::InvalidLogin));
    }

    #[test]
    fn an_empty_block_is_written_as_an_empty_list() {
        assert_eq!(render("users:\n  - name: a\n    password: h\nlanguage: en\n", &[]), "users: []\nlanguage: en\n");
        assert!(render("language: en\n", &[Account { name: "a".into(), hash: "h".into() }]).ends_with("users:\n  - name: a\n    password: h\n"));
    }

    #[test]
    fn passwords_become_bcrypt_hashes_and_long_ones_are_refused() {
        let hash = hash_password("s3cr3t-pass-word").unwrap();
        assert!(bcrypt::verify("s3cr3t-pass-word", &hash).unwrap());
        assert_eq!(hash_password(&"x".repeat(73)), Err(Refusal::InvalidPassword));
    }

    #[test]
    fn the_container_is_stopped_around_the_change() {
        assert_eq!(stop_call().args, ["stop", "adguardhome"]);
        assert_eq!(start_call().args, ["start", "adguardhome"]);
        let caps = capabilities();
        assert!(caps.roles.is_empty() && !caps.can_set_enabled && caps.can_set_password);
    }
}
