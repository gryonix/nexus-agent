//! Forgejo accounts through its admin REST API

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::forgejo::{CONTAINER, WEB_UI_PORT};
use crate::{discover, pb};

pub const SERVICE_ID: &str = "forgejo";
const ROLE_USER: &str = "user";
const TOKEN_FILE: &str = "forgejo-admin-token.json";
const PAGE_SIZE: usize = 50;
const MAX_PAGES: usize = 40;

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

pub struct Forgejo {
    token: String,
    owner: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}/api/v1")
}

pub fn request(token: &str, method: &'static str, path: &str, body: Option<Value>) -> Request {
    Request {
        method,
        url: format!("{}{path}", base()),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("token {token}")),
        ],
        body: body.map(|v| v.to_string()),
    }
}

/// The users in one page of `GET /admin/users`
pub fn parse_users(json: &str, owner: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.as_array().ok_or(Refusal::Failed)?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let flag = |key: &str| row.get(key).and_then(Value::as_bool).unwrap_or(false);
            let login = text("login");
            (!login.is_empty()).then(|| pb::ServiceUser {
                id: login.clone(),
                display_name: text("full_name"),
                email: text("email"),
                role: if flag("is_admin") { ADMIN_ROLE } else { ROLE_USER }.to_string(),
                enabled: !flag("prohibit_login"),
                is_self: login.eq_ignore_ascii_case(owner),
                login,
                ..Default::default()
            })
        })
        .collect())
}

pub fn create_body(new: &NewUser) -> Value {
    json!({
        "username": new.login,
        "email": new.email,
        "full_name": new.display_name,
        "password": new.password,
        "must_change_password": false,
        "send_notify": false,
    })
}

/// The first administrator in `forgejo admin user list`
pub fn first_admin(listing: &str) -> Option<String> {
    listing.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let numbered = fields.first().is_some_and(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()));
        (numbered && fields.len() >= 5 && fields[4] == "true").then(|| fields[1].to_string())
    })
}

pub fn token_is_plausible(token: &str) -> bool {
    (20..=128).contains(&token.len()) && token.chars().all(|c| c.is_ascii_alphanumeric())
}

pub fn token_file_text(owner: &str, token: &str) -> String {
    json!({ "owner": owner, "token": token }).to_string()
}

pub fn parse_token_file(text: &str) -> Option<(String, String)> {
    let value: Value = serde_json::from_str(text).ok()?;
    let owner = value.get("owner")?.as_str()?.to_string();
    let token = value.get("token")?.as_str()?.to_string();
    (!owner.is_empty() && token_is_plausible(&token)).then_some((owner, token))
}

fn token_path() -> PathBuf {
    crate::util::state_dir().join(TOKEN_FILE)
}

pub fn write_token(path: &Path, owner: &str, token: &str) -> std::io::Result<()> {
    let staged = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&staged);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&staged)?;
    file.write_all(token_file_text(owner, token).as_bytes())?;
    file.sync_all()?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&staged, path)
}

fn refusal_of_stderr(stderr: &str) -> Refusal {
    let text = stderr.to_lowercase();
    if text.contains("is not running") || text.contains("no such container") {
        Refusal::ServiceDown
    } else {
        Refusal::Failed
    }
}

async fn exec(args: &[&str]) -> Result<String, Refusal> {
    let output = tokio::process::Command::new("docker")
        .args(["exec", "-u", "git", CONTAINER])
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|_| Refusal::ServiceDown)?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(refusal_of_stderr(&String::from_utf8_lossy(&output.stderr)))
    }
}

/// A fresh admin token, minted inside the container
async fn mint_token() -> Result<(String, String), Refusal> {
    let listing = exec(&["forgejo", "admin", "user", "list"]).await?;
    let owner = first_admin(&listing).ok_or(Refusal::Failed)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let name = format!("gryonix-agent-{stamp}");
    let raw = exec(&[
        "forgejo", "admin", "user", "generate-access-token",
        "--username", &owner, "--token-name", &name, "--scopes", "all", "--raw",
    ])
    .await?;
    let token = raw.trim().to_string();
    if !token_is_plausible(&token) {
        return Err(Refusal::Failed);
    }
    Ok((owner, token))
}

async fn token_works(token: &str) -> Result<bool, Refusal> {
    let answer = http::send(&request(token, "GET", "/user", None)).await?;
    Ok(answer.ok())
}

impl Forgejo {
    pub async fn find() -> Result<Option<Forgejo>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let path = token_path();
        if let Some((owner, token)) = std::fs::read_to_string(&path).ok().and_then(|text| parse_token_file(&text)) {
            if token_works(&token).await? {
                return Ok(Some(Forgejo { token, owner }));
            }
        }
        let (owner, token) = mint_token().await?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|_| Refusal::Failed)?;
        }
        write_token(&path, &owner, &token).map_err(|_| Refusal::Failed)?;
        if !token_works(&token).await? {
            return Err(Refusal::Failed);
        }
        Ok(Some(Forgejo { token, owner }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(&self.token, method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn edit(&self, user_id: &str, body: Value) -> Done {
        self.call("PATCH", &format!("/admin/users/{user_id}"), Some(body)).await.map(|_| ())
    }
}

impl UserBackend for Forgejo {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let mut users = Vec::new();
        for page in 1..=MAX_PAGES {
            let answer = self.call("GET", &format!("/admin/users?page={page}&limit={PAGE_SIZE}"), None).await?;
            let rows = parse_users(&answer.body, &self.owner)?;
            let last = rows.len() < PAGE_SIZE;
            users.extend(rows);
            if last {
                break;
            }
        }
        users.sort_by_key(|user| user.login.to_lowercase());
        Ok(users)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/admin/users", Some(create_body(new))).await?;
        if new.role == ADMIN_ROLE {
            return self.edit(&new.login, json!({ "admin": true })).await;
        }
        Ok(())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/admin/users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.edit(user_id, json!({ "password": password })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.edit(user_id, json!({ "admin": role == ADMIN_ROLE })).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.edit(user_id, json!({ "prohibit_login": !enabled })).await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/forgejo/users.json");
    const LISTING: &str = include_str!("../../tests/fixtures/service_users/forgejo/user-list.txt");
    const TOKEN: &str = "0123456789abcdef0123456789abcdef01234567";

    fn new_user() -> NewUser {
        NewUser {
            login: "boris".into(),
            display_name: "Boris B".into(),
            email: "boris@example.org".into(),
            password: "s3cr3t-pass-word".into(),
            role: "user".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_admin_list_parses() {
        let users = parse_users(USERS, "Operator").unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["operator", "anna", "boris"]);
        assert_eq!((users[0].role.as_str(), users[0].is_self, users[0].enabled), ("admin", true, true));
        assert_eq!((users[1].display_name.as_str(), users[1].email.as_str()), ("Anna", "anna@example.org"));
        assert!(!users[2].enabled);
        assert!(users.iter().all(|u| u.id == u.login));
    }

    #[test]
    fn a_non_list_answer_is_a_failure() {
        assert_eq!(parse_users("{\"message\":\"x\"}", ""), Err(Refusal::Failed));
        assert!(parse_users("[]", "").unwrap().is_empty());
    }

    #[test]
    fn the_first_administrator_comes_from_the_cli_table() {
        assert_eq!(first_admin(LISTING).as_deref(), Some("operator"));
        assert_eq!(first_admin("ID Username Email IsActive IsAdmin 2FA\n"), None);
        assert_eq!(first_admin(""), None);
    }

    #[test]
    fn tokens_are_checked_before_they_are_trusted() {
        assert!(token_is_plausible(TOKEN));
        assert!(!token_is_plausible("short"));
        assert!(!token_is_plausible("has space in it 0123456789"));
        assert!(!token_is_plausible("error: the token name is used"));
    }

    #[test]
    fn the_token_file_round_trips_and_is_private() {
        let dir = std::env::temp_dir().join(format!("gnx-forgejo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token.json");
        write_token(&path, "operator", TOKEN).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(parse_token_file(&text), Some(("operator".to_string(), TOKEN.to_string())));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(parse_token_file("not json"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_token_and_passwords_stay_out_of_the_arguments_and_url() {
        let sent = [
            request(TOKEN, "POST", "/admin/users", Some(create_body(&new_user()))),
            request(TOKEN, "PATCH", "/admin/users/anna", Some(json!({ "password": "s3cr3t-pass-word" }))),
        ];
        for item in &sent {
            assert!(!item.url.contains("s3cr3t") && !item.url.contains(TOKEN));
            assert!(item.headers.contains(&("Authorization".to_string(), format!("token {TOKEN}"))));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains(TOKEN)));
    }

    #[test]
    fn the_create_body_has_the_admin_api_field_names() {
        let body = create_body(&new_user());
        assert_eq!(body["username"], "boris");
        assert_eq!(body["full_name"], "Boris B");
        assert_eq!(body["must_change_password"], false);
        assert_eq!(body["send_notify"], false);
    }

    #[test]
    fn this_service_has_roles_and_an_off_switch_but_no_quota() {
        let caps = capabilities();
        assert!(caps.can_set_enabled && caps.can_set_password && !caps.can_set_quota && caps.needs_email);
        assert!(!caps.user_id_is_email);
    }
}
