//! GitLab accounts through its REST API and a private root token

use std::process::Stdio;

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use super::http::{self, Request, Response};
use super::{token_store, NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::gitlab::{CONTAINER, WEB_UI_PORT};
use crate::{discover, pb};

pub const SERVICE_ID: &str = "gitlab";
const ROLE_USER: &str = "user";
const ROOT: &str = "root";
const TOKEN_FILE: &str = "gitlab-admin-token.json";
const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 20;
const MINT_SCRIPT: &str = "user = User.find_by_username('root')\ntoken = user.personal_access_tokens.create!(name: 'gryonix-agent', scopes: [:api], expires_at: 300.days.from_now)\nputs \"TOKEN=#{token.token}\"\n";

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

pub struct Gitlab {
    token: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}/api/v4")
}

pub fn request(token: &str, method: &'static str, path: &str, body: Option<Value>) -> Request {
    Request {
        method,
        url: format!("{}{path}", base()),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("PRIVATE-TOKEN".into(), token.to_string()),
        ],
        body: body.map(|v| v.to_string()),
    }
}

/// The users in one page of `GET /users`
pub fn parse_users(json: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.as_array().ok_or(Refusal::Failed)?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let id = row.get("id").and_then(Value::as_i64)?.to_string();
            let login = text("username");
            let admin = row.get("is_admin").and_then(Value::as_bool).unwrap_or(false);
            (!login.is_empty()).then(|| pb::ServiceUser {
                id,
                display_name: text("name"),
                email: text("email"),
                role: if admin { ADMIN_ROLE } else { ROLE_USER }.to_string(),
                enabled: text("state") == "active",
                is_self: login == ROOT,
                login,
                ..Default::default()
            })
        })
        .collect())
}

pub fn create_body(new: &NewUser) -> Value {
    let name = if new.display_name.is_empty() { new.login.clone() } else { new.display_name.clone() };
    json!({
        "username": new.login,
        "email": new.email,
        "name": name,
        "password": new.password,
        "admin": new.role == ADMIN_ROLE,
        "skip_confirmation": true,
    })
}

/// The token line printed by the rails runner
pub fn parse_runner_output(output: &str) -> Option<String> {
    let token = output.lines().find_map(|line| line.trim().strip_prefix("TOKEN="))?.trim();
    token_is_plausible(token).then(|| token.to_string())
}

pub fn token_is_plausible(token: &str) -> bool {
    (20..=128).contains(&token.len()) && token.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

async fn mint_token() -> Result<String, Refusal> {
    let mut child = tokio::process::Command::new("docker")
        .args(["exec", "-i", CONTAINER, "gitlab-rails", "runner", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Refusal::ServiceDown)?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(MINT_SCRIPT.as_bytes()).await.map_err(|_| Refusal::Failed)?;
        pipe.shutdown().await.map_err(|_| Refusal::Failed)?;
    }
    let output = child.wait_with_output().await.map_err(|_| Refusal::Failed)?;
    if !output.status.success() {
        return Err(Refusal::ServiceDown);
    }
    parse_runner_output(&String::from_utf8_lossy(&output.stdout)).ok_or(Refusal::Failed)
}

async fn token_works(token: &str) -> Result<bool, Refusal> {
    Ok(http::send(&request(token, "GET", "/user", None)).await?.ok())
}

impl Gitlab {
    pub async fn find() -> Result<Option<Gitlab>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let path = token_store::path_of(TOKEN_FILE);
        if let Some((_, token)) = token_store::read(&path) {
            if token_is_plausible(&token) && token_works(&token).await? {
                return Ok(Some(Gitlab { token }));
            }
        }
        let token = mint_token().await?;
        token_store::write(&path, ROOT, &token).map_err(|_| Refusal::Failed)?;
        if !token_works(&token).await? {
            return Err(Refusal::Failed);
        }
        Ok(Some(Gitlab { token }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(&self.token, method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn edit(&self, user_id: &str, body: Value) -> Done {
        self.call("PUT", &format!("/users/{user_id}"), Some(body)).await.map(|_| ())
    }
}

impl UserBackend for Gitlab {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let mut users = Vec::new();
        for page in 1..=MAX_PAGES {
            let path = format!("/users?exclude_internal=true&without_project_bots=true&per_page={PAGE_SIZE}&page={page}");
            let rows = parse_users(&self.call("GET", &path, None).await?.body)?;
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
        self.call("POST", "/users", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.edit(user_id, json!({ "password": password, "skip_reconfirmation": true })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.edit(user_id, json!({ "admin": role == ADMIN_ROLE })).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        let action = if enabled { "unblock" } else { "block" };
        self.call("POST", &format!("/users/{user_id}/{action}"), None).await.map(|_| ())
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/gitlab/users.json");
    const RUNNER: &str = include_str!("../../tests/fixtures/service_users/gitlab/runner-output.txt");
    const TOKEN: &str = "glpat-0123456789abcdefghij";

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
    fn the_user_list_parses() {
        let users = parse_users(USERS).unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["root", "anna", "boris"]);
        assert_eq!((users[0].id.as_str(), users[0].role.as_str(), users[0].is_self), ("1", "admin", true));
        assert_eq!((users[1].display_name.as_str(), users[1].email.as_str()), ("Anna", "anna@example.org"));
        assert!(users[1].enabled && !users[2].enabled);
    }

    #[test]
    fn an_error_object_is_a_failure() {
        assert_eq!(parse_users("{\"message\":\"401 Unauthorized\"}"), Err(Refusal::Failed));
        assert!(parse_users("[]").unwrap().is_empty());
    }

    #[test]
    fn the_minted_token_is_read_from_the_runner_output() {
        assert_eq!(parse_runner_output(RUNNER).as_deref(), Some(TOKEN));
        assert_eq!(parse_runner_output("TOKEN=short"), None);
        assert_eq!(parse_runner_output("Traceback: no such user"), None);
    }

    #[test]
    fn the_token_and_passwords_stay_out_of_the_arguments_and_url() {
        let sent = [
            request(TOKEN, "POST", "/users", Some(create_body(&new_user()))),
            request(TOKEN, "PUT", "/users/7", Some(json!({ "password": "s3cr3t-pass-word" }))),
        ];
        for item in &sent {
            assert!(!item.url.contains("s3cr3t") && !item.url.contains(TOKEN));
            assert!(item.headers.contains(&("PRIVATE-TOKEN".to_string(), TOKEN.to_string())));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains(TOKEN)));
        assert!(!MINT_SCRIPT.contains("password"));
    }

    #[test]
    fn a_new_account_skips_the_confirmation_mail_and_takes_the_role() {
        let body = create_body(&new_user());
        assert_eq!(body["skip_confirmation"], true);
        assert_eq!(body["admin"], true);
        assert_eq!(body["name"], "clara");
    }

    #[test]
    fn this_service_has_roles_and_an_off_switch_but_no_quota() {
        let caps = capabilities();
        assert!(caps.can_set_enabled && caps.can_set_password && !caps.can_set_quota && caps.needs_email);
    }
}
