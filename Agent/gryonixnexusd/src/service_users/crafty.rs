//! Crafty Controller accounts through its panel API

use serde_json::{json, Value};

use super::docker::{self, Call};
use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::crafty::{CONTAINER, WEB_UI_PORT};
use crate::{discover, pb};

pub const SERVICE_ID: &str = "crafty-controller";
const ROLE_USER: &str = "user";
const CREDS_FILE: &str = "/crafty/app/config/default-creds.txt";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_enabled: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        ..Default::default()
    }
}

pub struct Crafty {
    token: String,
    admin: String,
}

fn base() -> String {
    format!("https://127.0.0.1:{WEB_UI_PORT}/api/v2")
}

pub fn request(token: Option<&str>, method: &'static str, path: &str, body: Option<Value>) -> Request {
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    if let Some(token) = token {
        headers.push(("Authorization".into(), format!("Bearer {token}")));
    }
    Request { method, url: format!("{}{path}", base()), headers, body: body.map(|v| v.to_string()) }
}

pub fn login_request(username: &str, password: &str) -> Request {
    request(None, "POST", "/auth/login", Some(json!({ "username": username, "password": password })))
}

pub fn parse_login(body: &str) -> Result<String, Refusal> {
    let value: Value = serde_json::from_str(body.trim()).map_err(|_| Refusal::Failed)?;
    match value.get("data").and_then(|data| data.get("token")).and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(Refusal::AdminLoginFailed),
    }
}

/// The first-run account from `default-creds.txt`
pub fn parse_creds(text: &str) -> Option<(String, String)> {
    let value: Value = serde_json::from_str(text.trim()).ok()?;
    let username = value.get("username")?.as_str()?.to_string();
    let password = value.get("password")?.as_str()?.to_string();
    (!username.is_empty() && !password.is_empty()).then_some((username, password))
}

pub fn parse_users(json: &str, admin: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.get("data").and_then(Value::as_array).ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let (id, login) = (text("user_id"), text("username"));
            let superuser = row.get("superuser").and_then(Value::as_bool).unwrap_or(false);
            (!id.is_empty() && !login.is_empty()).then(|| pb::ServiceUser {
                id,
                email: text("email"),
                role: if superuser { ADMIN_ROLE } else { ROLE_USER }.to_string(),
                enabled: row.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                is_self: login.eq_ignore_ascii_case(admin),
                login,
                ..Default::default()
            })
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

pub fn create_body(new: &NewUser) -> Value {
    let mut body = json!({ "username": new.login, "password": new.password, "superuser": new.role == ADMIN_ROLE });
    if !new.email.is_empty() {
        body["email"] = json!(new.email);
    }
    body
}

impl Crafty {
    pub async fn find(vault: Option<(String, String)>) -> Result<Option<Crafty>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (admin, password) = match vault {
            Some(login) => login,
            None => first_run_login().await.ok_or(Refusal::AdminNotSetUp)?,
        };
        let answer = http::send_with(&login_request(&admin, &password), true).await?;
        if matches!(answer.status, 400 | 401 | 403) {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        Ok(Some(Crafty { token: parse_login(&answer.body)?, admin }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send_with(&request(Some(&self.token), method, path, body), true).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn patch(&self, user_id: &str, changes: Value) -> Done {
        self.call("PATCH", &format!("/users/{user_id}"), Some(changes)).await.map(|_| ())
    }
}

async fn first_run_login() -> Option<(String, String)> {
    let text = docker::run(&Call::new(&["exec", CONTAINER, "cat", CREDS_FILE])).await.ok()?;
    parse_creds(&text)
}

impl UserBackend for Crafty {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        parse_users(&self.call("GET", "/users", None).await?.body, &self.admin)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/users", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.patch(user_id, json!({ "password": password })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.patch(user_id, json!({ "superuser": role == ADMIN_ROLE })).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.patch(user_id, json!({ "enabled": enabled })).await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/crafty-controller/users.json");
    const LOGIN: &str = include_str!("../../tests/fixtures/service_users/crafty-controller/login.json");
    const CREDS: &str = include_str!("../../tests/fixtures/service_users/crafty-controller/default-creds.txt");

    fn new_user() -> NewUser {
        NewUser {
            login: "clara".into(),
            display_name: String::new(),
            email: String::new(),
            password: "s3cr3t-pass-word".into(),
            role: "admin".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_user_list_parses() {
        let users = parse_users(USERS, "Admin").unwrap();
        let rows: Vec<(&str, &str, bool, bool)> = users.iter().map(|u| (u.login.as_str(), u.role.as_str(), u.enabled, u.is_self)).collect();
        assert_eq!(rows, [("admin", "admin", true, true), ("anna", "user", true, false), ("boris", "user", false, false)]);
        assert_eq!(parse_users("{\"status\":\"error\"}", ""), Err(Refusal::Failed));
    }

    #[test]
    fn the_login_answer_gives_a_token_or_a_refusal() {
        assert_eq!(parse_login(LOGIN).unwrap(), "eyJhbGciOiJIUzI1NiJ9.example.signature");
        assert_eq!(parse_login("{\"status\":\"error\",\"error\":\"INCORRECT_CREDENTIALS\"}"), Err(Refusal::AdminLoginFailed));
    }

    #[test]
    fn the_first_run_account_is_read_from_the_credentials_file() {
        assert_eq!(parse_creds(CREDS), Some(("admin".to_string(), "generated-pass-12345".to_string())));
        assert_eq!(parse_creds("garbage"), None);
    }

    #[test]
    fn passwords_and_tokens_stay_out_of_the_arguments_and_url() {
        let sent = [
            login_request("admin", "s3cr3t-pass-word"),
            request(Some("tok-abcdef"), "POST", "/users", Some(create_body(&new_user()))),
        ];
        for item in &sent {
            assert!(item.url.starts_with("https://127.0.0.1:"));
            assert!(!item.url.contains("s3cr3t") && !item.url.contains("tok-abcdef"));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains("tok-abcdef")));
    }

    #[test]
    fn a_new_account_takes_the_role_and_an_optional_address() {
        let body = create_body(&new_user());
        assert_eq!(body["superuser"], true);
        assert!(body.get("email").is_none());
        let mut with_mail = new_user();
        with_mail.email = "clara@example.org".into();
        assert_eq!(create_body(&with_mail)["email"], "clara@example.org");
    }

    #[test]
    fn this_service_has_an_off_switch_but_no_quota() {
        let caps = capabilities();
        assert!(caps.can_set_enabled && caps.can_set_password && !caps.can_set_quota && !caps.needs_email);
    }
}
