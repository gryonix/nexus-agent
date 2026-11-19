//! Vaultwarden accounts through the admin panel

use serde_json::Value;

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend};
use crate::install::vaultwarden::WEB_UI_PORT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "vaultwarden";
const COOKIE_NAME: &str = "VW_ADMIN";
const TOKEN_KEY: &str = "ADMIN_TOKEN";
const JSON: &str = "application/json";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_enabled: true,
        needs_email: true,
        user_id_is_email: true,
        ..Default::default()
    }
}

pub struct Vaultwarden {
    cookie: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}")
}

/// The plain admin token in a `.env` file
pub fn parse_token(env: &str) -> Result<String, Refusal> {
    let prefix = format!("{TOKEN_KEY}=");
    let value = env
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .map(|value| value.trim().trim_matches(['"', '\'']).to_string())
        .unwrap_or_default();
    if value.is_empty() || value.starts_with("$argon2") || value.starts_with("$$argon2") {
        return Err(Refusal::NeedsAdminToken);
    }
    Ok(value)
}

pub fn login_request(token: &str) -> Request {
    Request {
        method: "POST",
        url: format!("{}/admin", base()),
        headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
        body: Some(format!("token={}", http::form_encode(token))),
    }
}

pub fn action_request(cookie: &str, method: &'static str, path: &str, body: Option<String>) -> Request {
    Request {
        method,
        url: format!("{}/admin{path}", base()),
        headers: vec![
            ("Cookie".into(), format!("{COOKIE_NAME}={cookie}")),
            ("Content-Type".into(), JSON.into()),
        ],
        body,
    }
}

/// The admin session value from the login answer
pub fn session_cookie(response: &Response) -> Option<String> {
    let header = response.header("set-cookie")?;
    let first = header.split(';').next()?;
    let value = first.strip_prefix(&format!("{COOKIE_NAME}="))?;
    (!value.is_empty()).then(|| value.to_string())
}

/// The users in the admin panel's JSON list
pub fn parse_users(json: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.as_array().ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let id = text("id");
            let email = text("email");
            (!id.is_empty()).then(|| pb::ServiceUser {
                id,
                login: email.clone(),
                display_name: text("name"),
                email,
                enabled: row.get("userEnabled").and_then(Value::as_bool).unwrap_or(true),
                ..Default::default()
            })
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

impl Vaultwarden {
    pub async fn find() -> Result<Option<Vaultwarden>, Refusal> {
        let directory = discover::directory_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        let Some(directory) = directory else { return Ok(None) };
        let env = std::fs::read_to_string(directory.join(".env")).map_err(|_| Refusal::NeedsAdminToken)?;
        let token = parse_token(&env)?;
        let answer = http::send(&login_request(&token)).await?;
        if answer.status == 401 || answer.status == 403 {
            return Err(Refusal::NeedsAdminToken);
        }
        match session_cookie(&answer) {
            Some(cookie) => Ok(Some(Vaultwarden { cookie })),
            None => Err(Refusal::Failed),
        }
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<String>) -> Result<Response, Refusal> {
        let answer = http::send(&action_request(&self.cookie, method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn post(&self, path: &str, body: &str) -> Done {
        self.call("POST", path, Some(body.to_string())).await.map(|_| ())
    }
}

impl UserBackend for Vaultwarden {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        parse_users(&self.call("GET", "/users", None).await?.body)
    }

    async fn create(&self, new: &NewUser) -> Done {
        let body = serde_json::json!({ "email": new.login }).to_string();
        self.post("/invite", &body).await
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.post(&format!("/users/{user_id}/delete"), "{}").await
    }

    async fn set_password(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_role(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        let verb = if enabled { "enable" } else { "disable" };
        self.post(&format!("/users/{user_id}/{verb}"), "{}").await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/vaultwarden/users.json");
    const LOGIN: &str = include_str!("../../tests/fixtures/service_users/vaultwarden/login-answer.txt");

    #[test]
    fn the_admin_users_json_parses() {
        let users = parse_users(USERS).unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["anna@example.org", "boris@example.org", "clara@example.org"]);
        assert_eq!(users[0].id, "6c0a2c5e-7d4f-4f0e-9d0c-0d3b1d1f0a01");
        assert_eq!(users[0].display_name, "Anna");
        assert_eq!(users[0].email, "anna@example.org");
        assert!(users[0].enabled);
        assert!(!users[1].enabled);
        assert!(users.iter().all(|u| !u.is_self && u.role.is_empty()));
    }

    #[test]
    fn a_non_list_answer_is_a_failure() {
        assert_eq!(parse_users("{\"error\":\"x\"}"), Err(Refusal::Failed));
        assert_eq!(parse_users("<html>"), Err(Refusal::Failed));
        assert!(parse_users("[]").unwrap().is_empty());
    }

    #[test]
    fn a_plain_token_is_read_and_a_hash_is_not() {
        assert_eq!(parse_token("ADMIN_TOKEN=abc123\n"), Ok("abc123".to_string()));
        assert_eq!(parse_token("X=1\nADMIN_TOKEN=\"abc123\"\n"), Ok("abc123".to_string()));
        assert_eq!(parse_token("ADMIN_TOKEN=$argon2id$v=19$m=65540\n"), Err(Refusal::NeedsAdminToken));
        assert_eq!(parse_token("ADMIN_TOKEN=\n"), Err(Refusal::NeedsAdminToken));
        assert_eq!(parse_token(""), Err(Refusal::NeedsAdminToken));
    }

    #[test]
    fn the_session_cookie_comes_from_the_login_answer() {
        let answer = http::parse_response(LOGIN).unwrap();
        assert_eq!(session_cookie(&answer).as_deref(), Some("aaa.bbb.ccc"));
    }

    #[test]
    fn the_token_is_form_encoded_in_the_body_only() {
        let request = login_request("a b&c=d");
        assert_eq!(request.body.as_deref(), Some("token=a%20b%26c%3Dd"));
        assert!(!request.url.contains("a b"));
        assert!(request.headers.iter().all(|(_, value)| !value.contains("a b")));
    }

    #[test]
    fn actions_carry_the_cookie_and_a_json_type() {
        let request = action_request("aaa.bbb.ccc", "POST", "/invite", Some("{}".into()));
        assert_eq!(request.url, "http://127.0.0.1:8082/admin/invite");
        assert!(request.headers.contains(&("Cookie".to_string(), "VW_ADMIN=aaa.bbb.ccc".to_string())));
        assert!(request.headers.contains(&("Content-Type".to_string(), "application/json".to_string())));
    }

    #[test]
    fn this_service_has_no_password_role_or_quota() {
        let caps = capabilities();
        assert!(caps.can_create && caps.can_delete && caps.can_set_enabled);
        assert!(!caps.can_set_password && !caps.can_set_quota && caps.roles.is_empty());
        assert!(caps.needs_email && caps.user_id_is_email);
    }
}
