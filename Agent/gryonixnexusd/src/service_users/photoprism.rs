//! PhotoPrism accounts through its REST API

use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::photoprism::{CONTAINER, WEB_UI_PORT};
use crate::{discover, pb};

pub const SERVICE_ID: &str = "photoprism";
const ROLE_USER: &str = "user";
const COUNT: usize = 1000;

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

pub struct Photoprism {
    token: String,
    admin: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}/api/v1")
}

pub fn request(token: Option<&str>, method: &'static str, path: &str, body: Option<Value>) -> Request {
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    if let Some(token) = token {
        headers.push(("Authorization".into(), format!("Bearer {token}")));
    }
    Request { method, url: format!("{}{path}", base()), headers, body: body.map(|v| v.to_string()) }
}

pub fn login_request(user: &str, password: &str) -> Request {
    request(None, "POST", "/session", Some(json!({ "username": user, "password": password })))
}

/// The access token of a session answer
pub fn parse_session(body: &str) -> Result<String, Refusal> {
    let value: Value = serde_json::from_str(body.trim()).map_err(|_| Refusal::Failed)?;
    match value.get("access_token").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(Refusal::Failed),
    }
}

pub fn parse_users(json: &str, admin: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.as_array().ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let (id, login) = (text("UID"), text("Name"));
            let is_admin = row.get("SuperAdmin").and_then(Value::as_bool).unwrap_or(false) || text("Role") == ADMIN_ROLE;
            (!id.is_empty() && !login.is_empty()).then(|| pb::ServiceUser {
                id,
                display_name: text("DisplayName"),
                email: text("Email"),
                role: if is_admin { ADMIN_ROLE } else { ROLE_USER }.to_string(),
                enabled: row.get("CanLogin").and_then(Value::as_bool).unwrap_or(true),
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
    let name = if new.display_name.is_empty() { new.login.clone() } else { new.display_name.clone() };
    json!({
        "Name": new.login,
        "DisplayName": name,
        "Email": new.email,
        "Role": new.role,
        "Password": new.password,
        "CanLogin": true,
    })
}

/// The admin the installer created, from the container's environment
async fn installer_login() -> Option<(String, String)> {
    let env = super::container_env(CONTAINER).await?;
    let user = super::env_value(&env, "PHOTOPRISM_ADMIN_USER")?;
    let password = super::env_value(&env, "PHOTOPRISM_ADMIN_PASSWORD")?;
    Some((user, password))
}

impl Photoprism {
    pub async fn find(vault: Option<(String, String)>) -> Result<Option<Photoprism>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (admin, password) = match vault {
            Some(login) => login,
            None => installer_login().await.ok_or(Refusal::AdminNotSetUp)?,
        };
        let answer = http::send(&login_request(&admin, &password)).await?;
        if matches!(answer.status, 400 | 401 | 403) {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        Ok(Some(Photoprism { token: parse_session(&answer.body)?, admin }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(Some(&self.token), method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn update(&self, user_id: &str, changes: Value) -> Done {
        self.call("PUT", &format!("/users/{user_id}"), Some(changes)).await.map(|_| ())
    }
}

impl UserBackend for Photoprism {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let answer = self.call("GET", &format!("/users?count={COUNT}&offset=0"), None).await?;
        parse_users(&answer.body, &self.admin)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/users", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.update(user_id, json!({ "Password": password })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.update(user_id, json!({ "Role": role })).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.update(user_id, json!({ "CanLogin": enabled })).await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/photoprism/users.json");
    const SESSION: &str = include_str!("../../tests/fixtures/service_users/photoprism/session.json");

    fn new_user() -> NewUser {
        NewUser {
            login: "clara".into(),
            display_name: String::new(),
            email: String::new(),
            password: "s3cr3t-pass-word".into(),
            role: "user".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_user_list_parses_and_skips_nameless_guests() {
        let users = parse_users(USERS, "Operator").unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["anna", "boris", "operator"]);
        assert_eq!(users[2].id, "uqxetse3cy5eo9z2");
        assert_eq!((users[2].role.as_str(), users[2].is_self), ("admin", true));
        assert!(users[0].enabled && !users[1].enabled);
        assert_eq!(users[0].email, "anna@example.org");
    }

    #[test]
    fn an_error_object_is_a_failure() {
        assert_eq!(parse_users("{\"error\":\"Unauthorized\"}", ""), Err(Refusal::Failed));
    }

    #[test]
    fn the_session_answer_gives_the_token() {
        assert_eq!(parse_session(SESSION).unwrap(), "0123456789abcdef0123456789abcdef0123456789abcdef");
        assert_eq!(parse_session("{\"error\":\"x\"}"), Err(Refusal::Failed));
    }

    #[test]
    fn passwords_and_tokens_stay_out_of_the_arguments_and_url() {
        let sent = [
            login_request("operator", "s3cr3t-pass-word"),
            request(Some("tok-abcdef"), "POST", "/users", Some(create_body(&new_user()))),
        ];
        for item in &sent {
            assert!(!item.url.contains("s3cr3t") && !item.url.contains("tok-abcdef"));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains("tok-abcdef")));
    }

    #[test]
    fn a_new_account_can_sign_in_and_is_named_after_its_login() {
        let body = create_body(&new_user());
        assert_eq!(body["Name"], "clara");
        assert_eq!(body["DisplayName"], "clara");
        assert_eq!(body["CanLogin"], true);
    }

    #[test]
    fn this_service_has_roles_and_an_off_switch_but_no_quota_or_mail() {
        let caps = capabilities();
        assert!(caps.can_set_enabled && caps.can_set_password && !caps.can_set_quota && !caps.needs_email);
    }
}
