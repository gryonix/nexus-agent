//! AnythingLLM accounts in multi-user mode through its developer API

use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::anythingllm::WEB_UI_PORT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "anythingllm";
const ROLE_MANAGER: &str = "manager";
const ROLE_DEFAULT: &str = "default";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_enabled: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_MANAGER.to_string(), ROLE_DEFAULT.to_string()],
        note: super::TOKEN_NOTE.to_string(),
        ..Default::default()
    }
}

pub struct Anythingllm {
    key: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}/api/v1")
}

pub fn request(key: &str, method: &'static str, path: &str, body: Option<Value>) -> Request {
    Request {
        method,
        url: format!("{}{path}", base()),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Authorization".into(), format!("Bearer {key}")),
        ],
        body: body.map(|v| v.to_string()),
    }
}

/// Whether the instance runs in multi-user mode
pub fn parse_multi_user(body: &str) -> Option<bool> {
    let value: Value = serde_json::from_str(body.trim()).ok()?;
    value.get("isMultiUser").and_then(Value::as_bool)
}

/// The users in `GET /admin/users`
pub fn parse_users(json: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.get("users").and_then(Value::as_array).ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter_map(|row| {
            let id = row.get("id").and_then(Value::as_i64)?.to_string();
            let login = row.get("username").and_then(Value::as_str)?.to_string();
            let role = row.get("role").and_then(Value::as_str).unwrap_or(ROLE_DEFAULT).to_string();
            let suspended = row.get("suspended").and_then(Value::as_i64).unwrap_or(0) != 0;
            Some(pb::ServiceUser { id, login, role, enabled: !suspended, ..Default::default() })
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

pub fn create_body(new: &NewUser) -> Value {
    json!({ "username": new.login, "password": new.password, "role": new.role })
}

impl Anythingllm {
    pub async fn find(vault: Option<(String, String)>) -> Result<Option<Anythingllm>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (_, key) = vault.ok_or(Refusal::NeedsAdminToken)?;
        let answer = http::send(&request(&key, "GET", "/admin/is-multi-user-mode", None)).await?;
        if matches!(answer.status, 401 | 403) {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        if parse_multi_user(&answer.body) != Some(true) {
            return Err(Refusal::NotSupported);
        }
        Ok(Some(Anythingllm { key }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(&self.key, method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn update(&self, user_id: &str, changes: Value) -> Done {
        self.call("POST", &format!("/admin/users/{user_id}"), Some(changes)).await.map(|_| ())
    }
}

impl UserBackend for Anythingllm {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        parse_users(&self.call("GET", "/admin/users", None).await?.body)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/admin/users/new", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/admin/users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.update(user_id, json!({ "password": password })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.update(user_id, json!({ "role": role })).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.update(user_id, json!({ "suspended": i64::from(!enabled) })).await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/anythingllm/users.json");
    const KEY: &str = "ABC123-DEF456-GHI789-JKL012";

    fn new_user() -> NewUser {
        NewUser {
            login: "clara".into(),
            display_name: String::new(),
            email: String::new(),
            password: "s3cr3t-pass-word".into(),
            role: "manager".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_user_list_parses() {
        let users = parse_users(USERS).unwrap();
        let rows: Vec<(&str, &str, &str, bool)> = users.iter().map(|u| (u.id.as_str(), u.login.as_str(), u.role.as_str(), u.enabled)).collect();
        assert_eq!(rows, [("2", "anna", "default", true), ("3", "boris", "manager", false), ("1", "operator", "admin", true)]);
        assert_eq!(parse_users("{\"error\":\"Invalid API Key\"}"), Err(Refusal::Failed));
    }

    #[test]
    fn single_user_mode_is_recognised() {
        assert_eq!(parse_multi_user("{\"isMultiUser\":true}"), Some(true));
        assert_eq!(parse_multi_user("{\"isMultiUser\":false}"), Some(false));
        assert_eq!(parse_multi_user("<html>"), None);
    }

    #[test]
    fn the_api_key_and_passwords_stay_out_of_the_arguments_and_url() {
        let sent = request(KEY, "POST", "/admin/users/new", Some(create_body(&new_user())));
        assert!(!sent.url.contains(KEY) && !sent.url.contains("s3cr3t"));
        assert!(sent.headers.contains(&("Authorization".to_string(), format!("Bearer {KEY}"))));
        assert!(http::arguments().iter().all(|arg| !arg.contains(KEY) && !arg.contains("s3cr3t")));
    }

    #[test]
    fn a_new_account_carries_its_role() {
        let body = create_body(&new_user());
        assert_eq!((body["username"].as_str(), body["role"].as_str()), (Some("clara"), Some("manager")));
    }

    #[test]
    fn three_roles_and_an_off_switch_but_no_mail_or_quota() {
        let caps = capabilities();
        assert_eq!(caps.roles, ["admin", "manager", "default"]);
        assert!(caps.can_set_enabled && !caps.needs_email && !caps.can_set_quota);
    }
}
