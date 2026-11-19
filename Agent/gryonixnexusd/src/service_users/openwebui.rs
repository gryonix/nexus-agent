//! Open WebUI accounts through its REST API

use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::open_webui::WEB_UI_PORT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "open-webui";
const ROLE_USER: &str = "user";
const ROLE_PENDING: &str = "pending";
const MAX_PAGES: usize = 40;

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string(), ROLE_PENDING.to_string()],
        needs_email: true,
        user_id_is_email: true,
        ..Default::default()
    }
}

pub struct OpenWebui {
    token: String,
    admin_email: String,
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

pub fn login_request(email: &str, password: &str) -> Request {
    request(None, "POST", "/auths/signin", Some(json!({ "email": email, "password": password })))
}

/// The token of an admin sign-in answer
pub fn parse_login(body: &str) -> Result<String, Refusal> {
    let value: Value = serde_json::from_str(body.trim()).map_err(|_| Refusal::Failed)?;
    if value.get("role").and_then(Value::as_str) != Some(ADMIN_ROLE) {
        return Err(Refusal::AdminLoginFailed);
    }
    match value.get("token").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(Refusal::Failed),
    }
}

pub fn parse_users(json: &str, admin_email: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.get("users").and_then(Value::as_array).or_else(|| value.as_array()).ok_or(Refusal::Failed)?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let (id, email) = (text("id"), text("email"));
            (!id.is_empty()).then(|| pb::ServiceUser {
                id,
                login: email.clone(),
                display_name: text("name"),
                is_self: email.eq_ignore_ascii_case(admin_email),
                email,
                role: text("role"),
                enabled: true,
                ..Default::default()
            })
        })
        .collect())
}

pub fn create_body(new: &NewUser) -> Value {
    let name = if new.display_name.is_empty() {
        new.login.split('@').next().unwrap_or_default().to_string()
    } else {
        new.display_name.clone()
    };
    json!({ "name": name, "email": new.login, "password": new.password, "role": new.role })
}

/// The update form: the current profile with one field changed
pub fn update_body(current: &Value, changes: Value) -> Value {
    let text = |key: &str| current.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    let mut body = json!({
        "name": text("name"),
        "email": text("email"),
        "role": text("role"),
        "profile_image_url": text("profile_image_url"),
    });
    if let (Some(target), Some(extra)) = (body.as_object_mut(), changes.as_object()) {
        target.extend(extra.clone());
    }
    body
}

/// The admin config with registration and the new-user role set
pub fn admin_config_update(current: &Value, signup: bool, role: &str) -> Option<Value> {
    let mut config = current.as_object()?.clone();
    config.insert("ENABLE_SIGNUP".into(), json!(signup));
    config.insert("DEFAULT_USER_ROLE".into(), json!(role));
    Some(Value::Object(config))
}

impl OpenWebui {
    /// Writes registration settings into the running service
    pub async fn set_registration(&self, signup: bool, role: &str, toggles: &[(&str, bool)]) -> Done {
        let answer = self.call("GET", "/auths/admin/config", None).await?;
        let current: Value = serde_json::from_str(answer.body.trim()).map_err(|_| Refusal::Failed)?;
        let mut body = admin_config_update(&current, signup, role).ok_or(Refusal::Failed)?;
        crate::install::runtime_apply_cmds::apply_toggles(&mut body, toggles);
        self.call("POST", "/auths/admin/config", Some(body)).await.map(|_| ())
    }

    pub async fn sign_in(email: &str, password: &str) -> Result<OpenWebui, Refusal> {
        let answer = http::send(&login_request(email, password)).await?;
        if matches!(answer.status, 400 | 401 | 403) {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        Ok(OpenWebui { token: parse_login(&answer.body)?, admin_email: email.to_string() })
    }

    pub async fn find(login: Option<(String, String)>) -> Result<Option<OpenWebui>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (email, password) = login.ok_or(Refusal::AdminNotSetUp)?;
        let answer = http::send(&login_request(&email, &password)).await?;
        if matches!(answer.status, 400 | 401 | 403) {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        Ok(Some(OpenWebui { token: parse_login(&answer.body)?, admin_email: email }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(Some(&self.token), method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn update(&self, user_id: &str, changes: Value) -> Done {
        let answer = self.call("GET", &format!("/users/{user_id}"), None).await?;
        let current: Value = serde_json::from_str(answer.body.trim()).map_err(|_| Refusal::Failed)?;
        let body = update_body(&current, changes);
        self.call("POST", &format!("/users/{user_id}/update"), Some(body)).await.map(|_| ())
    }
}

impl UserBackend for OpenWebui {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let mut users: Vec<pb::ServiceUser> = Vec::new();
        for page in 1..=MAX_PAGES {
            let answer = self.call("GET", &format!("/users/?page={page}"), None).await?;
            let rows = parse_users(&answer.body, &self.admin_email)?;
            let before = users.len();
            for row in rows {
                if !users.iter().any(|known| known.id == row.id) {
                    users.push(row);
                }
            }
            if users.len() == before {
                break;
            }
        }
        users.sort_by_key(|user| user.login.to_lowercase());
        Ok(users)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/auths/add", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.update(user_id, json!({ "password": password })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.update(user_id, json!({ "role": role })).await
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

    const USERS: &str = include_str!("../../tests/fixtures/service_users/open-webui/users.json");
    const SIGNIN: &str = include_str!("../../tests/fixtures/service_users/open-webui/signin.json");

    fn new_user() -> NewUser {
        NewUser {
            login: "clara@example.org".into(),
            display_name: String::new(),
            email: "clara@example.org".into(),
            password: "s3cr3t-pass-word".into(),
            role: "user".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_user_page_parses() {
        let users = parse_users(USERS, "Operator@example.org").unwrap();
        let roles: Vec<(&str, &str)> = users.iter().map(|u| (u.login.as_str(), u.role.as_str())).collect();
        assert_eq!(roles, [("operator@example.org", "admin"), ("anna@example.org", "user"), ("boris@example.org", "pending")]);
        assert!(users[0].is_self && !users[1].is_self);
        assert_eq!(users[1].display_name, "Anna");
    }

    #[test]
    fn a_bare_list_parses_too() {
        let bare = "[{\"id\":\"a1\",\"name\":\"A\",\"email\":\"a@example.org\",\"role\":\"user\"}]";
        assert_eq!(parse_users(bare, "").unwrap().len(), 1);
        assert_eq!(parse_users("{\"detail\":\"Not authenticated\"}", ""), Err(Refusal::Failed));
    }

    #[test]
    fn only_an_admin_sign_in_is_accepted() {
        assert_eq!(parse_login(SIGNIN).unwrap(), "eyJhbGciOiJIUzI1NiJ9.example.signature");
        let member = SIGNIN.replace("\"role\": \"admin\"", "\"role\": \"user\"");
        assert_eq!(parse_login(&member), Err(Refusal::AdminLoginFailed));
        assert_eq!(parse_login("{}"), Err(Refusal::AdminLoginFailed));
    }

    #[test]
    fn an_update_keeps_the_profile_and_changes_one_field() {
        let current: Value = serde_json::from_str(&SIGNIN).unwrap();
        let body = update_body(&current, json!({ "role": "user" }));
        assert_eq!(body["role"], "user");
        assert_eq!(body["email"], "operator@example.org");
        assert_eq!(body["profile_image_url"], "/user.png");
        assert_eq!(update_body(&current, json!({ "password": "x" }))["password"], "x");
    }

    #[test]
    fn passwords_and_tokens_stay_out_of_the_arguments_and_url() {
        let sent = [
            login_request("operator@example.org", "s3cr3t-pass-word"),
            request(Some("tok-abcdef"), "POST", "/auths/add", Some(create_body(&new_user()))),
        ];
        for item in &sent {
            assert!(!item.url.contains("s3cr3t") && !item.url.contains("tok-abcdef"));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains("tok-abcdef")));
    }

    #[test]
    fn the_admin_config_keeps_every_field_and_sets_two() {
        let current = json!({ "ENABLE_SIGNUP": false, "DEFAULT_USER_ROLE": "pending", "WEBUI_URL": "https://x", "JWT_EXPIRES_IN": "4w" });
        let body = admin_config_update(&current, true, "user").unwrap();
        assert_eq!(body["ENABLE_SIGNUP"], true);
        assert_eq!(body["DEFAULT_USER_ROLE"], "user");
        assert_eq!(body["WEBUI_URL"], "https://x");
        assert_eq!(body["JWT_EXPIRES_IN"], "4w");
        assert!(admin_config_update(&json!([1]), true, "user").is_none());
    }

    #[test]
    fn a_new_account_is_named_after_its_address() {
        let body = create_body(&new_user());
        assert_eq!(body["name"], "clara");
        assert_eq!(body["email"], "clara@example.org");
        assert_eq!(body["role"], "user");
    }

    #[test]
    fn pending_accounts_can_be_approved_but_not_switched_off() {
        let caps = capabilities();
        assert!(caps.roles.contains(&"pending".to_string()));
        assert!(!caps.can_set_enabled && !caps.can_set_quota && caps.user_id_is_email);
    }
}
