//! Immich accounts through its admin REST API

use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::immich::WEB_UI_PORT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "immich";
const ROLE_USER: &str = "user";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_quota: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        needs_email: true,
        user_id_is_email: true,
        ..Default::default()
    }
}

pub struct Immich {
    token: String,
    admin_email: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}/api")
}

pub fn request(token: Option<&str>, method: &'static str, path: &str, body: Option<Value>) -> Request {
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    if let Some(token) = token {
        headers.push(("Authorization".into(), format!("Bearer {token}")));
    }
    Request { method, url: format!("{}{path}", base()), headers, body: body.map(|v| v.to_string()) }
}

pub fn login_request(email: &str, password: &str) -> Request {
    request(None, "POST", "/auth/login", Some(json!({ "email": email, "password": password })))
}

/// The access token of an admin login answer
pub fn parse_login(body: &str) -> Result<String, Refusal> {
    let value: Value = serde_json::from_str(body.trim()).map_err(|_| Refusal::Failed)?;
    if value.get("isAdmin").and_then(Value::as_bool) != Some(true) {
        return Err(Refusal::AdminLoginFailed);
    }
    match value.get("accessToken").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(Refusal::Failed),
    }
}

/// The users in `GET /admin/users`
pub fn parse_users(json: &str, admin_email: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.as_array().ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter(|row| row.get("deletedAt").map_or(true, Value::is_null))
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let number = |key: &str| row.get(key).and_then(Value::as_i64).unwrap_or(0).max(0);
            let (id, email) = (text("id"), text("email"));
            let is_admin = row.get("isAdmin").and_then(Value::as_bool).unwrap_or(false);
            (!id.is_empty()).then(|| pb::ServiceUser {
                id,
                login: email.clone(),
                display_name: text("name"),
                is_self: email.eq_ignore_ascii_case(admin_email),
                email,
                role: if is_admin { ADMIN_ROLE } else { ROLE_USER }.to_string(),
                enabled: true,
                quota_bytes: number("quotaSizeInBytes"),
                used_bytes: number("quotaUsageInBytes"),
            })
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

pub fn create_body(new: &NewUser) -> Value {
    let name = if new.display_name.is_empty() {
        new.login.split('@').next().unwrap_or_default().to_string()
    } else {
        new.display_name.clone()
    };
    json!({
        "email": new.login,
        "password": new.password,
        "name": name,
        "isAdmin": new.role == ADMIN_ROLE,
        "quotaSizeInBytes": if new.quota_bytes > 0 { json!(new.quota_bytes) } else { Value::Null },
        "shouldChangePassword": false,
        "notify": false,
    })
}

impl Immich {
    pub async fn find(login: Option<(String, String)>) -> Result<Option<Immich>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (email, password) = login.ok_or(Refusal::AdminNotSetUp)?;
        let answer = http::send(&login_request(&email, &password)).await?;
        if answer.status == 401 || answer.status == 400 {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        Ok(Some(Immich { token: parse_login(&answer.body)?, admin_email: email }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(Some(&self.token), method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    async fn update(&self, user_id: &str, body: Value) -> Done {
        self.call("PUT", &format!("/admin/users/{user_id}"), Some(body)).await.map(|_| ())
    }
}

impl UserBackend for Immich {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        parse_users(&self.call("GET", "/admin/users", None).await?.body, &self.admin_email)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/admin/users", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        let body = json!({ "force": true });
        self.call("DELETE", &format!("/admin/users/{user_id}"), Some(body)).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.update(user_id, json!({ "password": password })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.update(user_id, json!({ "isAdmin": role == ADMIN_ROLE })).await
    }

    async fn set_enabled(&self, _: &str, _: bool) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_quota(&self, user_id: &str, bytes: i64) -> Done {
        let quota = if bytes > 0 { json!(bytes) } else { Value::Null };
        self.update(user_id, json!({ "quotaSizeInBytes": quota })).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/immich/users.json");
    const LOGIN: &str = include_str!("../../tests/fixtures/service_users/immich/login.json");

    fn new_user() -> NewUser {
        NewUser {
            login: "boris@example.org".into(),
            display_name: String::new(),
            email: "boris@example.org".into(),
            password: "s3cr3t-pass-word".into(),
            role: "user".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_admin_list_parses() {
        let users = parse_users(USERS, "Operator@Example.org").unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["anna@example.org", "operator@example.org"]);
        let anna = &users[0];
        assert_eq!((anna.role.as_str(), anna.quota_bytes, anna.used_bytes), ("user", 10_737_418_240, 1_048_576));
        assert!(!anna.is_self && anna.enabled);
        let operator = &users[1];
        assert_eq!((operator.role.as_str(), operator.quota_bytes), ("admin", 0));
        assert!(operator.is_self);
    }

    #[test]
    fn a_removed_user_is_not_listed() {
        assert!(!parse_users(USERS, "").unwrap().iter().any(|u| u.login == "gone@example.org"));
    }

    #[test]
    fn a_non_list_answer_is_a_failure() {
        assert_eq!(parse_users("{\"message\":\"x\"}", ""), Err(Refusal::Failed));
        assert!(parse_users("[]", "").unwrap().is_empty());
    }

    #[test]
    fn only_an_admin_login_gives_a_token() {
        assert_eq!(parse_login(LOGIN), Ok("tok-abc".to_string()));
        let plain = LOGIN.replace("\"isAdmin\": true", "\"isAdmin\": false");
        assert_eq!(parse_login(&plain), Err(Refusal::AdminLoginFailed));
        assert_eq!(parse_login("nope"), Err(Refusal::Failed));
    }

    #[test]
    fn the_admin_flag_is_named_is_admin_and_the_quota_quota_size_in_bytes() {
        let mut new = new_user();
        new.role = "admin".into();
        new.quota_bytes = 1024;
        let body = create_body(&new);
        assert_eq!(body["isAdmin"], true);
        assert_eq!(body["quotaSizeInBytes"], 1024);
        assert_eq!(body["name"], "boris");
        assert_eq!(create_body(&new_user())["quotaSizeInBytes"], Value::Null);
    }

    #[test]
    fn passwords_travel_in_the_body_never_in_the_url_or_arguments() {
        let sent = [login_request("operator@example.org", "s3cr3t-pass-word"), request(Some("tok"), "PUT", "/admin/users/x", Some(json!({"password": "s3cr3t-pass-word"})))];
        for request in &sent {
            assert!(!request.url.contains("s3cr3t"));
            assert!(request.body.as_deref().unwrap().contains("s3cr3t-pass-word"));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains("tok")));
    }

    #[test]
    fn requests_carry_a_bearer_token() {
        let sent = request(Some("tok-abc"), "GET", "/admin/users", None);
        assert_eq!(sent.url, "http://127.0.0.1:2283/api/admin/users");
        assert!(sent.headers.contains(&("Authorization".to_string(), "Bearer tok-abc".to_string())));
        assert!(request(None, "POST", "/auth/login", None).headers.iter().all(|(name, _)| name != "Authorization"));
    }

    #[test]
    fn this_service_has_roles_and_quota_but_no_off_switch() {
        let caps = capabilities();
        assert!(caps.can_set_quota && caps.can_set_password && !caps.can_set_enabled);
        assert_eq!(caps.roles, ["admin", "user"]);
        assert!(caps.user_id_is_email);
    }
}
