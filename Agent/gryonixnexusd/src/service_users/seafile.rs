//! Seafile accounts through the seahub admin API

use serde_json::Value;

use super::http::{self, form_body, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::seafile::{CONTAINER, WEB_UI_PORT};
use crate::{discover, pb};

pub const SERVICE_ID: &str = "seafile";
const ROLE_USER: &str = "user";
const MEGABYTE: i64 = 1 << 20;
const FORM: &str = "application/x-www-form-urlencoded";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_enabled: true,
        can_set_quota: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        needs_email: true,
        user_id_is_email: true,
        ..Default::default()
    }
}

pub struct Seafile {
    token: String,
    admin_email: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}")
}

pub fn request(token: Option<&str>, method: &'static str, path: &str, body: Option<String>) -> Request {
    let mut headers = vec![("Content-Type".to_string(), FORM.to_string())];
    if let Some(token) = token {
        headers.push(("Authorization".into(), format!("Token {token}")));
    }
    Request { method, url: format!("{}{path}", base()), headers, body }
}

pub fn login_request(email: &str, password: &str) -> Request {
    let body = form_body(&[("username", email), ("password", password)]);
    request(None, "POST", "/api2/auth-token/", Some(body))
}

pub fn parse_token(body: &str) -> Result<String, Refusal> {
    let value: Value = serde_json::from_str(body.trim()).map_err(|_| Refusal::Failed)?;
    match value.get("token").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(Refusal::Failed),
    }
}

/// The users in the admin list answer
pub fn parse_users(json: &str, admin_email: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.get("data").and_then(Value::as_array).ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let number = |key: &str| row.get(key).and_then(Value::as_i64).unwrap_or(0).max(0);
            let flag = |key: &str, default: bool| row.get(key).and_then(Value::as_bool).unwrap_or(default);
            let email = text("email");
            (!email.is_empty()).then(|| pb::ServiceUser {
                id: email.clone(),
                login: email.clone(),
                display_name: text("name"),
                is_self: email.eq_ignore_ascii_case(admin_email),
                email,
                role: if flag("is_staff", false) { ADMIN_ROLE } else { ROLE_USER }.to_string(),
                enabled: flag("is_active", true),
                quota_bytes: number("quota_total"),
                used_bytes: number("quota_usage"),
            })
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

fn megabytes(bytes: i64) -> String {
    ((bytes + MEGABYTE - 1) / MEGABYTE).to_string()
}

fn flag_text(on: bool) -> &'static str {
    if on { "True" } else { "False" }
}

pub fn create_body(new: &NewUser) -> String {
    let staff = flag_text(new.role == ADMIN_ROLE);
    let mut pairs = vec![("email", new.login.as_str()), ("password", new.password.as_str()), ("is_staff", staff)];
    if !new.display_name.is_empty() {
        pairs.push(("name", new.display_name.as_str()));
    }
    let quota = megabytes(new.quota_bytes);
    if new.quota_bytes > 0 {
        pairs.push(("quota_total", quota.as_str()));
    }
    form_body(&pairs)
}

impl Seafile {
    pub async fn find(vault: Option<(String, String)>) -> Result<Option<Seafile>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (email, password) = match vault {
            Some(login) => login,
            None => installer_login().await.ok_or(Refusal::AdminNotSetUp)?,
        };
        let answer = http::send(&login_request(&email, &password)).await?;
        if answer.status == 400 || answer.status == 401 || answer.status == 403 {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        Ok(Some(Seafile { token: parse_token(&answer.body)?, admin_email: email }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<String>) -> Result<Response, Refusal> {
        let answer = http::send(&request(Some(&self.token), method, path, body)).await?;
        match answer.status {
            403 => Err(Refusal::AdminLoginFailed),
            _ if answer.ok() => Ok(answer),
            _ => Err(Refusal::Failed),
        }
    }

    async fn update(&self, user_id: &str, pairs: &[(&str, &str)]) -> Done {
        let path = format!("/api/v2.1/admin/users/{user_id}/");
        self.call("PUT", &path, Some(form_body(pairs))).await.map(|_| ())
    }
}

/// The admin the installer created, from the container's environment
async fn installer_login() -> Option<(String, String)> {
    let env = super::container_env(CONTAINER).await?;
    let email = super::env_value(&env, "INIT_SEAFILE_ADMIN_EMAIL")?;
    let password = super::env_value(&env, "INIT_SEAFILE_ADMIN_PASSWORD")?;
    Some((email, password))
}

impl UserBackend for Seafile {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let answer = self.call("GET", "/api/v2.1/admin/users/?per_page=500", None).await?;
        parse_users(&answer.body, &self.admin_email)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/api/v2.1/admin/users/", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/api/v2.1/admin/users/{user_id}/"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.update(user_id, &[("password", password)]).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.update(user_id, &[("is_staff", flag_text(role == ADMIN_ROLE))]).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.update(user_id, &[("is_active", flag_text(enabled))]).await
    }

    async fn set_quota(&self, user_id: &str, bytes: i64) -> Done {
        if bytes <= 0 {
            return Err(Refusal::InvalidQuota);
        }
        self.update(user_id, &[("quota_total", &megabytes(bytes))]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/seafile/users.json");

    fn new_user() -> NewUser {
        NewUser {
            login: "boris@example.org".into(),
            display_name: "Boris B".into(),
            email: "boris@example.org".into(),
            password: "s3cr3t-pass&word".into(),
            role: "admin".into(),
            quota_bytes: 3 * MEGABYTE + 1,
        }
    }

    #[test]
    fn the_admin_list_parses() {
        let users = parse_users(USERS, "Operator@example.org").unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["anna@example.org", "boris@example.org", "operator@example.org"]);
        let anna = &users[0];
        assert_eq!((anna.id.as_str(), anna.display_name.as_str(), anna.role.as_str()), ("anna@example.org", "Anna", "user"));
        assert_eq!((anna.quota_bytes, anna.used_bytes), (5 * 1024 * MEGABYTE, 2 * MEGABYTE));
        assert!(!users[1].enabled);
        assert_eq!((users[2].role.as_str(), users[2].is_self, users[2].quota_bytes), ("admin", true, 0));
    }

    #[test]
    fn an_answer_without_data_is_a_failure() {
        assert_eq!(parse_users("{\"detail\":\"x\"}", ""), Err(Refusal::Failed));
        assert!(parse_users("{\"data\":[],\"total_count\":0}", "").unwrap().is_empty());
    }

    #[test]
    fn the_login_answer_carries_a_token() {
        assert_eq!(parse_token("{\"token\":\"abc123\"}"), Ok("abc123".to_string()));
        assert_eq!(parse_token("{\"non_field_errors\":[\"x\"]}"), Err(Refusal::Failed));
    }

    #[test]
    fn the_create_form_encodes_values_and_rounds_the_quota_up() {
        let body = create_body(&new_user());
        assert!(body.contains("email=boris%40example.org"));
        assert!(body.contains("password=s3cr3t-pass%26word"));
        assert!(body.contains("is_staff=True"));
        assert!(body.contains("name=Boris%20B"));
        assert!(body.ends_with("quota_total=4"));
    }

    #[test]
    fn the_password_travels_in_the_body_only() {
        let sent = [login_request("operator@example.org", "s3cr3t-pass"), request(Some("tok"), "PUT", "/api/v2.1/admin/users/a%40b.org/", Some(form_body(&[("password", "s3cr3t-pass")])))];
        for item in &sent {
            assert!(!item.url.contains("s3cr3t"));
            assert!(item.body.as_deref().unwrap().contains("s3cr3t-pass"));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains("tok")));
    }

    #[test]
    fn requests_carry_the_token_header() {
        let sent = request(Some("tok-1"), "GET", "/api/v2.1/admin/users/", None);
        assert!(sent.headers.contains(&("Authorization".to_string(), "Token tok-1".to_string())));
        assert!(!login_request("a", "b").headers.iter().any(|(name, _)| name == "Authorization"));
    }

    #[test]
    fn the_login_is_the_email() {
        let caps = capabilities();
        assert!(caps.user_id_is_email && caps.needs_email && caps.can_set_quota && caps.can_set_enabled);
        assert_eq!(megabytes(1), "1");
        assert_eq!(megabytes(MEGABYTE), "1");
    }
}
