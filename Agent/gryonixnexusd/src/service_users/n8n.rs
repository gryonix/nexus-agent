use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::n8n::WEB_UI_PORT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "n8n";
const ROLE_USER: &str = "user";
const OWNER: &str = "global:owner";
const MAX_PAGES: usize = 20;

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        needs_email: true,
        user_id_is_email: true,
        note: super::TOKEN_NOTE.to_string(),
        ..Default::default()
    }
}

pub struct N8n {
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
            ("X-N8N-API-KEY".into(), key.to_string()),
        ],
        body: body.map(|v| v.to_string()),
    }
}

pub fn n8n_role(role: &str) -> &'static str {
    if role == ADMIN_ROLE { "global:admin" } else { "global:member" }
}

pub fn parse_page(json: &str) -> Result<(Vec<pb::ServiceUser>, Option<String>), Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.get("data").and_then(Value::as_array).ok_or(Refusal::Failed)?;
    let users = rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let (id, email, role) = (text("id"), text("email"), text("role"));
            let name = format!("{} {}", text("firstName"), text("lastName")).trim().to_string();
            (!id.is_empty()).then(|| pb::ServiceUser {
                id,
                login: email.clone(),
                display_name: name,
                email,
                role: if role == "global:member" { ROLE_USER } else { ADMIN_ROLE }.to_string(),
                enabled: true,
                is_self: role == OWNER,
                ..Default::default()
            })
        })
        .collect();
    let cursor = value.get("nextCursor").and_then(Value::as_str).filter(|c| !c.is_empty()).map(String::from);
    Ok((users, cursor))
}

pub fn invite_body(new: &NewUser) -> Value {
    json!([{ "email": new.login, "role": n8n_role(&new.role) }])
}

impl N8n {
    pub async fn find(vault: Option<(String, String)>) -> Result<Option<N8n>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (_, key) = vault.ok_or(Refusal::NeedsAdminToken)?;
        Ok(Some(N8n { key }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(&self.key, method, path, body)).await?;
        match answer.status {
            401 | 403 => Err(Refusal::AdminLoginFailed),
            _ if answer.ok() => Ok(answer),
            _ => Err(Refusal::Failed),
        }
    }
}

impl UserBackend for N8n {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let mut users = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut path = "/users?limit=100&includeRole=true".to_string();
            if let Some(next) = &cursor {
                path.push_str(&format!("&cursor={}", http::form_encode(next)));
            }
            let (rows, next) = parse_page(&self.call("GET", &path, None).await?.body)?;
            users.extend(rows);
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        users.sort_by_key(|user| user.login.to_lowercase());
        Ok(users)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/users", Some(invite_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.call("PATCH", &format!("/users/{user_id}/role"), Some(json!({ "newRoleName": n8n_role(role) }))).await.map(|_| ())
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

    const USERS: &str = include_str!("../../tests/fixtures/service_users/n8n/users.json");
    const KEY: &str = "n8n_api_0123456789abcdef";

    #[test]
    fn the_user_page_parses_and_the_owner_is_protected() {
        let (users, cursor) = parse_page(USERS).unwrap();
        let rows: Vec<(&str, &str, bool)> = users.iter().map(|u| (u.login.as_str(), u.role.as_str(), u.is_self)).collect();
        assert_eq!(
            rows,
            [("operator@example.org", "admin", true), ("anna@example.org", "user", false), ("boris@example.org", "admin", false)]
        );
        assert_eq!(users[0].display_name, "Operator Admin");
        assert_eq!(users[2].display_name, "");
        assert_eq!(cursor, None);
    }

    #[test]
    fn a_next_cursor_is_returned_and_an_error_is_a_failure() {
        let (_, cursor) = parse_page("{\"data\":[],\"nextCursor\":\"abc==\"}").unwrap();
        assert_eq!(cursor.as_deref(), Some("abc=="));
        assert_eq!(parse_page("{\"message\":\"unauthorized\"}"), Err(Refusal::Failed));
    }

    #[test]
    fn an_invitation_is_a_list_with_the_role() {
        let new = NewUser {
            login: "clara@example.org".into(),
            display_name: String::new(),
            email: "clara@example.org".into(),
            password: String::new(),
            role: "user".into(),
            quota_bytes: 0,
        };
        assert_eq!(invite_body(&new), json!([{ "email": "clara@example.org", "role": "global:member" }]));
        assert_eq!(n8n_role("admin"), "global:admin");
    }

    #[test]
    fn the_api_key_stays_out_of_the_arguments_and_url() {
        let sent = request(KEY, "GET", "/users", None);
        assert!(!sent.url.contains(KEY));
        assert!(sent.headers.contains(&("X-N8N-API-KEY".to_string(), KEY.to_string())));
        assert!(http::arguments().iter().all(|arg| !arg.contains(KEY)));
    }

    #[test]
    fn invited_people_set_their_own_password() {
        let caps = capabilities();
        assert!(!caps.can_set_password && !caps.can_set_enabled && caps.needs_email && caps.user_id_is_email);
    }
}
