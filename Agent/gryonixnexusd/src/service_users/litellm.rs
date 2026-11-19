//! LiteLLM gateway users through its admin API and master key

use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::litellm::{CONTAINER, WEB_UI_PORT};
use crate::{discover, pb};

pub const SERVICE_ID: &str = "litellm";
const ROLE_USER: &str = "user";
const ROLE_VIEWER: &str = "viewer";
const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 20;
const DEFAULT_USER: &str = "default_user_id";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string(), ROLE_VIEWER.to_string()],
        ..Default::default()
    }
}

pub struct Litellm {
    key: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}")
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

pub fn to_role(litellm_role: &str) -> &'static str {
    match litellm_role {
        "proxy_admin" => ADMIN_ROLE,
        "internal_user_viewer" => ROLE_VIEWER,
        _ => ROLE_USER,
    }
}

pub fn from_role(role: &str) -> &'static str {
    match role {
        ADMIN_ROLE => "proxy_admin",
        ROLE_VIEWER => "internal_user_viewer",
        _ => "internal_user",
    }
}

pub fn parse_users(json: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.get("users").and_then(Value::as_array).ok_or(Refusal::Failed)?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let id = text("user_id");
            (!id.is_empty() && id != DEFAULT_USER).then(|| pb::ServiceUser {
                login: id.clone(),
                email: text("user_email"),
                role: to_role(&text("user_role")).to_string(),
                enabled: true,
                id,
                ..Default::default()
            })
        })
        .collect())
}

pub fn create_body(new: &NewUser) -> Value {
    json!({
        "user_id": new.login,
        "user_email": if new.email.is_empty() { Value::Null } else { json!(new.email) },
        "user_role": from_role(&new.role),
        "auto_create_key": false,
        "send_invite_email": false,
    })
}

impl Litellm {
    pub async fn find() -> Result<Option<Litellm>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let env = super::container_env(CONTAINER).await.ok_or(Refusal::ServiceDown)?;
        let key = super::env_value(&env, "LITELLM_MASTER_KEY").filter(|key| !key.is_empty()).ok_or(Refusal::NeedsAdminToken)?;
        Ok(Some(Litellm { key }))
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

impl UserBackend for Litellm {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let mut users = Vec::new();
        for page in 1..=MAX_PAGES {
            let path = format!("/user/list?page={page}&page_size={PAGE_SIZE}");
            let rows = parse_users(&self.call("GET", &path, None).await?.body)?;
            let more = rows.len() >= PAGE_SIZE - 1;
            users.extend(rows);
            if !more {
                break;
            }
        }
        users.sort_by_key(|user| user.login.to_lowercase());
        Ok(users)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.call("POST", "/user/new", Some(create_body(new))).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("POST", "/user/delete", Some(json!({ "user_ids": [user_id] }))).await.map(|_| ())
    }

    async fn set_password(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.call("POST", "/user/update", Some(json!({ "user_id": user_id, "user_role": from_role(role) }))).await.map(|_| ())
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

    const USERS: &str = include_str!("../../tests/fixtures/service_users/litellm/users.json");
    const KEY: &str = "sk-master-0123456789";

    fn new_user() -> NewUser {
        NewUser {
            login: "clara".into(),
            display_name: String::new(),
            email: "clara@example.org".into(),
            password: String::new(),
            role: "viewer".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_user_page_parses_and_hides_the_default_user() {
        let users = parse_users(USERS).unwrap();
        let rows: Vec<(&str, &str, &str)> = users.iter().map(|u| (u.id.as_str(), u.role.as_str(), u.email.as_str())).collect();
        assert_eq!(rows, [("operator", "admin", "operator@example.org"), ("anna", "user", "anna@example.org"), ("boris", "viewer", "")]);
        assert_eq!(parse_users("{\"detail\":\"Authentication Error\"}"), Err(Refusal::Failed));
    }

    #[test]
    fn roles_map_both_ways() {
        for (ours, theirs) in [("admin", "proxy_admin"), ("user", "internal_user"), ("viewer", "internal_user_viewer")] {
            assert_eq!(from_role(ours), theirs);
            assert_eq!(to_role(theirs), ours);
        }
        assert_eq!(to_role("customer"), "user");
    }

    #[test]
    fn the_master_key_stays_out_of_the_arguments_and_url() {
        let sent = request(KEY, "POST", "/user/new", Some(create_body(&new_user())));
        assert!(!sent.url.contains(KEY));
        assert!(sent.headers.contains(&("Authorization".to_string(), format!("Bearer {KEY}"))));
        assert!(http::arguments().iter().all(|arg| !arg.contains(KEY)));
    }

    #[test]
    fn a_new_user_gets_no_key_and_no_invitation_mail() {
        let body = create_body(&new_user());
        assert_eq!(body["user_role"], "internal_user_viewer");
        assert_eq!(body["auto_create_key"], false);
        assert_eq!(body["send_invite_email"], false);
        let mut without = new_user();
        without.email.clear();
        assert!(create_body(&without)["user_email"].is_null());
    }

    #[test]
    fn this_service_has_no_passwords_and_no_off_switch() {
        let caps = capabilities();
        assert!(!caps.can_set_password && !caps.can_set_enabled && !caps.can_set_quota && caps.roles.len() == 3);
    }
}
