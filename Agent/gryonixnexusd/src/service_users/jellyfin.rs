//! Jellyfin accounts through its REST API

use serde_json::{json, Value};

use super::http::{self, Request, Response};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::jellyfin::WEB_UI_PORT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "jellyfin";
const ROLE_USER: &str = "user";
const CLIENT: &str = "Client=\"gryonix\", Device=\"agent\", DeviceId=\"gryonixnexusd\", Version=\"1\"";

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

pub struct Jellyfin {
    token: String,
    admin_name: String,
}

fn base() -> String {
    format!("http://127.0.0.1:{WEB_UI_PORT}")
}

pub fn request(token: Option<&str>, method: &'static str, path: &str, body: Option<Value>) -> Request {
    let auth = match token {
        Some(token) => format!("MediaBrowser {CLIENT}, Token=\"{token}\""),
        None => format!("MediaBrowser {CLIENT}"),
    };
    Request {
        method,
        url: format!("{}{path}", base()),
        headers: vec![("Content-Type".into(), "application/json".into()), ("Authorization".into(), auth)],
        body: body.map(|v| v.to_string()),
    }
}

pub fn login_request(name: &str, password: &str) -> Request {
    request(None, "POST", "/Users/AuthenticateByName", Some(json!({ "Username": name, "Pw": password })))
}

/// The access token of an administrator's login answer
pub fn parse_login(body: &str) -> Result<String, Refusal> {
    let value: Value = serde_json::from_str(body.trim()).map_err(|_| Refusal::Failed)?;
    let admin = value.pointer("/User/Policy/IsAdministrator").and_then(Value::as_bool);
    if admin != Some(true) {
        return Err(Refusal::AdminLoginFailed);
    }
    match value.get("AccessToken").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(Refusal::Failed),
    }
}

fn parse_user(row: &Value, admin_name: &str) -> Option<pb::ServiceUser> {
    let id = row.get("Id").and_then(Value::as_str).filter(|id| !id.is_empty())?;
    let name = row.get("Name").and_then(Value::as_str).unwrap_or_default();
    let flag = |key: &str| row.pointer(&format!("/Policy/{key}")).and_then(Value::as_bool).unwrap_or(false);
    Some(pb::ServiceUser {
        id: id.to_string(),
        login: name.to_string(),
        display_name: name.to_string(),
        role: if flag("IsAdministrator") { ADMIN_ROLE } else { ROLE_USER }.to_string(),
        enabled: !flag("IsDisabled"),
        is_self: name.eq_ignore_ascii_case(admin_name),
        ..Default::default()
    })
}

/// The users in `GET /Users`
pub fn parse_users(json: &str, admin_name: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value: Value = serde_json::from_str(json.trim()).map_err(|_| Refusal::Failed)?;
    let rows = value.as_array().ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows.iter().filter_map(|row| parse_user(row, admin_name)).collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

pub fn policy_with(user: &str, key: &str, value: bool) -> Result<Value, Refusal> {
    let mut parsed: Value = serde_json::from_str(user.trim()).map_err(|_| Refusal::Failed)?;
    let policy = parsed.get_mut("Policy").and_then(Value::as_object_mut).ok_or(Refusal::Failed)?;
    policy.insert(key.to_string(), Value::Bool(value));
    Ok(Value::Object(policy.clone()))
}

/// The server configuration with boolean fields set
pub fn config_with_flags(config: &str, flags: &[(&str, bool)]) -> Result<Value, Refusal> {
    let mut parsed: Value = serde_json::from_str(config.trim()).map_err(|_| Refusal::Failed)?;
    let map = parsed.as_object_mut().ok_or(Refusal::Failed)?;
    for (name, on) in flags {
        map.insert((*name).to_string(), Value::Bool(*on));
    }
    Ok(parsed)
}

impl Jellyfin {
    pub async fn find(login: Option<(String, String)>) -> Result<Option<Jellyfin>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (name, password) = login.ok_or(Refusal::AdminNotSetUp)?;
        let answer = http::send(&login_request(&name, &password)).await?;
        if answer.status == 401 || answer.status == 400 || answer.status == 403 {
            return Err(Refusal::AdminLoginFailed);
        }
        if !answer.ok() {
            return Err(Refusal::Failed);
        }
        Ok(Some(Jellyfin { token: parse_login(&answer.body)?, admin_name: name }))
    }

    async fn call(&self, method: &'static str, path: &str, body: Option<Value>) -> Result<Response, Refusal> {
        let answer = http::send(&request(Some(&self.token), method, path, body)).await?;
        if answer.ok() { Ok(answer) } else { Err(Refusal::Failed) }
    }

    /// Sets flags in the server configuration, keeping the rest
    pub async fn set_server_flags(&self, flags: &[(&str, bool)]) -> Done {
        let current = self.call("GET", "/System/Configuration", None).await?;
        let body = config_with_flags(&current.body, flags)?;
        self.call("POST", "/System/Configuration", Some(body)).await.map(|_| ())
    }

    async fn set_flag(&self, user_id: &str, key: &str, value: bool) -> Done {
        let current = self.call("GET", &format!("/Users/{user_id}"), None).await?;
        let policy = policy_with(&current.body, key, value)?;
        self.call("POST", &format!("/Users/{user_id}/Policy"), Some(policy)).await.map(|_| ())
    }
}

impl UserBackend for Jellyfin {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        parse_users(&self.call("GET", "/Users", None).await?.body, &self.admin_name)
    }

    async fn create(&self, new: &NewUser) -> Done {
        let body = json!({ "Name": new.login, "Password": new.password });
        let created = self.call("POST", "/Users/New", Some(body)).await?;
        if new.role != ADMIN_ROLE {
            return Ok(());
        }
        let id = serde_json::from_str::<Value>(&created.body)
            .ok()
            .and_then(|user| user.get("Id").and_then(Value::as_str).map(String::from))
            .ok_or(Refusal::Failed)?;
        self.set_flag(&id, "IsAdministrator", true).await
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.call("DELETE", &format!("/Users/{user_id}"), None).await.map(|_| ())
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        let body = json!({ "NewPw": password });
        self.call("POST", &format!("/Users/Password?userId={user_id}"), Some(body)).await.map(|_| ())
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.set_flag(user_id, "IsAdministrator", role == ADMIN_ROLE).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.set_flag(user_id, "IsDisabled", !enabled).await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/jellyfin/users.json");
    const LOGIN: &str = include_str!("../../tests/fixtures/service_users/jellyfin/login.json");
    const USER: &str = include_str!("../../tests/fixtures/service_users/jellyfin/user.json");

    #[test]
    fn the_server_configuration_keeps_its_fields_and_sets_flags() {
        let body = config_with_flags("{\"ServerName\":\"x\",\"QuickConnectAvailable\":true}", &[("QuickConnectAvailable", false)]).unwrap();
        assert_eq!(body["ServerName"], "x");
        assert_eq!(body["QuickConnectAvailable"], false);
        assert!(config_with_flags("[]", &[]).is_err());
    }

    #[test]
    fn the_user_list_parses() {
        let users = parse_users(USERS, "Operator").unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["anna", "boris", "operator"]);
        assert_eq!((users[0].role.as_str(), users[0].enabled, users[0].is_self), ("user", true, false));
        assert!(!users[1].enabled);
        assert_eq!((users[2].role.as_str(), users[2].is_self), ("admin", true));
        assert_eq!(users[0].id, "11111111111111111111111111111111");
    }

    #[test]
    fn a_non_list_answer_is_a_failure() {
        assert_eq!(parse_users("{\"title\":\"x\"}", ""), Err(Refusal::Failed));
        assert!(parse_users("[]", "").unwrap().is_empty());
    }

    #[test]
    fn only_an_administrators_login_gives_a_token() {
        assert_eq!(parse_login(LOGIN), Ok("token-abc".to_string()));
        let plain = LOGIN.replace("\"IsAdministrator\": true", "\"IsAdministrator\": false");
        assert_eq!(parse_login(&plain), Err(Refusal::AdminLoginFailed));
    }

    #[test]
    fn a_policy_change_keeps_every_other_field() {
        let policy = policy_with(USER, "IsDisabled", true).unwrap();
        assert_eq!(policy["IsDisabled"], true);
        assert_eq!(policy["IsAdministrator"], false);
        assert_eq!(policy["EnableAllFolders"], true);
        assert_eq!(policy["LoginAttemptsBeforeLockout"], -1);
        assert_eq!(policy_with("{}", "IsDisabled", true), Err(Refusal::Failed));
    }

    #[test]
    fn passwords_travel_in_the_body_only() {
        let sent = [
            login_request("operator", "s3cr3t-pass-word"),
            request(Some("tok"), "POST", "/Users/Password?userId=abc", Some(json!({ "NewPw": "s3cr3t-pass-word" }))),
        ];
        for sent in &sent {
            assert!(!sent.url.contains("s3cr3t"));
            assert!(sent.body.as_deref().unwrap().contains("s3cr3t-pass-word"));
        }
        assert!(http::arguments().iter().all(|arg| !arg.contains("s3cr3t") && !arg.contains("tok")));
    }

    #[test]
    fn the_token_rides_in_the_media_browser_header() {
        let sent = request(Some("tok-1"), "GET", "/Users", None);
        let auth = &sent.headers.iter().find(|(name, _)| name == "Authorization").unwrap().1;
        assert!(auth.starts_with("MediaBrowser Client=\"gryonix\""));
        assert!(auth.ends_with("Token=\"tok-1\""));
        assert!(!login_request("a", "b").headers.iter().any(|(_, value)| value.contains("Token=")));
    }

    #[test]
    fn this_service_has_roles_and_an_off_switch_but_no_quota() {
        let caps = capabilities();
        assert!(caps.can_set_enabled && caps.can_set_password && !caps.can_set_quota);
        assert_eq!(caps.roles, ["admin", "user"]);
        assert!(!caps.user_id_is_email && !caps.needs_email);
    }
}
