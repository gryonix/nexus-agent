//! Home Assistant accounts through its WebSocket API and a long-lived token

use serde_json::{json, Value};

use super::ws::Socket;
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::home_assistant::WEB_UI_PORT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "home-assistant";
const ROLE_USER: &str = "user";
const GROUP_ADMIN: &str = "system-admin";
const GROUP_USER: &str = "system-users";
const PATH: &str = "/api/websocket";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_enabled: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        note: super::TOKEN_NOTE.to_string(),
        ..Default::default()
    }
}

pub struct HomeAssistant {
    token: String,
}

pub fn auth_message(token: &str) -> String {
    json!({ "type": "auth", "access_token": token }).to_string()
}

pub fn command_message(id: u64, command: &Value) -> String {
    let mut message = command.clone();
    if let Some(object) = message.as_object_mut() {
        object.insert("id".to_string(), json!(id));
    }
    message.to_string()
}

/// The `type` of a server message
pub fn message_type(text: &str) -> Option<String> {
    serde_json::from_str::<Value>(text).ok()?.get("type")?.as_str().map(String::from)
}

/// The result of a command answer, or why it failed
pub fn result_of(text: &str, id: u64) -> Option<Result<Value, Refusal>> {
    let value: Value = serde_json::from_str(text).ok()?;
    if value.get("id").and_then(Value::as_u64) != Some(id) || value.get("type").and_then(Value::as_str) != Some("result") {
        return None;
    }
    if value.get("success").and_then(Value::as_bool) == Some(true) {
        return Some(Ok(value.get("result").cloned().unwrap_or(Value::Null)));
    }
    let code = value.get("error").and_then(|error| error.get("code")).and_then(Value::as_str).unwrap_or_default();
    Some(Err(if code == "not_found" { Refusal::UnknownUser } else { Refusal::Failed }))
}

pub fn parse_users(result: &Value) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let rows = result.as_array().ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter(|row| !row.get("system_generated").and_then(Value::as_bool).unwrap_or(false))
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
            let id = text("id");
            let name = text("name");
            let username = text("username");
            let groups = row.get("group_ids").and_then(Value::as_array);
            let admin = groups.is_some_and(|groups| groups.iter().any(|group| group.as_str() == Some(GROUP_ADMIN)));
            (!id.is_empty()).then(|| pb::ServiceUser {
                id,
                login: if username.is_empty() { name.clone() } else { username },
                display_name: name,
                role: if admin { ADMIN_ROLE } else { ROLE_USER }.to_string(),
                enabled: row.get("is_active").and_then(Value::as_bool).unwrap_or(true),
                is_self: row.get("is_owner").and_then(Value::as_bool).unwrap_or(false),
                ..Default::default()
            })
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

fn group_of(role: &str) -> &'static str {
    if role == ADMIN_ROLE { GROUP_ADMIN } else { GROUP_USER }
}

pub fn create_commands(new: &NewUser) -> Value {
    let name = if new.display_name.is_empty() { new.login.clone() } else { new.display_name.clone() };
    json!({ "type": "config/auth/create", "name": name, "group_ids": [group_of(&new.role)], "local_only": false })
}

pub fn credentials_command(user_id: &str, username: &str, password: &str) -> Value {
    json!({ "type": "config/auth_provider/homeassistant/create", "user_id": user_id, "username": username, "password": password })
}

/// The id of the user a `config/auth/create` answer made
pub fn created_id(result: &Value) -> Option<String> {
    result.get("user")?.get("id")?.as_str().map(String::from)
}

impl HomeAssistant {
    pub async fn find(vault: Option<(String, String)>) -> Result<Option<HomeAssistant>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let (_, token) = vault.ok_or(Refusal::NeedsAdminToken)?;
        Ok(Some(HomeAssistant { token }))
    }

    async fn open(&self) -> Result<Socket, Refusal> {
        let mut socket = Socket::connect(WEB_UI_PORT, PATH).await?;
        if message_type(&socket.receive().await?).as_deref() != Some("auth_required") {
            return Err(Refusal::Failed);
        }
        socket.send(&auth_message(&self.token)).await?;
        match message_type(&socket.receive().await?).as_deref() {
            Some("auth_ok") => Ok(socket),
            Some("auth_invalid") => Err(Refusal::AdminLoginFailed),
            _ => Err(Refusal::Failed),
        }
    }

    async fn ask(socket: &mut Socket, id: u64, command: &Value) -> Result<Value, Refusal> {
        socket.send(&command_message(id, command)).await?;
        loop {
            if let Some(result) = result_of(&socket.receive().await?, id) {
                return result;
            }
        }
    }

    async fn run(&self, commands: &[Value]) -> Result<Vec<Value>, Refusal> {
        let mut socket = self.open().await?;
        let mut results = Vec::new();
        for (index, command) in commands.iter().enumerate() {
            results.push(Self::ask(&mut socket, index as u64 + 1, command).await?);
        }
        Ok(results)
    }

    async fn one(&self, command: Value) -> Done {
        self.run(&[command]).await.map(|_| ())
    }
}

impl UserBackend for HomeAssistant {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let results = self.run(&[json!({ "type": "config/auth/list" })]).await?;
        parse_users(results.first().ok_or(Refusal::Failed)?)
    }

    async fn create(&self, new: &NewUser) -> Done {
        let mut socket = self.open().await?;
        let made = Self::ask(&mut socket, 1, &create_commands(new)).await?;
        let id = created_id(&made).ok_or(Refusal::Failed)?;
        let credentials = credentials_command(&id, &new.login, &new.password);
        if let Err(refusal) = Self::ask(&mut socket, 2, &credentials).await {
            let _ = Self::ask(&mut socket, 3, &json!({ "type": "config/auth/delete", "user_id": id })).await;
            return Err(refusal);
        }
        Ok(())
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.one(json!({ "type": "config/auth/delete", "user_id": user_id })).await
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.one(json!({ "type": "config/auth_provider/homeassistant/admin_change_password", "user_id": user_id, "password": password })).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.one(json!({ "type": "config/auth/update", "user_id": user_id, "group_ids": [group_of(role)] })).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.one(json!({ "type": "config/auth/update", "user_id": user_id, "is_active": enabled })).await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = include_str!("../../tests/fixtures/service_users/home-assistant/auth-list.json");
    const CREATED: &str = include_str!("../../tests/fixtures/service_users/home-assistant/auth-create.json");
    const ERROR: &str = include_str!("../../tests/fixtures/service_users/home-assistant/auth-error.json");

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
    fn the_user_list_hides_system_accounts_and_marks_the_owner() {
        let result = result_of(LIST, 1).unwrap().unwrap();
        let users = parse_users(&result).unwrap();
        let rows: Vec<(&str, &str, bool, bool)> = users.iter().map(|u| (u.login.as_str(), u.role.as_str(), u.enabled, u.is_self)).collect();
        assert_eq!(rows, [("anna", "user", true, false), ("operator", "admin", true, true), ("Tablet", "user", false, false)]);
        assert_eq!(users[2].display_name, "Tablet");
        assert_eq!(parse_users(&json!({})), Err(Refusal::Failed));
    }

    #[test]
    fn answers_are_matched_by_id_and_errors_become_refusals() {
        assert!(result_of(LIST, 2).is_none());
        assert!(result_of("{\"type\":\"event\",\"id\":1}", 1).is_none());
        assert_eq!(created_id(&result_of(CREATED, 2).unwrap().unwrap()).as_deref(), Some("0123456789abcdef0123456789abcd05"));
        assert_eq!(result_of(ERROR, 3).unwrap().err(), Some(Refusal::UnknownUser));
        assert!(result_of("not json", 1).is_none());
    }

    #[test]
    fn the_token_and_password_travel_in_messages_only() {
        let auth = auth_message("tok-abcdef-long");
        assert_eq!(serde_json::from_str::<Value>(&auth).unwrap()["access_token"], "tok-abcdef-long");
        let credentials = credentials_command("id1", "clara", "s3cr3t-pass-word");
        let message = command_message(2, &credentials);
        assert!(message.contains("\"id\":2") && message.contains("s3cr3t-pass-word"));
        assert_eq!(message_type(r#"{"type":"auth_required","ha_version":"2026.9.3"}"#).as_deref(), Some("auth_required"));
    }

    #[test]
    fn a_new_person_joins_the_group_of_the_role_and_may_sign_in_from_anywhere() {
        let command = create_commands(&new_user());
        assert_eq!(command["group_ids"], json!(["system-admin"]));
        assert_eq!((command["name"].as_str(), command["local_only"].as_bool()), (Some("clara"), Some(false)));
        let mut member = new_user();
        member.role = "user".into();
        assert_eq!(create_commands(&member)["group_ids"], json!(["system-users"]));
    }

    #[test]
    fn the_service_asks_for_a_token_and_has_no_quota() {
        let caps = capabilities();
        assert_eq!(caps.note, "admin_token");
        assert!(caps.can_set_enabled && caps.can_set_password && !caps.can_set_quota && !caps.needs_email);
    }
}
