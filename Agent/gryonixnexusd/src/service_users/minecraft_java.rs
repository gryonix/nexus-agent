//! Minecraft Java players on the whitelist and operators, through rcon-cli

use serde_json::Value;

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend};
use crate::install::minecraft::JAVA_CONTAINER;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "minecraft-java";
pub const OPERATOR: &str = "operator";
pub const PLAYER: &str = "player";
const WHITELIST_FILE: &str = "/data/whitelist.json";
const OPS_FILE: &str = "/data/ops.json";
const NAME_MIN: usize = 3;
const NAME_MAX: usize = 16;

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        roles: vec![OPERATOR.to_string(), PLAYER.to_string()],
        ..Default::default()
    }
}

/// Whether a name is a Minecraft player name
pub fn valid_player(name: &str) -> bool {
    (NAME_MIN..=NAME_MAX).contains(&name.chars().count()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn names_in(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(json.trim()) else { return Vec::new() };
    value
        .as_array()
        .map(|rows| rows.iter().filter_map(|row| row.get("name").and_then(Value::as_str)).map(String::from).collect())
        .unwrap_or_default()
}

/// Players on either list, operators marked
pub fn merge(whitelist: &[String], ops: &[String]) -> Vec<pb::ServiceUser> {
    let mut names: Vec<&String> = whitelist.iter().collect();
    names.extend(ops.iter().filter(|op| !whitelist.contains(op)));
    let mut users: Vec<pb::ServiceUser> = names
        .into_iter()
        .map(|name| pb::ServiceUser {
            id: name.clone(),
            login: name.clone(),
            role: if ops.contains(name) { OPERATOR } else { PLAYER }.to_string(),
            enabled: true,
            ..Default::default()
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    users
}

pub fn command(container: &str, words: &[&str]) -> Call {
    let mut args = vec!["exec", container, "rcon-cli"];
    args.extend(words);
    Call::new(&args)
}

pub struct MinecraftJava;

impl MinecraftJava {
    pub async fn find() -> Result<Option<MinecraftJava>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        Ok((!containers.is_empty()).then_some(MinecraftJava))
    }

    async fn names(file: &str) -> Vec<String> {
        match docker::run(&Call::new(&["exec", JAVA_CONTAINER, "cat", file])).await {
            Ok(text) => names_in(&text),
            Err(_) => Vec::new(),
        }
    }

    async fn rcon(words: &[&str]) -> Done {
        docker::run(&command(JAVA_CONTAINER, words)).await.map(|_| ())
    }
}

impl UserBackend for MinecraftJava {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        docker::run(&Call::new(&["inspect", "--format", "{{.State.Running}}", JAVA_CONTAINER])).await?;
        Ok(merge(&Self::names(WHITELIST_FILE).await, &Self::names(OPS_FILE).await))
    }

    async fn create(&self, new: &NewUser) -> Done {
        if !valid_player(&new.login) {
            return Err(Refusal::InvalidLogin);
        }
        Self::rcon(&["whitelist", "add", &new.login]).await?;
        if new.role == OPERATOR {
            return Self::rcon(&["op", &new.login]).await;
        }
        Ok(())
    }

    async fn delete(&self, user_id: &str) -> Done {
        Self::rcon(&["deop", user_id]).await?;
        Self::rcon(&["whitelist", "remove", user_id]).await
    }

    async fn set_password(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        Self::rcon(&[if role == OPERATOR { "op" } else { "deop" }, user_id]).await
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

    const WHITELIST: &str = include_str!("../../tests/fixtures/service_users/minecraft-java/whitelist.json");
    const OPS: &str = include_str!("../../tests/fixtures/service_users/minecraft-java/ops.json");

    #[test]
    fn the_files_give_players_and_operators() {
        let users = merge(&names_in(WHITELIST), &names_in(OPS));
        let rows: Vec<(&str, &str)> = users.iter().map(|u| (u.login.as_str(), u.role.as_str())).collect();
        assert_eq!(rows, [("Anna_Builds", "player"), ("BorisMines", "player"), ("Operator", "operator")]);
    }

    #[test]
    fn an_operator_missing_from_the_whitelist_is_still_listed() {
        let users = merge(&["Anna_Builds".to_string()], &["Chief".to_string()]);
        assert_eq!(users.len(), 2);
        assert_eq!(users[1].role, "operator");
        assert!(names_in("not json").is_empty() && names_in("{}").is_empty());
    }

    #[test]
    fn player_names_follow_the_game_rules() {
        for good in ["Anna_Builds", "abc", "a_b_c_d_e_f_g_h_"] {
            assert!(valid_player(good), "{good}");
        }
        for bad in ["ab", "seventeen_chars_xx", "an na", "anna;op", "ännä", ""] {
            assert!(!valid_player(bad), "{bad:?}");
        }
    }

    #[test]
    fn commands_run_in_the_server_container_without_secrets() {
        let call = command("minecraft-java", &["whitelist", "add", "Anna_Builds"]);
        assert_eq!(call.args, ["exec", "minecraft-java", "rcon-cli", "whitelist", "add", "Anna_Builds"]);
        assert!(call.stdin.is_none());
    }

    #[test]
    fn players_have_no_passwords_quota_or_off_switch() {
        let caps = capabilities();
        assert!(!caps.can_set_password && !caps.can_set_enabled && !caps.can_set_quota && caps.roles == ["operator", "player"]);
    }
}
