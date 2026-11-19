//! Minecraft Bedrock players on the allowlist, through send-command

use super::docker::{self, Call};
use super::minecraft_java::{names_in, valid_player};
use super::{NewUser, Refusal, UserBackend};
use crate::install::minecraft::BEDROCK_CONTAINER;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "minecraft-bedrock";
const ALLOWLIST_FILE: &str = "/data/allowlist.json";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities { supported: true, can_create: true, can_delete: true, ..Default::default() }
}

pub fn users_of(names: &[String]) -> Vec<pb::ServiceUser> {
    let mut users: Vec<pb::ServiceUser> = names
        .iter()
        .map(|name| pb::ServiceUser { id: name.clone(), login: name.clone(), enabled: true, ..Default::default() })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    users
}

pub fn allowlist_call(action: &str, name: &str) -> Call {
    Call::new(&["exec", BEDROCK_CONTAINER, "send-command", "allowlist", action, name])
}

pub struct MinecraftBedrock;

impl MinecraftBedrock {
    pub async fn find() -> Result<Option<MinecraftBedrock>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        Ok((!containers.is_empty()).then_some(MinecraftBedrock))
    }
}

impl UserBackend for MinecraftBedrock {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        docker::run(&Call::new(&["inspect", "--format", "{{.State.Running}}", BEDROCK_CONTAINER])).await?;
        let file = docker::run(&Call::new(&["exec", BEDROCK_CONTAINER, "cat", ALLOWLIST_FILE])).await.unwrap_or_default();
        Ok(users_of(&names_in(&file)))
    }

    async fn create(&self, new: &NewUser) -> Done {
        if !valid_player(&new.login) {
            return Err(Refusal::InvalidLogin);
        }
        docker::run(&allowlist_call("add", &new.login)).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        docker::run(&allowlist_call("remove", user_id)).await.map(|_| ())
    }

    async fn set_password(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_role(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
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

    const ALLOWLIST: &str = include_str!("../../tests/fixtures/service_users/minecraft-bedrock/allowlist.json");

    #[test]
    fn the_allowlist_gives_players() {
        let users = users_of(&names_in(ALLOWLIST));
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["AnnaPlays", "BorisPlays"]);
        assert!(users.iter().all(|u| u.role.is_empty() && u.enabled));
    }

    #[test]
    fn the_command_names_the_action_and_the_player() {
        assert_eq!(
            allowlist_call("add", "AnnaPlays").args,
            ["exec", "minecraft-bedrock", "send-command", "allowlist", "add", "AnnaPlays"]
        );
        assert!(allowlist_call("remove", "AnnaPlays").args.contains(&"remove".to_string()));
    }

    #[test]
    fn players_have_no_roles_passwords_or_quota() {
        let caps = capabilities();
        assert!(caps.roles.is_empty() && !caps.can_set_password && !caps.can_set_enabled && !caps.can_set_quota);
    }
}
