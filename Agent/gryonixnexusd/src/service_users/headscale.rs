//! Headscale mesh users, shown on the shared screen

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend};
use crate::install::headscale::CONTAINER;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "headscale";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities { supported: true, can_create: true, can_delete: true, ..Default::default() }
}

/// A mesh user name the engine accepts
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn headscale(words: &[&str]) -> Call {
    let mut args = vec!["exec", CONTAINER, "headscale"];
    args.extend(words);
    Call::new(&args)
}

pub fn list_call() -> Call {
    headscale(&["users", "list", "-o", "json"])
}

pub fn create_call(name: &str) -> Call {
    headscale(&["users", "create", name])
}

pub fn delete_call(id: &str) -> Call {
    headscale(&["users", "destroy", "--identifier", id, "--force"])
}

pub fn parse_users(output: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let mesh = crate::mesh::parse_users(output).map_err(|_| Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = mesh
        .into_iter()
        .map(|user| pb::ServiceUser { id: user.id, login: user.name, enabled: true, ..Default::default() })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

pub struct Headscale;

impl Headscale {
    pub async fn find() -> Result<Option<Headscale>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        Ok((!containers.is_empty()).then_some(Headscale))
    }
}

impl UserBackend for Headscale {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        parse_users(&docker::run(&list_call()).await?)
    }

    async fn create(&self, new: &NewUser) -> Done {
        if !valid_name(&new.login) {
            return Err(Refusal::InvalidLogin);
        }
        docker::run(&create_call(&new.login)).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        docker::run(&delete_call(user_id)).await.map(|_| ())
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

    const USERS: &str = include_str!("../../tests/fixtures/service_users/headscale/users.json");

    #[test]
    fn the_engine_list_becomes_users() {
        let users = parse_users(USERS).unwrap();
        let rows: Vec<(&str, &str)> = users.iter().map(|u| (u.id.as_str(), u.login.as_str())).collect();
        assert_eq!(rows, [("1", "anna"), ("2", "boris"), ("3", "family.phones")]);
        assert!(parse_users("null").unwrap().is_empty());
        assert!(parse_users("not json").is_err());
    }

    #[test]
    fn names_follow_the_engines_rules() {
        for good in ["anna", "family.phones", "a_b-c"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", "-anna", "an na", "anna;ls", "ännä"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(!valid_name(&"a".repeat(65)));
    }

    #[test]
    fn deleting_names_the_numeric_id_and_forces_the_prompt() {
        assert_eq!(
            delete_call("2").args,
            ["exec", "headscale", "headscale", "users", "destroy", "--identifier", "2", "--force"]
        );
        assert_eq!(create_call("anna").args.last().map(String::as_str), Some("anna"));
        assert!(create_call("anna").stdin.is_none());
    }

    #[test]
    fn users_have_no_passwords_roles_or_quota() {
        let caps = capabilities();
        assert!(caps.roles.is_empty() && !caps.can_set_password && !caps.can_set_enabled && !caps.can_set_quota);
    }
}
