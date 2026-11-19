//! Mosquitto logins from the broker's password file

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend};
use crate::discover;
use crate::install::mosquitto::{CONTAINER, USERS};
use crate::pb;

pub const SERVICE_ID: &str = "mosquitto";
const PASSWD: &str = "/mosquitto/config/passwd";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        ..Default::default()
    }
}

pub struct Mosquitto;

pub fn parse_users(file: &str) -> Vec<pb::ServiceUser> {
    let mut users: Vec<pb::ServiceUser> = file
        .lines()
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty())
        .map(|name| pb::ServiceUser {
            id: name.to_string(),
            login: name.to_string(),
            enabled: true,
            is_self: USERS.contains(&name),
            ..Default::default()
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    users
}

pub fn list_call() -> Call {
    Call::new(&["exec", CONTAINER, "cat", PASSWD])
}

pub fn password_call(login: &str, password: &str) -> Call {
    Call::new(&["exec", "-i", CONTAINER, "mosquitto_passwd", PASSWD, login]).with_stdin(format!("{password}\n{password}\n"))
}

pub fn delete_call(login: &str) -> Call {
    Call::new(&["exec", CONTAINER, "mosquitto_passwd", "-D", PASSWD, login])
}

pub fn reload_call() -> Call {
    Call::new(&["kill", "-s", "HUP", CONTAINER])
}

impl Mosquitto {
    pub async fn find() -> Result<Option<Mosquitto>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        Ok((!containers.is_empty()).then_some(Mosquitto))
    }

    async fn change(&self, call: Call) -> Done {
        docker::run(&call).await?;
        docker::run(&reload_call()).await.map(|_| ())
    }
}

impl UserBackend for Mosquitto {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        Ok(parse_users(&docker::run(&list_call()).await?))
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.change(password_call(&new.login, &new.password)).await
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.change(delete_call(user_id)).await
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.change(password_call(user_id, password)).await
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

    const PASSWD_FILE: &str = include_str!("../../tests/fixtures/service_users/mosquitto/passwd");

    #[test]
    fn the_password_file_gives_logins_and_protects_the_services() {
        let users = parse_users(PASSWD_FILE);
        let logins: Vec<(&str, bool)> = users.iter().map(|u| (u.login.as_str(), u.is_self)).collect();
        assert_eq!(logins, [("anna", false), ("homeassistant", true), ("zigbee2mqtt", true)]);
        assert!(parse_users("").is_empty());
    }

    #[test]
    fn a_password_goes_through_stdin_and_never_through_batch_mode() {
        let call = password_call("anna", "s3cr3t-pass-word");
        assert!(call.args.iter().all(|arg| !arg.contains("s3cr3t") && arg != "-b" && arg != "-c"));
        assert_eq!(call.stdin.as_deref(), Some("s3cr3t-pass-word\ns3cr3t-pass-word\n"));
        assert!(call.args.contains(&"-i".to_string()));
        assert_eq!(call.args.last().map(String::as_str), Some("anna"));
    }

    #[test]
    fn deleting_names_the_login_and_reloading_signals_the_broker() {
        assert!(delete_call("anna").args.windows(2).any(|pair| pair == ["-D", PASSWD]));
        assert_eq!(reload_call().args, ["kill", "-s", "HUP", "mosquitto"]);
    }

    #[test]
    fn logins_have_no_roles_quota_or_off_switch() {
        let caps = capabilities();
        assert!(caps.roles.is_empty() && !caps.can_set_enabled && !caps.can_set_quota && caps.can_set_password);
    }
}
