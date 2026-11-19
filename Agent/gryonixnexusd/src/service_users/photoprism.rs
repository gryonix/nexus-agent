//! PhotoPrism accounts through its own command line

use serde_json::Value;

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::discover;
use crate::install::photoprism::CONTAINER;
use crate::pb;

pub const SERVICE_ID: &str = "photoprism";
const ROLE_GUEST: &str = "guest";
const LIST_LIMIT: &str = "1000";
const ADD_SCRIPT: &str = "p=\"$(cat)\"; exec photoprism users add -p \"$p\" \"$@\"";
const PASSWORD_SCRIPT: &str = "p=\"$(cat)\"; exec photoprism users mod -p \"$p\" \"$1\"";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_enabled: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_GUEST.to_string()],
        ..Default::default()
    }
}

pub struct Photoprism {
    admin: String,
}

/// The first JSON array in the command's output
fn json_of(output: &str) -> Option<Value> {
    let start = output.find("[{").or_else(|| output.find("[]"))?;
    serde_json::Deserializer::from_str(&output[start..]).into_iter::<Value>().next()?.ok()
}

pub fn parse_users(output: &str, admin: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let value = json_of(output).ok_or(Refusal::Failed)?;
    let rows = value.as_array().ok_or(Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = rows
        .iter()
        .filter_map(|row| {
            let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default();
            let login = text("username");
            let is_admin = text("role").eq_ignore_ascii_case("admin") || text("super_admin") == "Yes";
            (!login.is_empty()).then(|| pb::ServiceUser {
                id: login.to_string(),
                login: login.to_string(),
                role: if is_admin { ADMIN_ROLE } else { ROLE_GUEST }.to_string(),
                enabled: text("web_login") != "Disabled",
                is_self: login.eq_ignore_ascii_case(admin),
                ..Default::default()
            })
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

fn exec(words: &[&str]) -> Call {
    let mut args = vec!["exec", CONTAINER, "photoprism", "users"];
    args.extend_from_slice(words);
    Call::new(&args)
}

pub fn list_call() -> Call {
    exec(&["ls", "--json", "-n", LIST_LIMIT])
}

/// A call whose password arrives on stdin
fn shell_call(script: &str, words: &[&str], password: &str) -> Call {
    let mut args = vec!["exec", "-i", CONTAINER, "sh", "-c", script, "sh"];
    args.extend_from_slice(words);
    Call::new(&args).with_stdin(password.to_string())
}

pub fn create_call(new: &NewUser) -> Call {
    let name = if new.display_name.is_empty() { new.login.as_str() } else { new.display_name.as_str() };
    let mut words = vec!["-n", name];
    if !new.email.is_empty() {
        words.extend(["-m", new.email.as_str()]);
    }
    if new.role == ADMIN_ROLE {
        words.extend(["-r", ADMIN_ROLE, "--superadmin"]);
    } else {
        words.extend(["-r", ROLE_GUEST]);
    }
    words.push(new.login.as_str());
    shell_call(ADD_SCRIPT, &words, &new.password)
}

pub fn password_call(login: &str, password: &str) -> Call {
    shell_call(PASSWORD_SCRIPT, &[login], password)
}

pub fn role_call(login: &str, role: &str) -> Call {
    if role == ADMIN_ROLE {
        exec(&["mod", "-r", ADMIN_ROLE, "--superadmin=true", login])
    } else {
        exec(&["mod", "-r", ROLE_GUEST, "--superadmin=false", login])
    }
}

pub fn enabled_call(login: &str, enabled: bool) -> Call {
    exec(&["mod", if enabled { "--no-login=false" } else { "--no-login=true" }, login])
}

pub fn delete_call(login: &str) -> Call {
    exec(&["rm", "-f", login])
}

impl Photoprism {
    pub async fn find() -> Result<Option<Photoprism>, Refusal> {
        let containers = discover::containers_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        if containers.is_empty() {
            return Ok(None);
        }
        let env = super::container_env(CONTAINER).await.unwrap_or_default();
        let admin = super::env_value(&env, "PHOTOPRISM_ADMIN_USER").unwrap_or_default();
        Ok(Some(Photoprism { admin }))
    }

    async fn run(&self, call: Call) -> Done {
        docker::run(&call).await.map(|_| ())
    }
}

impl UserBackend for Photoprism {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        parse_users(&docker::run(&list_call()).await?, &self.admin)
    }

    async fn create(&self, new: &NewUser) -> Done {
        self.run(create_call(new)).await
    }

    async fn delete(&self, user_id: &str) -> Done {
        self.run(delete_call(user_id)).await
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        self.run(password_call(user_id, password)).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        self.run(role_call(user_id, role)).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        self.run(enabled_call(user_id, enabled)).await
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/photoprism/users.json");

    fn new_user(role: &str) -> NewUser {
        NewUser {
            login: "clara".into(),
            display_name: String::new(),
            email: String::new(),
            password: "s3cr3t-pass-word".into(),
            role: role.into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_listing_gives_logins_roles_and_the_off_switch() {
        let users = parse_users(USERS, "Operator").unwrap();
        let rows: Vec<(&str, &str, bool, bool)> =
            users.iter().map(|u| (u.login.as_str(), u.role.as_str(), u.enabled, u.is_self)).collect();
        assert_eq!(
            rows,
            [("anna", "guest", true, false), ("boris", "guest", false, false), ("operator", "admin", true, true)]
        );
    }

    #[test]
    fn log_lines_before_the_listing_are_skipped_and_garbage_fails() {
        assert_eq!(parse_users("time=1 level=info msg=\"x\"\n[]\n", "").unwrap(), Vec::new());
        assert_eq!(parse_users("not json", ""), Err(Refusal::Failed));
    }

    #[test]
    fn a_password_goes_through_stdin_and_never_through_the_arguments() {
        let calls = [create_call(&new_user("guest")), password_call("clara", "s3cr3t-pass-word")];
        for call in &calls {
            assert!(call.args.iter().all(|arg| !arg.contains("s3cr3t")));
            assert_eq!(call.stdin.as_deref(), Some("s3cr3t-pass-word"));
            assert!(call.args.contains(&"-i".to_string()));
        }
    }

    #[test]
    fn a_new_account_is_named_after_its_login_and_has_the_role_asked_for() {
        let guest = create_call(&new_user("guest")).args;
        assert!(guest.windows(2).any(|pair| pair == ["-n", "clara"]) && guest.windows(2).any(|pair| pair == ["-r", "guest"]));
        assert_eq!(guest.last().map(String::as_str), Some("clara"));
        let admin = create_call(&new_user("admin")).args;
        assert!(admin.contains(&"--superadmin".to_string()));
    }

    #[test]
    fn the_flags_come_before_the_login_as_the_tool_requires() {
        let mut new = new_user("guest");
        new.email = "clara@example.org".into();
        let args = create_call(&new).args;
        let login = args.iter().rposition(|arg| arg == "clara").unwrap();
        let email = args.iter().position(|arg| arg == "-m").unwrap();
        assert!(email < login && login == args.len() - 1);
    }

    #[test]
    fn role_off_switch_and_removal_name_the_login() {
        assert!(role_call("clara", "admin").args.contains(&"--superadmin=true".to_string()));
        assert!(role_call("clara", "guest").args.contains(&"--superadmin=false".to_string()));
        assert!(enabled_call("clara", false).args.contains(&"--no-login=true".to_string()));
        assert!(enabled_call("clara", true).args.contains(&"--no-login=false".to_string()));
        assert_eq!(delete_call("clara").args.last().map(String::as_str), Some("clara"));
        assert!(delete_call("clara").args.contains(&"-f".to_string()));
    }

    #[test]
    fn this_service_has_two_roles_and_an_off_switch_but_no_quota_or_mail() {
        let caps = capabilities();
        assert_eq!(caps.roles, ["admin", "guest"]);
        assert!(caps.can_set_enabled && caps.can_set_password && !caps.can_set_quota && !caps.needs_email);
    }
}
