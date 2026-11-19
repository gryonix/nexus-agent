//! Psono accounts through its management commands and database

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::psono::CONTAINER;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "psono";
const ROLE_USER: &str = "user";
const SUPERUSER: &str = "superuser";
const LIST_SQL: &str = "SELECT username, is_active, is_superuser FROM restapi_user ORDER BY create_date";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_enabled: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        needs_email: true,
        user_id_is_email: true,
        ..Default::default()
    }
}

pub struct Psono {
    database: String,
}

pub fn parse_users(output: &str) -> Vec<pb::ServiceUser> {
    let rows: Vec<(String, bool, bool)> = output
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim().split('|');
            let name = fields.next()?.trim();
            let active = fields.next()? == "t";
            let admin = fields.next()? == "t";
            (!name.is_empty()).then(|| (name.to_string(), active, admin))
        })
        .collect();
    let first_admin = rows.iter().position(|(_, _, admin)| *admin);
    let mut users: Vec<pb::ServiceUser> = rows
        .into_iter()
        .enumerate()
        .map(|(index, (name, active, admin))| pb::ServiceUser {
            id: name.clone(),
            login: name.clone(),
            email: name,
            role: if admin { ADMIN_ROLE } else { ROLE_USER }.to_string(),
            enabled: active,
            is_self: first_admin == Some(index),
            ..Default::default()
        })
        .collect();
    users.sort_by_key(|user| user.login.to_lowercase());
    users
}

fn manage(command: &str, args: &[&str]) -> Call {
    let mut all = vec!["exec", CONTAINER, "python3", "./psono/manage.py", command];
    all.extend(args);
    Call::new(&all)
}

pub fn list_call(database: &str) -> Call {
    Call::new(&["exec", database, "psql", "-U", "psono", "-d", "psono", "-At", "-F", "|", "-c", LIST_SQL])
}

pub fn delete_call(login: &str) -> Call {
    manage("deleteuser", &[login])
}

pub fn enabled_call(login: &str, enabled: bool) -> Call {
    manage(if enabled { "enableuser" } else { "disableuser" }, &[login])
}

pub fn role_call(login: &str, admin: bool) -> Call {
    manage(if admin { "promoteuser" } else { "demoteuser" }, &[login, SUPERUSER])
}

fn python_text(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

pub fn create_call(new: &NewUser) -> Call {
    let script = format!(
        "from restapi.utils import create_user\ncreate_user({}, {}, {})\n",
        python_text(&new.login),
        python_text(&new.password),
        python_text(&new.login)
    );
    Call::new(&["exec", "-i", CONTAINER, "python3", "./psono/manage.py", "shell"]).with_stdin(script)
}

/// The container that runs the database
pub fn pick_database(containers: &[pb::Container]) -> Option<String> {
    containers.iter().find(|c| c.image.to_lowercase().contains("postgres")).map(|c| c.name.clone())
}

impl Psono {
    pub async fn find() -> Result<Option<Psono>, Refusal> {
        let snapshot = discover::service_snapshot(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        let Some(service) = snapshot else { return Ok(None) };
        let database = pick_database(&service.containers).ok_or(Refusal::ServiceDown)?;
        Ok(Some(Psono { database }))
    }
}

impl UserBackend for Psono {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        Ok(parse_users(&docker::run(&list_call(&self.database)).await?))
    }

    async fn create(&self, new: &NewUser) -> Done {
        docker::run(&create_call(new)).await.map(|_| ())
    }

    async fn delete(&self, user_id: &str) -> Done {
        docker::run(&delete_call(user_id)).await.map(|_| ())
    }

    async fn set_password(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        docker::run(&role_call(user_id, role == ADMIN_ROLE)).await.map(|_| ())
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        docker::run(&enabled_call(user_id, enabled)).await.map(|_| ())
    }

    async fn set_quota(&self, _: &str, _: i64) -> Done {
        Err(Refusal::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = include_str!("../../tests/fixtures/service_users/psono/users.txt");

    fn new_user(password: &str) -> NewUser {
        NewUser {
            login: "clara@example.org".into(),
            display_name: String::new(),
            email: "clara@example.org".into(),
            password: password.into(),
            role: "user".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_database_rows_parse_and_the_oldest_admin_is_the_apps() {
        let users = parse_users(USERS);
        let rows: Vec<(&str, bool, bool, &str)> = users.iter().map(|u| (u.login.as_str(), u.enabled, u.is_self, u.role.as_str())).collect();
        assert_eq!(
            rows,
            [("anna@example.org", true, false, "user"), ("boris@example.org", false, false, "user"), ("operator@example.org", true, true, "admin")]
        );
        assert!(parse_users("").is_empty());
        assert!(parse_users("psql: error: connection failed").is_empty());
    }

    #[test]
    fn the_password_reaches_the_shell_on_stdin_only() {
        let call = create_call(&new_user("s3cr3t-pass-word"));
        assert!(call.args.iter().all(|arg| !arg.contains("s3cr3t")));
        assert!(call.args.contains(&"-i".to_string()) && call.args.last().map(String::as_str) == Some("shell"));
        let script = call.stdin.unwrap();
        assert!(script.contains("create_user('clara@example.org', 's3cr3t-pass-word', 'clara@example.org')"), "{script}");
    }

    #[test]
    fn quotes_and_backslashes_cannot_end_the_python_string() {
        let call = create_call(&new_user("it's\\a-long-one"));
        let script = call.stdin.unwrap();
        assert!(script.contains("'it\\'s\\\\a-long-one'"), "{script}");
        assert_eq!(script.lines().count(), 2);
    }

    #[test]
    fn management_commands_name_the_login_and_the_only_role() {
        assert_eq!(delete_call("anna@example.org").args.last().map(String::as_str), Some("anna@example.org"));
        assert!(enabled_call("a@example.org", false).args.contains(&"disableuser".to_string()));
        assert!(enabled_call("a@example.org", true).args.contains(&"enableuser".to_string()));
        let promote = role_call("a@example.org", true).args;
        assert_eq!(&promote[promote.len() - 3..], ["promoteuser", "a@example.org", "superuser"]);
        assert!(role_call("a@example.org", false).args.contains(&"demoteuser".to_string()));
    }

    #[test]
    fn the_listing_asks_the_database_without_a_password_argument() {
        let call = list_call("psono-db-1");
        assert!(call.args.iter().all(|arg| !arg.to_lowercase().contains("password")));
        assert!(call.args.contains(&LIST_SQL.to_string()));
    }

    #[test]
    fn the_database_container_is_the_postgres_one() {
        let containers = vec![
            pb::Container { name: "psono".into(), image: "psono/psono-combo:7.3.0".into(), ..Default::default() },
            pb::Container { name: "psono-db-1".into(), image: "postgres:16-alpine".into(), ..Default::default() },
        ];
        assert_eq!(pick_database(&containers).as_deref(), Some("psono-db-1"));
        assert_eq!(pick_database(&containers[..1]), None);
    }

    #[test]
    fn there_is_no_password_reset_for_a_zero_knowledge_vault() {
        let caps = capabilities();
        assert!(!caps.can_set_password && caps.can_set_enabled && caps.user_id_is_email);
    }
}
