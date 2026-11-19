//! Passbolt accounts through its console commands and database

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::install::passbolt::CONTAINER;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "passbolt";
const ROLE_USER: &str = "user";
const ROOT_ROLE: &str = "root";
const GUEST_ROLE: &str = "guest";
const CAKE: &str = "/usr/share/php/passbolt/bin/cake";
const LIST_SQL: &str = "SELECT u.id, u.username, u.active, u.disabled, r.name, p.first_name, p.last_name FROM users u JOIN roles r ON r.id = u.role_id LEFT JOIN profiles p ON p.user_id = u.id WHERE u.deleted = 0 ORDER BY u.created";
const FALLBACK_NAME: &str = "User";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        needs_email: true,
        user_id_is_email: true,
        ..Default::default()
    }
}

pub struct Passbolt {
    database: String,
}

fn text_of(field: &str) -> String {
    if field == "NULL" { String::new() } else { field.to_string() }
}

pub fn parse_users(output: &str) -> Vec<pb::ServiceUser> {
    let mut users: Vec<pb::ServiceUser> = Vec::new();
    let mut first_admin: Option<usize> = None;
    for line in output.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 7 || fields[4] == ROOT_ROLE || fields[4] == GUEST_ROLE {
            continue;
        }
        let name = format!("{} {}", text_of(fields[5]), text_of(fields[6])).trim().to_string();
        let role = if fields[4] == ADMIN_ROLE { ADMIN_ROLE } else { ROLE_USER };
        if role == ADMIN_ROLE && first_admin.is_none() {
            first_admin = Some(users.len());
        }
        users.push(pb::ServiceUser {
            id: fields[0].to_string(),
            login: fields[1].to_string(),
            display_name: name,
            email: fields[1].to_string(),
            role: role.to_string(),
            enabled: text_of(fields[3]).is_empty(),
            ..Default::default()
        });
    }
    if let Some(index) = first_admin {
        users[index].is_self = true;
    }
    users.sort_by_key(|user| user.login.to_lowercase());
    users
}

pub fn list_call(database: &str) -> Call {
    let script = format!("MYSQL_PWD=\"$MYSQL_PASSWORD\" mariadb -N -B -u passbolt passbolt -e \"{LIST_SQL}\"");
    Call::new(&["exec", database, "sh", "-c", &script])
}

fn safe_email(email: &str) -> bool {
    !email.is_empty() && email.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-'))
}

fn plain_name(word: &str) -> String {
    word.chars().filter(|c| c.is_alphanumeric() || *c == '-').collect()
}

pub fn names_of(display_name: &str, email: &str) -> (String, String) {
    let source = if display_name.trim().is_empty() { email.split('@').next().unwrap_or_default() } else { display_name };
    let mut words = source.split_whitespace().map(plain_name).filter(|word| !word.is_empty());
    let first = words.next().unwrap_or_else(|| FALLBACK_NAME.to_string());
    let last: Vec<String> = words.collect();
    (first, if last.is_empty() { FALLBACK_NAME.to_string() } else { last.join("-") })
}

fn cake(app: &str, command: &str) -> Call {
    let line = format!("{CAKE} passbolt {command}");
    Call::new(&["exec", app, "su", "-m", "-c", &line, "-s", "/bin/sh", "www-data"])
}

pub fn create_call(app: &str, new: &NewUser) -> Result<Call, Refusal> {
    if !safe_email(&new.login) {
        return Err(Refusal::InvalidEmail);
    }
    let (first, last) = names_of(&new.display_name, &new.login);
    let role = if new.role == ADMIN_ROLE { ADMIN_ROLE } else { ROLE_USER };
    Ok(cake(app, &format!("register_user -u {} -f {first} -l {last} -r {role}", new.login)))
}

pub fn promote_call(app: &str, target: &str, by: &str) -> Result<Call, Refusal> {
    if !safe_email(target) || !safe_email(by) {
        return Err(Refusal::InvalidEmail);
    }
    Ok(cake(app, &format!("user_promote_to_administrator -u {target} -a {by}")))
}

/// The pick of the app and database containers
pub fn pick_containers(containers: &[pb::Container]) -> Option<(String, String)> {
    let database = containers.iter().find(|c| c.image.to_lowercase().contains("mariadb"))?;
    Some((CONTAINER.to_string(), database.name.clone()))
}

impl Passbolt {
    pub async fn find() -> Result<Option<Passbolt>, Refusal> {
        let snapshot = discover::service_snapshot(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        let Some(service) = snapshot else { return Ok(None) };
        let (_, database) = pick_containers(&service.containers).ok_or(Refusal::ServiceDown)?;
        Ok(Some(Passbolt { database }))
    }

    async fn users(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        Ok(parse_users(&docker::run(&list_call(&self.database)).await?))
    }
}

impl UserBackend for Passbolt {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        self.users().await
    }

    async fn create(&self, new: &NewUser) -> Done {
        docker::run(&create_call(CONTAINER, new)?).await.map(|_| ())
    }

    async fn delete(&self, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_password(&self, _: &str, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        if role != ADMIN_ROLE {
            return Err(Refusal::NotSupported);
        }
        let users = self.users().await?;
        let target = users.iter().find(|user| user.id == user_id).ok_or(Refusal::UnknownUser)?;
        let admin = users.iter().find(|user| user.is_self).ok_or(Refusal::Failed)?;
        docker::run(&promote_call(CONTAINER, &target.email, &admin.email)?).await.map(|_| ())
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

    const USERS: &str = include_str!("../../tests/fixtures/service_users/passbolt/users.tsv");

    fn new_user(login: &str, name: &str) -> NewUser {
        NewUser {
            login: login.into(),
            display_name: name.into(),
            email: login.into(),
            password: String::new(),
            role: "user".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn the_query_rows_parse_without_the_system_account() {
        let users = parse_users(USERS);
        let rows: Vec<(&str, &str, bool, bool)> = users.iter().map(|u| (u.login.as_str(), u.role.as_str(), u.enabled, u.is_self)).collect();
        assert_eq!(
            rows,
            [
                ("anna@example.org", "user", true, false),
                ("boris@example.org", "user", true, false),
                ("carl@example.org", "user", false, false),
                ("operator@example.org", "admin", true, true),
            ]
        );
        assert_eq!(users[0].display_name, "Anna Example");
        assert_eq!(users[0].id, "0b1f2c3d-0000-4000-8000-000000000002");
        assert!(parse_users("ERROR 1045 (28000): Access denied").is_empty());
    }

    #[test]
    fn registration_uses_the_console_without_secrets_and_validated_text() {
        let call = create_call("passbolt", &new_user("clara@example.org", "Clara Example")).unwrap();
        let line = call.args.iter().find(|arg| arg.contains("register_user")).unwrap();
        assert_eq!(line, "/usr/share/php/passbolt/bin/cake passbolt register_user -u clara@example.org -f Clara -l Example -r user");
        assert_eq!(&call.args[call.args.len() - 3..], ["-s", "/bin/sh", "www-data"].map(String::from));
        assert!(call.stdin.is_none());
    }

    #[test]
    fn a_hostile_address_never_reaches_the_shell() {
        for bad in ["a@b.org; rm -rf /", "a b@example.org", "a@b.org`id`", "$(id)@b.org", ""] {
            assert_eq!(create_call("passbolt", &new_user(bad, "")).err(), Some(Refusal::InvalidEmail), "{bad:?}");
        }
        assert!(promote_call("passbolt", "a@b.org", "x@y.org; id").is_err());
    }

    #[test]
    fn names_come_from_the_display_name_or_the_address() {
        assert_eq!(names_of("Anna Maria Example", "a@b.org"), ("Anna".into(), "Maria-Example".into()));
        assert_eq!(names_of("", "carl@example.org"), ("carl".into(), "User".into()));
        assert_eq!(names_of("$(id) `x`", "a@b.org"), ("id".into(), "x".into()));
        assert_eq!(names_of("***", "***@b.org"), ("User".into(), "User".into()));
    }

    #[test]
    fn promotion_names_both_administrators() {
        let call = promote_call("passbolt", "anna@example.org", "operator@example.org").unwrap();
        let line = call.args.iter().find(|arg| arg.contains("promote")).unwrap();
        assert!(line.ends_with("user_promote_to_administrator -u anna@example.org -a operator@example.org"));
    }

    #[test]
    fn the_listing_reads_the_password_from_the_database_container() {
        let call = list_call("passbolt-db-1");
        let script = call.args.last().unwrap();
        assert!(script.starts_with("MYSQL_PWD=\"$MYSQL_PASSWORD\" mariadb"));
        assert!(script.contains("WHERE u.deleted = 0") && script.contains("mariadb -N -B -u passbolt passbolt -e"));
    }

    #[test]
    fn only_invitations_and_promotion_exist() {
        let caps = capabilities();
        assert!(caps.can_create && !caps.can_delete && !caps.can_set_password && !caps.can_set_enabled);
        let containers = vec![
            pb::Container { name: "passbolt".into(), image: "passbolt/passbolt:5.14.3-1-ce".into(), ..Default::default() },
            pb::Container { name: "passbolt-db-1".into(), image: "mariadb:10.11".into(), ..Default::default() },
        ];
        assert_eq!(pick_containers(&containers), Some(("passbolt".to_string(), "passbolt-db-1".to_string())));
    }
}
