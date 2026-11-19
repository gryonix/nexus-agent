//! Nextcloud users through `occ` inside the app container

use std::process::Stdio;

use serde_json::Value;

use super::{NewUser, Refusal, UserBackend, ADMIN_ROLE};
use crate::{discover, pb};

pub const SERVICE_ID: &str = "nextcloud";
const ROLE_USER: &str = "user";
const ADMIN_ENV: &str = "NEXTCLOUD_ADMIN_USER";
const SECRET_ENV: &str = "OC_PASS";
const RUN_AS: &str = "www-data";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities {
        supported: true,
        can_create: true,
        can_delete: true,
        can_set_password: true,
        can_set_enabled: true,
        can_set_quota: true,
        roles: vec![ADMIN_ROLE.to_string(), ROLE_USER.to_string()],
        needs_email: false,
        user_id_is_email: false,
        note: String::new(),
    }
}

pub struct Nextcloud {
    container: String,
    admin: String,
}

/// One `docker` call; the secret travels in the environment only
pub struct Invocation {
    pub args: Vec<String>,
    pub secret: Option<String>,
}

fn occ(container: &str, occ_args: &[&str], secret: Option<&str>) -> Invocation {
    let mut args: Vec<String> = vec!["exec".into(), "-u".into(), RUN_AS.into()];
    if secret.is_some() {
        args.push("-e".into());
        args.push(SECRET_ENV.into());
    }
    args.push(container.into());
    args.extend(["php", "occ"].map(String::from));
    args.extend(occ_args.iter().map(|arg| arg.to_string()));
    Invocation { args, secret: secret.map(String::from) }
}

// ─────────────────────────── Commands ───────────────────────────

pub fn list_command(container: &str) -> Invocation {
    occ(container, &["user:list", "--output=json", "--info"], None)
}

pub fn create_commands(container: &str, new: &NewUser) -> Vec<Invocation> {
    let name = format!("--display-name={}", new.display_name);
    let mut add = vec!["user:add", "--password-from-env"];
    if !new.display_name.is_empty() {
        add.push(&name);
    }
    add.push(&new.login);
    let mut steps = vec![occ(container, &add, Some(&new.password))];
    if !new.email.is_empty() {
        let set: [&str; 5] = ["user:setting", &new.login, "settings", "email", &new.email];
        steps.push(occ(container, &set, None));
    }
    if new.role == ADMIN_ROLE {
        steps.push(role_command(container, &new.login, ADMIN_ROLE));
    }
    if new.quota_bytes > 0 {
        steps.push(quota_command(container, &new.login, new.quota_bytes));
    }
    steps
}

pub fn delete_command(container: &str, user_id: &str) -> Invocation {
    occ(container, &["user:delete", user_id], None)
}

pub fn password_command(container: &str, user_id: &str, password: &str) -> Invocation {
    occ(container, &["user:resetpassword", "--password-from-env", user_id], Some(password))
}

pub fn enabled_command(container: &str, user_id: &str, enabled: bool) -> Invocation {
    let verb = if enabled { "user:enable" } else { "user:disable" };
    occ(container, &[verb, user_id], None)
}

pub fn role_command(container: &str, user_id: &str, role: &str) -> Invocation {
    let verb = if role == ADMIN_ROLE { "group:adduser" } else { "group:removeuser" };
    occ(container, &[verb, ADMIN_ROLE, user_id], None)
}

pub fn quota_command(container: &str, user_id: &str, bytes: i64) -> Invocation {
    let quota = if bytes > 0 { format!("{bytes} B") } else { "none".to_string() };
    occ(container, &["user:setting", user_id, "files", "quota", quota.as_str()], None)
}

// ─────────────────────────── Parsing ───────────────────────────

const UNITS: [(&str, f64); 6] = [
    ("B", 1.0),
    ("KB", 1024.0),
    ("MB", 1024.0 * 1024.0),
    ("GB", 1024.0 * 1024.0 * 1024.0),
    ("TB", 1024.0 * 1024.0 * 1024.0 * 1024.0),
    ("PB", 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0),
];

pub fn parse_size(text: &str) -> i64 {
    let text = text.trim();
    let split = text.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(text.len());
    let Ok(number) = text[..split].parse::<f64>() else { return 0 };
    let unit = text[split..].trim().to_ascii_uppercase();
    let unit = if unit.is_empty() { "B" } else { unit.as_str() };
    let scale = UNITS.iter().find(|(name, _)| *name == unit).map(|(_, scale)| *scale);
    scale.map(|scale| (number * scale) as i64).unwrap_or(0)
}

fn text_of(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn used_bytes(info: &Value) -> i64 {
    let used = info.get("storage").and_then(|storage| storage.get("used")).or_else(|| info.get("used"));
    match used {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(0).max(0),
        Some(Value::String(text)) => parse_size(text),
        _ => 0,
    }
}

fn parse_user(id: &str, info: &Value, admin: &str) -> pb::ServiceUser {
    if let Some(name) = info.as_str() {
        return pb::ServiceUser {
            id: id.into(),
            login: id.into(),
            display_name: name.into(),
            role: ROLE_USER.into(),
            enabled: true,
            is_self: id == admin,
            ..Default::default()
        };
    }
    let is_admin = info
        .get("groups")
        .and_then(Value::as_array)
        .is_some_and(|groups| groups.iter().any(|group| group.as_str() == Some(ADMIN_ROLE)));
    pb::ServiceUser {
        id: id.into(),
        login: id.into(),
        display_name: text_of(info, "display_name"),
        email: text_of(info, "email"),
        role: if is_admin { ADMIN_ROLE } else { ROLE_USER }.into(),
        enabled: info.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        quota_bytes: parse_size(&text_of(info, "quota")),
        used_bytes: used_bytes(info),
        is_self: id == admin,
    }
}

/// The users in `occ user:list --output=json` output
pub fn parse_users(output: &str, admin: &str) -> Result<Vec<pb::ServiceUser>, Refusal> {
    let Some(start) = output.find(['{', '[']) else { return Err(Refusal::Failed) };
    let value: Value = serde_json::from_str(output[start..].trim()).map_err(|_| Refusal::Failed)?;
    let mut users: Vec<pb::ServiceUser> = match &value {
        Value::Object(map) => map.iter().map(|(id, info)| parse_user(id, info, admin)).collect(),
        _ => Vec::new(),
    };
    users.sort_by_key(|user| user.login.to_lowercase());
    Ok(users)
}

pub fn parse_admin(env_json: &str) -> Option<String> {
    super::env_value(env_json, ADMIN_ENV)
}

/// The app container among the project's containers
pub fn pick_app_container(containers: &[pb::Container]) -> Option<String> {
    containers
        .iter()
        .find(|c| c.image.to_lowercase().contains("nextcloud") && !c.name.contains("cron"))
        .map(|c| c.name.clone())
}

// ─────────────────────────── Running ───────────────────────────

fn refusal_of_stderr(stderr: &str) -> Refusal {
    let text = stderr.to_lowercase();
    if text.contains("is not running") || text.contains("no such container") {
        Refusal::ServiceDown
    } else {
        Refusal::Failed
    }
}

async fn run(invocation: &Invocation) -> Result<String, Refusal> {
    let mut command = tokio::process::Command::new("docker");
    command
        .args(&invocation.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(secret) = &invocation.secret {
        command.env(SECRET_ENV, secret);
    }
    let child = command.spawn().map_err(|_| Refusal::ServiceDown)?;
    let output = child.wait_with_output().await.map_err(|_| Refusal::Failed)?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(refusal_of_stderr(&String::from_utf8_lossy(&output.stderr)))
    }
}

async fn run_all(steps: Vec<Invocation>) -> Done {
    for step in &steps {
        run(step).await?;
    }
    Ok(())
}

async fn admin_of(container: &str) -> Option<String> {
    parse_admin(&super::container_env(container).await?)
}

impl Nextcloud {
    pub async fn find() -> Result<Option<Nextcloud>, Refusal> {
        let snapshot = discover::service_snapshot(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        let Some(service) = snapshot else { return Ok(None) };
        let Some(container) = pick_app_container(&service.containers) else { return Ok(None) };
        let admin = admin_of(&container).await.ok_or(Refusal::Failed)?;
        Ok(Some(Nextcloud { container, admin }))
    }
}

impl UserBackend for Nextcloud {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        let output = run(&list_command(&self.container)).await?;
        parse_users(&output, &self.admin)
    }

    async fn create(&self, new: &NewUser) -> Done {
        run_all(create_commands(&self.container, new)).await
    }

    async fn delete(&self, user_id: &str) -> Done {
        run_all(vec![delete_command(&self.container, user_id)]).await
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        run_all(vec![password_command(&self.container, user_id, password)]).await
    }

    async fn set_role(&self, user_id: &str, role: &str) -> Done {
        run_all(vec![role_command(&self.container, user_id, role)]).await
    }

    async fn set_enabled(&self, user_id: &str, enabled: bool) -> Done {
        run_all(vec![enabled_command(&self.container, user_id, enabled)]).await
    }

    async fn set_quota(&self, user_id: &str, bytes: i64) -> Done {
        run_all(vec![quota_command(&self.container, user_id, bytes)]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = include_str!("../../tests/fixtures/service_users/nextcloud/list-info.json");
    const PLAIN: &str = include_str!("../../tests/fixtures/service_users/nextcloud/list-plain.json");
    const EMPTY: &str = include_str!("../../tests/fixtures/service_users/nextcloud/list-empty.json");
    const ENV: &str = include_str!("../../tests/fixtures/service_users/nextcloud/env.json");

    fn new_user(password: &str) -> NewUser {
        NewUser {
            login: "boris".into(),
            display_name: "Boris B".into(),
            email: "boris@example.org".into(),
            password: password.into(),
            role: "admin".into(),
            quota_bytes: 1024,
        }
    }

    #[test]
    fn the_info_listing_parses_into_users() {
        let users = parse_users(INFO, "operator").unwrap();
        let logins: Vec<&str> = users.iter().map(|u| u.login.as_str()).collect();
        assert_eq!(logins, ["anna", "boris", "operator"]);
        let anna = &users[0];
        assert_eq!((anna.role.as_str(), anna.enabled, anna.is_self), ("user", true, false));
        assert_eq!(anna.quota_bytes, 5 * 1024 * 1024 * 1024);
        assert_eq!(anna.used_bytes, 1_048_576);
        assert_eq!(anna.email, "anna@example.org");
        let boris = &users[1];
        assert_eq!((boris.role.as_str(), boris.enabled, boris.quota_bytes), ("admin", false, 0));
        assert_eq!(boris.email, "");
        assert!(users[2].is_self);
    }

    #[test]
    fn the_plain_listing_still_gives_names() {
        let users = parse_users(PLAIN, "operator").unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].display_name, "Anna");
        assert!(users[1].is_self);
    }

    #[test]
    fn an_empty_listing_is_no_users() {
        assert!(parse_users(EMPTY, "operator").unwrap().is_empty());
    }

    #[test]
    fn output_that_is_not_json_is_a_failure() {
        assert_eq!(parse_users("Nextcloud is in maintenance mode", "operator"), Err(Refusal::Failed));
    }

    #[test]
    fn a_warning_before_the_json_is_skipped() {
        let text = format!("PHP Warning: something\n{PLAIN}");
        assert_eq!(parse_users(&text, "operator").unwrap().len(), 2);
    }

    #[test]
    fn quota_texts_become_bytes() {
        assert_eq!(parse_size("5 GB"), 5 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1.5 MB"), 1_572_864);
        assert_eq!(parse_size("2048 B"), 2048);
        assert_eq!(parse_size("none"), 0);
        assert_eq!(parse_size("default"), 0);
    }

    #[test]
    fn the_admin_comes_from_the_container_environment() {
        assert_eq!(parse_admin(ENV).as_deref(), Some("operator"));
        assert_eq!(parse_admin("[\"PATH=/bin\"]"), None);
    }

    #[test]
    fn the_app_container_is_not_cron_or_the_database() {
        let container = |name: &str, image: &str| pb::Container {
            name: name.into(),
            image: image.into(),
            ..Default::default()
        };
        let all = [
            container("nextcloud-db-1", "mariadb:11"),
            container("nextcloud-cron-1", "nextcloud:35-apache"),
            container("nextcloud-app-1", "nextcloud:35-apache"),
        ];
        assert_eq!(pick_app_container(&all).as_deref(), Some("nextcloud-app-1"));
    }

    #[test]
    fn the_password_never_appears_in_any_argument() {
        let secret = "s3cr3t-pass-word";
        let mut all: Vec<Invocation> = create_commands("nc", &new_user(secret));
        all.push(password_command("nc", "anna", secret));
        for invocation in &all {
            assert!(invocation.args.iter().all(|arg| !arg.contains(secret)), "{:?}", invocation.args);
        }
    }

    #[test]
    fn the_password_travels_by_environment_variable_name() {
        let add = &create_commands("nc", &new_user("s3cr3t-pass-word"))[0];
        assert_eq!(add.secret.as_deref(), Some("s3cr3t-pass-word"));
        let position = add.args.iter().position(|arg| arg == "-e").unwrap();
        assert_eq!(add.args[position + 1], "OC_PASS");
        assert!(add.args.iter().any(|arg| arg == "--password-from-env"));
        let reset = password_command("nc", "anna", "s3cr3t-pass-word");
        assert!(reset.args.iter().any(|arg| arg == "--password-from-env"));
        assert_eq!(reset.secret.as_deref(), Some("s3cr3t-pass-word"));
    }

    #[test]
    fn commands_without_a_password_carry_no_secret() {
        for invocation in [
            list_command("nc"),
            delete_command("nc", "anna"),
            enabled_command("nc", "anna", false),
            role_command("nc", "anna", "user"),
            quota_command("nc", "anna", 0),
        ] {
            assert!(invocation.secret.is_none());
            assert!(!invocation.args.iter().any(|arg| arg == "-e"));
        }
    }

    #[test]
    fn creating_an_admin_with_a_quota_takes_four_steps_in_order() {
        let steps = create_commands("nc", &new_user("s3cr3t-pass-word"));
        let verbs: Vec<&str> = steps.iter().map(|s| s.args[s.args.iter().position(|a| a == "occ").unwrap() + 1].as_str()).collect();
        assert_eq!(verbs, ["user:add", "user:setting", "group:adduser", "user:setting"]);
        assert!(steps[0].args.contains(&"--display-name=Boris B".to_string()));
        assert_eq!(steps[3].args.last().unwrap(), "1024 B");
    }

    #[test]
    fn a_roleless_quotaless_user_is_one_step() {
        let mut new = new_user("s3cr3t-pass-word");
        (new.role, new.quota_bytes, new.email) = ("user".into(), 0, String::new());
        assert_eq!(create_commands("nc", &new).len(), 1);
    }

    #[test]
    fn role_and_quota_commands_name_the_right_occ_verbs() {
        assert!(role_command("nc", "anna", "user").args.ends_with(&["group:removeuser".into(), "admin".into(), "anna".into()]));
        assert!(quota_command("nc", "anna", 0).args.ends_with(&["none".into()]));
    }

    #[test]
    fn a_stopped_container_reads_as_service_down() {
        assert_eq!(refusal_of_stderr("Error response from daemon: container x is not running"), Refusal::ServiceDown);
        assert_eq!(refusal_of_stderr("The user does not exist"), Refusal::Failed);
    }
}
