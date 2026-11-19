//! The single web password of Pi-hole, kept in the service's environment file

use std::path::PathBuf;

use super::docker::{self, Call};
use super::{NewUser, Refusal, UserBackend};
use crate::install::pihole::COMPOSE_PROJECT;
use crate::{discover, pb};

pub const SERVICE_ID: &str = "pihole";
const ENV_KEY: &str = "PIHOLE_ADMIN_PASSWORD";
const ADMIN: &str = "admin";

type Done = Result<(), Refusal>;

pub fn capabilities() -> pb::UserCapabilities {
    pb::UserCapabilities { supported: true, can_set_password: true, ..Default::default() }
}

/// Whether the password can sit in a single-quoted environment value
pub fn storable(password: &str) -> bool {
    !password.contains('\'') && !password.chars().any(char::is_control)
}

/// The environment text with the password line replaced or added
pub fn with_password(env: &str, password: &str) -> String {
    let line = format!("{ENV_KEY}='{password}'");
    let mut replaced = false;
    let mut lines: Vec<String> = env
        .lines()
        .map(|existing| {
            if existing.trim_start().starts_with(&format!("{ENV_KEY}=")) {
                replaced = true;
                line.clone()
            } else {
                existing.to_string()
            }
        })
        .collect();
    if !replaced {
        lines.push(line);
    }
    lines.join("\n") + "\n"
}

pub fn recreate_call(directory: &str) -> Call {
    let file = format!("{directory}/docker-compose.yml");
    Call::new(&["compose", "-p", COMPOSE_PROJECT, "-f", &file, "--project-directory", directory, "up", "-d"])
}

pub struct Pihole {
    directory: PathBuf,
}

impl Pihole {
    pub async fn find() -> Result<Option<Pihole>, Refusal> {
        let directory = discover::directory_of_service(SERVICE_ID).await.map_err(|_| Refusal::ServiceDown)?;
        Ok(directory.map(|directory| Pihole { directory }))
    }
}

impl UserBackend for Pihole {
    fn capabilities(&self) -> pb::UserCapabilities {
        capabilities()
    }

    async fn list(&self) -> Result<Vec<pb::ServiceUser>, Refusal> {
        Ok(vec![pb::ServiceUser {
            id: ADMIN.into(),
            login: ADMIN.into(),
            enabled: true,
            is_self: true,
            ..Default::default()
        }])
    }

    async fn create(&self, _: &NewUser) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn delete(&self, _: &str) -> Done {
        Err(Refusal::NotSupported)
    }

    async fn set_password(&self, user_id: &str, password: &str) -> Done {
        if user_id != ADMIN {
            return Err(Refusal::UnknownUser);
        }
        if !storable(password) {
            return Err(Refusal::InvalidPassword);
        }
        let path = self.directory.join(".env");
        let env = std::fs::read_to_string(&path).map_err(|_| Refusal::Failed)?;
        crate::util::write_file_atomic(&path, with_password(&env, password).as_bytes(), 0o600).map_err(|_| Refusal::Failed)?;
        docker::run(&recreate_call(&self.directory.to_string_lossy())).await.map(|_| ())
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

    #[test]
    fn the_password_line_is_replaced_and_other_lines_stay() {
        let env = "OTHER=1\nPIHOLE_ADMIN_PASSWORD=oldvalue\nLAST=2\n";
        assert_eq!(with_password(env, "new-pass-123"), "OTHER=1\nPIHOLE_ADMIN_PASSWORD='new-pass-123'\nLAST=2\n");
        assert_eq!(with_password("OTHER=1\n", "x-long-enough"), "OTHER=1\nPIHOLE_ADMIN_PASSWORD='x-long-enough'\n");
    }

    #[test]
    fn a_dollar_sign_stays_literal_inside_single_quotes() {
        assert!(storable("pa$$word-1"));
        assert!(with_password("", "pa$$word-1").contains("='pa$$word-1'"));
        assert!(!storable("it's-a-trap"));
        assert!(!storable("line\nbreak-here"));
    }

    #[test]
    fn the_service_is_recreated_from_its_own_folder_without_the_password_in_argv() {
        let call = recreate_call("/opt/pihole");
        assert_eq!(
            call.args,
            ["compose", "-p", "pihole", "-f", "/opt/pihole/docker-compose.yml", "--project-directory", "/opt/pihole", "up", "-d"]
        );
        assert!(call.stdin.is_none());
    }

    #[test]
    fn there_is_one_password_and_nothing_else() {
        let caps = capabilities();
        assert!(caps.can_set_password && !caps.can_create && !caps.can_delete && !caps.can_set_enabled && caps.roles.is_empty());
    }
}
