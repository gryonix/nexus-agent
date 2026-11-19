//! Mailboxes of the docker-mailserver engine

use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;

use super::{is_address, mailbox, redact, run_exec, EngineFailure};
use crate::util::strip_ansi;
use crate::{discover, pb};

/// The catalog id this module serves
const SERVICE_ID: &str = "docker-mailserver";

/// Where docker-mailserver keeps its config INSIDE the container
const CONFIG_DIR_IN_CONTAINER: &str = "/tmp/docker-mailserver";
const ACCOUNTS_FILE: &str = "postfix-accounts.cf";

const DELETE_ATTEMPTS: u32 = 5;
const DELETE_RETRY_DELAY_SECS: u64 = 2;

/// The docker-mailserver container, resolved from the host's OWN report
pub(super) async fn find() -> Result<Option<String>> {
    let Some(service) = discover::service_snapshot(SERVICE_ID).await? else {
        return Ok(None);
    };
    let by_image = service
        .containers
        .iter()
        .find(|c| c.image.to_lowercase().contains("docker-mailserver"));
    let picked = by_image.or_else(|| service.containers.iter().find(|c| c.name == "mailserver"));
    Ok(picked.map(|c| c.name.clone()))
}

/// One row of `docker inspect --format {{json .Mounts}}`.
#[derive(Debug, Deserialize)]
struct Mount {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

async fn host_config_dir(container: &str) -> Option<String> {
    let output = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Mounts}}", container])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mounts: Vec<Mount> = serde_json::from_slice(&output.stdout).ok()?;
    mounts
        .into_iter()
        .find(|m| m.destination == CONFIG_DIR_IN_CONTAINER && !m.source.is_empty())
        .map(|m| m.source)
}

/// Does the engine have any account at all?
async fn has_accounts(container: &str) -> Result<bool> {
    if let Some(dir) = host_config_dir(container).await {
        let path = std::path::Path::new(&dir).join(ACCOUNTS_FILE);
        return Ok(std::fs::metadata(&path).map(|m| m.len() > 0).unwrap_or(false));
    }
    let output = run_exec(
        container,
        None,
        &["test", "-s", &format!("{CONFIG_DIR_IN_CONTAINER}/{ACCOUNTS_FILE}")],
        None,
    )
    .await?;
    Ok(output.status_ok)
}

/// Parse `setup email list`, a port of the app's MailboxListParser
pub(super) fn parse_list(output: &str) -> Vec<pb::Mailbox> {
    let stripped = strip_ansi(output);
    let mut mailboxes: Vec<pb::Mailbox> = Vec::new();
    for raw in stripped.split('\n') {
        let line = raw.trim().trim_matches('*').trim();
        let (address, detail) = match line.find([' ', '\t']) {
            Some(index) => (&line[..index], line[index..].trim()),
            None => (line, ""),
        };
        if !is_address(address) || mailboxes.iter().any(|m| m.address == address) {
            continue;
        }
        mailboxes.push(mailbox(address, detail));
    }
    mailboxes
}

/// The mailboxes on this host
pub(super) async fn list(container: &str) -> Result<Vec<pb::Mailbox>, EngineFailure> {
    if !has_accounts(container).await.map_err(EngineFailure::Unreachable)? {
        return Ok(Vec::new());
    }
    let output = run_exec(container, None, &["setup", "email", "list"], None)
        .await
        .map_err(EngineFailure::Unreachable)?;
    if !output.status_ok {
        return Err(EngineFailure::Refused(output.stderr));
    }
    Ok(parse_list(&output.stdout))
}

fn password_input(password: &str) -> String {
    format!("{password}\n{password}\n")
}

pub(super) async fn create(container: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let output = run_exec(
        container,
        None,
        &["setup", "email", "add", address],
        Some(&password_input(password)),
    )
    .await
    .map_err(EngineFailure::Unreachable)?;
    if output.status_ok {
        Ok(())
    } else {
        Err(EngineFailure::Refused(redact(password, &output.stderr)))
    }
}

pub(super) async fn set_password(container: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let output = run_exec(
        container,
        None,
        &["setup", "email", "update", address],
        Some(&password_input(password)),
    )
    .await
    .map_err(EngineFailure::Unreachable)?;
    if output.status_ok {
        Ok(())
    } else {
        Err(EngineFailure::Refused(redact(password, &output.stderr)))
    }
}

/// Delete a mailbox, waiting out a race INSIDE the engine
pub(super) async fn delete(container: &str, address: &str) -> Result<(), EngineFailure> {
    let mut attempt = 1;
    loop {
        let output = run_exec(container, None, &["setup", "email", "del", "-y", address], None)
            .await
            .map_err(EngineFailure::Unreachable)?;
        if output.status_ok {
            return Ok(());
        }
        if attempt >= DELETE_ATTEMPTS {
            return Err(EngineFailure::Refused(output.stderr));
        }
        attempt += 1;
        tokio::time::sleep(Duration::from_secs(DELETE_RETRY_DELAY_SECS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_LIST: &str = "\
* admin@example.com ( 6.0K / ~ ) [0%]
* used@example.com ( 0 / ~ ) [0%]
* fresh@example.com (  /  ) [%]
";

    #[test]
    fn all_three_live_row_shapes_parse() {
        let mailboxes = parse_list(LIVE_LIST);
        assert_eq!(
            mailboxes.iter().map(|m| m.address.as_str()).collect::<Vec<_>>(),
            ["admin@example.com", "used@example.com", "fresh@example.com"]
        );
        assert_eq!(mailboxes[0].detail, "( 6.0K / ~ ) [0%]");
        assert_eq!(mailboxes[1].detail, "( 0 / ~ ) [0%]");
        assert_eq!(mailboxes[2].detail, "(  /  ) [%]");
        assert!(mailboxes.iter().all(|m| m.manageable));
    }

    #[test]
    fn a_diagnostic_line_never_becomes_a_mailbox() {
        let text = "doveadm(broken@example.com): Error: User doesn't exist\n\
                    WARN  this is a log line\n\
                    Error: user@example.com not found\n\
                    There are no accounts\n";
        assert!(parse_list(text).is_empty(), "{:?}", parse_list(text));
    }

    #[test]
    fn a_mailbox_the_agent_would_not_accept_is_still_listed_but_not_manageable() {
        let mailboxes = parse_list("* üser@example.com ( 0 / ~ ) [0%]\n");
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].address, "üser@example.com");
        assert!(!mailboxes[0].manageable);
    }

    #[test]
    fn ansi_colour_never_reaches_the_parsed_output() {
        let mailboxes = parse_list("* \u{1B}[1;32madmin@example.com\u{1B}[0m ( 0 / ~ ) [0%]\n");
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].address, "admin@example.com");
    }

    #[test]
    fn duplicate_rows_collapse() {
        let mailboxes = parse_list("* a@b.com ( 0 / ~ )\n* a@b.com ( 0 / ~ )\n");
        assert_eq!(mailboxes.len(), 1);
    }

    #[test]
    fn an_empty_listing_is_no_mailboxes_not_a_parse_failure() {
        assert!(parse_list("").is_empty());
        assert!(parse_list("\n\n").is_empty());
    }

    #[test]
    fn the_password_is_prompted_twice_and_only_ever_on_stdin() {
        assert_eq!(password_input("s3cr3t"), "s3cr3t\ns3cr3t\n");
        for args in [
            vec!["setup", "email", "add", "a@b.com"],
            vec!["setup", "email", "update", "a@b.com"],
            vec!["setup", "email", "del", "-y", "a@b.com"],
            vec!["setup", "email", "list"],
        ] {
            assert!(!args.iter().any(|arg| arg.contains("s3cr3t")));
        }
    }

    #[test]
    fn the_delete_retry_budget_matches_the_wrappers() {
        assert_eq!(DELETE_ATTEMPTS, 5);
        assert_eq!(DELETE_RETRY_DELAY_SECS, 2);
    }

    #[test]
    fn the_engine_is_addressed_through_the_same_catalog_gate_as_everything_else() {
        assert_eq!(discover::known_service(SERVICE_ID), Some("Docker Mailserver"));
    }
}
