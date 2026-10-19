//! Mailboxes of the docker-mailserver engine

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use hyper::StatusCode;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use crate::api::{connect_error, Codec, Resp};
use crate::util::strip_ansi;
use crate::{discover, pb};

/// The catalog id this module serves
const SERVICE_ID: &str = "docker-mailserver";

/// Where docker-mailserver keeps its config INSIDE the container
const CONFIG_DIR_IN_CONTAINER: &str = "/tmp/docker-mailserver";
const ACCOUNTS_FILE: &str = "postfix-accounts.cf";

/// One engine call's deadline
const ENGINE_TIMEOUT_SECS: u64 = 120;

const DELETE_ATTEMPTS: u32 = 5;
const DELETE_RETRY_DELAY_SECS: u64 = 2;

const ECHO_LIMIT: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The address failed the same check the wrapper applies.
    InvalidAddress(String),
    /// A mutation arrived without a password
    EmptyPassword,
    /// The engine is not installed on this host.
    NotInstalled,
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::InvalidAddress(address) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("invalid address: {}", truncate(address)),
            ),
            Rejection::EmptyPassword => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "the password is empty".to_string(),
            ),
            Rejection::NotInstalled => (
                StatusCode::NOT_FOUND,
                "not_found",
                "docker-mailserver is not installed on this host".to_string(),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

pub fn valid_address(address: &str) -> bool {
    if address.is_empty() || address.starts_with('-') {
        return false;
    }
    let allowed = address.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '@' | '_' | '+' | '-')
    });
    if !allowed {
        return false;
    }
    let parts: Vec<&str> = address.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty()
}

// ─────────────────────────── Engine plumbing ───────────────────────────

/// The docker-mailserver container, resolved from the host's OWN report
async fn engine_container() -> Result<Option<String>> {
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
    let output = run_engine(
        container,
        &["test", "-s", &format!("{CONFIG_DIR_IN_CONTAINER}/{ACCOUNTS_FILE}")],
        None,
    )
    .await?;
    Ok(output.status_ok)
}

struct EngineOutput {
    status_ok: bool,
    stdout: String,
    stderr: String,
}

/// Run one command in the engine container
async fn run_engine(container: &str, args: &[&str], stdin: Option<&str>) -> Result<EngineOutput> {
    let mut command = tokio::process::Command::new("docker");
    command.arg("exec");
    if stdin.is_some() {
        command.arg("-i");
    }
    command.arg(container);
    command.args(args);
    let mut child = command
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    if let Some(secret) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(secret.as_bytes()).await?;
            pipe.shutdown().await?;
        }
    }

    let output = tokio::time::timeout(Duration::from_secs(ENGINE_TIMEOUT_SECS), child.wait_with_output())
        .await
        .map_err(|_| anyhow::anyhow!("the mail engine did not answer within {ENGINE_TIMEOUT_SECS}s"))??;

    Ok(EngineOutput {
        status_ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: strip_ansi(&String::from_utf8_lossy(&output.stderr)).trim().to_string(),
    })
}

// ─────────────────────────── Listing ───────────────────────────

/// Parse `setup email list`, a port of the app's MailboxListParser
pub fn parse_list(output: &str) -> Vec<pb::Mailbox> {
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
        mailboxes.push(pb::Mailbox {
            address: address.to_string(),
            detail: detail.to_string(),
            manageable: valid_address(address),
        });
    }
    mailboxes
}

/// Is this token an address the SERVER printed?
fn is_address(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    if token.contains(|c| "()<>[]{},;:\"'\\|".contains(c)) {
        return false;
    }
    let parts: Vec<&str> = token.split('@').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[1].contains('.')
        && !token.chars().any(char::is_whitespace)
}

/// The mailboxes on this host
async fn list(container: &str) -> Result<Vec<pb::Mailbox>, EngineFailure> {
    if !has_accounts(container).await.map_err(EngineFailure::Unreachable)? {
        return Ok(Vec::new());
    }
    let output = run_engine(container, &["setup", "email", "list"], None)
        .await
        .map_err(EngineFailure::Unreachable)?;
    if !output.status_ok {
        return Err(EngineFailure::Refused(output.stderr));
    }
    // STDOUT only — see the module note about the stderr diagnostic.
    Ok(parse_list(&output.stdout))
}

enum EngineFailure {
    /// docker could not be run/reached at all.
    Unreachable(anyhow::Error),
    /// docker ran and the engine said no
    Refused(String),
}

impl EngineFailure {
    fn response(&self) -> Resp {
        match self {
            EngineFailure::Unreachable(err) => connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("container engine unavailable: {err}"),
            ),
            EngineFailure::Refused(detail) => connect_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                if detail.is_empty() { "the mail engine refused the request" } else { detail },
            ),
        }
    }
}

// ─────────────────────────── Mutations ───────────────────────────

fn password_input(password: &str) -> String {
    format!("{password}\n{password}\n")
}

async fn create(container: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let output = run_engine(
        container,
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

async fn set_password(container: &str, address: &str, password: &str) -> Result<(), EngineFailure> {
    let output = run_engine(
        container,
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
async fn delete(container: &str, address: &str) -> Result<(), EngineFailure> {
    let mut attempt = 1;
    loop {
        let output = run_engine(container, &["setup", "email", "del", "-y", address], None)
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

fn redact(password: &str, text: &str) -> String {
    if password.is_empty() || !text.contains(password) {
        return text.to_string();
    }
    text.replace(password, "***")
}

// ─────────────────────────── RPCs ───────────────────────────

async fn resolve() -> Result<String, Resp> {
    match engine_container().await {
        Ok(Some(container)) => Ok(container),
        Ok(None) => Err(Rejection::NotInstalled.response()),
        Err(err) => Err(EngineFailure::Unreachable(err).response()),
    }
}

async fn respond_with_listing(codec: Codec, container: &str) -> Resp {
    match list(container).await {
        Ok(mailboxes) => encode(codec, &pb::MailboxList { mailboxes }),
        Err(failure) => failure.response(),
    }
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

pub async fn list_mailboxes(codec: Codec, _req: pb::ListMailboxesRequest) -> Resp {
    match resolve().await {
        Ok(container) => respond_with_listing(codec, &container).await,
        Err(refusal) => refusal,
    }
}

pub async fn create_mailbox(codec: Codec, req: pb::CreateMailboxRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    if req.password.is_empty() {
        return Rejection::EmptyPassword.response();
    }
    let container = match resolve().await {
        Ok(container) => container,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = create(&container, &req.address, &req.password).await {
        return failure.response();
    }
    respond_with_listing(codec, &container).await
}

pub async fn delete_mailbox(codec: Codec, req: pb::DeleteMailboxRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    let container = match resolve().await {
        Ok(container) => container,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = delete(&container, &req.address).await {
        return failure.response();
    }
    respond_with_listing(codec, &container).await
}

pub async fn set_mailbox_password(codec: Codec, req: pb::SetMailboxPasswordRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    if req.password.is_empty() {
        return Rejection::EmptyPassword.response();
    }
    let container = match resolve().await {
        Ok(container) => container,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = set_password(&container, &req.address, &req.password).await {
        return failure.response();
    }
    respond_with_listing(codec, &container).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_rule_is_the_wrappers_rule() {
        // Accepted — the shapes a user actually types.
        for good in ["admin@example.com", "a.b+tag_1@sub.example.co.uk", "x@y"] {
            assert!(valid_address(good), "{good} must be accepted");
        }
        for bad in [
            "",                       // nothing at all
            "-admin@example.com",     // could read as a flag
            "admin",                  // no domain
            "@example.com",           // no local part
            "admin@",                 // no domain
            "a@b@c",                  // two @
            "admin example@com",      // space
            "admin@example.com; rm -rf /", // shell metacharacters, refused as an ADDRESS
            "admin@exam ple.com",
            "admin$@example.com",
            "admin@example.com\n",    // a newline is not part of an address
            "üser@example.com",       // non-ASCII: the engine's userdb will not resolve it
        ] {
            assert!(!valid_address(bad), "{bad:?} must be refused");
        }
    }

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
    fn a_secret_is_blanked_out_of_anything_going_back_to_the_user() {
        assert_eq!(redact("s3cr3t", "usage: add <a> s3cr3t"), "usage: add <a> ***");
        assert_eq!(redact("", "nothing to do"), "nothing to do");
    }

    #[test]
    fn the_delete_retry_budget_matches_the_wrappers() {
        assert_eq!(DELETE_ATTEMPTS, 5);
        assert_eq!(DELETE_RETRY_DELAY_SECS, 2);
    }

    #[test]
    fn refusals_carry_distinct_codes_and_bounded_text() {
        let (status, code, message) = Rejection::InvalidAddress("zz@zz.com".into()).parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_argument");
        assert!(message.contains("zz@zz.com"));

        let (status, code, _) = Rejection::NotInstalled.parts();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code, "not_found");

        let (_, _, message) = Rejection::InvalidAddress("a".repeat(5000)).parts();
        assert!(message.len() < 200, "message was {} bytes", message.len());
    }

    #[test]
    fn an_engine_that_refuses_is_told_apart_from_an_engine_that_is_not_there() {
        let refused = EngineFailure::Refused("container mailserver is not running".into());
        assert_eq!(refused.response().status(), StatusCode::UNPROCESSABLE_ENTITY);
        let unreachable = EngineFailure::Unreachable(anyhow::anyhow!("docker: command not found"));
        assert_eq!(unreachable.response().status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(Rejection::NotInstalled.parts().0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_engine_is_addressed_through_the_same_catalog_gate_as_everything_else() {
        assert_eq!(discover::known_service(SERVICE_ID), Some("Docker Mailserver"));
    }
}
