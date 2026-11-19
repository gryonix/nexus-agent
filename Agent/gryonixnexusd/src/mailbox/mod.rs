//! Mailboxes of whichever mail engine is installed on this host

mod dms;
mod mailcow;
mod mailu;

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use hyper::StatusCode;
use tokio::io::AsyncWriteExt;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

/// One engine call's deadline
const ENGINE_TIMEOUT_SECS: u64 = 120;

const ECHO_LIMIT: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The address failed the same check the wrapper applies.
    InvalidAddress(String),
    /// A mutation arrived without a password
    EmptyPassword,
    /// No mail engine is installed on this host.
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
                "no mail engine is installed on this host".to_string(),
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

fn mailbox(address: &str, detail: &str) -> pb::Mailbox {
    pb::Mailbox {
        address: address.to_string(),
        detail: detail.to_string(),
        manageable: valid_address(address),
    }
}

/// A byte count the way the engines print sizes
fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}{}", UNITS[0])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

// ─────────────────────────── Engine plumbing ───────────────────────────

pub(crate) struct EngineOutput {
    pub(crate) status_ok: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Run one prepared command, feeding the secret through stdin only
async fn run_command(mut command: tokio::process::Command, stdin: Option<&str>) -> Result<EngineOutput> {
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
        stderr: crate::util::strip_ansi(&String::from_utf8_lossy(&output.stderr)).trim().to_string(),
    })
}

/// The `docker exec` argument list for one engine command
fn exec_args(container: &str, user: Option<&str>, args: &[&str], with_stdin: bool) -> Vec<String> {
    let mut all = vec!["exec".to_string()];
    if with_stdin {
        all.push("-i".to_string());
    }
    if let Some(user) = user {
        all.push("-u".to_string());
        all.push(user.to_string());
    }
    all.push(container.to_string());
    all.extend(args.iter().map(|arg| arg.to_string()));
    all
}

/// Run one command in the engine container
pub(crate) async fn run_exec(
    container: &str,
    user: Option<&str>,
    args: &[&str],
    stdin: Option<&str>,
) -> Result<EngineOutput> {
    let mut command = tokio::process::Command::new("docker");
    command.args(exec_args(container, user, args, stdin.is_some()));
    run_command(command, stdin).await
}

pub(crate) enum EngineFailure {
    /// docker could not be run/reached at all.
    Unreachable(anyhow::Error),
    /// The engine ran and said no
    Refused(String),
}

impl EngineFailure {
    fn response(&self) -> Resp {
        match self {
            EngineFailure::Unreachable(err) => crate::api::engine_unavailable(&err.to_string()),
            EngineFailure::Refused(detail) => connect_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                if detail.is_empty() { "the mail engine refused the request" } else { detail },
            ),
        }
    }
}

fn redact(password: &str, text: &str) -> String {
    if password.is_empty() || !text.contains(password) {
        return text.to_string();
    }
    text.replace(password, "***")
}

/// The installed engine, with what it needs to be driven
enum Engine {
    Dms(String),
    Mailcow(mailcow::Access),
    Mailu(String),
}

async fn engine() -> Result<Option<Engine>, EngineFailure> {
    if let Some(container) = dms::find().await.map_err(EngineFailure::Unreachable)? {
        return Ok(Some(Engine::Dms(container)));
    }
    if let Some(access) = mailcow::find().await? {
        return Ok(Some(Engine::Mailcow(access)));
    }
    let admin = mailu::find().await.map_err(EngineFailure::Unreachable)?;
    Ok(admin.map(Engine::Mailu))
}

impl Engine {
    async fn list(&self) -> Result<Vec<pb::Mailbox>, EngineFailure> {
        match self {
            Engine::Dms(container) => dms::list(container).await,
            Engine::Mailcow(access) => mailcow::list(access).await,
            Engine::Mailu(admin) => mailu::list(admin).await,
        }
    }

    async fn create(&self, address: &str, password: &str) -> Result<(), EngineFailure> {
        match self {
            Engine::Dms(container) => dms::create(container, address, password).await,
            Engine::Mailcow(access) => mailcow::create(access, address, password).await,
            Engine::Mailu(admin) => mailu::create(admin, address, password).await,
        }
    }

    async fn set_password(&self, address: &str, password: &str) -> Result<(), EngineFailure> {
        match self {
            Engine::Dms(container) => dms::set_password(container, address, password).await,
            Engine::Mailcow(access) => mailcow::set_password(access, address, password).await,
            Engine::Mailu(admin) => mailu::set_password(admin, address, password).await,
        }
    }

    async fn delete(&self, address: &str) -> Result<(), EngineFailure> {
        match self {
            Engine::Dms(container) => dms::delete(container, address).await,
            Engine::Mailcow(access) => mailcow::delete(access, address).await,
            Engine::Mailu(admin) => mailu::delete(admin, address).await,
        }
    }
}

// ─────────────────────────── RPCs ───────────────────────────

async fn resolve() -> Result<Engine, Resp> {
    match engine().await {
        Ok(Some(engine)) => Ok(engine),
        Ok(None) => Err(Rejection::NotInstalled.response()),
        Err(failure) => Err(failure.response()),
    }
}

async fn respond_with_listing(codec: Codec, engine: &Engine) -> Resp {
    match engine.list().await {
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
        Ok(engine) => respond_with_listing(codec, &engine).await,
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
    let engine = match resolve().await {
        Ok(engine) => engine,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = engine.create(&req.address, &req.password).await {
        return failure.response();
    }
    respond_with_listing(codec, &engine).await
}

pub async fn delete_mailbox(codec: Codec, req: pb::DeleteMailboxRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    let engine = match resolve().await {
        Ok(engine) => engine,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = engine.delete(&req.address).await {
        return failure.response();
    }
    respond_with_listing(codec, &engine).await
}

pub async fn set_mailbox_password(codec: Codec, req: pb::SetMailboxPasswordRequest) -> Resp {
    if !valid_address(&req.address) {
        return Rejection::InvalidAddress(req.address).response();
    }
    if req.password.is_empty() {
        return Rejection::EmptyPassword.response();
    }
    let engine = match resolve().await {
        Ok(engine) => engine,
        Err(refusal) => return refusal,
    };
    if let Err(failure) = engine.set_password(&req.address, &req.password).await {
        return failure.response();
    }
    respond_with_listing(codec, &engine).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_rule_is_the_wrappers_rule() {
        for good in ["admin@example.com", "a.b+tag_1@sub.example.co.uk", "x@y"] {
            assert!(valid_address(good), "{good} must be accepted");
        }
        for bad in [
            "",
            "-admin@example.com",
            "admin",
            "@example.com",
            "admin@",
            "a@b@c",
            "admin example@com",
            "admin@example.com; rm -rf /",
            "admin@exam ple.com",
            "admin$@example.com",
            "admin@example.com\n",
            "üser@example.com",
        ] {
            assert!(!valid_address(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_secret_is_blanked_out_of_anything_going_back_to_the_user() {
        assert_eq!(redact("s3cr3t", "usage: add <a> s3cr3t"), "usage: add <a> ***");
        assert_eq!(redact("", "nothing to do"), "nothing to do");
    }

    #[test]
    fn the_exec_command_line_never_holds_the_password() {
        let args = exec_args("admin", Some("mailu"), &["flask", "mailu", "config-import", "-q", "-u"], true);
        assert_eq!(args[..4], ["exec", "-i", "-u", "mailu"]);
        assert!(!args.iter().any(|arg| arg.contains("s3cr3t")));
        let plain = exec_args("mailserver", None, &["setup", "email", "list"], false);
        assert_eq!(plain, ["exec", "mailserver", "setup", "email", "list"]);
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
        let (status, _, _) = Rejection::EmptyPassword.parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
    fn sizes_read_like_the_other_engines() {
        assert_eq!(human(0), "0B");
        assert_eq!(human(1536), "1.5K");
        assert_eq!(human(3 * 1024 * 1024 * 1024), "3.0G");
    }

    #[test]
    fn a_listed_mailbox_the_agent_would_not_accept_is_not_manageable() {
        assert!(mailbox("a@example.com", "").manageable);
        assert!(!mailbox("üser@example.com", "").manageable);
    }
}

#[cfg(test)]
mod reason_tests {
    use super::*;

    #[tokio::test]
    async fn a_silent_engine_answers_with_the_docker_reason() {
        let silent = EngineFailure::Unreachable(anyhow::anyhow!("no socket")).response();
        assert_eq!(crate::api::reason_of(silent).await, "host.docker_unavailable");
    }
}
