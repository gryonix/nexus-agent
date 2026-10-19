//! The VPN panel's only way to its protocol containers

use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub const DIR: &str = "/run/gryonixnexus-panel";
const SOCKET: &str = "/run/gryonixnexus-panel/broker.sock";
const PROTOCOLS: [&str; 4] = ["shadowsocks", "xray", "openvpn", "awgvpn"];
const MAILCOW_DB: &str = "mailcowdockerized-mysql-mailcow-1";
const MAILBOX_QUERY: &str = "SELECT username FROM mailbox WHERE active = 1 ORDER BY username";
const PROFILE_SCRIPT: &str = "mkdir -p /etc/openvpn/panel && ovpn_getclient \"$1\" > \"/etc/openvpn/panel/$1.ovpn\"";
const MAX_REQUEST: u64 = 4096;

#[derive(Debug, PartialEq)]
pub enum Request {
    Restart(String),
    State(String),
    LogTail(String),
    OpenVpnBuild(String),
    OpenVpnProfile(String),
    OpenVpnRevoke(String),
    Mailboxes { user: String, password: String, db: String },
}

/// One docker run: its arguments and extra environment
#[derive(Debug, PartialEq)]
pub struct DockerRun {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

pub fn parse(line: &str) -> Result<Request, String> {
    let value: Value = serde_json::from_str(line).map_err(|_| "not a JSON request".to_string())?;
    let field = |key: &str| value.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    let op = field("op");
    match op.as_str() {
        "restart" => protocol_container(&field("name")).map(Request::Restart),
        "state" => protocol_container(&field("name")).map(Request::State),
        "log_tail" => protocol_container(&field("name")).map(Request::LogTail),
        "openvpn_build" => client_name(&field("name")).map(Request::OpenVpnBuild),
        "openvpn_profile" => client_name(&field("name")).map(Request::OpenVpnProfile),
        "openvpn_revoke" => client_name(&field("name")).map(Request::OpenVpnRevoke),
        "mailboxes" => mailboxes(field("user"), field("password"), field("db")),
        other => Err(format!("unknown op {other:?}")),
    }
}

fn protocol_container(name: &str) -> Result<String, String> {
    PROTOCOLS
        .contains(&name)
        .then(|| name.to_string())
        .ok_or_else(|| format!("{name:?} is not a VPN protocol container"))
}

pub fn is_client_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with(['-', '.'])
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

fn client_name(name: &str) -> Result<String, String> {
    is_client_name(name).then(|| name.to_string()).ok_or_else(|| "not a client name".to_string())
}

fn is_sql_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn mailboxes(user: String, password: String, db: String) -> Result<Request, String> {
    if !is_sql_name(&user) || !is_sql_name(&db) || password.is_empty() {
        return Err("not a mailcow database login".into());
    }
    Ok(Request::Mailboxes { user, password, db })
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// The docker commands one request runs, in order
pub fn docker_runs(request: &Request) -> Vec<DockerRun> {
    let plain = |args: Vec<String>| DockerRun { args, env: Vec::new() };
    match request {
        Request::Restart(name) => vec![plain(strings(&["restart", "-t", "3", name]))],
        Request::State(name) => {
            vec![plain(strings(&["inspect", "--format", "{{json .State}}|{{.RestartCount}}", name]))]
        }
        Request::LogTail(name) => vec![plain(strings(&["logs", "--tail", "20", name]))],
        Request::OpenVpnBuild(name) => vec![plain(strings(&[
            "exec", "-e", "EASYRSA_BATCH=1", "openvpn", "easyrsa", "build-client-full", name, "nopass",
        ]))],
        Request::OpenVpnProfile(name) => {
            vec![plain(strings(&["exec", "openvpn", "sh", "-c", PROFILE_SCRIPT, "sh", name]))]
        }
        Request::OpenVpnRevoke(name) => vec![plain(strings(&[
            "exec", "-e", "EASYRSA_BATCH=1", "openvpn", "ovpn_revokeclient", name, "remove",
        ]))],
        Request::Mailboxes { user, password, db } => vec![DockerRun {
            args: strings(&["exec", "-e", "MYSQL_PWD", MAILCOW_DB, "mysql", "-u", user, db, "-N", "-B", "-e", MAILBOX_QUERY]),
            env: vec![("MYSQL_PWD".into(), password.clone())],
        }],
    }
}

/// `inspect`'s `<state json>|<restart count>` as the panel reads it
pub fn state_answer(output: &str) -> Value {
    let Some((state, count)) = output.trim().rsplit_once('|') else { return json!({ "ok": false }) };
    match serde_json::from_str::<Value>(state) {
        Ok(state) => json!({ "ok": true, "state": state, "restart_count": count.trim().parse::<u64>().unwrap_or(0) }),
        Err(_) => json!({ "ok": false }),
    }
}

async fn run(docker: &DockerRun) -> (bool, String) {
    let mut command = tokio::process::Command::new("docker");
    command.args(&docker.args).stdin(Stdio::null()).kill_on_drop(true);
    for (key, value) in &docker.env {
        command.env(key, value);
    }
    match command.output().await {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.success(), text)
        }
        Err(error) => (false, error.to_string()),
    }
}

async fn answer(request: &Request) -> Value {
    let mut output = String::new();
    for docker in docker_runs(request) {
        let (ok, text) = run(&docker).await;
        if !ok {
            return json!({ "ok": false, "error": text.chars().take(400).collect::<String>() });
        }
        output = text;
    }
    match request {
        Request::State(_) => state_answer(&output),
        _ => json!({ "ok": true, "out": output }),
    }
}

async fn serve(stream: UnixStream) {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    if BufReader::new(read.take(MAX_REQUEST)).read_line(&mut line).await.is_err() {
        return;
    }
    let reply = match parse(&line) {
        Ok(request) => answer(&request).await,
        Err(why) => json!({ "ok": false, "error": why }),
    };
    let _ = write.write_all(format!("{reply}\n").as_bytes()).await;
}

fn bind(dir: &str, socket: &str) -> std::io::Result<UnixListener> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn spawn() {
    tokio::spawn(async {
        let listener = match bind(DIR, SOCKET) {
            Ok(listener) => listener,
            Err(error) => {
                tracing::warn!("VPN panel broker not started: {error}");
                return;
            }
        };
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_protocol_containers_are_reachable() {
        assert_eq!(parse(r#"{"op":"restart","name":"xray"}"#), Ok(Request::Restart("xray".into())));
        assert!(parse(r#"{"op":"restart","name":"vaultwarden"}"#).is_err());
        assert!(parse(r#"{"op":"exec","name":"xray"}"#).is_err());
        assert!(parse("not json").is_err());
    }

    #[test]
    fn client_names_cannot_become_options_or_paths() {
        for bad in ["-rf", "../x", "a b", "a;b", ".hidden", "", &"a".repeat(33)] {
            assert!(!is_client_name(bad), "{bad:?} must be refused");
        }
        assert!(is_client_name("iPhone_15.pro-max"));
    }

    #[test]
    fn the_profile_name_travels_as_an_argument_not_as_script() {
        let runs = docker_runs(&Request::OpenVpnProfile("phone".into()));
        assert_eq!(runs[0].args.last().map(String::as_str), Some("phone"));
        assert!(!runs[0].args.iter().any(|a| a.contains("phone") && a.contains("ovpn_getclient")));
    }

    #[test]
    fn the_mailcow_password_stays_off_the_command_line() {
        let request = parse(r#"{"op":"mailboxes","user":"mailcow","password":"s3cret","db":"mailcow"}"#).unwrap();
        let runs = docker_runs(&request);
        assert!(!runs[0].args.iter().any(|a| a.contains("s3cret")));
        assert_eq!(runs[0].env, vec![("MYSQL_PWD".to_string(), "s3cret".to_string())]);
        assert!(parse(r#"{"op":"mailboxes","user":"x; drop","password":"p","db":"m"}"#).is_err());
    }

    #[test]
    fn inspect_output_becomes_the_state_the_panel_reads() {
        let reply = state_answer("{\"Running\":true,\"Restarting\":false,\"Status\":\"running\"}|2\n");
        assert_eq!(reply["state"]["Running"], true);
        assert_eq!(reply["restart_count"], 2);
        assert_eq!(state_answer("garbage")["ok"], false);
    }

    #[tokio::test]
    async fn a_refused_request_is_answered_not_dropped() {
        let dir = std::env::temp_dir().join(format!("gnx-broker-{}", std::process::id()));
        let socket = dir.join("broker.sock");
        let listener = bind(dir.to_str().unwrap(), socket.to_str().unwrap()).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve(stream).await;
        });
        let mut client = UnixStream::connect(&socket).await.unwrap();
        client.write_all(b"{\"op\":\"restart\",\"name\":\"vaultwarden\"}\n").await.unwrap();
        let mut reply = String::new();
        BufReader::new(client).read_line(&mut reply).await.unwrap();
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(serde_json::from_str::<Value>(&reply).unwrap()["ok"], false);
    }
}
