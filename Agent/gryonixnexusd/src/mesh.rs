//! Headscale's control plane, driven through the `headscale` CLI inside its own container

use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;
use serde_json::Value;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const CONTAINER: &str = "headscale";
const TIMEOUT: Duration = Duration::from_secs(30);

/// Why a call could not be answered
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No Headscale on this host.
    NotInstalled,
    /// The request named something the engine rejects.
    BadRequest(String),
    /// The engine ran and said something unusable.
    Engine(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NotInstalled => write!(
                f,
                "this server does not run Headscale, so it has no mesh to manage — \
                 install it first"
            ),
            Refusal::BadRequest(detail) => write!(f, "{detail}"),
            Refusal::Engine(detail) => write!(f, "the mesh control server could not do that: {detail}"),
        }
    }
}

impl Refusal {
    fn response(&self) -> Resp {
        let (status, code) = match self {
            Refusal::NotInstalled => (StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition"),
            Refusal::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_argument"),
            Refusal::Engine(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        connect_error(status, code, &self.to_string())
    }
}

/// Run one `headscale` subcommand and hand back its stdout
async fn headscale(args: &[&str]) -> Result<String, Refusal> {
    let mut command = tokio::process::Command::new("docker");
    command.arg("exec").arg(CONTAINER).arg("headscale").args(args);
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| Refusal::Engine(format!("could not run docker ({err})")))?;
    let output = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| Refusal::Engine(format!("the mesh control server did not answer within {}s", TIMEOUT.as_secs())))?
        .map_err(|err| Refusal::Engine(format!("could not run docker ({err})")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let lowered = stderr.to_lowercase();
    if lowered.contains("no such container") || lowered.contains("is not running") {
        return Err(Refusal::NotInstalled);
    }
    Err(Refusal::Engine(truncate(if stderr.trim().is_empty() { &stdout } else { &stderr })))
}

fn truncate(text: &str) -> String {
    let one_line: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(300).collect()
}

fn array_or_empty(text: &str) -> Result<Vec<Value>, Refusal> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(trimmed)
        .map_err(|err| Refusal::Engine(format!("unreadable answer ({err})")))?;
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => Ok(items),
        other => Err(Refusal::Engine(format!("expected a list, got {other}"))),
    }
}

pub fn parse_users(text: &str) -> Result<Vec<pb::MeshUser>, Refusal> {
    Ok(array_or_empty(text)?
        .into_iter()
        .filter_map(|item| {
            let id = item.get("id")?;
            let name = item.get("name")?.as_str()?.to_string();
            Some(pb::MeshUser { id: id.to_string().trim_matches('"').to_string(), name })
        })
        .collect())
}

/// Only the fields the app shows
pub fn parse_nodes(text: &str) -> Result<Vec<pb::MeshNode>, Refusal> {
    Ok(array_or_empty(text)?
        .into_iter()
        .filter_map(|item| {
            let id = item.get("id")?.to_string().trim_matches('"').to_string();
            let name = item
                .get("given_name")
                .and_then(Value::as_str)
                .or_else(|| item.get("name").and_then(Value::as_str))
                .unwrap_or_default()
                .to_string();
            let addresses = item
                .get("ip_addresses")
                .and_then(Value::as_array)
                .map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            let user = item
                .get("user")
                .and_then(|u| u.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let online = item.get("online").and_then(Value::as_bool).unwrap_or(false);
            let last_seen = item
                .get("last_seen")
                .and_then(|t| t.get("seconds"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            Some(pb::MeshNode { id, name, addresses, user, online, last_seen })
        })
        .collect())
}

pub fn parse_auth_key(text: &str) -> Result<pb::MeshAuthKey, Refusal> {
    let value: Value = serde_json::from_str(text.trim())
        .map_err(|err| Refusal::Engine(format!("unreadable answer ({err})")))?;
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::Engine("the engine returned no key".to_string()))?
        .to_string();
    Ok(pb::MeshAuthKey {
        key,
        reusable: value.get("reusable").and_then(Value::as_bool).unwrap_or(false),
        expires_at: value
            .get("expiration")
            .and_then(|t| t.get("seconds"))
            .and_then(Value::as_i64)
            .unwrap_or(0),
    })
}

fn checked_id(raw: &str, what: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(Refusal::BadRequest(format!("'{}' is not a {what}", truncate(raw))));
    }
    Ok(trimmed.to_string())
}

fn checked_name(raw: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(Refusal::BadRequest("a mesh user needs a name of 1 to 64 characters".to_string()));
    }
    // Same leading-dash rule as ids, for the same reason.
    if trimmed.starts_with('-')
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Refusal::BadRequest(
            "a mesh user's name may contain letters, digits, dot, dash and underscore".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

async fn users() -> Result<pb::MeshUserList, Refusal> {
    let out = headscale(&["users", "list", "-o", "json"]).await?;
    Ok(pb::MeshUserList { users: parse_users(&out)? })
}

async fn nodes() -> Result<pb::MeshNodeList, Refusal> {
    let out = headscale(&["nodes", "list", "-o", "json"]).await?;
    Ok(pb::MeshNodeList { nodes: parse_nodes(&out)? })
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec
        .encode(message)
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn list_users(codec: Codec, _req: pb::ListMeshUsersRequest) -> Resp {
    match users().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn create_user(codec: Codec, req: pb::CreateMeshUserRequest) -> Resp {
    let name = match checked_name(&req.name) {
        Ok(name) => name,
        Err(refusal) => return refusal.response(),
    };
    if let Err(refusal) = headscale(&["users", "create", &name]).await {
        return refusal.response();
    }
    match users().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn create_auth_key(codec: Codec, req: pb::CreateMeshAuthKeyRequest) -> Resp {
    let user = match checked_id(&req.user_id, "mesh user id") {
        Ok(id) => id,
        Err(refusal) => return refusal.response(),
    };
    let hours = if req.expiration_hours == 0 { 24 } else { req.expiration_hours.min(24 * 365) };
    let expiration = format!("{hours}h");
    let mut args: Vec<&str> = vec!["preauthkeys", "create", "--user", &user, "--expiration", &expiration];
    if req.reusable {
        args.push("--reusable");
    }
    args.extend(["-o", "json"]);
    match headscale(&args).await {
        Ok(out) => match parse_auth_key(&out) {
            Ok(key) => encode(codec, &key),
            Err(refusal) => refusal.response(),
        },
        Err(refusal) => refusal.response(),
    }
}

pub async fn list_nodes(codec: Codec, _req: pb::ListMeshNodesRequest) -> Resp {
    match nodes().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

pub async fn delete_node(codec: Codec, req: pb::DeleteMeshNodeRequest) -> Resp {
    let id = match checked_id(&req.node_id, "node id") {
        Ok(id) => id,
        Err(refusal) => return refusal.response(),
    };
    if let Err(refusal) = headscale(&["nodes", "delete", "--identifier", &id, "--force"]).await {
        return refusal.response();
    }
    match nodes().await {
        Ok(list) => encode(codec, &list),
        Err(refusal) => refusal.response(),
    }
}

/// A name fit to publish
fn checked_hostname(raw: &str) -> Result<String, Refusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(Refusal::BadRequest("a hostname needs 1 to 253 characters".to_string()));
    }
    if trimmed.starts_with('-')
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(Refusal::BadRequest(format!(
            "{trimmed} is not a hostname — publish the name a service is served under, \
             with no scheme and no path"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Publish this deployment's service names inside the mesh
pub async fn publish_names(codec: Codec, req: pb::PublishMeshNamesRequest) -> Resp {
    let mut names = Vec::new();
    for raw in &req.names {
        match checked_hostname(raw) {
            Ok(name) => names.push(name),
            Err(refusal) => return refusal.response(),
        }
    }

    let all = match nodes().await {
        Ok(list) => list.nodes,
        Err(refusal) => return refusal.response(),
    };
    let wanted = match req.node_name.trim() {
        "" => own_node_name().await.unwrap_or_default(),
        named => named.to_string(),
    };
    let node = if wanted.is_empty() {
        let mut own = all.iter().filter(|node| node.user == super::install::tailscale::MESH_USER);
        match (own.next(), own.next()) {
            (Some(only), None) => only.clone(),
            (Some(_), Some(_)) => {
                return Refusal::BadRequest(
                    "this mesh has more than one node under the server's own user, and the node \
                     container is not running to say which one is this server — name it"
                        .to_string(),
                )
                .response()
            }
            _ => {
                return Refusal::BadRequest(
                    "this server has not joined its own mesh yet, so it has no address to publish"
                        .to_string(),
                )
                .response()
            }
        }
    } else {
        match all.iter().find(|node| node.name == wanted) {
            Some(node) => node.clone(),
            None => return Refusal::BadRequest(format!("no node named {wanted} in this mesh")).response(),
        }
    };

    let address = match node.addresses.iter().find(|address| address.contains('.')) {
        Some(address) => address.clone(),
        None => {
            return Refusal::Engine(format!("node {} has no IPv4 mesh address", node.name)).response()
        }
    };

    let mut records = kept_records(read_extra_records().await, &address);
    records.extend(names.into_iter().map(|name| pb::MeshName { name, address: address.clone() }));
    if let Err(refusal) = write_extra_records(&records).await {
        return refusal.response();
    }
    encode(codec, &pb::MeshNameList { records })
}

fn kept_records(existing: Vec<pb::MeshName>, address: &str) -> Vec<pb::MeshName> {
    existing.into_iter().filter(|record| record.address != address).collect()
}

async fn read_extra_records() -> Vec<pb::MeshName> {
    let Some(dir) = host_config_dir().await else { return Vec::new() };
    let path = std::path::Path::new(&dir).join(crate::install::headscale::EXTRA_RECORDS_FILE);
    std::fs::read_to_string(path).map(|text| parse_extra_records(&text)).unwrap_or_default()
}

fn parse_extra_records(text: &str) -> Vec<pb::MeshName> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    items
        .iter()
        .filter_map(|item| {
            Some(pb::MeshName {
                name: item.get("Name")?.as_str()?.to_string(),
                address: item.get("Value")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn extra_records_json(records: &[pb::MeshName]) -> String {
    let items: Vec<Value> = records
        .iter()
        .map(|record| {
            serde_json::json!({ "Name": record.name, "Type": "A", "Value": record.address })
        })
        .collect();
    format!("{}\n", serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string()))
}

async fn write_extra_records(records: &[pb::MeshName]) -> Result<(), Refusal> {
    let dir = host_config_dir().await.ok_or_else(|| {
        Refusal::Engine(
            "the control server's configuration is not on a bind mount, so its records file \
             cannot be reached from here"
                .to_string(),
        )
    })?;
    let path = std::path::Path::new(&dir).join(crate::install::headscale::EXTRA_RECORDS_FILE);
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, extra_records_json(records))
        .map_err(|err| Refusal::Engine(format!("could not write {}: {err}", temp.display())))?;
    std::fs::rename(&temp, &path)
        .map_err(|err| Refusal::Engine(format!("could not replace {}: {err}", path.display())))?;
    Ok(())
}

async fn own_node_name() -> Option<String> {
    let output = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Config.Env}}", crate::install::tailscale::CONTAINER])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let env: Vec<String> = serde_json::from_slice(&output.stdout).ok()?;
    env.iter()
        .find_map(|entry| entry.strip_prefix("TS_HOSTNAME="))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

#[derive(Debug, serde::Deserialize)]
struct Mount {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

async fn host_config_dir() -> Option<String> {
    let output = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Mounts}}", CONTAINER])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mounts: Vec<Mount> = serde_json::from_slice(&output.stdout).ok()?;
    mounts
        .into_iter()
        .find(|mount| mount.destination == "/etc/headscale" && !mount.source.is_empty())
        .map(|mount| mount.source)
}

/// This host's mesh address, when Tailscale runs here
pub async fn own_address() -> Option<String> {
    let in_container = ["exec", crate::install::tailscale::CONTAINER, "tailscale", "ip", "-4"];
    match ip_from("docker", &in_container).await {
        Some(address) => Some(address),
        None => ip_from("tailscale", &["ip", "-4"]).await,
    }
}

async fn ip_from(program: &str, args: &[&str]) -> Option<String> {
    let run = tokio::process::Command::new(program).args(args).output();
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), run).await.ok()?.ok()?;
    if !out.status.success() {
        return None;
    }
    first_mesh_address(&String::from_utf8_lossy(&out.stdout))
}

/// The first CGNAT address in `tailscale ip -4` output
pub fn first_mesh_address(text: &str) -> Option<String> {
    text.lines().map(str::trim).find_map(|line| {
        let ip: std::net::Ipv4Addr = line.parse().ok()?;
        let [a, b, ..] = ip.octets();
        (a == 100 && (64..128).contains(&b)).then(|| line.to_string())
    })
}

#[cfg(test)]
mod record_merge_tests {
    use super::*;

    fn record(name: &str, address: &str) -> pb::MeshName {
        pb::MeshName { name: name.into(), address: address.into() }
    }

    #[test]
    fn another_nodes_names_survive_a_publish() {
        let file = extra_records_json(&[record("a.mesh", "100.64.0.1"), record("b.mesh", "100.64.0.2")]);
        let kept = kept_records(parse_extra_records(&file), "100.64.0.1");
        assert_eq!(kept, vec![record("b.mesh", "100.64.0.2")]);
    }

    #[test]
    fn an_unreadable_file_reads_as_empty() {
        assert!(parse_extra_records("not json").is_empty());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_mesh_address_is_the_cgnat_one() {
        assert_eq!(first_mesh_address("100.101.7.3\n").as_deref(), Some("100.101.7.3"));
        assert_eq!(first_mesh_address("192.168.1.2\n100.64.0.9\n").as_deref(), Some("100.64.0.9"));
        assert_eq!(first_mesh_address("no state\n"), None);
    }
    use super::*;

    #[test]
    fn the_records_file_uses_the_engines_own_key_names() {
        let json = extra_records_json(&[pb::MeshName {
            name: "vault.example.com".to_string(),
            address: "100.64.0.1".to_string(),
        }]);
        assert!(json.contains("\"Name\": \"vault.example.com\""), "{json}");
        assert!(json.contains("\"Type\": \"A\""), "{json}");
        assert!(json.contains("\"Value\": \"100.64.0.1\""), "{json}");
    }

    #[test]
    fn publishing_nothing_writes_an_empty_array() {
        assert_eq!(extra_records_json(&[]).trim(), "[]");
    }

    /// The shape a FRESH server answers with
    #[test]
    fn an_empty_listing_is_empty_rather_than_an_error() {
        assert_eq!(parse_nodes("null").unwrap(), Vec::new());
        assert_eq!(parse_nodes("").unwrap(), Vec::new());
        assert_eq!(parse_users("null").unwrap(), Vec::new());
        assert_eq!(parse_nodes("[]").unwrap(), Vec::new());
    }

    #[test]
    fn a_node_gives_up_only_the_fields_the_app_shows() {
        let json = r#"[{
            "id": 1,
            "machine_key": "mkey:9ec8",
            "node_key": "nodekey:d2d8",
            "ip_addresses": ["100.64.0.1", "fd7a:115c:a1e0::1"],
            "name": "shapenode",
            "given_name": "shapenode",
            "user": {"id": 1, "name": "meshops"},
            "last_seen": {"seconds": 1786724741},
            "online": true,
            "pre_auth_key": {"key": "hskey-auth-SECRET"}
        }]"#;
        let nodes = parse_nodes(json).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.id, "1");
        assert_eq!(node.name, "shapenode");
        assert_eq!(node.addresses, vec!["100.64.0.1", "fd7a:115c:a1e0::1"]);
        assert_eq!(node.user, "meshops");
        assert!(node.online);
        assert_eq!(node.last_seen, 1_786_724_741);
        // The whole reason this parser names its fields.
        let rendered = format!("{node:?}");
        assert!(!rendered.contains("SECRET"), "a node's join key must not reach the client");
        assert!(!rendered.contains("mkey"), "a node's machine key is not the app's business");
    }

    #[test]
    fn a_minted_key_carries_its_secret_and_its_terms() {
        let json = r#"{"key": "hskey-auth-abc", "reusable": true, "expiration": {"seconds": 1786728304}}"#;
        let key = parse_auth_key(json).unwrap();
        assert_eq!(key.key, "hskey-auth-abc");
        assert!(key.reusable);
        assert_eq!(key.expires_at, 1_786_728_304);
        assert!(parse_auth_key(r#"{"reusable": true}"#).is_err());
    }

    /// These values reach the engine's argv
    #[test]
    fn ids_and_names_are_checked_before_they_reach_argv() {
        assert!(checked_id("12", "node id").is_ok());
        assert!(checked_id("a-b", "node id").is_ok());
        for bad in ["", " ", "1; rm -rf /", "--force", "1 2", "$(id)"] {
            assert!(checked_id(bad, "node id").is_err(), "{bad:?} must be refused");
        }
        assert!(checked_name("laptops").is_ok());
        assert!(checked_name("home_2.lab").is_ok());
        for bad in ["", "  ", "has space", "semi;colon", "--reusable", &"x".repeat(65)] {
            assert!(checked_name(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_two_failures_are_told_apart() {
        assert_eq!(
            Refusal::NotInstalled.to_string(),
            "this server does not run Headscale, so it has no mesh to manage — install it first"
        );
        assert!(Refusal::Engine("boom".into()).to_string().contains("boom"));
    }
}
