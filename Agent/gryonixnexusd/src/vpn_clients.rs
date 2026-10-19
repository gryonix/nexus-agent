//! VPN client devices, driven through the panel's own API

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PROTOCOLS: &[(&str, &str)] = &[
    ("wireguard", "wireguard-vpn"),
    ("amneziawg", "amnezia-wg"),
    ("shadowsocks", "shadowsocks"),
    ("xray", "xray-reality"),
    ("openvpn", "openvpn"),
];

const EXTENSIONS: &[(&str, &str)] = &[
    ("wireguard", ".conf"),
    ("amneziawg", ".conf"),
    ("openvpn", ".ovpn"),
    ("shadowsocks", ".txt"),
    ("xray", ".txt"),
];

const NO_QR: &[&str] = &["openvpn"];

/// The panel's loopback port, as its compose file publishes it.
const PANEL_PORT: u16 = 51900;

/// One request's budget
const TIMEOUT: Duration = Duration::from_secs(60);

/// Resolve a client-supplied protocol to the panel's own name
pub fn panel_protocol(requested: &str) -> Option<&'static str> {
    let requested = requested.trim();
    PROTOCOLS
        .iter()
        .find(|(panel, catalog)| *panel == requested || *catalog == requested)
        .map(|(panel, _)| *panel)
}

pub fn config_extension(panel_protocol: &str) -> &'static str {
    EXTENSIONS.iter().find(|(name, _)| *name == panel_protocol).map(|(_, ext)| *ext).unwrap_or(".txt")
}

pub fn qr_is_useful(panel_protocol: &str) -> bool {
    !NO_QR.contains(&panel_protocol)
}

/// Where the panel's environment file lives
fn env_path() -> PathBuf {
    match std::env::var("GRYONIXNEXUSD_VPN_PANEL_ENV") {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from("/opt/gryonix-vpn-panel/.env"),
    }
}

fn panel_port() -> u16 {
    std::env::var("GRYONIXNEXUSD_VPN_PANEL_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(PANEL_PORT)
}

pub fn parse_env(text: &str) -> (String, String) {
    let mut user = String::new();
    let mut password = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("ADMIN_USER=") {
            user = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("ADMIN_PASSWORD=") {
            password = value.trim().to_string();
        }
    }
    (user, password)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    UnknownProtocol(String),
    NoPanel,
    /// A real protocol, but not one THIS host installed.
    NotInstalled(String),
    LoginRefused(String),
    /// The panel answered something this cannot use.
    Panel(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::UnknownProtocol(name) => {
                write!(f, "'{}' is not a VPN protocol this server manages", name.chars().take(40).collect::<String>())
            }
            Refusal::NoPanel => write!(
                f,
                "this server has no VPN panel ({}), so it has no VPN clients to manage — \
                 install a VPN protocol first",
                env_path().display()
            ),
            Refusal::NotInstalled(name) => write!(
                f,
                "this server does not run {} — the VPN panel manages only the protocols \
                 that were installed on it",
                name.chars().take(40).collect::<String>()
            ),
            Refusal::LoginRefused(detail) => write!(
                f,
                "the VPN panel refused the stored administrator password ({detail}). \
                 If it was changed inside the panel, the panel is the only place that \
                 knows it — change it back there or re-install the VPN"
            ),
            Refusal::Panel(detail) => write!(f, "the VPN panel could not do that: {detail}"),
        }
    }
}

/// One client device, as the panel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub detail: String,
    pub dns: Vec<String>,
}

/// Parse the panel's `GET /api/<proto>/clients` answer.
pub fn parse_clients(json: &str) -> Result<Vec<Client>, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|err| err.to_string())?;
    let array = value.as_array().ok_or_else(|| "expected a list of clients".to_string())?;
    Ok(array
        .iter()
        .map(|item| Client {
            id: item.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            name: item.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            detail: item.get("detail").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            dns: strings(item.get("dns")),
        })
        .filter(|client| !client.id.is_empty())
        .collect())
}

fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// The panel's `{"dns": [...]}` answer
pub fn parse_dns(json: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(json).ok().map(|v| strings(v.get("dns"))).unwrap_or_default()
}

pub fn parse_error(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("error").and_then(|v| v.as_str()).map(str::to_string))
}

/// A live session against the panel.
pub struct Panel {
    port: u16,
    cookie: String,
}

impl Panel {
    /// Log in with the credentials on disk.
    pub async fn open() -> Result<Panel, Refusal> {
        let env = tokio::fs::read_to_string(env_path()).await.map_err(|_| Refusal::NoPanel)?;
        let (user, password) = parse_env(&env);
        if password.is_empty() {
            return Err(Refusal::LoginRefused("the panel's environment carries no password".into()));
        }
        let port = panel_port();
        let body = serde_json::json!({ "username": user, "password": password }).to_string();
        let response = request(port, "POST", "/login", None, Some(&body)).await.map_err(Refusal::Panel)?;
        if response.status != 200 {
            let detail = parse_error(&response.body).unwrap_or_else(|| format!("HTTP {}", response.status));
            return Err(Refusal::LoginRefused(detail));
        }
        let cookie = response.session_cookie.ok_or_else(|| {
            Refusal::Panel("the panel accepted the login without handing back a session".into())
        })?;
        Ok(Panel { port, cookie })
    }

    pub async fn list(&self, protocol: &'static str) -> Result<Vec<Client>, Refusal> {
        let path = format!("/api/{protocol}/clients");
        let response = self.call("GET", &path, None).await?;
        parse_clients(&response).map_err(Refusal::Panel)
    }

    pub async fn add(&self, protocol: &'static str, name: &str, dns: &[String]) -> Result<(), Refusal> {
        let path = format!("/api/{protocol}/clients");
        let body = if dns.is_empty() {
            serde_json::json!({ "name": name })
        } else {
            serde_json::json!({ "name": name, "dns": dns })
        };
        self.call("POST", &path, Some(&body.to_string())).await.map(|_| ())
    }

    pub async fn set_dns(&self, protocol: &'static str, client_id: &str, dns: &[String]) -> Result<(), Refusal> {
        let known = self.list(protocol).await?;
        if !known.iter().any(|client| client.id == client_id) {
            return Err(Refusal::Panel(format!("no client '{}' here", client_id.chars().take(40).collect::<String>())));
        }
        let path = format!("/api/{protocol}/clients/{client_id}/dns");
        let body = serde_json::json!({ "dns": dns }).to_string();
        self.call("PUT", &path, Some(&body)).await.map(|_| ())
    }

    pub async fn default_dns(&self) -> Result<Vec<String>, Refusal> {
        self.call("GET", "/api/dns", None).await.map(|body| parse_dns(&body))
    }

    pub async fn set_default_dns(&self, dns: &[String]) -> Result<Vec<String>, Refusal> {
        let body = serde_json::json!({ "dns": dns }).to_string();
        self.call("PUT", "/api/dns", Some(&body)).await.map(|body| parse_dns(&body))
    }

    pub async fn delete(&self, protocol: &'static str, client_id: &str) -> Result<(), Refusal> {
        let known = self.list(protocol).await?;
        if !known.iter().any(|client| client.id == client_id) {
            return Err(Refusal::Panel(format!("no client '{}' here", client_id.chars().take(40).collect::<String>())));
        }
        let path = format!("/api/{protocol}/clients/{client_id}");
        self.call("DELETE", &path, None).await.map(|_| ())
    }

    pub async fn config(&self, protocol: &'static str, client_id: &str) -> Result<String, Refusal> {
        let known = self.list(protocol).await?;
        if !known.iter().any(|client| client.id == client_id) {
            return Err(Refusal::Panel(format!("no client '{}' here", client_id.chars().take(40).collect::<String>())));
        }
        let path = format!("/api/{protocol}/clients/{client_id}/config");
        self.call("GET", &path, None).await
    }

    async fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<String, Refusal> {
        let response =
            request(self.port, method, path, Some(&self.cookie), body).await.map_err(Refusal::Panel)?;
        match response.status {
            200..=299 => Ok(response.body),
            status => Err(Refusal::Panel(
                parse_error(&response.body).unwrap_or_else(|| format!("HTTP {status}")),
            )),
        }
    }
}

struct Response {
    status: u16,
    body: String,
    session_cookie: Option<String>,
}

/// One HTTP/1.1 request to the panel on loopback
async fn request(
    port: u16,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<&str>,
) -> Result<Response, String> {
    let work = async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.map_err(|err| err.to_string())?;
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nX-Gryonix-Auth: 1\r\n"
        );
        if let Some(cookie) = cookie {
            head.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        match body {
            Some(body) => {
                head.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                ));
            }
            None => head.push_str("\r\n"),
        }
        stream.write_all(head.as_bytes()).await.map_err(|err| err.to_string())?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.map_err(|err| err.to_string())?;
        parse_response(&String::from_utf8_lossy(&raw))
    };
    tokio::time::timeout(TIMEOUT, work).await.map_err(|_| "the VPN panel did not answer in time".to_string())?
}

/// Split a raw HTTP response into status, headers and body.
fn parse_response(raw: &str) -> Result<Response, String> {
    let (head, body) = raw.split_once("\r\n\r\n").ok_or_else(|| "the panel's answer had no body".to_string())?;
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| "the panel's answer had no status".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("could not read a status from '{status_line}'"))?;
    // The session cookie, without the attributes: only `name=value` travels back.
    let mut session_cookie = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("Set-Cookie: ").or_else(|| line.strip_prefix("set-cookie: ")) {
            let pair = value.split(';').next().unwrap_or_default().trim().to_string();
            if !pair.is_empty() {
                session_cookie = Some(pair);
            }
        }
    }
    Ok(Response { status, body: body.to_string(), session_cookie })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_client_carries_its_dns_and_an_older_panel_none() {
        let clients = parse_clients(r#"[{"id":"a","name":"phone","detail":"10.9.0.2","dns":["94.140.14.14","2a10:50c0::ad1:ff"]},{"id":"b","name":"old","detail":"x"}]"#).unwrap();
        assert_eq!(clients[0].dns, vec!["94.140.14.14", "2a10:50c0::ad1:ff"]);
        assert!(clients[1].dns.is_empty());
    }

    #[test]
    fn the_default_dns_answer_is_read() {
        assert_eq!(parse_dns(r#"{"dns":["9.9.9.9","149.112.112.112"]}"#), vec!["9.9.9.9", "149.112.112.112"]);
        assert!(parse_dns("not json").is_empty());
    }

    #[test]
    fn the_panels_declaration_says_which_protocols_this_host_runs() {
        let one = r#"{"services":[{"id":"wireguard","name":"WireGuard","port":"51821"}]}"#;
        assert_eq!(parse_declared_protocols(one), Some(vec!["wireguard".to_string()]));
        let several = r#"{"services":[{"id":"wireguard"},{"id":"openvpn"},{"id":"xray"}]}"#;
        assert_eq!(
            parse_declared_protocols(several),
            Some(vec!["wireguard".to_string(), "openvpn".to_string(), "xray".to_string()])
        );
        assert_eq!(parse_declared_protocols(r#"{"services":[]}"#), Some(vec![]));
        assert_eq!(parse_declared_protocols("not json"), None);
        assert_eq!(parse_declared_protocols("{}"), None);
        assert_eq!(parse_declared_protocols(r#"{"services":"wireguard"}"#), None);
    }

    #[test]
    fn both_spellings_of_a_protocol_resolve_and_nothing_else_does() {
        assert_eq!(panel_protocol("wireguard-vpn"), Some("wireguard"));
        assert_eq!(panel_protocol("wireguard"), Some("wireguard"));
        assert_eq!(panel_protocol("amnezia-wg"), Some("amneziawg"));
        assert_eq!(panel_protocol("xray-reality"), Some("xray"));
        assert_eq!(panel_protocol("openvpn"), Some("openvpn"));
        assert_eq!(panel_protocol("shadowsocks"), Some("shadowsocks"));
        assert_eq!(panel_protocol("vpn"), None);
        assert_eq!(panel_protocol("../../etc/passwd"), None);
        assert_eq!(panel_protocol("wireguard/../openvpn"), None);
        assert_eq!(panel_protocol(""), None);
    }

    #[test]
    fn the_file_names_and_qr_rule_match_the_panels_own() {
        assert_eq!(config_extension("wireguard"), ".conf");
        assert_eq!(config_extension("amneziawg"), ".conf");
        assert_eq!(config_extension("openvpn"), ".ovpn");
        assert_eq!(config_extension("shadowsocks"), ".txt");
        assert_eq!(config_extension("xray"), ".txt");
        assert!(!qr_is_useful("openvpn"));
        for protocol in ["wireguard", "amneziawg", "shadowsocks", "xray"] {
            assert!(qr_is_useful(protocol));
        }
    }

    /// The real `.env` shape the installer writes.
    #[test]
    fn credentials_are_read_from_the_panels_own_environment() {
        let env = "ADMIN_USER=admin\nADMIN_PASSWORD=3249cc5911685a9221211a42\nWG_HOST=vpn.example.com\nWG_PORT=51830\n";
        assert_eq!(parse_env(env), ("admin".to_string(), "3249cc5911685a9221211a42".to_string()));
        assert_eq!(parse_env("ADMIN_USER=\nADMIN_PASSWORD=x\n"), (String::new(), "x".to_string()));
        assert_eq!(parse_env(""), (String::new(), String::new()));
    }

    #[test]
    fn the_panels_answers_are_read_as_the_panel_writes_them() {
        let listing = r#"[{"detail":"10.9.0.2","id":"9b79430d6f89","name":"smoke-client"}]"#;
        assert_eq!(
            parse_clients(listing).expect("a listing"),
            vec![Client { id: "9b79430d6f89".into(), name: "smoke-client".into(), detail: "10.9.0.2".into(), dns: Vec::new() }]
        );
        assert!(parse_clients("[]").expect("empty is a listing too").is_empty());
        assert!(parse_clients(r#"[{"name":"x"}]"#).expect("parsed").is_empty());
        assert!(parse_clients("not json").is_err());
        assert_eq!(parse_error(r#"{"error":"Wrong username or password."}"#).as_deref(),
                   Some("Wrong username or password."));
        assert_eq!(parse_error("{}"), None);
    }

    #[test]
    fn a_response_is_split_into_status_body_and_session() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                   Set-Cookie: session=abc123; HttpOnly; Path=/; SameSite=Lax\r\n\r\n{\"ok\":true}";
        let response = parse_response(raw).expect("a response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "{\"ok\":true}");
        assert_eq!(response.session_cookie.as_deref(), Some("session=abc123"));
        let refused = parse_response("HTTP/1.1 401 UNAUTHORIZED\r\n\r\n{\"error\":\"nope\"}").expect("a response");
        assert_eq!(refused.status, 401);
        assert_eq!(refused.session_cookie, None);
        assert!(parse_response("garbage").is_err());
    }

    #[test]
    fn a_file_name_survives_a_client_name_that_is_not_one() {
        assert_eq!(sanitise_file_name("iPhone 15"), "iPhone-15");
        assert_eq!(sanitise_file_name("../../etc/passwd"), "etc-passwd");
        assert_eq!(sanitise_file_name(""), "client");
        assert_eq!(sanitise_file_name("---"), "client");
        assert_eq!(sanitise_file_name("laptop.work"), "laptop.work");
    }

    #[tokio::test]
    async fn a_session_is_opened_and_reused_against_a_socket_that_behaves_like_the_panel() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let port = listener.local_addr().expect("addr").port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept().await else { return };
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                let mut request = String::new();
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                    request.push('\n');
                }
                let is_login = request.starts_with("POST /login");
                recorder.lock().expect("lock").push(request);
                let body = if is_login { "{\"ok\":true}" } else { "[{\"id\":\"a1\",\"name\":\"phone\",\"detail\":\"10.9.0.2\"}]" };
                let cookie = if is_login { "Set-Cookie: session=abc; HttpOnly; Path=/\r\n" } else { "" };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = write.write_all(response.as_bytes()).await;
            }
        });

        let dir = std::env::temp_dir().join(format!("gryonixnexusd-panel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let env_file = dir.join("panel.env");
        std::fs::write(&env_file, "ADMIN_USER=admin\nADMIN_PASSWORD=secret\n").expect("env");
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_VPN_PANEL_ENV", &env_file);
        std::env::set_var("GRYONIXNEXUSD_VPN_PANEL_PORT", port.to_string());

        let panel = Panel::open().await.expect("the panel lets us in");
        let clients = panel.list("wireguard").await.expect("a listing");
        assert_eq!(clients, vec![Client { id: "a1".into(), name: "phone".into(), detail: "10.9.0.2".into(), dns: Vec::new() }]);

        std::env::remove_var("GRYONIXNEXUSD_VPN_PANEL_ENV");
        std::env::remove_var("GRYONIXNEXUSD_VPN_PANEL_PORT");
        let _ = std::fs::remove_dir_all(&dir);

        let requests = seen.lock().expect("lock");
        assert!(requests[0].contains("X-Gryonix-Auth: 1"), "the panel rejects a state-changing call without it");
        assert!(requests[0].contains("Content-Length: "), "Flask needs a length to read the body at all");
        assert!(requests[1].contains("Cookie: session=abc"), "the session has to ride the next request");
        assert!(!requests[1].contains("HttpOnly"), "the cookie's attributes are the browser's business, not ours");
        assert!(requests[1].starts_with("GET /api/wireguard/clients"));
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn every_refusal_explains_itself() {
        assert!(Refusal::UnknownProtocol("nope".into()).to_string().contains("not a VPN protocol"));
        assert!(Refusal::NoPanel.to_string().contains("install a VPN protocol first"));
        let login = Refusal::LoginRefused("Wrong username or password.".into()).to_string();
        assert!(login.contains("changed inside the panel"), "{login}");
        assert!(Refusal::Panel("boom".into()).to_string().contains("boom"));
    }
}

// ─────────────────────────── RPC entry points ───────────────────────────

use crate::api::{connect_error, Codec, Resp};
use crate::pb;
use hyper::StatusCode;

impl Refusal {
    fn response(&self) -> Resp {
        let (status, code) = match self {
            Refusal::UnknownProtocol(_) => (StatusCode::BAD_REQUEST, "invalid_argument"),
            Refusal::NoPanel | Refusal::NotInstalled(_) | Refusal::LoginRefused(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition")
            }
            Refusal::Panel(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        connect_error(status, code, &self.to_string())
    }
}

fn listing(clients: Vec<Client>) -> pb::VpnClientList {
    pb::VpnClientList {
        clients: clients
            .into_iter()
            .map(|client| pb::VpnClient { id: client.id, name: client.name, detail: client.detail, dns: client.dns })
            .collect(),
    }
}

async fn resolve(protocol: &str) -> Result<(&'static str, Panel), Refusal> {
    let resolved = panel_protocol(protocol).ok_or_else(|| Refusal::UnknownProtocol(protocol.to_string()))?;
    if let Some(installed) = declared_protocols() {
        if !installed.iter().any(|name| name == resolved) {
            return Err(Refusal::NotInstalled(resolved.to_string()));
        }
    }
    Ok((resolved, Panel::open().await?))
}

fn declared_protocols() -> Option<Vec<String>> {
    let text = std::fs::read_to_string(services_path()).ok()?;
    parse_declared_protocols(&text)
}

/// Where that declaration lives. Redirectable like every other path here.
pub(crate) fn services_path() -> PathBuf {
    match std::env::var("GRYONIXNEXUSD_VPN_PANEL_SERVICES") {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from("/opt/gryonix-vpn-panel/data/services.json"),
    }
}

/// `{"services":[{"id":"wireguard",…},…]}` → the ids
pub fn parse_declared_protocols(text: &str) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let services = value.get("services")?.as_array()?;
    Some(services.iter().filter_map(|entry| Some(entry.get("id")?.as_str()?.to_string())).collect())
}

pub async fn list_clients(codec: Codec, req: pb::ListVpnClientsRequest) -> Resp {
    let (protocol, panel) = match resolve(&req.protocol).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };
    match panel.list(protocol).await {
        Ok(clients) => encode(codec, &listing(clients)),
        Err(refusal) => refusal.response(),
    }
}

pub async fn add_client(codec: Codec, req: pb::AddVpnClientRequest) -> Resp {
    let (protocol, panel) = match resolve(&req.protocol).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };
    if let Err(refusal) = panel.add(protocol, req.name.trim(), &req.dns).await {
        return refusal.response();
    }
    crate::vpn_dns::prepare_for(&req.dns);
    match panel.list(protocol).await {
        Ok(clients) => encode(codec, &listing(clients)),
        Err(refusal) => refusal.response(),
    }
}

pub async fn delete_client(codec: Codec, req: pb::DeleteVpnClientRequest) -> Resp {
    let (protocol, panel) = match resolve(&req.protocol).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };
    if let Err(refusal) = panel.delete(protocol, req.client_id.trim()).await {
        return refusal.response();
    }
    match panel.list(protocol).await {
        Ok(clients) => encode(codec, &listing(clients)),
        Err(refusal) => refusal.response(),
    }
}

pub async fn client_config(codec: Codec, req: pb::GetVpnClientConfigRequest) -> Resp {
    let (protocol, panel) = match resolve(&req.protocol).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };
    let client_id = req.client_id.trim();
    let text = match panel.config(protocol, client_id).await {
        Ok(text) => text,
        Err(refusal) => return refusal.response(),
    };
    let found = panel.list(protocol).await.ok().and_then(|clients| clients.into_iter().find(|client| client.id == client_id));
    let name = found.as_ref().map(|client| client.name.clone()).unwrap_or_else(|| client_id.to_string());
    let response = pb::VpnClientConfig {
        text,
        filename: format!("{}{}", sanitise_file_name(&name), config_extension(protocol)),
        qr_is_useful: qr_is_useful(protocol),
        dns: found.map(|client| client.dns).unwrap_or_default(),
    };
    encode(codec, &response)
}

pub async fn set_client_dns(codec: Codec, req: pb::SetVpnClientDnsRequest) -> Resp {
    let (protocol, panel) = match resolve(&req.protocol).await {
        Ok(pair) => pair,
        Err(refusal) => return refusal.response(),
    };
    if let Err(refusal) = panel.set_dns(protocol, req.client_id.trim(), &req.dns).await {
        return refusal.response();
    }
    crate::vpn_dns::prepare_for(&req.dns);
    match panel.list(protocol).await {
        Ok(clients) => encode(codec, &listing(clients)),
        Err(refusal) => refusal.response(),
    }
}

pub async fn default_dns(codec: Codec, _req: pb::GetVpnDnsRequest) -> Resp {
    let panel = match Panel::open().await {
        Ok(panel) => panel,
        Err(refusal) => return refusal.response(),
    };
    match panel.default_dns().await {
        Ok(dns) => encode(codec, &with_local(dns).await),
        Err(refusal) => refusal.response(),
    }
}

pub async fn set_default_dns(codec: Codec, req: pb::VpnDns) -> Resp {
    let panel = match Panel::open().await {
        Ok(panel) => panel,
        Err(refusal) => return refusal.response(),
    };
    match panel.set_default_dns(&req.dns).await {
        Ok(dns) => {
            crate::vpn_dns::prepare_for(&dns);
            encode(codec, &with_local(dns).await)
        }
        Err(refusal) => refusal.response(),
    }
}

/// The order this server's DNS relay asks resolvers in
pub async fn dns_priority(codec: Codec, _req: pb::GetVpnDnsPriorityRequest) -> Resp {
    encode(codec, &priority_answer().await)
}

pub async fn set_dns_priority(codec: Codec, req: pb::VpnDnsPriority) -> Resp {
    let order = match crate::vpn_dns_priority::validate(&req.resolvers) {
        Ok(order) => order,
        Err(why) => return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &why),
    };
    if let Err(why) = crate::vpn_dns_priority::save(&order) {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &why);
    }
    crate::vpn_dns::refresh().await;
    encode(codec, &priority_answer().await)
}

async fn priority_answer() -> pb::VpnDnsPriority {
    let (local_available, reachable) = crate::vpn_dns::reachability().await;
    pb::VpnDnsPriority { resolvers: crate::vpn_dns_priority::load(), local_available, reachable }
}

/// The default DNS, with what this server's own resolver offers
async fn with_local(dns: Vec<String>) -> pb::VpnDns {
    pb::VpnDns {
        dns,
        local_address: crate::vpn_dns::ADDRESS.to_string(),
        local_services: crate::vpn_dns::local_services().await,
    }
}

pub fn sanitise_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '-' })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '-' || c == '.').to_string();
    if trimmed.is_empty() {
        "client".to_string()
    } else {
        trimmed
    }
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec
        .encode(message)
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}
