//! Keeps an iPhone's VPN session Live Activity in step with the server.
//!
//! For WireGuard-family tunnels the peer's traffic and handshake are read
//! from the protocol's container; changes go out through the relay, and a
//! long-silent peer ends the activity.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::notify;

const POLL: Duration = Duration::from_secs(60);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// No handshake for this long shows "Reconnecting…"
const QUIET_AFTER: i64 = 5 * 60;
/// No handshake for this long ends the activity
const GONE_AFTER: i64 = 30 * 60;
/// The system ends every Live Activity by then
const LONGEST: i64 = 12 * 3600;

#[derive(Clone, Debug, PartialEq)]
struct Watch {
    container: &'static str,
    address: String,
    started_at: f64,
    watched_at: i64,
    sent: Option<(u64, u64, bool)>,
}

/// One WireGuard peer, as `wg show all dump` reports it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub allowed_ips: Vec<String>,
    pub handshake: i64,
    pub received: u64,
    pub sent: u64,
}

fn watches() -> &'static Mutex<HashMap<String, Watch>> {
    static WATCHES: OnceLock<Mutex<HashMap<String, Watch>>> = OnceLock::new();
    WATCHES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The container that carries this protocol's peers
pub fn container(protocol: &str) -> Option<&'static str> {
    match protocol {
        "wireguard-vpn" | "wireguard" => Some(crate::install::vpn::panel::CONTAINER),
        "amnezia-wg" | "amneziawg" => Some(crate::install::vpn::protocols::amnezia::CONTAINER),
        _ => None,
    }
}

/// Starts or stops following one activity; false when not measurable
pub fn watch(token: &str, protocol: &str, address: &str, started_at: f64, stop: bool) -> bool {
    let mut all = watches().lock().unwrap_or_else(|e| e.into_inner());
    if stop {
        all.remove(token);
        return true;
    }
    let address = address.split('/').next().unwrap_or_default().trim().to_string();
    let Some(container) = container(protocol).filter(|_| !address.is_empty()) else { return false };
    let watch = Watch { container, address, started_at, watched_at: notify::now(), sent: None };
    all.insert(token.to_string(), watch);
    drop(all);
    start_polling();
    true
}

fn start_polling() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    runtime.spawn(async {
        loop {
            tokio::time::sleep(POLL).await;
            poll_once().await;
        }
    });
}

async fn poll_once() {
    let snapshot: Vec<(String, Watch)> = {
        let all = watches().lock().unwrap_or_else(|e| e.into_inner());
        all.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };
    let mut dumps: HashMap<&'static str, Option<Vec<Peer>>> = HashMap::new();
    for (token, watch) in snapshot {
        if !dumps.contains_key(watch.container) {
            dumps.insert(watch.container, read_peers(watch.container).await);
        }
        let Some(Some(peers)) = dumps.get(watch.container) else { continue };
        let peer = find_peer(peers, &watch.address);
        match next_step(&watch, peer, notify::now()) {
            Step::Nothing => {}
            Step::Forget => forget(&token),
            Step::Update(body, mark) => {
                remember(&token, mark);
                crate::live::send(with_token(body, &token));
            }
            Step::End(body) => {
                forget(&token);
                crate::live::send(with_token(body, &token));
            }
        }
    }
}

fn forget(token: &str) {
    watches().lock().unwrap_or_else(|e| e.into_inner()).remove(token);
}

fn remember(token: &str, mark: (u64, u64, bool)) {
    if let Some(watch) = watches().lock().unwrap_or_else(|e| e.into_inner()).get_mut(token) {
        watch.sent = Some(mark);
    }
}

fn with_token(mut body: Value, token: &str) -> Value {
    body["token"] = json!(token);
    body
}

#[derive(Debug, PartialEq)]
enum Step {
    Nothing,
    Forget,
    Update(Value, (u64, u64, bool)),
    End(Value),
}

/// What one poll does for one watched session
fn next_step(watch: &Watch, peer: Option<&Peer>, now: i64) -> Step {
    if now - watch.watched_at > LONGEST {
        return Step::Forget;
    }
    let Some(peer) = peer else { return Step::Nothing };
    let silent = if peer.handshake > 0 { now - peer.handshake } else { now - watch.watched_at };
    if silent > GONE_AFTER {
        return Step::End(json!({
            "end": true,
            "state": content_state(watch.started_at, peer, false),
            "dismiss_at": now,
        }));
    }
    let quiet = silent > QUIET_AFTER;
    let mark = (peer.received, peer.sent, quiet);
    if watch.sent == Some(mark) {
        return Step::Nothing;
    }
    Step::Update(json!({ "state": content_state(watch.started_at, peer, !quiet), "urgent": true }), mark)
}

/// The app's ContentState, from the phone's side
pub fn content_state(started_at: f64, peer: &Peer, connected: bool) -> Value {
    let status = if connected { "connected" } else { "reasserting" };
    json!({
        "status": { status: { "since": started_at } },
        "statistics": { "received": peer.sent, "sent": peer.received },
    })
}

/// Peer lines of `wg show all dump`
pub fn parse_dump(text: &str) -> Vec<Peer> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 9 {
                return None;
            }
            Some(Peer {
                allowed_ips: fields[4].split(',').map(|ip| ip.trim().to_string()).collect(),
                handshake: fields[5].parse().ok()?,
                received: fields[6].parse().ok()?,
                sent: fields[7].parse().ok()?,
            })
        })
        .collect()
}

/// The peer whose allowed IPs hold this device address
pub fn find_peer<'a>(peers: &'a [Peer], address: &str) -> Option<&'a Peer> {
    peers.iter().find(|peer| {
        peer.allowed_ips.iter().any(|ip| ip.split('/').next() == Some(address))
    })
}

async fn read_peers(container: &str) -> Option<Vec<Peer>> {
    let mut command = tokio::process::Command::new("docker");
    command
        .args(["exec", container, "sh", "-c", "awg show all dump 2>/dev/null || wg show all dump"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let child = command.spawn().ok()?;
    let output = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output()).await.ok()?.ok()?;
    output.status.success().then(|| parse_dump(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "wgpanel\tPRIV\tPUB\t51820\toff\n\
        wgpanel\tPEER1\t(none)\t1.2.3.4:5000\t10.9.0.4/32,fd09::4/128\t1700000000\t1000\t5000\t25\n\
        wgpanel\tPEER2\t(none)\t(none)\t10.9.0.5/32\t0\t0\t0\toff\n";

    fn watch_at(now: i64) -> Watch {
        Watch { container: "vpnpanel", address: "10.9.0.4".into(), started_at: 8.12e8, watched_at: now, sent: None }
    }

    #[test]
    fn peers_are_read_and_found_by_address() {
        let peers = parse_dump(DUMP);
        assert_eq!(peers.len(), 2);
        let peer = find_peer(&peers, "10.9.0.4").unwrap();
        assert_eq!((peer.handshake, peer.received, peer.sent), (1_700_000_000, 1000, 5000));
        assert!(find_peer(&peers, "10.9.0.40").is_none());
    }

    #[test]
    fn the_state_matches_the_app_with_directions_swapped() {
        let peer = &parse_dump(DUMP)[0];
        assert_eq!(content_state(8.12e8, peer, true), json!({
            "status": { "connected": { "since": 8.12e8 } },
            "statistics": { "received": 5000, "sent": 1000 },
        }));
    }

    #[test]
    fn traffic_is_sent_once_per_change() {
        let peer = parse_dump(DUMP)[0].clone();
        let now = peer.handshake + 30;
        let mut watch = watch_at(now);
        let Step::Update(_, mark) = next_step(&watch, Some(&peer), now) else { panic!("no update") };
        watch.sent = Some(mark);
        assert_eq!(next_step(&watch, Some(&peer), now), Step::Nothing);
    }

    #[test]
    fn a_silent_peer_reconnects_then_ends() {
        let peer = parse_dump(DUMP)[0].clone();
        let quiet = peer.handshake + QUIET_AFTER + 1;
        let Step::Update(body, _) = next_step(&watch_at(quiet), Some(&peer), quiet) else { panic!("no update") };
        assert!(body["state"]["status"].get("reasserting").is_some());
        assert_eq!(body["urgent"], true);
        let gone = peer.handshake + GONE_AFTER + 1;
        assert!(matches!(next_step(&watch_at(gone), Some(&peer), gone), Step::End(_)));
    }

    #[test]
    fn only_wireguard_family_is_measured_and_stop_forgets() {
        assert!(!watch("tok-ss", "shadowsocks", "10.0.0.2", 0.0, false));
        assert!(watch("tok-wg", "wireguard-vpn", "10.9.0.4/32", 0.0, false));
        assert!(watches().lock().unwrap().contains_key("tok-wg"));
        watch("tok-wg", "", "", 0.0, true);
        assert!(!watches().lock().unwrap().contains_key("tok-wg"));
    }
}
