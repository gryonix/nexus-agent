//! The order in which the VPN DNS relay asks resolvers.
//!
//! `local` stands for this deployment's AdGuard Home or Pi-hole: on its
//! own machine through loopback, from a relay through the home tunnel.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The entry for this deployment's own resolver
pub const LOCAL: &str = "local";
/// The most resolvers the order may name
pub const MAX: usize = 4;
/// The port of the home machine's resolver bridge
pub const BRIDGE_PORT: u16 = 10054;

const FILE: &str = "vpn-dns-priority.json";
const HOME_FILE: &str = "relay-home.json";

#[derive(Serialize, Deserialize)]
struct Stored {
    resolvers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Home {
    address: String,
}

/// Our own resolver first, then Cloudflare
pub fn default_order() -> Vec<String> {
    vec![LOCAL.to_string(), "1.1.1.1".to_string()]
}

fn path(name: &str) -> PathBuf {
    crate::util::state_dir().join(name)
}

/// The saved order, or the default one
pub fn load() -> Vec<String> {
    std::fs::read_to_string(path(FILE))
        .ok()
        .and_then(|text| serde_json::from_str::<Stored>(&text).ok())
        .and_then(|stored| validate(&stored.resolvers).ok())
        .unwrap_or_else(default_order)
}

pub fn save(order: &[String]) -> Result<(), String> {
    let text = serde_json::to_string(&Stored { resolvers: order.to_vec() }).map_err(|err| err.to_string())?;
    write(FILE, &text)
}

fn write(name: &str, text: &str) -> Result<(), String> {
    let dir = crate::util::state_dir();
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    std::fs::write(path(name), text).map_err(|err| format!("{name}: {err}"))
}

/// One to four unique entries: `local` or addresses
pub fn validate(order: &[String]) -> Result<Vec<String>, String> {
    let mut clean: Vec<String> = Vec::new();
    for entry in order.iter().map(|entry| entry.trim()) {
        let entry = if entry.eq_ignore_ascii_case(LOCAL) { LOCAL.to_string() } else { canonical(entry)? };
        if !clean.contains(&entry) {
            clean.push(entry);
        }
    }
    match clean.len() {
        0 => Err("name at least one resolver".to_string()),
        n if n > MAX => Err(format!("at most {MAX} resolvers")),
        _ => Ok(clean),
    }
}

fn canonical(entry: &str) -> Result<String, String> {
    let ip: IpAddr = entry.parse().map_err(|_| format!("not an address: {entry}"))?;
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!("not a resolver address: {entry}"));
    }
    Ok(ip.to_string())
}

/// The order as sockets; `local` only where it leads somewhere
pub fn sockets(order: &[String], local: Option<SocketAddr>) -> Vec<SocketAddr> {
    order
        .iter()
        .filter_map(|entry| match entry.as_str() {
            LOCAL => local,
            address => address.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)),
        })
        .collect()
}

/// Remembers which home machine this relay forwards to
pub fn remember_home(address: &str) {
    let address = address.trim();
    if address.parse::<IpAddr>().is_err() {
        return;
    }
    let Ok(text) = serde_json::to_string(&Home { address: address.to_string() }) else { return };
    if let Err(err) = write(HOME_FILE, &text) {
        tracing::warn!(%err, "could not remember the home machine's tunnel address");
    }
}

/// This machine forwards a home machine's traffic
pub fn is_relay() -> bool {
    home_bridge().is_some()
}

/// The home machine's resolver bridge, when this is a relay
pub fn home_bridge() -> Option<SocketAddr> {
    let text = std::fs::read_to_string(path(HOME_FILE)).ok()?;
    let home: Home = serde_json::from_str(&text).ok()?;
    let ip: IpAddr = home.address.parse().ok()?;
    Some(SocketAddr::new(ip, BRIDGE_PORT))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| entry.to_string()).collect()
    }

    #[test]
    fn the_default_asks_our_resolver_first() {
        assert_eq!(default_order(), order(&["local", "1.1.1.1"]));
    }

    #[test]
    fn entries_are_trimmed_deduplicated_and_canonical() {
        let clean = validate(&order(&[" LOCAL ", "1.1.1.1", "local", "2606:4700:4700:0::1111"])).unwrap();
        assert_eq!(clean, order(&["local", "1.1.1.1", "2606:4700:4700::1111"]));
    }

    #[test]
    fn bad_orders_are_refused() {
        assert!(validate(&[]).is_err());
        assert!(validate(&order(&["dns.example.org"])).is_err());
        assert!(validate(&order(&["0.0.0.0"])).is_err());
        assert!(validate(&order(&["224.0.0.1"])).is_err());
        assert!(validate(&order(&["local", "1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"])).is_err());
    }

    #[test]
    fn local_becomes_the_given_socket_or_nothing() {
        let loopback: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let wanted: Vec<SocketAddr> = vec![loopback, "1.1.1.1:53".parse().unwrap()];
        assert_eq!(sockets(&default_order(), Some(loopback)), wanted);
        assert_eq!(sockets(&default_order(), None), vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn the_order_and_the_home_survive_a_restart() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!("vpn-dns-priority-{}", std::process::id()));
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &dir);
        assert_eq!(load(), default_order());
        save(&order(&["9.9.9.9", "local"])).unwrap();
        assert_eq!(load(), order(&["9.9.9.9", "local"]));
        assert_eq!(home_bridge(), None);
        remember_home("10.8.0.2");
        assert_eq!(home_bridge(), Some("10.8.0.2:10054".parse().unwrap()));
        remember_home("not an address");
        assert_eq!(home_bridge(), Some("10.8.0.2:10054".parse().unwrap()));
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
