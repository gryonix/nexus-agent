//! Wake on LAN from the host's own side.
//!
//! Finds the card of the default route, reads its MAC and broadcast
//! address, and arms it for magic packets on every start and hourly,
//! since many drivers forget the setting after a reboot.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::pb;

const REFRESH: Duration = Duration::from_secs(3600);

fn last() -> &'static Mutex<Option<pb::WakeOnLanInfo>> {
    static LAST: OnceLock<Mutex<Option<pb::WakeOnLanInfo>>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new(None))
}

/// The latest reading, if any
pub fn current() -> Option<pb::WakeOnLanInfo> {
    last().lock().unwrap().clone()
}

pub fn spawn() {
    tokio::spawn(async {
        loop {
            let info = read_and_arm().await;
            if let Some(info) = &info {
                tracing::info!(interface = %info.interface, support = info.support, "wake on lan checked");
            }
            *last().lock().unwrap() = info;
            tokio::time::sleep(REFRESH).await;
        }
    });
}

async fn read_and_arm() -> Option<pb::WakeOnLanInfo> {
    let interface = default_interface(&std::fs::read_to_string("/proc/net/route").ok()?)?;
    let mac = std::fs::read_to_string(format!("/sys/class/net/{interface}/address")).ok()?.trim().to_string();
    let addr = output("ip", &["-4", "-o", "addr", "show", "dev", &interface]).await.unwrap_or_default();
    let wireless = std::path::Path::new(&format!("/sys/class/net/{interface}/wireless")).exists();
    let support = if wireless { pb::WakeSupport::Unsupported } else { arm(&interface).await };
    Some(pb::WakeOnLanInfo { mac, broadcast: broadcast(&addr).unwrap_or_default(), interface, support: support as i32 })
}

async fn arm(interface: &str) -> pb::WakeSupport {
    let Some(text) = output("ethtool", &[interface]).await else { return pb::WakeSupport::Unknown };
    let (supports, active) = wake_modes(&text);
    if !supports.contains('g') {
        return pb::WakeSupport::Unsupported;
    }
    if active.contains('g') {
        return pb::WakeSupport::Armed;
    }
    let armed = tokio::process::Command::new("ethtool")
        .args(["-s", interface, "wol", "g"])
        .status()
        .await
        .is_ok_and(|s| s.success());
    if armed { pb::WakeSupport::Armed } else { pb::WakeSupport::NotArmed }
}

/// The interface of the default IPv4 route
pub fn default_interface(route_table: &str) -> Option<String> {
    route_table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.len() > 2 && fields[1] == "00000000").then(|| fields[0].to_string())
    })
}

/// The `brd` address from `ip -o addr` output
pub fn broadcast(ip_output: &str) -> Option<String> {
    let mut words = ip_output.split_whitespace();
    words.find(|w| *w == "brd")?;
    words.next().map(str::to_string)
}

/// Supported and active wake modes from `ethtool` output
pub fn wake_modes(ethtool: &str) -> (String, String) {
    let value = |key: &str| {
        ethtool
            .lines()
            .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string()))
            .unwrap_or_default()
    };
    (value("Supports Wake-on:"), value("Wake-on:"))
}

async fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = tokio::process::Command::new(program).args(args).output().await.ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_route_names_the_card() {
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     docker0\t000011AC\t00000000\t0001\n\
                     eth0\t00000000\t01B2A8C0\t0003\n";
        assert_eq!(default_interface(table).as_deref(), Some("eth0"));
        assert_eq!(default_interface("Iface\tDestination\n"), None);
    }

    #[test]
    fn the_broadcast_comes_from_ip() {
        let line = "2: eth0    inet 192.168.178.100/24 brd 192.168.178.255 scope global dynamic eth0";
        assert_eq!(broadcast(line).as_deref(), Some("192.168.178.255"));
        assert_eq!(broadcast("2: wg0 inet 10.0.0.1/32 scope global wg0"), None);
    }

    #[test]
    fn wake_modes_are_read_apart() {
        let text = "Settings for eth0:\n\tSupports Wake-on: pumbg\n\tWake-on: d\n\tLink detected: yes\n";
        assert_eq!(wake_modes(text), ("pumbg".to_string(), "d".to_string()));
        assert_eq!(wake_modes("Settings for eth0:\n"), (String::new(), String::new()));
    }
}
