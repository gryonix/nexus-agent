//! The VPN interfaces' MTU, and what decides the tunnels' speed.

use std::time::Duration;

/// The MTU phones get; the server sends nothing larger
pub const MTU: u32 = 1280;

/// Each VPN container and its tunnel interface
const INTERFACES: [(&str, &str); 2] = [("vpnpanel", "wgpanel"), ("awgvpn", "wg0")];
/// The panel's protocol name for each container
const PROTOCOLS: [(&str, &str); 2] = [("vpnpanel", "wireguard"), ("awgvpn", "amneziawg")];
const TIMEOUT: Duration = Duration::from_secs(20);

/// The MTU `ip link show` reports
pub fn mtu_of(text: &str) -> Option<u32> {
    let mut words = text.split_whitespace();
    words.find(|word| *word == "mtu")?;
    words.next()?.parse().ok()
}

fn exec(container: &str, args: &[&str]) -> Vec<String> {
    ["exec", container].iter().chain(args).map(|part| part.to_string()).collect()
}

/// Sets the MTU where it differs; the interfaces it changed
pub async fn refresh() -> Vec<String> {
    let mut changed = Vec::new();
    for (container, interface) in INTERFACES {
        let shown = super::super::execute::run_docker_capture(&exec(container, &["ip", "link", "show", interface]), TIMEOUT).await;
        let Ok((true, text)) = shown else { continue };
        if mtu_of(&text).is_none_or(|mtu| mtu == MTU) {
            continue;
        }
        let mtu = MTU.to_string();
        let set = exec(container, &["ip", "link", "set", interface, "mtu", &mtu]);
        if matches!(super::super::execute::run_docker_capture(&set, TIMEOUT).await, Ok((true, _))) {
            changed.push(format!("{container}/{interface}"));
        }
    }
    changed
}

/// The link, with details where `ip` supports them
async fn link_details(container: &str, interface: &str) -> Option<String> {
    for args in [&["ip", "-d", "link", "show", interface][..], &["ip", "link", "show", interface][..]] {
        if let Ok((true, text)) = super::super::execute::run_docker_capture(&exec(container, args), TIMEOUT).await {
            return Some(text);
        }
    }
    None
}

/// Kernel or program, by link, process and module
async fn runs_in_kernel(container: &str, protocol: &str, details: &str) -> bool {
    if is_kernel(details) {
        return true;
    }
    if details.split_whitespace().any(|word| word == "tun") {
        return false;
    }
    let program = if protocol == "amneziawg" { "amneziawg-go" } else { "wireguard-go" };
    let running = super::super::execute::run_docker_capture(&exec(container, &["pgrep", program]), TIMEOUT).await;
    if matches!(running, Ok((true, _))) {
        return false;
    }
    let module = if protocol == "amneziawg" { "/sys/module/amneziawg" } else { "/sys/module/wireguard" };
    std::path::Path::new(module).exists()
}

/// The tunnel runs in the kernel, not as a program
pub fn is_kernel(details: &str) -> bool {
    details.split_whitespace().any(|word| word == "wireguard" || word == "amneziawg")
}

/// One counter from the `Udp:` lines of /proc/net/snmp
pub fn udp_counter(snmp: &str, name: &str) -> u64 {
    let rows: Vec<&str> = snmp.lines().filter(|line| line.starts_with("Udp:")).collect();
    let (Some(names), Some(values)) = (rows.first(), rows.get(1)) else { return 0 };
    let index = names.split_whitespace().position(|field| field == name);
    index.and_then(|i| values.split_whitespace().nth(i)?.parse().ok()).unwrap_or(0)
}

/// The one-minute load from /proc/loadavg
pub fn load_of(loadavg: &str) -> f64 {
    loadavg.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0.0)
}

/// Everything the app shows about the tunnels' speed
pub async fn speed_facts() -> crate::pb::VpnSpeedFacts {
    let mut interfaces = Vec::new();
    for ((container, interface), (_, protocol)) in INTERFACES.iter().zip(PROTOCOLS) {
        let Some(text) = link_details(container, interface).await else { continue };
        interfaces.push(crate::pb::VpnInterfaceFacts {
            protocol: protocol.to_string(),
            interface: interface.to_string(),
            mtu: mtu_of(&text).unwrap_or(0),
            kernel: runs_in_kernel(container, protocol, &text).await,
        });
    }
    let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    crate::pb::VpnSpeedFacts {
        interfaces,
        cpu_cores: std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(0),
        load: load_of(&std::fs::read_to_string("/proc/loadavg").unwrap_or_default()),
        udp_receive_errors: udp_counter(&snmp, "InErrors"),
        udp_buffer_errors: udp_counter(&snmp, "RcvbufErrors"),
        client_mtu: MTU,
        ..kernel_facts()
    }
}

/// The AmneziaWG module's switch, as the facts carry it
fn kernel_facts() -> crate::pb::VpnSpeedFacts {
    let state = crate::awg_kernel::load();
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let free = crate::move_transfer::free_bytes(std::path::Path::new("/")).unwrap_or(0);
    let status = if state.status.is_empty() {
        if crate::awg_kernel::module_loaded() { "on" } else { "off" }.to_string()
    } else {
        state.status
    };
    // While it works, the note says how far it got
    let note = if status == "working" { crate::awg_kernel::current_progress() } else { state.note };
    crate::pb::VpnSpeedFacts {
        amnezia_kernel_status: status,
        amnezia_kernel_note: note,
        amnezia_kernel_possible: crate::awg_kernel::supported(&os)
            && (crate::awg_kernel::module_loaded() || free >= crate::awg_kernel::NEEDED_FREE_BYTES),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mtu_is_read_from_ip_link() {
        let shown = "4: wgpanel: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT\n    link/none\n";
        assert_eq!(mtu_of(shown), Some(1420));
        assert_eq!(mtu_of("Device \"wg0\" does not exist."), None);
    }

    #[test]
    fn exec_names_the_container_first() {
        assert_eq!(exec("awgvpn", &["ip", "link"]), vec!["exec", "awgvpn", "ip", "link"]);
    }

    #[test]
    fn a_kernel_tunnel_is_told_from_a_userspace_one() {
        let kernel = "5: wgpanel: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280 qdisc noqueue\n    link/none  promiscuity 0\n    wireguard addrgenmode none";
        let userspace = "7: wg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq_codel\n    link/none  promiscuity 0\n    tun type tun pi off vnet_hdr off";
        assert!(is_kernel(kernel));
        assert!(!is_kernel(userspace));
    }

    #[test]
    fn udp_drops_and_load_are_read() {
        let snmp = "Ip: Forwarding\nIp: 1\nUdp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\nUdp: 900 3 17 800 12 0\n";
        assert_eq!(udp_counter(snmp, "InErrors"), 17);
        assert_eq!(udp_counter(snmp, "RcvbufErrors"), 12);
        assert_eq!(udp_counter("", "InErrors"), 0);
        assert_eq!(load_of("0.42 0.30 0.20 1/123 4567\n"), 0.42);
    }
}
