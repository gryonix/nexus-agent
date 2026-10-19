//! Pre-flight: is anything on this host already holding a port this install is about to publish?

use std::collections::{BTreeMap, BTreeSet};

use tokio::process::Command;

use super::firewall::{Port, Proto};

pub const WILDCARD: &str = "0.0.0.0";

pub fn addresses_collide(want: &str, held: &str) -> bool {
    want == held || is_wildcard(want) || is_wildcard(held)
}

fn is_wildcard(address: &str) -> bool {
    address.is_empty() || address == WILDCARD || address == "::" || address == "[::]" || address == "*"
}

/// One mapping an install wants to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub address: String,
    pub port: Port,
}

impl Wanted {
    pub fn new(address: &str, port: Port) -> Self {
        Self { address: address.to_string(), port }
    }

    pub fn any(port: Port) -> Self {
        Self::new(WILDCARD, port)
    }
}

/// One socket the host already holds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Binding {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub port: Port,
    pub holder: Option<String>,
}

impl Conflict {
    /// One sentence per conflict, for the refusal the client sees.
    pub fn describe(&self) -> String {
        match &self.holder {
            Some(holder) => format!("{}/{} is already published by {}", self.port.port, self.port.proto, holder),
            None => format!("{}/{} is already bound by something on this host", self.port.port, self.port.proto),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub project: String,
    pub container: String,
    pub address: String,
    pub port: Port,
}

/// The `/proc/net` tables, in the order `bound_ports` reads them.
const PROC_TABLES: [(&str, Proto); 4] = [
    ("/proc/net/tcp", Proto::Tcp),
    ("/proc/net/tcp6", Proto::Tcp),
    ("/proc/net/udp", Proto::Udp),
    ("/proc/net/udp6", Proto::Udp),
];

/// `st` of a TCP socket that is listening
const TCP_LISTEN: &str = "0A";

/// What one `/proc/net` table says this host holds, address included.
pub fn parse_bound_ports(table: &str, proto: Proto) -> BTreeSet<Binding> {
    let mut held = BTreeSet::new();
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(_sl), Some(local), Some(remote), Some(state)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(local_port) = hex_port(local) else { continue };
        let Some(local_address) = hex_address(local) else { continue };
        let keep = match proto {
            Proto::Tcp => state.eq_ignore_ascii_case(TCP_LISTEN),
            Proto::Udp => hex_port(remote) == Some(0),
        };
        if keep {
            held.insert(Binding { address: local_address, port: local_port });
        }
    }
    held
}

/// `ADDR:PORT` in `/proc/net` notation — the port half is hex, big-endian.
fn hex_port(address: &str) -> Option<u16> {
    let (_, port) = address.rsplit_once(':')?;
    u16::from_str_radix(port, 16).ok()
}

/// The address half of a `/proc/net` row
fn hex_address(local: &str) -> Option<String> {
    let (address, _) = local.rsplit_once(':')?;
    match address.len() {
        8 => {
            let byte = |at: usize| u8::from_str_radix(&address[at..at + 2], 16).ok();
            if address.chars().all(|c| c == '0') {
                return Some(WILDCARD.to_string());
            }
            Some(format!("{}.{}.{}.{}", byte(6)?, byte(4)?, byte(2)?, byte(0)?))
        }
        32 if address.chars().all(|c| c == '0') => Some(WILDCARD.to_string()),
        _ => None,
    }
}

/// Parse `docker ps --format '{{.Label "com.docker.compose.project"}}\t{{.Names}}\t{{.Ports}}'`
pub fn parse_published_ports(listing: &str) -> Vec<Published> {
    let mut published = Vec::new();
    for line in listing.lines() {
        let mut columns = line.split('\t');
        let (Some(project), Some(container), Some(ports)) = (columns.next(), columns.next(), columns.next()) else {
            continue;
        };
        for mapping in ports.split(',') {
            let mapping = mapping.trim();
            let Some((host_side, container_side)) = mapping.split_once("->") else { continue };
            let Some((host_address, host_port)) = host_side.rsplit_once(':') else { continue };
            let Ok(host_port) = host_port.parse::<u16>() else { continue };
            let proto = match container_side.rsplit_once('/') {
                Some((_, "udp")) => Proto::Udp,
                Some((_, "tcp")) => Proto::Tcp,
                _ => continue,
            };
            published.push(Published {
                project: project.to_string(),
                container: container.to_string(),
                address: host_address.to_string(),
                port: Port { proto, port: host_port },
            });
        }
    }
    published
}

pub fn conflicts(
    wanted: &[Wanted],
    bound: &BTreeMap<Proto, BTreeSet<Binding>>,
    published: &[Published],
    ours: &[String],
) -> Vec<Conflict> {
    let mut seen: BTreeSet<(String, u16, &'static str)> = BTreeSet::new();
    let mut conflicts = Vec::new();
    for want in wanted {
        let key = (
            want.address.clone(),
            want.port.port,
            if want.port.proto == Proto::Tcp { "tcp" } else { "udp" },
        );
        if !seen.insert(key) {
            continue;
        }
        let by_docker = published
            .iter()
            .find(|p| p.port == want.port && addresses_collide(&want.address, &p.address));
        if let Some(entry) = by_docker {
            if ours.iter().any(|project| project == &entry.project) {
                continue;
            }
        }
        let is_bound = bound.get(&want.port.proto).is_some_and(|set| {
            set.iter()
                .any(|held| held.port == want.port.port && addresses_collide(&want.address, &held.address))
        });
        if !is_bound && by_docker.is_none() {
            continue;
        }
        conflicts.push(Conflict {
            port: want.port,
            holder: by_docker.map(|entry| format!("container '{}' (compose project '{}')", entry.container, entry.project)),
        });
    }
    conflicts
}

/// Every host mapping a compose body publishes
pub fn published_in_compose(compose: &str) -> Vec<Wanted> {
    let mut found = Vec::new();
    let mut list_indent: Option<usize> = None;
    for line in compose.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if trimmed == "ports:" {
            list_indent = Some(indent);
            continue;
        }
        let Some(open_indent) = list_indent else { continue };
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(entry) = trimmed.strip_prefix("- ").filter(|_| indent > open_indent) else {
            list_indent = None;
            continue;
        };
        if let Some(mapping) = compose_entry(entry) {
            found.push(mapping);
        }
    }
    found
}

/// One `ports:` entry — `"IP:HOST:CONTAINER/proto"` or `"HOST:CONTAINER"`
pub fn compose_entry(raw: &str) -> Option<Wanted> {
    let mut text = raw.trim();
    for quote in ['"', '\''] {
        if text.len() >= 2 && text.starts_with(quote) && text.ends_with(quote) {
            text = &text[1..text.len() - 1];
        }
    }
    let mut proto = Proto::Tcp;
    let mut body = text;
    if let Some((head, tail)) = text.rsplit_once('/') {
        proto = match tail.to_ascii_lowercase().as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => return None,
        };
        body = head;
    }
    let parts: Vec<&str> = body.split(':').collect();
    let (address, host_side) = match parts.len() {
        3 => (parts[0], parts[1]),
        2 => (WILDCARD, parts[0]),
        _ => return None,
    };
    let port: u16 = host_side.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(Wanted::new(address, Port { proto, port }))
}

/// Read the host: every mapping held according to `/proc/net`
async fn bound_ports() -> BTreeMap<Proto, BTreeSet<Binding>> {
    let mut bound: BTreeMap<Proto, BTreeSet<Binding>> = BTreeMap::new();
    for (path, proto) in PROC_TABLES {
        let Ok(text) = tokio::fs::read_to_string(path).await else { continue };
        bound.entry(proto).or_default().extend(parse_bound_ports(&text, proto));
    }
    bound
}

/// Read the host: what docker has published, per compose project
async fn published_ports() -> Vec<Published> {
    let output = Command::new("docker")
        .args(["ps", "--format", "{{.Label \"com.docker.compose.project\"}}\t{{.Names}}\t{{.Ports}}"])
        .output()
        .await;
    match output {
        Ok(output) if output.status.success() => parse_published_ports(&String::from_utf8_lossy(&output.stdout)),
        _ => Vec::new(),
    }
}

/// The mappings docker reports for ONE compose project, right now
pub async fn published_ports_of_project(project: &str) -> Vec<Port> {
    published_ports()
        .await
        .into_iter()
        .filter(|entry| entry.project == project)
        .map(|entry| entry.port)
        .collect()
}

pub async fn holder_process(port: &Port) -> Option<String> {
    if !crate::install::packages::have_binary("ss") {
        return None;
    }
    let filter = format!("sport = :{}", port.port);
    let flag = match port.proto {
        Proto::Tcp => "-lptnH",
        Proto::Udp => "-lpunH",
    };
    let out = tokio::process::Command::new("ss")
        .args([flag, &filter])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .ok()?;
    holder_name_in(&String::from_utf8_lossy(&out.stdout))
}

fn holder_name_in(text: &str) -> Option<String> {
    // `users:(("ollama",pid=2193,fd=4))` — the first quoted word is the name.
    let start = text.find("users:((\"")? + "users:((\"".len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    let name = &rest[..end];
    (!name.is_empty()).then(|| name.to_string())
}

pub async fn check(wanted: &[Wanted], ours: &[String]) -> Vec<Conflict> {
    if wanted.is_empty() {
        return Vec::new();
    }
    let bound = bound_ports().await;
    let published = published_ports().await;
    conflicts(wanted, &bound, &published, ours)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATIVE_OLLAMA_SS: &str =
        "LISTEN 0      4096   127.0.0.1:11434 0.0.0.0:* users:((\"ollama\",pid=2193,fd=4))";

    #[test]
    fn the_holder_of_a_port_is_named_from_the_real_line() {
        assert_eq!(holder_name_in(NATIVE_OLLAMA_SS), Some("ollama".to_string()));
    }

    #[test]
    fn a_socket_with_no_process_names_nobody() {
        assert_eq!(
            holder_name_in("LISTEN 0 128 0.0.0.0:51820 0.0.0.0:*"),
            None
        );
        assert_eq!(holder_name_in(""), None);
    }

    const RELAY_PROC_UDP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   68: 0100007F:0143 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 27081 2 ffff89fec5215e80 0
  310: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   989        0 7969296 2 ffff89fec5210fc0 0
  365: 00000000:CA6C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2879528 2 ffff89fec5214ec0 0
";

    const MIDDLE_PROC_UDP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 2153: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2742187 2 000000000e2327d2 0
 2153: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10423 2 00000000dc4bf342 0
 2153: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10421 2 0000000005217025 0
 3359: 00000000:14EB 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10408 2 000000009063fdf3 0
";

    const MIDDLE_PROC_UDP_NO_FILTER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 2153: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10423 2 00000000dc4bf342 0
 2153: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10421 2 0000000005217025 0
 3359: 00000000:14EB 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 10408 2 000000009063fdf3 0
";

    /// The TCP half of the same `vps-middle` pair, verbatim
    const MIDDLE_PROC_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10422 1 000000004c9dc27e 100 0 0 10 5
  17: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10424 1 000000003177a356 100 0 0 10 5
  18: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2746582 1 00000000aab15fa4 100 0 0 10 0
";

    /// The same table with ONLY the filter's row removed.
    const MIDDLE_PROC_TCP_NO_FILTER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10422 1 000000004c9dc27e 100 0 0 10 5
  17: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   990        0 10424 1 000000003177a356 100 0 0 10 5
";

    const LAB_PROC_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 136811 1 ffff8df1fe873900 100 0 0 10 0
   1: 00000000:20C4 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 133247 1 ffff8df1f62a7200 100 0 0 10 0
   2: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23642 1 ffff8df1f62a2f80 100 0 0 10 0
";

    const LAB_DOCKER_PS: &str = "vaultwarden\tvaultwarden\t127.0.0.1:8082->80/tcp
vpnpanel\tvpnpanel\t0.0.0.0:51830->51830/udp, [::]:51830->51830/udp, 127.0.0.1:51900->80/tcp
openvpn\topenvpn\t0.0.0.0:1194->1194/udp, [::]:1194->1194/udp
xray\txray\t0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
shadowsocks\tshadowsocks\t0.0.0.0:8388->8388/tcp, 0.0.0.0:8388->8388/udp, [::]:8388->8388/tcp, [::]:8388->8388/udp
awgvpn\tawgvpn\t
psono\tpsono\t127.0.0.1:8089->80/tcp
psono\tpsono-db-1\t5432/tcp
adguardhome\tadguardhome\t80/tcp, 67-68/udp, 443/tcp, 443/udp, 853/udp, 853/tcp, 3000/udp, 5443/tcp, 127.0.0.1:53->53/tcp, 127.0.0.1:53->53/udp, 5443/udp, 6060/tcp, 127.0.0.1:8087->3000/tcp
passbolt\tpassbolt\t443/tcp, 127.0.0.1:8090->80/tcp
";

    const MIDDLE_DOCKER_PS: &str = "vaultwarden\tvaultwarden\t127.0.0.1:8082->80/tcp
pihole\tpihole\t67/udp, 127.0.0.1:53->53/tcp, 127.0.0.1:53->53/udp, 123/udp, 443/tcp, 127.0.0.1:8092->80/tcp
";

    fn adguard_wants() -> Vec<Wanted> {
        vec![
            Wanted::new("127.0.0.1", Port::tcp(8087)),
            Wanted::new("127.0.0.1", Port::tcp(53)),
            Wanted::new("127.0.0.1", Port::udp(53)),
        ]
    }

    fn bound_from(tcp: &str, udp: &str) -> BTreeMap<Proto, BTreeSet<Binding>> {
        let mut map = BTreeMap::new();
        map.insert(Proto::Tcp, parse_bound_ports(tcp, Proto::Tcp));
        map.insert(Proto::Udp, parse_bound_ports(udp, Proto::Udp));
        map
    }

    fn holds(held: &BTreeSet<Binding>, address: &str, port: u16) -> bool {
        held.contains(&Binding { address: address.to_string(), port })
    }

    #[test]
    fn a_wireguard_interface_is_visible_in_proc_even_though_no_process_owns_it() {
        let held = parse_bound_ports(RELAY_PROC_UDP, Proto::Udp);
        assert!(holds(&held, WILDCARD, 51820), "wg0's kernel socket has to count as a holder: {held:?}");
        assert!(holds(&held, "127.0.0.53", 53), "the resolver's stub is a holder too");
    }

    #[test]
    fn an_ipv4_address_is_decoded_little_endian() {
        let held = parse_bound_ports(MIDDLE_PROC_UDP, Proto::Udp);
        assert!(holds(&held, "127.0.0.1", 53), "{held:?}");
        assert!(holds(&held, "127.0.0.53", 53), "{held:?}");
        assert!(holds(&held, "127.0.0.54", 53), "{held:?}");
        assert!(holds(&held, WILDCARD, 5355), "{held:?}");
    }

    #[test]
    fn only_listening_tcp_sockets_count() {
        let held = parse_bound_ports(LAB_PROC_TCP, Proto::Tcp);
        assert!(holds(&held, WILDCARD, 8443));
        let established = LAB_PROC_TCP.replace(" 0A ", " 01 ");
        assert!(parse_bound_ports(&established, Proto::Tcp).is_empty());
    }

    #[test]
    fn a_connected_udp_socket_is_not_a_holder() {
        let connected = RELAY_PROC_UDP.replace("00000000:CA6C 00000000:0000", "00000000:CA6C 08080808:0035");
        assert!(!holds(&parse_bound_ports(&connected, Proto::Udp), WILDCARD, 51820));
    }

    #[test]
    fn published_ports_are_read_per_project_and_exposed_only_ports_are_ignored() {
        let published = parse_published_ports(LAB_DOCKER_PS);
        assert!(published.contains(&Published {
            project: "vpnpanel".into(),
            container: "vpnpanel".into(),
            address: "0.0.0.0".into(),
            port: Port::udp(51830)
        }));
        assert!(published.contains(&Published {
            project: "vaultwarden".into(),
            container: "vaultwarden".into(),
            address: "127.0.0.1".into(),
            port: Port::tcp(8082)
        }));
        // `5432/tcp` and `443/tcp` are exposed by the image, not published.
        assert!(!published.iter().any(|p| p.port == Port::tcp(5432)));
        assert!(!published.iter().any(|p| p.port == Port::tcp(443)));
    }

    #[test]
    fn the_leftover_tunnel_that_broke_a_real_install_is_reported_without_a_name() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let found = conflicts(&[Wanted::any(Port::udp(51820))], &bound, &parse_published_ports(LAB_DOCKER_PS), &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, Port::udp(51820));
        assert_eq!(found[0].holder, None, "a kernel socket has no name to report");
        assert!(found[0].describe().contains("51820/udp"));
    }

    #[test]
    fn a_port_held_by_another_project_names_the_container() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let found = conflicts(
            &[Wanted::any(Port::tcp(8443))],
            &bound,
            &parse_published_ports(LAB_DOCKER_PS),
            &["vpnpanel".into()],
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].holder.as_deref(), Some("container 'xray' (compose project 'xray')"));
    }

    #[test]
    fn our_own_running_containers_are_never_a_conflict() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let ours: Vec<String> = vec!["vpnpanel".into(), "xray".into(), "shadowsocks".into(), "openvpn".into()];
        let wanted = vec![
            Wanted::any(Port::udp(51830)),
            Wanted::any(Port::tcp(8443)),
            Wanted::any(Port::tcp(8388)),
            Wanted::any(Port::udp(8388)),
            Wanted::any(Port::udp(1194)),
        ];
        assert!(
            conflicts(&wanted, &bound, &parse_published_ports(LAB_DOCKER_PS), &ours).is_empty(),
            "a re-install of the VPN on the host that already runs it must not be refused"
        );
    }

    #[test]
    fn a_free_port_is_free() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        assert!(conflicts(&[Wanted::any(Port::udp(51999))], &bound, &parse_published_ports(LAB_DOCKER_PS), &[]).is_empty());
    }

    #[test]
    fn a_docker_publish_counts_even_when_no_socket_is_visible() {
        let empty = BTreeMap::new();
        let found = conflicts(&[Wanted::any(Port::udp(1194))], &empty, &parse_published_ports(LAB_DOCKER_PS), &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].holder.as_deref(), Some("container 'openvpn' (compose project 'openvpn')"));
    }

    #[test]
    fn one_conflict_per_mapping_even_when_the_request_repeats_it() {
        let bound = bound_from(LAB_PROC_TCP, RELAY_PROC_UDP);
        let found = conflicts(
            &[Wanted::any(Port::udp(51820)), Wanted::any(Port::udp(51820))],
            &bound,
            &parse_published_ports(LAB_DOCKER_PS),
            &[],
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_second_dns_filter_is_refused_and_pihole_is_named() {
        let bound = bound_from(MIDDLE_PROC_TCP, MIDDLE_PROC_UDP);
        let found = conflicts(&adguard_wants(), &bound, &parse_published_ports(MIDDLE_DOCKER_PS), &[]);
        let ports: Vec<String> = found.iter().map(|c| format!("{}/{}", c.port.port, c.port.proto)).collect();
        assert_eq!(ports, vec!["53/tcp", "53/udp"], "8087 is free on that host and must not be reported");
        for conflict in &found {
            assert_eq!(conflict.holder.as_deref(), Some("container 'pihole' (compose project 'pihole')"));
        }
    }

    #[test]
    fn systemd_resolved_alone_does_not_hold_the_filters_53() {
        let bound = bound_from(MIDDLE_PROC_TCP_NO_FILTER, MIDDLE_PROC_UDP_NO_FILTER);
        assert!(
            conflicts(&adguard_wants(), &bound, &[], &[]).is_empty(),
            "127.0.0.53 and 127.0.0.54 are different addresses from 127.0.0.1"
        );
    }

    #[test]
    fn a_wildcard_on_either_side_collides_with_anything() {
        assert!(addresses_collide(WILDCARD, "127.0.0.1"));
        assert!(addresses_collide("127.0.0.1", WILDCARD));
        assert!(addresses_collide("::", "10.8.0.1"));
        assert!(!addresses_collide("127.0.0.1", "127.0.0.53"));
        let bound = bound_from(
            "  sl  local_address rem_address   st\n   0: 0100007F:0019 00000000:0000 0A x\n",
            RELAY_PROC_UDP,
        );
        assert_eq!(conflicts(&[Wanted::any(Port::tcp(25))], &bound, &[], &[]).len(), 1);
    }

    #[test]
    fn compose_entries_are_read_in_every_shape_the_catalog_writes() {
        assert_eq!(compose_entry("\"127.0.0.1:8087:3000\""), Some(Wanted::new("127.0.0.1", Port::tcp(8087))));
        assert_eq!(compose_entry("\"127.0.0.1:53:53/udp\""), Some(Wanted::new("127.0.0.1", Port::udp(53))));
        assert_eq!(compose_entry("\"25:25\""), Some(Wanted::any(Port::tcp(25))));
        assert_eq!(compose_entry("\"51820:51820/udp\""), Some(Wanted::any(Port::udp(51820))));
        assert_eq!(compose_entry("\"3000\""), None);
    }

    #[test]
    fn only_the_ports_list_is_read_out_of_a_compose_body() {
        let compose = "services:\n  adguardhome:\n    image: adguard/adguardhome:v0.107.78\n    ports:\n      - \"127.0.0.1:8087:3000\"\n      # Loopback ONLY.\n      - \"127.0.0.1:53:53/tcp\"\n      - \"127.0.0.1:53:53/udp\"\n    volumes:\n      - /opt/adguardhome/conf:/opt/adguardhome/conf\n";
        let found = published_in_compose(compose);
        assert_eq!(
            found,
            vec![
                Wanted::new("127.0.0.1", Port::tcp(8087)),
                Wanted::new("127.0.0.1", Port::tcp(53)),
                Wanted::new("127.0.0.1", Port::udp(53)),
            ],
            "a comment between entries belongs to the list; a volume never does"
        );
    }
}
