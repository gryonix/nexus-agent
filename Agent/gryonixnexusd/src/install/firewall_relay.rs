//! Scenario B's routing halves: the relay's DNAT/forward/SNAT ruleset, and the home half's connection marks

use std::fmt::Write as _;

use super::execute::EventSink;
use super::firewall;

/// The tunnel's interface name
pub const WG_INTERFACE: &str = "wg0";

/// docker's bridges: the default one and compose networks
const DOCKER_BRIDGES: [&str; 2] = ["docker0", "br-*"];

/// One block of rules per docker bridge
fn per_bridge(rules: impl Fn(&str) -> String) -> String {
    DOCKER_BRIDGES.iter().map(|bridge| rules(bridge)).collect::<Vec<_>>().join("\n\x20       ")
}

/// One machine this relay forwards to
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Peer {
    /// Its address inside the tunnel — the DNAT destination.
    pub ip: String,
    /// TCP ports DNATed to THIS peer.
    pub tcp_ports: Vec<u16>,
    /// UDP ports DNATed to this peer — a VPN protocol's, always.
    pub udp_ports: Vec<u16>,
}

impl Peer {
    /// The nftables variable holding this peer's address
    fn var(index: usize) -> String {
        if index == 0 { "home_ip".to_string() } else { format!("peer{}_ip", index + 1) }
    }
}

/// Everything the relay's ruleset needs and cannot see for itself
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    pub peers: Vec<Peer>,
    pub vps_public: String,
    /// The relay's WireGuard listen port
    pub wg_port: u16,
}

impl Topology {
    pub fn single(home_ip: String, vps_public: String, wg_port: u16, tcp: Vec<u16>, udp: Vec<u16>) -> Self {
        Topology {
            peers: vec![Peer { ip: home_ip, tcp_ports: tcp, udp_ports: udp }],
            vps_public,
            wg_port,
        }
    }

    /// The first peer's address
    pub fn home_ip(&self) -> &str {
        self.peers.first().map(|p| p.ip.as_str()).unwrap_or("")
    }

    /// Every forwarded TCP port, across all peers
    pub fn all_tcp_ports(&self) -> Vec<u16> {
        self.peers.iter().flat_map(|p| p.tcp_ports.iter().copied()).collect()
    }

    pub fn all_udp_ports(&self) -> Vec<u16> {
        self.peers.iter().flat_map(|p| p.udp_ports.iter().copied()).collect()
    }

    /// Every peer with the nftables variable that holds its address.
    fn addressed(&self) -> Vec<(String, &Peer)> {
        self.peers.iter().enumerate().map(|(i, peer)| (Peer::var(i), peer)).collect()
    }

    pub fn is_complete(&self) -> bool {
        !self.peers.is_empty()
            && !self.vps_public.is_empty()
            && self.wg_port > 0
            && self.peers.iter().all(|p| !p.ip.is_empty() && !p.tcp_ports.is_empty())
            && !self.has_port_collision()
    }

    pub fn has_port_collision(&self) -> bool {
        let mut tcp: Vec<u16> = Vec::new();
        let mut udp: Vec<u16> = Vec::new();
        for peer in &self.peers {
            for port in &peer.tcp_ports {
                if tcp.contains(port) {
                    return true;
                }
                tcp.push(*port);
            }
            for port in &peer.udp_ports {
                if udp.contains(port) {
                    return true;
                }
                udp.push(*port);
            }
        }
        false
    }

    /// The tunnel's /24, derived from the home address
    pub fn subnet(&self) -> String {
        format!("{}.0/24", octets_prefix(self.home_ip()))
    }

    pub fn hairpin_src(&self) -> String {
        format!("{}.254", octets_prefix(self.home_ip()))
    }
}

fn octets_prefix(address: &str) -> String {
    let parts: Vec<&str> = address.split('.').collect();
    if parts.len() == 4 {
        parts[..3].join(".")
    } else {
        address.to_string()
    }
}

fn port_set(ports: &[u16]) -> String {
    ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
}

fn per_peer(
    topo: &Topology,
    tcp_line: impl Fn(&str, &str) -> String,
    udp_line: impl Fn(&str, &str) -> String,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (var, peer) in topo.addressed() {
        lines.push(tcp_line(&var, &port_set(&peer.tcp_ports)));
        if !peer.udp_ports.is_empty() {
            lines.push(udp_line(&var, &port_set(&peer.udp_ports)));
        }
    }
    lines.join("\n\x20       ")
}

pub fn relay_ruleset(topo: &Topology, pub_if: &str, drop_in_dir: &str) -> String {
    let wg = WG_INTERFACE;
    let chain = firewall::CHAIN;
    let mut out = String::new();
    let _ = write!(
        out,
        "#!/usr/sbin/nft -f\n\
         # Managed by gryonixNexus — written by the control-plane agent.\n\
         # Scenario B relay: firewall + DNAT of the deployment's ports into the\n\
         # tunnel, symmetric SNAT for the home half's egress.\n\
         #\n\
         # No `flush ruleset`: it would erase docker's NAT table and cut every\n\
         # container on this host off the network. Only our own tables are\n\
         # replaced, which is what makes re-applying this safe.\n\
         table inet filter\n\
         delete table inet filter\n\
         table ip {nat_table}\n\
         delete table ip {nat_table}\n\
         \n\
         define pub_if = \"{pub_if}\"\n\
{peer_defines}\
         define vps_public = {vps_public}\n\
         # A DISTINCT SNAT source for hairpinned VPN-client traffic, kept apart\n\
         # from the relay masquerade so the home admin guard can tell a VPN\n\
         # client from a relayed public visitor — both otherwise arrive with the\n\
         # same source and the guard, which sees only L3, blocked everyone.\n\
         define hairpin_src = {hairpin_src}\n\
         \n\
         table inet filter {{\n\
         \x20   # Filled by the agent when it installs a service that needs a\n\
         \x20   # port open (`flush chain` + `add rule`). Empty opens nothing.\n\
         \x20   chain {chain} {{\n\
         \x20   }}\n\
         \n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority filter; policy drop;\n\
         \x20       iif \"lo\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       ct state invalid drop\n\
         \x20       meta l4proto icmp icmp type {{ echo-request, destination-unreachable, time-exceeded, parameter-problem }} limit rate 10/second accept\n\
         \x20       meta l4proto ipv6-icmp accept\n\
{ssh_throttle}\
         \x20       udp dport {wg_port} accept comment \"WireGuard\"\n\
         \x20       # The forwarded ports are NOT accepted here: that traffic is\n\
         \x20       # DNATed and only ever passes through the forward chain.\n\
         \x20       jump {chain}\n\
         \x20   }}\n\
         \n\
         \x20   # **MSS clamping, and it is not an optimisation.** Without it a\n\
         \x20   # relayed HTTPS connection completes its TCP handshake and then\n\
         \x20   # HANGS. The client's TLS ClientHello arrived at\n\
         \x20   # sequence 1449 with the first 1448 bytes missing, and the home\n\
         \x20   # node answered with a SACK naming the hole. A public client\n\
         \x20   # sizes segments for ITS OWN path and knows nothing about a\n\
         \x20   # 1420-byte tunnel in the middle. Everything tested through this\n\
         \x20   # relay before then was small — an ACME challenge, an SMTP\n\
         \x20   # handshake — which is why nothing caught it.\n\
         \x20   #\n\
         \x20   # Its own chain at MANGLE priority: the filter chain below runs\n\
         \x20   # at filter priority and its verdicts would end traversal before\n\
         \x20   # an option rewrite could happen. `rt mtu` is the route's own\n\
         \x20   # MTU, so no number is hardcoded.\n\
         \x20   chain mangle_forward {{\n\
         \x20       type filter hook forward priority mangle; policy accept;\n\
         \x20       oifname \"{wg}\" tcp flags syn tcp option maxseg size set rt mtu\n\
         \x20       iifname \"{wg}\" tcp flags syn tcp option maxseg size set rt mtu\n\
         \x20   }}\n\
         \n\
         \x20   chain forward {{\n\
         \x20       # policy ACCEPT, and every drop below names an interface.\n\
         \x20       # nftables offers a forwarded packet to EVERY chain at this\n\
         \x20       # hook and one drop verdict anywhere is final, so a drop\n\
         \x20       # policy here would also veto docker's per-container accepts\n\
         \x20       # and leave containers with no network at all — which reads\n\
         \x20       # as \"docker is broken\". The other rulesets avoid that by\n\
         \x20       # declaring no forward chain; the relay cannot, its forward\n\
         \x20       # rules ARE the relay, so the default is inverted and the\n\
         \x20       # deny is spelled out for the paths this host routes.\n\
         \x20       type filter hook forward priority filter; policy accept;\n\
         \x20       iifname \"{wg}\" ct state invalid drop\n\
         \x20       oifname \"{wg}\" ct state invalid drop\n\
         \x20       ct state established,related accept\n\
         \x20       {relay_accepts}\n",
        relay_accepts = per_peer(
            topo,
            |var, ports| format!("iifname $pub_if oifname \"{wg}\" ip daddr ${var} tcp dport {{ {ports} }} accept"),
            |var, ports| format!("iifname $pub_if oifname \"{wg}\" ip daddr ${var} udp dport {{ {ports} }} accept"),
        ),
        nat_table = NAT_TABLE,
        ssh_throttle = super::firewall_base::ssh_throttle(),
        wg_port = topo.wg_port,
        peer_defines = topo
            .addressed()
            .iter()
            .map(|(var, peer)| format!("         define {var} = {}\n", peer.ip))
            .collect::<String>(),
        vps_public = topo.vps_public,
        hairpin_src = topo.hairpin_src(),
    );
    let _ = write!(
        out,
        "\x20       # Hairpinned tunnel traffic to the deployment's own sites —\n\
         \x20       # DNATed back into the tunnel, so both interfaces are {wg}.\n\
         \x20       {hairpin_accepts}\n",
        hairpin_accepts = per_peer(
            topo,
            |var, ports| format!("iifname \"{wg}\" oifname \"{wg}\" ip daddr ${var} tcp dport {{ {ports} }} accept"),
            |var, ports| format!("iifname \"{wg}\" oifname \"{wg}\" ip daddr ${var} udp dport {{ {ports} }} accept"),
        ),
    );
    let _ = write!(
        out,
        "\x20       # VPN containers on this relay reaching the deployment's sites.\n\
         \x20       {container_accepts}\n",
        container_accepts = per_bridge(|bridge| {
            per_peer(
                topo,
                |var, ports| format!("iifname \"{bridge}\" oifname \"{wg}\" ip daddr ${var} tcp dport {{ {ports} }} accept"),
                |var, ports| format!("iifname \"{bridge}\" oifname \"{wg}\" ip daddr ${var} udp dport {{ {ports} }} accept"),
            )
        }),
    );
    let _ = write!(
        out,
        "\x20       # Traffic the home half starts (outgoing mail, updates) —\n\
         \x20       # out through this relay.\n\
         \x20       iifname \"{wg}\" oifname $pub_if accept\n\
         \x20       # The deny the policy used to provide, restated for the two\n\
         \x20       # paths that need it: nothing else enters or leaves the\n\
         \x20       # tunnel, and this relay is not an open router between\n\
         \x20       # public interfaces. docker's bridges are named in neither,\n\
         \x20       # which is the point — no interface list to go stale.\n\
         \x20       iifname \"{wg}\" drop\n\
         \x20       oifname \"{wg}\" drop\n\
         \x20       iifname $pub_if oifname $pub_if drop\n\
         \x20   }}\n\
         }}\n\
         \n\
         # OUR OWN nat table, never docker's `ip nat`: replacing that one would\n\
         # take docker's published ports with it, and adding to it would\n\
         # duplicate these rules on every re-apply. Safe here and not for\n\
         # filtering — NAT has no drop verdict to be vetoed by.\n\
         table ip {nat_table} {{\n\
         \x20   chain prerouting {{\n\
         \x20       type nat hook prerouting priority dstnat;\n\
         \x20       {public_dnat}\n",
        nat_table = NAT_TABLE,
        public_dnat = per_peer(
            topo,
            |var, ports| format!("iifname $pub_if tcp dport {{ {ports} }} dnat to ${var}"),
            |var, ports| format!("iifname $pub_if udp dport {{ {ports} }} dnat to ${var}"),
        ),
    );
    let _ = writeln!(
        out,
        "\x20       {container_dnat}",
        container_dnat = per_bridge(|bridge| {
            per_peer(
                topo,
                |var, ports| format!("iifname \"{bridge}\" ip daddr $vps_public tcp dport {{ {ports} }} dnat to ${var}"),
                |var, ports| format!("iifname \"{bridge}\" ip daddr $vps_public udp dport {{ {ports} }} dnat to ${var}"),
            )
        }),
    );
    let _ = writeln!(
        out,
        "\x20       {hairpin_dnat}",
        hairpin_dnat = per_peer(
            topo,
            |var, ports| {
                format!("iifname \"{wg}\" ip daddr $vps_public tcp dport {{ {ports} }} dnat to ${var}")
            },
            |var, ports| {
                format!("iifname \"{wg}\" ip daddr $vps_public udp dport {{ {ports} }} dnat to ${var}")
            },
        ),
    );
    let _ = write!(
        out,
        "\x20   }}\n\
         \x20   chain output {{\n\
         \x20       type nat hook output priority dstnat;\n\
         \x20       # This relay reaching its own forwarded sites\n\
         \x20       {local_dnat}\n\
         \x20   }}\n\
         \x20   chain postrouting {{\n\
         \x20       type nat hook postrouting priority srcnat;\n\
         \x20       # First matching NAT wins, so the hairpin source precedes\n\
         \x20       # the masquerade below.\n\
         \x20       iifname \"{wg}\" oifname \"{wg}\" ip daddr $home_ip snat to $hairpin_src\n\
         \x20       # Relayed public traffic is deliberately NOT NATed: DNAT\n\
         \x20       # alone survives the round trip, so the real client IP rides\n\
         \x20       # all the way home instead of collapsing into this relay's\n\
         \x20       # tunnel address. The home half routes the reply back through\n\
         \x20       # the tunnel itself — see `relay_routes`.\n\
         \x20       oifname $pub_if ip saddr {subnet} masquerade\n\
         \x20       oifname \"{wg}\" ip saddr $vps_public masquerade\n\
         \x20   }}\n\
         \x20   # VPN containers on this relay: ahead of docker's masquerade.\n\
         \x20   chain postrouting_containers {{\n\
         \x20       type nat hook postrouting priority srcnat - 5;\n\
         \x20       iifname \"docker0\" oifname \"{wg}\" ip daddr $home_ip snat to $hairpin_src\n\
         \x20       iifname \"br-*\" oifname \"{wg}\" ip daddr $home_ip snat to $hairpin_src\n\
         \x20   }}\n\
         }}\n\
         \n\
         include \"{drop_in_dir}/{glob}\"\n",
        subnet = topo.subnet(),
        glob = firewall::DROP_IN_GLOB,
        local_dnat = topo
            .addressed()
            .iter()
            .map(|(var, peer)| {
                format!("ip daddr $vps_public tcp dport {{ {} }} dnat to ${var}", port_set(&peer.tcp_ports))
            })
            .collect::<Vec<_>>()
            .join("\n\x20       "),
    );
    out
}

/// Our NAT table's name. Not `nat`: that is docker's.
pub const NAT_TABLE: &str = "gryonixnexus_nat";

const OUTBOUND_MAIL_MARK: &str = "\x20       # Outbound SMTP goes through the relay so it leaves from the\n\
                                  \x20       # address SPF authorises and PTR names; `!= local` keeps mail\n\
                                  \x20       # ARRIVING for this host out of it.\n\
                                  \x20       ct state new tcp dport 25 fib daddr type != local ct mark set 0x1\n";

fn relay_sites_mark(topo: &Topology) -> String {
    let tcp = topo.all_tcp_ports();
    if tcp.is_empty() {
        return String::new();
    }
    format!(
        "\x20       # The relay's own sites go through the tunnel, so VPN clients\n\
         \x20       # reach them as the relay's hairpin address.\n\
         \x20       ct state new ip daddr {} tcp dport {{ {} }} ct mark set 0x1\n",
        topo.vps_public,
        port_set(&tcp)
    )
}

/// A marked host connection leaves as the tunnel address
fn host_masquerade() -> String {
    format!(
        "\n\
         \x20   # The mark reroutes a host process after it picked its\n\
         \x20   # source; the tunnel takes only its own address.\n\
         \x20   chain postrouting {{\n\
         \x20       type nat hook postrouting priority srcnat; policy accept;\n\
         \x20       oifname \"{WG_INTERFACE}\" meta mark 0x1 masquerade\n\
         \x20   }}\n"
    )
}

/// A home half's file given the host masquerade it lacks
pub fn with_host_masquerade(conf: &str) -> Option<String> {
    if !super::firewall_base::already_ours(conf) || conf.contains("meta mark 0x1 masquerade") {
        return None;
    }
    let output = conf.find("type route hook output")?;
    let end = "\n    }\n";
    let close = output + conf[output..].find(end)? + end.len();
    Some(format!("{}{}{}", &conf[..close], host_masquerade(), &conf[close..]))
}

pub fn tunnel_accepted_ports(conf: &str) -> Vec<u16> {
    let needle = format!("iifname \"{WG_INTERFACE}\"");
    let mut ports = Vec::new();
    for line in conf.lines() {
        let line = line.trim();
        if !line.starts_with(&needle) || !line.contains("dport") || !line.contains("accept") {
            continue;
        }
        let Some(open) = line.find('{') else { continue };
        let Some(close) = line[open..].find('}') else { continue };
        for piece in line[open + 1..open + close].split(',') {
            if let Ok(port) = piece.trim().parse::<u16>() {
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
        }
    }
    ports.sort_unstable();
    ports
}

pub fn home_ruleset(drop_in_dir: &str, topo: Option<&Topology>, home_discovery: bool) -> String {
    let base = super::firewall_base::ruleset(drop_in_dir, home_discovery);
    let wg = WG_INTERFACE;
    let tunnel_accepts = match topo {
        None => String::new(),
        Some(topo) => {
            let tcp: Vec<u16> = topo
                .all_tcp_ports()
                .into_iter()
                .filter(|port| !super::firewall_base::BASE_TCP_PORTS.contains(port))
                .collect();
            let mut lines = String::new();
            if !tcp.is_empty() {
                let _ = write!(
                    lines,
                    "\x20       iifname \"{wg}\" tcp dport {{ {} }} accept comment \"from the tunnel\"\n",
                    port_set(&tcp)
                );
            }
            let udp = topo.all_udp_ports();
            if !udp.is_empty() {
                let _ = write!(
                    lines,
                    "\x20       iifname \"{wg}\" udp dport {{ {} }} accept comment \"VPN clients\"\n",
                    port_set(&udp)
                );
            }
            lines
        }
    };
    let relay_sites = topo.map(relay_sites_mark).unwrap_or_default();
    let marks = format!(
        "\n\
         \x20   # Scenario B, home half. A relayed connection arrives from the\n\
         \x20   # tunnel with the REAL public client's source address, which\n\
         \x20   # nothing in the main routing table sends back through {wg}. The\n\
         \x20   # mark set here is what `relay_routes`' policy-routing table\n\
         \x20   # matches on.\n\
         \x20   chain prerouting {{\n\
         \x20       type filter hook prerouting priority mangle; policy accept;\n\
         \x20       ct state new iifname \"{wg}\" ct mark set 0x1\n\
         {OUTBOUND_MAIL_MARK}\
         {relay_sites}\
         \x20       # Restore the connection's mark onto every packet, both\n\
         \x20       # directions: `ct mark` alone is invisible to `ip rule`.\n\
         \x20       meta mark set ct mark\n\
         \x20   }}\n\
         \n\
         \x20   # Every relayed service here terminates in a LOCAL process\n\
         \x20   # (Caddy binds the host's address; the mail engines the same), so\n\
         \x20   # its replies are OUTPUT packets and the prerouting chain never\n\
         \x20   # sees them. The request arrived marked\n\
         \x20   # and correct, Caddy's SYN-ACK carried no mark, fell through to\n\
         \x20   # the main table and never found the tunnel — the connection just\n\
         \x20   # hung. `type route hook output` is the kernel's own mechanism\n\
         \x20   # for re-running the route lookup after a mark changes.\n\
         \x20   chain output {{\n\
         \x20       type route hook output priority mangle; policy accept;\n\
         {OUTBOUND_MAIL_MARK}\
         {relay_sites}\
         \x20       meta mark set ct mark\n\
         \x20   }}\n\
         {masquerade}\
         }}\n",
        masquerade = host_masquerade()
    );
    let jump = format!("\x20       jump {}\n", firewall::CHAIN);
    let base = match (tunnel_accepts.is_empty(), base.find(&jump)) {
        (false, Some(index)) => format!("{}{}{}", &base[..index], tunnel_accepts, &base[index..]),
        _ => base,
    };
    match base.rfind("}\n\ninclude ") {
        Some(index) => format!("{}{}{}", &base[..index], marks, &base[index + 2..]),
        None => base,
    }
}

/// sysctl for the relay: DNAT into the tunnel requires forwarding
pub const RELAY_SYSCTL: &str = "\
# Managed by gryonixNexus — forwarding is mandatory: the VPS DNATs traffic into the tunnel.
net.ipv4.ip_forward = 1
# Loose rp_filter: strict mode may drop tunnel traffic.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
";

/// sysctl for the home half
pub const HOME_SYSCTL: &str = "\
# Managed by gryonixNexus — loose rp_filter: relayed traffic arrives with a
# foreign source IP (the real public visitor, not a tunnel peer), which
# strict reverse-path filtering would otherwise drop as spoofed.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
";

pub const RELAY_SYSCTL_PATH: &str = "/etc/sysctl.d/99-gryonixnexus-forwarding.conf";
pub const HOME_SYSCTL_PATH: &str = "/etc/sysctl.d/99-gryonixnexus-rpfilter.conf";

/// The public interface, as the kernel routes to the internet
pub fn parse_public_interface(route_output: &str) -> Option<String> {
    let mut tokens = route_output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(str::to_string).filter(|name| !name.is_empty());
        }
    }
    None
}

/// Ask the kernel which interface reaches the internet
pub async fn public_interface() -> Option<String> {
    let output = tokio::process::Command::new(ip_bin()).args(["route", "get", "1.1.1.1"]).output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    parse_public_interface(&String::from_utf8_lossy(&output.stdout))
}

/// Overridable for tests, the same technique `docker_bin`/`systemctl_bin` use.
fn ip_bin() -> String {
    std::env::var("GRYONIXNEXUSD_IP_BIN").unwrap_or_else(|_| "ip".to_string())
}

/// Write and apply this role's sysctl file
pub(super) async fn apply_sysctl(path: &str, contents: &str, sink: &EventSink) -> Result<(), String> {
    let script = format!(
        "set -e\numask 022\ncat > '{path}' <<'GRYONIXNEXUS_SYSCTL_EOF'\n{contents}GRYONIXNEXUS_SYSCTL_EOF\n\
         chmod 0644 '{path}'\nsysctl -p '{path}' >/dev/null\n"
    );
    super::packages::run_outside_sandbox(&script, "applying the kernel network settings", sink).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SWIFT_RELAY: &str = include_str!("../../tests/fixtures/relay/vps.nft");
    const SWIFT_HOME: &str = include_str!("../../tests/fixtures/relay/home.nft");
    const SWIFT_RELAY_SYSCTL: &str = include_str!("../../tests/fixtures/relay/vps-sysctl.conf");
    const SWIFT_HOME_SYSCTL: &str = include_str!("../../tests/fixtures/relay/home-sysctl.conf");

    fn fixture_topology() -> Topology {
        Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![51821])
    }

    /// Rules only: comments and blank lines dropped, whitespace collapsed
    fn rules(text: &str) -> Vec<String> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    }

    fn chain_rules(rules: &[String], name: &str) -> Vec<String> {
        let opener = format!("chain {name} {{");
        let mut out = Vec::new();
        let mut inside = false;
        for rule in rules {
            if rule == &opener {
                inside = true;
                continue;
            }
            if inside {
                if rule == "}" {
                    break;
                }
                out.push(rule.clone());
            }
        }
        out
    }

    fn swift_rules_adjusted(text: &str) -> Vec<String> {
        rules(text)
            .into_iter()
            .filter(|line| line != "flush ruleset")
            .map(|line| line.replace("table ip nat {", &format!("table ip {NAT_TABLE} {{")))
            .collect()
    }

    /// Agent-only rules for VPN containers running on the relay
    fn from_a_container(rule: &str) -> bool {
        rule.starts_with("iifname \"docker0\"")
            || rule.starts_with("iifname \"br-*\"")
            || rule == "chain postrouting_containers {"
            || rule == "type nat hook postrouting priority srcnat - 5;"
            || rule == "}"
    }

    #[test]
    fn vpn_containers_on_the_relay_reach_home_sites_as_the_hairpin() {
        let text = relay_ruleset(&fixture_topology(), "ens6", "/etc/nftables.d");
        let all = rules(&text);
        for bridge in ["docker0", "br-*"] {
            let dnat = format!("iifname \"{bridge}\" ip daddr $vps_public tcp dport");
            assert!(all.iter().any(|rule| rule.starts_with(&dnat) && rule.contains("dnat to $home_ip")), "{text}");
            let accept = format!("iifname \"{bridge}\" oifname \"wg0\" ip daddr $home_ip tcp dport");
            assert!(all.iter().any(|rule| rule.starts_with(&accept) && rule.ends_with("accept")), "{text}");
            let snat = format!("iifname \"{bridge}\" oifname \"wg0\" ip daddr $home_ip snat to $hairpin_src");
            assert!(chain_rules(&all, "postrouting_containers").contains(&snat), "{text}");
        }
        let forward = chain_rules(&all, "forward");
        let accept_at = forward.iter().position(|rule| rule.starts_with("iifname \"docker0\"")).unwrap();
        let drop_at = forward.iter().position(|rule| rule == "oifname \"wg0\" drop").unwrap();
        assert!(accept_at < drop_at, "containers are let in before the tunnel's deny");
    }

    #[test]
    fn the_relay_routes_exactly_what_the_setup_script_routes() {
        let ours = relay_ruleset(&fixture_topology(), "@PUB_IF@", "/etc/nftables.d");
        let mine = rules(&ours);
        let theirs = swift_rules_adjusted(SWIFT_RELAY);
        for rule in &theirs {
            assert!(mine.contains(rule), "the relay ruleset is missing a rule the setup script has:\n  {rule}");
        }
        for rule in &mine {
            assert!(
                theirs.contains(rule)
                    || rule.starts_with("delete table")
                    || rule == "table inet filter"
                    || *rule == format!("table ip {NAT_TABLE}")
                    || from_a_container(rule),
                "the relay ruleset has a rule the setup script does not:\n  {rule}"
            );
        }
    }

    #[test]
    fn the_relay_never_flushes_everything_and_never_touches_dockers_nat_table() {
        let text = relay_ruleset(&fixture_topology(), "ens6", "/etc/nftables.d");
        let rules = rules(&text).join("\n");
        assert!(!rules.contains("flush ruleset"), "flushing everything erases docker's NAT");
        assert!(rules.contains("delete table inet filter"));
        assert!(rules.contains(&format!("delete table ip {NAT_TABLE}")));
        assert!(!rules.contains("table ip nat {"), "that table is docker's");
    }

    /// The tunnel port, and the live measurement behind it.
    #[test]
    fn the_tunnel_port_is_accepted_on_input() {
        let text = relay_ruleset(&fixture_topology(), "ens6", "/etc/nftables.d");
        assert!(text.contains("udp dport 51820 accept comment \"WireGuard\""));
        let with_other_port = relay_ruleset(
            &Topology { wg_port: 51830, ..fixture_topology() },
            "ens6",
            "/etc/nftables.d",
        );
        assert!(with_other_port.contains("udp dport 51830 accept"));
    }

    #[test]
    fn a_deployment_with_no_udp_forward_emits_no_udp_rules() {
        let topo = Topology { peers: vec![Peer { udp_ports: vec![], ..fixture_topology().peers[0].clone() }], ..fixture_topology() };
        let text = relay_ruleset(&topo, "ens6", "/etc/nftables.d");
        assert!(!text.contains("udp dport {"), "an empty port set would be a syntax error, not a no-op");
        assert!(text.contains("udp dport 51820 accept"));
    }

    #[test]
    fn the_hairpin_source_and_subnet_come_from_the_home_address() {
        let topo = fixture_topology();
        assert_eq!(topo.hairpin_src(), "10.8.0.254");
        assert_eq!(topo.subnet(), "10.8.0.0/24");
        assert!(swift_rules_adjusted(SWIFT_RELAY)
            .iter()
            .any(|rule| rule.contains("ip saddr 10.8.0.0/24 masquerade")));
        assert!(SWIFT_RELAY.contains("define hairpin_src = 10.8.0.254"));
    }

    #[test]
    fn an_incomplete_topology_is_recognised() {
        assert!(fixture_topology().is_complete());
        for broken in [
            Topology { peers: vec![Peer { ip: String::new(), ..fixture_topology().peers[0].clone() }], ..fixture_topology() },
            Topology { vps_public: String::new(), ..fixture_topology() },
            Topology { wg_port: 0, ..fixture_topology() },
            Topology { peers: vec![Peer { tcp_ports: vec![], ..fixture_topology().peers[0].clone() }], ..fixture_topology() },
        ] {
            assert!(!broken.is_complete(), "{broken:?} must not be treated as a relay topology");
        }
    }

    #[test]
    fn the_home_ruleset_marks_relayed_connections_and_keeps_the_base_intact() {
        let text = home_ruleset("/etc/nftables.d", None, false);
        let mine = rules(&text);
        for chain in ["prerouting", "output"] {
            let theirs = chain_rules(&swift_rules_adjusted(SWIFT_HOME), chain);
            let ours = chain_rules(&mine, chain);
            assert!(!theirs.is_empty(), "the Swift artifact must have a `{chain}` chain to compare against");
            assert_eq!(ours, theirs, "`chain {chain}` differs from the generator's");
        }
        assert!(text.contains(&format!("chain {} {{", firewall::CHAIN)));
        assert!(text.contains(&format!("jump {}", firewall::CHAIN)));
        assert!(text.contains(&format!("include \"/etc/nftables.d/{}\"", firewall::DROP_IN_GLOB)));
        assert!(!rules(&text).join("\n").contains("flush ruleset"));
        let table_end = text.find("\ninclude ").expect("the include closes the file");
        assert!(text[..table_end].contains("chain output {"), "the mark chains must sit inside the table");
    }

    #[test]
    fn the_tunnel_accepts_are_read_back_out_of_a_real_home_ruleset() {
        let topo = Topology { peers: vec![Peer { tcp_ports: vec![25, 80, 143, 443, 465, 587, 993, 4190], udp_ports: vec![51821], ..fixture_topology().peers[0].clone() }], ..fixture_topology() };
        let text = home_ruleset("/etc/nftables.d", Some(&topo), false);
        assert_eq!(tunnel_accepted_ports(&text), vec![25, 143, 465, 587, 993, 4190, 51821]);
    }

    #[test]
    fn a_home_half_without_forwarded_ports_reads_back_empty() {
        assert!(tunnel_accepted_ports(&home_ruleset("/etc/nftables.d", None, false)).is_empty());
        // And a single-host ruleset, which has no tunnel at all.
        assert!(tunnel_accepted_ports(&super::super::firewall_base::ruleset("/etc/nftables.d", false)).is_empty());
    }

    #[test]
    fn the_home_half_accepts_the_forwarded_ports_from_the_tunnel() {
        // The real port set from the production home half.
        let topo = Topology { peers: vec![Peer { tcp_ports: vec![25, 80, 143, 443, 465, 587, 993, 4190], udp_ports: vec![51821], ..fixture_topology().peers[0].clone() }], ..fixture_topology() };
        let text = home_ruleset("/etc/nftables.d", Some(&topo), false);
        assert!(
            text.contains("iifname \"wg0\" tcp dport { 25, 143, 465, 587, 993, 4190 } accept"),
            "the mail ports must be accepted from the tunnel:\n{text}"
        );
        assert!(text.contains("iifname \"wg0\" udp dport { 51821 } accept"));
        assert!(text.contains("tcp dport { 80, 443 } accept"));
        assert!(text.contains("tcp dport 22 meter gryonixnexus_ssh_throttle4"));
        assert!(
            !text.lines().any(|line| line.contains("tcp dport { 25, 80, 143, 443") && line.ends_with("accept")),
            "the base ports must not be repeated"
        );
        let mark = format!("ct state new ip daddr {} tcp dport {{ 25, 80, 143, 443, 465, 587, 993, 4190 }} ct mark set 0x1", topo.vps_public);
        assert_eq!(text.matches(&mark).count(), 2, "{text}");
        assert!(text.contains("oifname \"wg0\" meta mark 0x1 masquerade"), "{text}");
        let older = text.replace(&host_masquerade(), "");
        assert_eq!(with_host_masquerade(&older).as_deref(), Some(text.as_str()));
        assert_eq!(with_host_masquerade(&text), None);
        assert_eq!(with_host_masquerade(&super::super::firewall_base::ruleset("/etc/nftables.d", false)), None);
        let jump = text.find("jump gryonixnexus_services").expect("the input chain jumps");
        assert!(text.find("iifname \"wg0\" tcp dport").expect("the tunnel accept") < jump);

        let bare = home_ruleset("/etc/nftables.d", None, false);
        assert!(!bare.contains("iifname \"wg0\" tcp dport"));
        assert!(bare.contains("tcp dport { 80, 443 } accept"));
        assert!(bare.contains("tcp dport 22 meter gryonixnexus_ssh_throttle4"));
    }

    #[test]
    fn the_home_ruleset_declares_no_forward_chain() {
        assert!(!rules(&home_ruleset("/etc/nftables.d", None, false)).join("\n").contains("hook forward"));
    }

    #[test]
    fn both_sysctl_files_match_the_generator_byte_for_byte() {
        assert_eq!(RELAY_SYSCTL, SWIFT_RELAY_SYSCTL);
        assert_eq!(HOME_SYSCTL, SWIFT_HOME_SYSCTL);
    }

    #[test]
    fn the_public_interface_is_read_from_the_kernels_own_answer() {
        // Real `ip route get 1.1.1.1` output from the relay.
        assert_eq!(
            parse_public_interface("1.1.1.1 via 203.0.113.1 dev ens6 src 203.0.113.150 uid 0 \n    cache "),
            Some("ens6".to_string())
        );
        assert_eq!(parse_public_interface("10.8.0.2 dev wg0 src 10.8.0.1 uid 0"), Some("wg0".to_string()));
        assert_eq!(parse_public_interface("something unexpected"), None);
        assert_eq!(parse_public_interface(""), None);
    }

    #[test]
    fn a_second_peer_gets_its_own_address_and_its_own_rules() {
        let topo = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![25, 587], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![8080], udp_ports: vec![51821] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert!(topo.is_complete());
        let text = relay_ruleset(&topo, "eth0", "/etc/nftables.d");

        assert!(text.contains("define home_ip = 10.8.0.2"), "{text}");
        assert!(text.contains("define peer2_ip = 10.8.0.3"), "{text}");

        // Public DNAT: each port set aimed at its OWN peer.
        assert!(text.contains("iifname $pub_if tcp dport { 25, 587 } dnat to $home_ip"), "{text}");
        assert!(text.contains("iifname $pub_if tcp dport { 8080 } dnat to $peer2_ip"), "{text}");
        assert!(text.contains("iifname $pub_if udp dport { 51821 } dnat to $peer2_ip"), "{text}");
        assert!(!text.contains("udp dport { 51821 } dnat to $home_ip"), "{text}");

        // The forward chain and the hairpin follow the same split.
        assert!(text.contains("ip daddr $peer2_ip tcp dport { 8080 } accept"), "{text}");
        assert!(text.contains("ip daddr $peer2_ip snat to") || text.contains("snat to $hairpin_src"), "{text}");
    }

    #[test]
    fn one_peer_still_speaks_of_home_ip() {
        let text = relay_ruleset(&fixture_topology(), "eth0", "/etc/nftables.d");
        assert!(text.contains("define home_ip = "), "{text}");
        assert!(!text.contains("peer2_ip"), "a single peer introduces no second variable: {text}");
    }

    #[test]
    fn two_peers_cannot_claim_the_same_port() {
        let clash = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![443], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![443], udp_ports: vec![] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert!(clash.has_port_collision());
        assert!(!clash.is_complete(), "a relay that cannot express its own rules is not complete");

        // Different ports on the same two peers are fine.
        let fine = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![443], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![8443], udp_ports: vec![] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert!(fine.is_complete());
    }

    #[test]
    fn every_peer_must_be_addressable() {
        let base = fixture_topology();
        let mut topo = Topology { peers: base.peers.clone(), ..fixture_topology() };
        topo.peers.push(Peer { ip: String::new(), tcp_ports: vec![8080], udp_ports: vec![] });
        assert!(!topo.is_complete(), "a peer with no address is not addressable");

        let mut topo = Topology { peers: base.peers.clone(), ..fixture_topology() };
        topo.peers.push(Peer { ip: "10.8.0.3".into(), tcp_ports: vec![], udp_ports: vec![] });
        assert!(!topo.is_complete(), "a peer with no forwarded port has nothing to relay");
    }

    #[test]
    fn the_home_half_accepts_every_peers_ports() {
        let topo = Topology {
            peers: vec![
                Peer { ip: "10.8.0.2".into(), tcp_ports: vec![25], udp_ports: vec![] },
                Peer { ip: "10.8.0.3".into(), tcp_ports: vec![8080], udp_ports: vec![51821] },
            ],
            vps_public: "203.0.113.10".into(),
            wg_port: 51820,
        };
        assert_eq!(topo.all_tcp_ports(), vec![25, 8080]);
        assert_eq!(topo.all_udp_ports(), vec![51821]);
        let text = home_ruleset("/etc/nftables.d", Some(&topo), false);
        assert!(text.contains("tcp dport { 25, 8080 } accept"), "{text}");
        assert!(text.contains("udp dport { 51821 } accept"), "{text}");
    }
}
