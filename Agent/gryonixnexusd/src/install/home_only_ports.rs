//! Keeps chosen ports to private addresses, Docker-published ones included.

use super::firewall::{Port, Proto};

pub const LABEL: &str = "home-only";
pub const TABLE: &str = "inet gryonixnexus_home_only";

const PRIVATE_V4: &str = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8 }";
const PRIVATE_V6: &str = "{ fc00::/7, fe80::/10, ::1 }";

fn port_set(ports: &[Port], proto: Proto) -> Option<String> {
    let mut list: Vec<u16> = ports.iter().filter(|p| p.proto == proto).map(|p| p.port).collect();
    list.sort_unstable();
    list.dedup();
    (!list.is_empty()).then(|| format!("{{ {} }}", list.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")))
}

/// The drop-in text; empty without ports
pub fn rules(ports: &[Port]) -> String {
    let sets: Vec<(Proto, String)> =
        [Proto::Tcp, Proto::Udp].into_iter().filter_map(|proto| port_set(ports, proto).map(|set| (proto, set))).collect();
    if sets.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "# Managed by gryonixNexus: home-only ports.\nadd table {TABLE}\nflush table {TABLE}\n\
         add chain {TABLE} input {{ type filter hook input priority -5; policy accept; }}\n\
         add chain {TABLE} forward {{ type filter hook forward priority -5; policy accept; }}\n"
    );
    for (proto, set) in &sets {
        for (family, private) in [("ip", PRIVATE_V4), ("ip6", PRIVATE_V6)] {
            out.push_str(&format!("add rule {TABLE} input {proto} dport {set} {family} saddr != {private} drop\n"));
            out.push_str(&format!(
                "add rule {TABLE} forward ct status dnat meta l4proto {proto} ct original proto-dst {set} {family} saddr != {private} drop\n"
            ));
        }
    }
    out
}

/// Ports from the request, refusing unknown protocols
pub fn parse(ports: &[(String, u32)]) -> Result<Vec<Port>, String> {
    ports
        .iter()
        .map(|(proto, port)| {
            let port = u16::try_from(*port).ok().filter(|p| *p > 0).ok_or_else(|| format!("{port} is not a port"))?;
            match proto.as_str() {
                "tcp" => Ok(Port::tcp(port)),
                "udp" => Ok(Port::udp(port)),
                other => Err(format!("{other} is not tcp or udp")),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_and_host_ports_are_kept_to_private_sources() {
        let text = rules(&[Port::udp(51820), Port::tcp(25565), Port::udp(51820)]);
        assert!(text.contains("add rule inet gryonixnexus_home_only input udp dport { 51820 } ip saddr != { 10.0.0.0/8"), "{text}");
        assert!(text.contains("forward ct status dnat meta l4proto tcp ct original proto-dst { 25565 } ip6 saddr != { fc00::/7"));
        assert_eq!(text.matches("drop\n").count(), 8);
        assert!(text.starts_with("# Managed by gryonixNexus: home-only ports.\nadd table inet gryonixnexus_home_only\nflush table"));
        assert_eq!(rules(&[]), "");
    }

    #[test]
    fn bad_ports_are_refused() {
        assert!(parse(&[("sctp".into(), 1)]).is_err());
        assert!(parse(&[("tcp".into(), 70000)]).is_err());
        assert_eq!(parse(&[("udp".into(), 53)]).unwrap(), vec![Port::udp(53)]);
    }
}
