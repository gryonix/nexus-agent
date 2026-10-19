use std::net::Ipv4Addr;

/// Mailu's compose network, kept across reinstalls
const OWN_NETWORK: &str = "mailu_default";

/// Ranges tried after a taken one, outside Docker's pools
const FALLBACKS: std::ops::RangeInclusive<u8> = 29..=60;

/// An IPv4 range as network bits and mask
fn range(text: &str) -> Option<(u32, u32)> {
    let (address, prefix) = text.trim().split_once('/')?;
    let address: Ipv4Addr = address.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some((u32::from(address) & mask, mask))
}

fn overlaps(a: (u32, u32), b: (u32, u32)) -> bool {
    let mask = a.1 & b.1;
    a.0 & mask == b.0 & mask
}

pub fn choose(wanted: &str, networks: &str, routes: &str) -> Option<String> {
    let mut taken = Vec::new();
    for line in networks.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        let subnets: Vec<&str> = fields.collect();
        if name == OWN_NETWORK {
            if let Some(own) = subnets.iter().find(|s| range(s).is_some()) {
                return Some((*own).to_string());
            }
        }
        taken.extend(subnets.iter().filter_map(|s| range(s)));
    }
    let docker_bridge = |line: &str| line.contains(" dev br-") || line.contains(" dev docker0");
    for line in routes.lines().filter(|line| !docker_bridge(line)) {
        if let Some(route) = line.split_whitespace().next().and_then(range) {
            if route.1 != 0 {
                taken.push(route);
            }
        }
    }
    let free = |candidate: &str| range(candidate).is_some_and(|c| !taken.iter().any(|t| overlaps(c, *t)));
    if free(wanted) {
        return Some(wanted.to_string());
    }
    FALLBACKS.map(|third| format!("10.254.{third}.0/24")).find(|candidate| free(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTES: &str = "default via 192.168.178.1 dev eth0\n192.168.178.0/24 dev eth0 proto kernel\n\
                          10.8.0.0/24 dev wg0 proto kernel\n172.29.0.0/16 dev br-1a2b proto kernel\n";

    #[test]
    fn a_free_wanted_subnet_is_kept() {
        assert_eq!(choose("10.254.29.0/24", "bridge 172.17.0.0/16\n", ROUTES).as_deref(), Some("10.254.29.0/24"));
    }

    #[test]
    fn a_subnet_taken_by_docker_moves_to_the_first_free_one() {
        let networks = "adguardhome_default 172.29.0.0/16\nx 10.254.30.0/24\n";
        assert_eq!(choose("172.29.0.0/24", networks, ROUTES).as_deref(), Some("10.254.29.0/24"));
        let busy = "a 10.254.29.0/24\nb 10.254.30.0/24\n";
        assert_eq!(choose("10.254.29.0/24", busy, ROUTES).as_deref(), Some("10.254.31.0/24"));
    }

    #[test]
    fn the_home_network_counts_and_the_default_route_does_not() {
        assert_eq!(choose("192.168.178.0/24", "", ROUTES).as_deref(), Some("10.254.29.0/24"));
        assert_eq!(choose("10.8.0.128/25", "", ROUTES).as_deref(), Some("10.254.29.0/24"));
    }

    #[test]
    fn a_reinstall_keeps_mailus_own_network() {
        let networks = "mailu_default 172.29.0.0/24\nadguardhome_default 172.29.0.0/16\n";
        assert_eq!(choose("10.254.29.0/24", networks, ROUTES).as_deref(), Some("172.29.0.0/24"));
    }
}
