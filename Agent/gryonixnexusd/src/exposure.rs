//! Read-only checks of what the internet can reach, and Caddy's local root CA.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use hyper::StatusCode;
use tokio::net::TcpStream;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PORTS: usize = 64;
const ROOT_CA_PATH: &str = "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt";

fn root_ca_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_LOCAL_ROOT_CA").unwrap_or_else(|_| ROOT_CA_PATH.to_string()))
}

/// Global addresses this machine owns, IPv4 first
fn own_global_addresses(ip_output: &str) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = ip_output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3))
        .filter_map(|cidr| cidr.split('/').next())
        .filter_map(|text| text.parse::<IpAddr>().ok())
        .collect();
    found.sort_by_key(|address| address.is_ipv6());
    found
}

async fn global_addresses() -> Vec<IpAddr> {
    let output = tokio::process::Command::new("ip")
        .args(["-o", "addr", "show", "scope", "global"])
        .output()
        .await
        .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
        .unwrap_or_default();
    own_global_addresses(&output)
}

/// Ports named by destination-NAT rules in an nft listing
fn dnat_ports(ruleset: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in ruleset.lines().filter(|line| line.contains("dnat")) {
        let Some(at) = line.find("dport") else { continue };
        let spec = line[at + 5..].split("dnat").next().unwrap_or("");
        for token in spec.split(|c: char| !c.is_ascii_digit() && c != '-').filter(|t| !t.is_empty()) {
            match token.split_once('-') {
                Some((low, high)) => {
                    let (Ok(low), Ok(high)) = (low.parse::<u16>(), high.parse::<u16>()) else { continue };
                    ports.extend(low..=high.min(low.saturating_add(1024)));
                }
                None => ports.extend(token.parse::<u16>().ok()),
            }
        }
    }
    ports
}

async fn forwarded_ports() -> Vec<u16> {
    let output = tokio::process::Command::new("nft").args(["list", "ruleset"]).output().await;
    output.map(|out| dnat_ports(&String::from_utf8_lossy(&out.stdout))).unwrap_or_default()
}

async fn connects(address: IpAddr, port: u16) -> bool {
    let attempt = TcpStream::connect(SocketAddr::new(address, port));
    matches!(tokio::time::timeout(CONNECT_TIMEOUT, attempt).await, Ok(Ok(_)))
}

fn target_address(host: &str, own: &[IpAddr]) -> Result<IpAddr, String> {
    match host.parse::<IpAddr>() {
        Ok(address) if own.contains(&address) => Ok(address),
        Ok(_) => Err("host is not an address of this server".to_string()),
        Err(_) => own.first().copied().ok_or_else(|| "this server has no public address".to_string()),
    }
}

fn validated_ports(ports: &[u32]) -> Result<Vec<u16>, String> {
    if ports.is_empty() || ports.len() > MAX_PORTS {
        return Err(format!("between 1 and {MAX_PORTS} ports"));
    }
    ports.iter().map(|p| u16::try_from(*p).ok().filter(|p| *p != 0).ok_or_else(|| format!("{p} is not a port"))).collect()
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

/// Which of the requested ports answer on the public address
pub async fn probe_public_ports(codec: Codec, req: pb::ProbePublicPortsRequest) -> Resp {
    let ports = match validated_ports(&req.ports) {
        Ok(ports) => ports,
        Err(why) => return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &why),
    };
    let own = global_addresses().await;
    let address = match target_address(req.host.trim(), &own) {
        Ok(address) => address,
        Err(why) => return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &why),
    };
    let forwarded = forwarded_ports().await;
    let mut probes = Vec::new();
    for port in ports {
        let open = forwarded.contains(&port) || connects(address, port).await;
        probes.push(pb::PortProbe { port: u32::from(port), open });
    }
    encode(codec, &pb::ProbePublicPortsResponse { ports: probes })
}

/// Caddy's local root certificate, PEM
pub async fn get_local_root_ca(codec: Codec, _req: pb::GetLocalRootCaRequest) -> Resp {
    let pem = std::fs::read_to_string(root_ca_path()).unwrap_or_default();
    let pem = if pem.contains("BEGIN CERTIFICATE") { pem } else { String::new() };
    encode(codec, &pb::GetLocalRootCaResponse { pem })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_addresses_come_from_ip_output_ipv4_first() {
        let text = "2: eth0 inet6 2001:db8::5/64 scope global\n2: eth0 inet 203.0.113.5/24 brd x scope global eth0\n";
        let found = own_global_addresses(text);
        assert_eq!(found[0], "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn dnat_rules_name_their_ports() {
        let rules = "tcp dport 25 dnat to 10.8.0.2\n tcp dport { 80, 443 } dnat to 10.8.0.2\n udp dport 51820 accept\n tcp dport 8000-8002 dnat to 10.8.0.2";
        let ports = dnat_ports(rules);
        for port in [25, 80, 443, 8001] {
            assert!(ports.contains(&port), "{port}");
        }
        assert!(!ports.contains(&51820));
    }

    #[test]
    fn only_own_addresses_are_probed() {
        let own: Vec<IpAddr> = vec!["203.0.113.5".parse().unwrap()];
        assert!(target_address("198.51.100.9", &own).is_err());
        assert!(target_address("203.0.113.5", &own).is_ok());
        assert_eq!(target_address("example.net", &own).unwrap(), own[0]);
        assert!(target_address("example.net", &[]).is_err());
    }

    #[test]
    fn port_lists_are_bounded() {
        assert!(validated_ports(&[]).is_err());
        assert!(validated_ports(&[0]).is_err());
        assert!(validated_ports(&[70000]).is_err());
        assert_eq!(validated_ports(&[25, 443]).unwrap(), vec![25, 443]);
        assert!(validated_ports(&vec![80; 65]).is_err());
    }

    #[tokio::test]
    async fn an_open_local_port_connects_and_a_closed_one_does_not() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(connects(loopback, open).await);
        drop(listener);
        assert!(!connects(loopback, open).await);
    }
}
