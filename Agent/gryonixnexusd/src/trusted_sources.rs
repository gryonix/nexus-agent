//! The pair's own addresses and the VPN, never banned or penalised

use std::path::Path;

pub const SSHD_DROP_IN: &str = "/etc/ssh/sshd_config.d/60-gryonixnexus-tunnel.conf";
pub const RELAY_ADDRESS: &str = "10.8.0.1";
const RELAY_SUBNET: &str = "10.8.0.0/24";
/// VPN clients that reach the home host through the relay
const RELAY_HAIRPIN: &str = "10.8.0.254/32";
/// WireGuard panel, AmneziaWG, OpenVPN, tailnet
const VPN_SUBNETS: [&str; 4] = ["10.9.0.0/24", "10.10.0.0/24", "10.11.0.0/24", "100.64.0.0/10"];
/// Home network and the containerised VPN protocols
const LOCAL_RANGES: [&str; 2] = ["192.168.0.0/16", "172.16.0.0/12"];
/// Comments marking entries this agent may also take away
pub const OWN_COMMENTS: [&str; 2] = ["gryonixNexus trusted source", "WireGuard peer of this host"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Relay,
    Home,
    Single,
}

/// Which end of the pair tunnel this host is
pub fn role(tunnel_address: Option<&str>) -> Role {
    match tunnel_address {
        Some(RELAY_ADDRESS) => Role::Relay,
        Some(_) => Role::Home,
        None => Role::Single,
    }
}

/// Every source this host trusts, peers first
pub fn trusted(role: Role, peers: &[String]) -> Vec<String> {
    let mut list: Vec<String> = peers.to_vec();
    let relay: &[&str] = match role {
        Role::Relay => &[RELAY_SUBNET],
        Role::Home => &[RELAY_HAIRPIN],
        Role::Single => &[],
    };
    for range in relay.iter().chain(&VPN_SUBNETS).chain(&LOCAL_RANGES) {
        if !list.iter().any(|known| known == range) {
            list.push(range.to_string());
        }
    }
    list
}

pub fn sshd_drop_in(list: &[String]) -> String {
    format!("# Managed by gryonixNexus.\nPerSourcePenaltyExemptList {}\n", list.join(","))
}

/// This host's address on the pair tunnel, if any
pub fn tunnel_address(ip_output: &str) -> Option<String> {
    ip_output
        .split_whitespace()
        .skip_while(|word| *word != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .map(String::from)
}

/// Whether the drop-in on disk already says `wanted`
pub fn sshd_exemption_current(path: &Path, list: &[String]) -> bool {
    std::fs::read_to_string(path).ok().as_deref() == Some(sshd_drop_in(list).as_str())
}

/// Shell that writes the drop-in, checks sshd and reloads it
pub fn sshd_exemption_script(path: &str, list: &[String]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(sshd_drop_in(list));
    format!(
        "set -u\n\
         F='{path}'\n\
         mkdir -p \"$(dirname \"$F\")\"\n\
         rm -f \"$F.gnx-old\"\n\
         [ -f \"$F\" ] && cp -p \"$F\" \"$F.gnx-old\"\n\
         printf '%s' '{body}' | base64 -d > \"$F.gnx-new\" && mv \"$F.gnx-new\" \"$F\" || exit 4\n\
         if sshd -t; then\n\
         \x20 rm -f \"$F.gnx-old\"\n\
         \x20 systemctl reload ssh 2>/dev/null || systemctl reload sshd\n\
         \x20 exit 0\n\
         fi\n\
         if [ -f \"$F.gnx-old\" ]; then mv \"$F.gnx-old\" \"$F\"; else rm -f \"$F\"; fi\n\
         exit 3\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_home_host_never_trusts_the_whole_relay_subnet() {
        let list = trusted(Role::Home, &["203.0.113.150".to_string()]);
        assert_eq!(list[0], "203.0.113.150");
        assert!(list.contains(&"10.8.0.254/32".to_string()));
        assert!(!list.contains(&"10.8.0.0/24".to_string()), "relayed visitors arrive from 10.8.0.x");
        assert!(list.contains(&"10.9.0.0/24".to_string()));
    }

    #[test]
    fn the_relay_trusts_the_tunnel_and_the_home_address() {
        let list = trusted(Role::Relay, &["198.51.100.240".to_string()]);
        assert!(list.contains(&"198.51.100.240".to_string()));
        assert!(list.contains(&"10.8.0.0/24".to_string()));
        assert!(!list.iter().any(|entry| entry == "0.0.0.0/0"));
    }

    #[test]
    fn a_lone_host_trusts_only_its_vpn_and_local_ranges() {
        let list = trusted(Role::Single, &[]);
        assert!(!list.iter().any(|entry| entry.starts_with("10.8.")));
        assert_eq!(list.len(), VPN_SUBNETS.len() + LOCAL_RANGES.len());
    }

    #[test]
    fn the_tunnel_address_is_read_from_ip_output() {
        let text = "5: wg0    inet 10.8.0.1/24 scope global wg0 valid_lft forever";
        assert_eq!(tunnel_address(text).as_deref(), Some("10.8.0.1"));
        assert_eq!(role(tunnel_address(text).as_deref()), Role::Relay);
        assert_eq!(role(Some("10.8.0.2")), Role::Home);
        assert_eq!(tunnel_address(""), None);
    }

    #[test]
    fn the_drop_in_names_every_source_once() {
        let text = sshd_drop_in(&["1.2.3.4".to_string(), "10.9.0.0/24".to_string()]);
        assert_eq!(text.lines().last(), Some("PerSourcePenaltyExemptList 1.2.3.4,10.9.0.0/24"));
        let dir = std::env::temp_dir().join(format!("gnx-trusted-{}", std::process::id()));
        let path = dir.join("60.conf");
        assert!(!sshd_exemption_current(&path, &["1.2.3.4".to_string()]));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, sshd_drop_in(&["1.2.3.4".to_string()])).unwrap();
        assert!(sshd_exemption_current(&path, &["1.2.3.4".to_string()]));
        assert!(!sshd_exemption_current(&path, &["5.6.7.8".to_string()]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_script_writes_the_drop_in_and_puts_the_old_one_back_if_sshd_refuses() {
        let dir = std::env::temp_dir().join(format!("gnx-trusted-script-{}", std::process::id()));
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let path = dir.join("sshd_config.d/60.conf");
        let run = |sshd_ok: bool| {
            let verdict = if sshd_ok { "exit 0" } else { "exit 1" };
            std::fs::write(bin.join("sshd"), format!("#!/bin/sh\n{verdict}\n")).unwrap();
            std::fs::write(bin.join("systemctl"), "#!/bin/sh\nexit 0\n").unwrap();
            for tool in ["sshd", "systemctl"] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(bin.join(tool), std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let script = sshd_exemption_script(path.to_str().unwrap(), &["1.2.3.4".to_string()]);
            let path_var = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
            std::process::Command::new("/bin/sh").args(["-c", &script]).env("PATH", path_var).status().unwrap()
        };
        assert!(run(true).success());
        assert!(sshd_exemption_current(&path, &["1.2.3.4".to_string()]));
        std::fs::write(&path, "# earlier\n").unwrap();
        assert_eq!(run(false).code(), Some(3));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# earlier\n");
        assert!(!dir.join("sshd_config.d/60.conf.gnx-old").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
