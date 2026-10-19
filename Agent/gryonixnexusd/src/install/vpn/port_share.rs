//! AmneziaWG on the WireGuard port; first bytes pick the server.

use super::panel::Protocol;
use crate::install::context::Input;
use crate::install::firewall;

/// The drop-in's label: `gryonixnexus-svc-vpn-share.nft`
pub const LABEL: &str = "vpn-share";

/// The table the drop-in owns
pub const TABLE: &str = "inet gryonixnexus_vpn_share";

/// The port AmneziaWG shares, when WireGuard runs beside it
pub fn shared_port(input: &Input, protocols: &[Protocol]) -> Option<u16> {
    let both = protocols.contains(&Protocol::WireGuard) && protocols.contains(&Protocol::AmneziaWG);
    (both && input.wireguard_vpn_port != input.amnezia_wg_port).then_some(input.wireguard_vpn_port)
}

/// WireGuard's own packets stay; every other flow moves to AmneziaWG
pub fn drop_in(wireguard_port: u16, amnezia_port: u16) -> String {
    format!(
        "# Managed by gryonixNexus: AmneziaWG answers on the WireGuard port.\n\
         # WireGuard packets start with type 1-4 and three zeros.\n\
         table {TABLE}\n\
         delete table {TABLE}\n\
         table {TABLE} {{\n\
         \x20   chain prerouting {{\n\
         \x20       type nat hook prerouting priority dstnat - 10; policy accept;\n\
         \x20       udp dport {wireguard_port} @th,64,32 != {{ 0x01000000, 0x02000000, 0x03000000, 0x04000000 }} \
         redirect to :{amnezia_port}\n\
         \x20   }}\n\
         }}\n"
    )
}

/// Writes or clears the drop-in to match the installed protocols
pub async fn apply(input: &Input, protocols: &[Protocol]) -> Result<bool, String> {
    match shared_port(input, protocols) {
        Some(port) => {
            firewall::apply_rules(LABEL, &drop_in(port, input.amnezia_wg_port)).await?;
            Ok(true)
        }
        None => {
            clear().await?;
            Ok(false)
        }
    }
}

/// Removes the drop-in and its live table
pub async fn clear() -> Result<(), String> {
    firewall::apply_rules(LABEL, "").await?;
    let _ = tokio::process::Command::new(firewall::nft_bin())
        .args(["delete", "table", "inet", "gryonixnexus_vpn_share"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        Input { wireguard_vpn_port: 51821, amnezia_wg_port: 51822, ..Input::default() }
    }

    #[test]
    fn the_port_is_shared_only_with_both_protocols() {
        let both = [Protocol::WireGuard, Protocol::AmneziaWG];
        assert_eq!(shared_port(&input(), &both), Some(51821));
        assert_eq!(shared_port(&input(), &[Protocol::AmneziaWG]), None);
        assert_eq!(shared_port(&input(), &[Protocol::WireGuard]), None);
        let same = Input { amnezia_wg_port: 51821, ..input() };
        assert_eq!(shared_port(&same, &both), None);
    }

    #[test]
    fn the_drop_in_replaces_its_own_table_and_moves_other_flows() {
        let text = drop_in(51821, 51822);
        assert!(text.starts_with("# Managed by gryonixNexus"));
        assert!(text.contains("table inet gryonixnexus_vpn_share\ndelete table inet gryonixnexus_vpn_share\n"));
        assert!(text.contains(
            "udp dport 51821 @th,64,32 != { 0x01000000, 0x02000000, 0x03000000, 0x04000000 } redirect to :51822\n"
        ));
        assert!(text.contains("priority dstnat - 10;"));
    }
}
