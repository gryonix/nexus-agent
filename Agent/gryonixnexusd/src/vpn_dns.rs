//! This server's AdGuard Home or Pi-hole as DNS for VPN devices.
//!
//! Devices ask one constant address. Every protocol container sends it
//! to the host, where nftables turns it into the relay's local port.
//! Nothing about it is reachable from the internet.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::install::{firewall, firewall_relay};
use crate::vpn_dns_priority as priority;
use crate::vpn_dns_relay::{self, Resolvers};

/// The address devices are given
pub const ADDRESS: &str = "10.53.0.53";

/// The port the relay listens on
pub const RELAY_PORT: u16 = 10053;

/// Catalog services that can answer for VPN devices
pub const RESOLVERS: [&str; 2] = ["adguard-home", "pihole"];

/// The drop-in's label: `gryonixnexus-svc-vpn-dns.nft`
pub const LABEL: &str = "vpn-dns";

const TABLE: &str = "inet gryonixnexus_vpn_dns";
const RECHECK: Duration = Duration::from_secs(300);
const REPORT_EVERY: Duration = Duration::from_secs(60);

static READY: AtomicBool = AtomicBool::new(false);
static ORDER: OnceLock<Arc<Resolvers>> = OnceLock::new();
static BRIDGE: OnceLock<Arc<Resolvers>> = OnceLock::new();
static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// The home bridge's firewall drop-in label
pub const BRIDGE_LABEL: &str = "vpn-dns-bridge";

/// Docker bridges only: the default one and compose networks
const BRIDGES: [&str; 2] = ["docker0", "br-*"];

/// Bridges reach the relay through the address; nothing else does
pub fn drop_in() -> String {
    let mut redirects = String::new();
    let mut accepts = String::new();
    for bridge in BRIDGES {
        for proto in ["udp", "tcp"] {
            redirects.push_str(&format!(
                "\x20       iifname \"{bridge}\" ip daddr {ADDRESS} {proto} dport 53 redirect to :{RELAY_PORT}\n"
            ));
            accepts.push_str(&format!(
                "add rule {} {} iifname \"{bridge}\" {proto} dport {RELAY_PORT} accept comment \"{LABEL}\"\n",
                firewall::TABLE,
                firewall::CHAIN
            ));
        }
    }
    format!(
        "# Managed by gryonixNexus: VPN devices reach this server's DNS.\n\
         table {TABLE}\n\
         delete table {TABLE}\n\
         table {TABLE} {{\n\
         \x20   chain prerouting {{\n\
         \x20       type nat hook prerouting priority dstnat - 10; policy accept;\n\
         {redirects}\
         \x20   }}\n\
         }}\n\
         {accepts}"
    )
}

/// True once the relay listens and the firewall carries it
pub fn ready() -> bool {
    READY.load(Ordering::Relaxed)
}

/// Does this DNS list point at the local resolver?
pub fn names_local(dns: &[String]) -> bool {
    dns.iter().any(|address| address.trim() == ADDRESS)
}

/// Installed resolvers, only when devices can reach them
pub async fn local_services() -> Vec<String> {
    if !ready() {
        return Vec::new();
    }
    let Ok(projects) = crate::discover::installed_projects().await else { return Vec::new() };
    resolvers_among(projects.iter().map(|project| project.service_id))
}

/// Catalog ids that are resolvers, once each, in catalog order
pub fn resolvers_among<'a>(ids: impl Iterator<Item = &'a str>) -> Vec<String> {
    let ids: Vec<&str> = ids.collect();
    RESOLVERS.iter().filter(|id| ids.contains(*id)).map(|id| id.to_string()).collect()
}

/// Starts and keeps up the relay and the home bridge
pub fn spawn() {
    tokio::spawn(async {
        let (mut bound, mut bridged) = (false, false);
        loop {
            bound = reconcile(bound).await;
            bridged = reconcile_bridge(bridged).await;
            tokio::select! {
                _ = tokio::time::sleep(RECHECK) => {}
                _ = WAKE.notified() => {}
            }
        }
    });
}

/// Checks again now, after an install changed this machine
pub fn wake() {
    WAKE.notify_one();
}

/// Lets a running XRay reach the resolver relay
async fn allow_through_xray() {
    use crate::install::vpn::protocols::xray;
    let format = format!("{{{{range .Mounts}}}}{{{{if eq .Destination \"{}\"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}", xray::CONTAINER_CONFIG_DIR);
    let Ok(output) = tokio::process::Command::new(crate::install::execute::docker_bin())
        .args(["inspect", "--format", &format, xray::CONTAINER])
        .output()
        .await
    else {
        return;
    };
    let source = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || source.is_empty() {
        return;
    }
    match crate::install::execute::allow_vpn_dns_through_xray(&std::path::Path::new(&source).join("config.json")) {
        Ok(true) => {
            let _ = tokio::process::Command::new(crate::install::execute::docker_bin())
                .args(["restart", xray::CONTAINER])
                .output()
                .await;
        }
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not let XRay reach the VPN DNS relay"),
    }
}

async fn reconcile(bound: bool) -> bool {
    let firewalled = std::path::Path::new(&firewall::drop_in_dir_display()).is_dir();
    if !firewalled || !crate::vpn_clients::services_path().exists() {
        READY.store(false, Ordering::Relaxed);
        if let Err(err) = clear().await {
            tracing::warn!(%err, "could not remove the VPN DNS firewall rules");
        }
        return bound;
    }
    refresh().await;
    allow_through_xray().await;
    let bound = bound || start(RELAY_PORT, resolvers()).await;
    let applied = bound && apply().await;
    READY.store(applied, Ordering::Relaxed);
    bound
}

fn resolvers() -> Arc<Resolvers> {
    ORDER.get_or_init(|| Resolvers::new(Vec::new())).clone()
}

/// Re-reads the order and where `local` leads
pub async fn refresh() {
    resolvers().set(current_order(local_resolver().await));
}

/// The saved order as sockets, never empty
pub fn current_order(local: Option<SocketAddr>) -> Vec<SocketAddr> {
    let order = priority::sockets(&priority::load(), local);
    if order.is_empty() { priority::sockets(&["1.1.1.1".to_string()], None) } else { order }
}

/// This machine's resolver, else the home machine's bridge
async fn local_resolver() -> Option<SocketAddr> {
    if installed_resolver().await {
        Some(vpn_dns_relay::LOOPBACK_RESOLVER)
    } else {
        priority::home_bridge()
    }
}

async fn installed_resolver() -> bool {
    let Ok(projects) = crate::discover::installed_projects().await else { return false };
    !resolvers_among(projects.iter().map(|project| project.service_id)).is_empty()
}

/// Per resolver of the order: whether it answered lately
pub async fn reachability() -> (bool, Vec<bool>) {
    let local = local_resolver().await;
    let relay = resolvers();
    let reachable = priority::load()
        .iter()
        .map(|entry| match priority::sockets(std::slice::from_ref(entry), local).first() {
            Some(server) => relay.reachable(*server),
            None => false,
        })
        .collect();
    (local.is_some(), reachable)
}

async fn start(port: u16, resolvers: Arc<Resolvers>) -> bool {
    match vpn_dns_relay::bind(port).await {
        Ok((udp, tcp)) => {
            tokio::spawn(vpn_dns_relay::serve_udp(udp, resolvers.clone()));
            tokio::spawn(vpn_dns_relay::serve_tcp(tcp, resolvers.clone()));
            tokio::spawn(report_trouble(port, resolvers));
            true
        }
        Err(err) => {
            tracing::warn!(%err, port, "the VPN DNS relay could not listen");
            false
        }
    }
}

/// Once a minute, what went wrong, for the journal
async fn report_trouble(port: u16, resolvers: Arc<Resolvers>) {
    let name = if port == RELAY_PORT { "VPN DNS relay" } else { "home DNS bridge" };
    loop {
        tokio::time::sleep(REPORT_EVERY).await;
        if let Some(tally) = resolvers.report() {
            tracing::warn!(relay = name, "DNS trouble in the last minute: {}", tally.line());
        }
    }
}

/// A home machine lends its resolver to the relay
async fn reconcile_bridge(bound: bool) -> bool {
    let tunnelled = std::path::Path::new("/etc/wireguard").join(format!("{}.conf", firewall_relay::WG_INTERFACE));
    let firewalled = std::path::Path::new(&firewall::drop_in_dir_display()).is_dir();
    if !firewalled || !tunnelled.exists() || priority::home_bridge().is_some() || !installed_resolver().await {
        if firewall::drop_in_path(BRIDGE_LABEL).exists() {
            let _ = firewall::apply_rules(BRIDGE_LABEL, "").await;
        }
        return bound;
    }
    let bridge = BRIDGE.get_or_init(|| Resolvers::new(vec![vpn_dns_relay::LOOPBACK_RESOLVER])).clone();
    if !bound {
        prepare_for(&[ADDRESS.to_string()]);
    }
    let bound = bound || start(priority::BRIDGE_PORT, bridge).await;
    if bound {
        if let Err(err) = firewall::apply_rules(BRIDGE_LABEL, &bridge_drop_in()).await {
            tracing::warn!(%err, "could not open the resolver bridge to the tunnel");
        }
    }
    bound
}

/// The tunnel, and only the tunnel, reaches the bridge
pub fn bridge_drop_in() -> String {
    ["udp", "tcp"]
        .iter()
        .map(|proto| {
            format!(
                "add rule {} {} iifname \"{}\" {proto} dport {} accept comment \"{BRIDGE_LABEL}\"\n",
                firewall::TABLE,
                firewall::CHAIN,
                firewall_relay::WG_INTERFACE,
                priority::BRIDGE_PORT
            )
        })
        .collect()
}

async fn apply() -> bool {
    match firewall::apply_rules(LABEL, &drop_in()).await {
        Ok(firewall::Outcome::Applied) => true,
        Ok(_) => false,
        Err(err) => {
            tracing::warn!(%err, "could not apply the VPN DNS firewall rules");
            false
        }
    }
}

async fn clear() -> Result<(), String> {
    if !firewall::drop_in_path(LABEL).exists() {
        return Ok(());
    }
    firewall::apply_rules(LABEL, "").await?;
    let _ = tokio::process::Command::new(firewall::nft_bin())
        .args(["delete", "table", "inet", "gryonixnexus_vpn_dns"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    Ok(())
}

/// AdGuard's per-client limit, lifted: every device arrives as one
pub fn patch_ratelimit(yaml: &str) -> Option<String> {
    let mut changed = false;
    let lines: Vec<String> = yaml
        .lines()
        .map(|line| {
            let indent = line.len() - line.trim_start().len();
            let rest = &line[indent..];
            match rest.strip_prefix("ratelimit: ") {
                Some(value) if value.trim() != "0" => {
                    changed = true;
                    format!("{}ratelimit: 0", &line[..indent])
                }
                _ => line.to_string(),
            }
        })
        .collect();
    let mut out = lines.join("\n");
    if yaml.ends_with('\n') {
        out.push('\n');
    }
    changed.then_some(out)
}

/// Readies the local resolver once devices are pointed at it
pub fn prepare_for(dns: &[String]) {
    if !names_local(dns) {
        return;
    }
    tokio::spawn(async {
        if let Err(err) = lift_adguard_ratelimit().await {
            tracing::warn!(%err, "could not lift AdGuard Home's rate limit");
        }
    });
}

async fn lift_adguard_ratelimit() -> Result<(), String> {
    let projects = crate::discover::installed_projects().await.map_err(|err| err.to_string())?;
    let Some(adguard) = projects.iter().find(|project| project.service_id == "adguard-home") else {
        return Ok(());
    };
    let path = adguard.directory.join("conf/AdGuardHome.yaml");
    let yaml = std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    let Some(patched) = patch_ratelimit(&yaml) else { return Ok(()) };
    std::fs::write(&path, patched).map_err(|err| format!("{}: {err}", path.display()))?;
    let args = crate::install::execute::compose_restart_args(&adguard.project, &adguard.directory);
    let status = tokio::process::Command::new(crate::install::execute::docker_bin())
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map_err(|err| err.to_string())?;
    status.success().then_some(()).ok_or_else(|| format!("docker compose restart exited with {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_drop_in_redirects_only_bridge_traffic_to_the_address() {
        let text = drop_in();
        assert!(text.starts_with("# Managed by gryonixNexus"));
        assert!(text.contains("table inet gryonixnexus_vpn_dns\ndelete table inet gryonixnexus_vpn_dns\n"));
        assert!(text.contains("priority dstnat - 10;"), "before docker's own DNAT: {text}");
        for bridge in ["docker0", "br-*"] {
            for proto in ["udp", "tcp"] {
                let redirect =
                    format!("iifname \"{bridge}\" ip daddr 10.53.0.53 {proto} dport 53 redirect to :10053\n");
                assert!(text.contains(&redirect), "{text}");
                let accept = format!(
                    "add rule inet filter gryonixnexus_services iifname \"{bridge}\" {proto} dport 10053 accept comment \"vpn-dns\"\n"
                );
                assert!(text.contains(&accept), "{text}");
            }
        }
        assert_eq!(text.matches("accept comment").count(), 4, "nothing opens without a bridge: {text}");
        assert!(!text.contains("dnat to"), "a plain host stays a single host: {text}");
    }

    #[test]
    fn only_the_tunnel_reaches_the_resolver_bridge() {
        let text = bridge_drop_in();
        for proto in ["udp", "tcp"] {
            let rule = format!(
                "add rule inet filter gryonixnexus_services iifname \"wg0\" {proto} dport 10054 accept comment \"vpn-dns-bridge\"\n"
            );
            assert!(text.contains(&rule), "{text}");
        }
        assert_eq!(text.lines().count(), 2, "{text}");
    }

    #[test]
    fn an_order_that_leads_nowhere_still_asks_cloudflare() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!("vpn-dns-order-{}", std::process::id()));
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &dir);
        priority::save(&["local".to_string()]).unwrap();
        assert_eq!(current_order(None), vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()]);
        let loopback = vpn_dns_relay::LOOPBACK_RESOLVER;
        assert_eq!(current_order(Some(loopback)), vec![loopback]);
        std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_address_is_private_and_the_label_fits_the_include_glob() {
        let address: std::net::Ipv4Addr = ADDRESS.parse().unwrap();
        assert!(address.is_private());
        let name = firewall::drop_in_path(LABEL).file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name, "gryonixnexus-svc-vpn-dns.nft");
    }

    #[test]
    fn a_dns_list_names_the_local_resolver_by_its_address() {
        assert!(names_local(&["10.53.0.53".to_string()]));
        assert!(names_local(&["1.1.1.1".to_string(), " 10.53.0.53".to_string()]));
        assert!(!names_local(&["1.1.1.1".to_string()]));
        assert!(!names_local(&[]));
    }

    #[test]
    fn only_resolvers_are_offered_once_each_in_catalog_order() {
        let ids = ["vpn-panel", "pihole", "nextcloud", "adguard-home", "pihole"];
        assert_eq!(resolvers_among(ids.into_iter()), vec!["adguard-home", "pihole"]);
        assert!(resolvers_among(["wireguard-vpn"].into_iter()).is_empty());
    }

    #[test]
    fn adguards_rate_limit_is_lifted_and_its_neighbours_are_left_alone() {
        let yaml = "dns:\n  bind_hosts:\n    - 0.0.0.0\n  ratelimit: 20\n  ratelimit_subnet_len_ipv4: 24\n  ratelimit_whitelist: []\n";
        let patched = patch_ratelimit(yaml).unwrap();
        assert_eq!(
            patched,
            "dns:\n  bind_hosts:\n    - 0.0.0.0\n  ratelimit: 0\n  ratelimit_subnet_len_ipv4: 24\n  ratelimit_whitelist: []\n"
        );
        assert_eq!(patch_ratelimit(&patched), None, "already lifted");
        assert_eq!(patch_ratelimit("dns:\n  port: 53\n"), None);
    }
}
