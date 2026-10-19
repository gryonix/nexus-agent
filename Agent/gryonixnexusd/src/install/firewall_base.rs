//! The nftables ruleset itself, for a host that has none

use super::execute::EventSink;
use super::firewall;

/// Where the ruleset lives
pub fn conf_path() -> String {
    std::env::var("GRYONIXNEXUSD_NFTABLES_CONF").unwrap_or_else(|_| "/etc/nftables.conf".to_string())
}

pub const BASE_TCP_PORTS: [u16; 3] = [22, 80, 443];

pub fn ssh_throttle() -> String {
    ssh_throttle_for(&sshd_ports())
}

pub(crate) fn ssh_throttle_for(ports: &[u16]) -> String {
    let dport = match ports {
        [one] => one.to_string(),
        many => format!("{{ {} }}", many.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")),
    };
    format!(
        "\x20       tcp dport {dport} meter gryonixnexus_ssh_throttle4 {{ ip saddr timeout 60s limit rate 10/minute burst 5 packets }} accept comment \"SSH, per-source throttle\"\n\
         \x20       tcp dport {dport} meter gryonixnexus_ssh_throttle6 {{ ip6 saddr timeout 60s limit rate 10/minute burst 5 packets }} accept comment \"SSH, per-source throttle\"\n\
         \x20       tcp dport {dport} drop comment \"SSH: per-source rate exceeded\"\n"
    )
}

pub(crate) fn sshd_ports() -> Vec<u16> {
    if cfg!(test) {
        return vec![22];
    }
    let mut ports = vec![22];
    ports.extend(ports_in_config(std::path::Path::new("/etc/ssh/sshd_config"), 0));
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn ports_in_config(path: &std::path::Path, depth: u8) -> Vec<u16> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let mut ports = Vec::new();
    for line in text.lines().map(str::trim) {
        let mut words = line.split_whitespace();
        match (words.next().map(str::to_ascii_lowercase).as_deref(), words.next()) {
            (Some("match"), _) => break,
            (Some("port"), Some(port)) => ports.extend(port.parse::<u16>().ok()),
            (Some("include"), Some(pattern)) if depth < 2 => {
                for file in expand_include(pattern) {
                    ports.extend(ports_in_config(&file, depth + 1));
                }
            }
            _ => {}
        }
    }
    ports
}

/// Files an `Include` names: a plain path, or `dir/*.conf`
fn expand_include(pattern: &str) -> Vec<std::path::PathBuf> {
    let full = if pattern.starts_with('/') { pattern.to_string() } else { format!("/etc/ssh/{pattern}") };
    match full.rsplit_once('/') {
        Some((dir, name)) if name.contains('*') => {
            let suffix = name.trim_start_matches('*');
            let mut files: Vec<_> = std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.to_string_lossy().ends_with(suffix))
                .collect();
            files.sort();
            files
        }
        _ => vec![std::path::PathBuf::from(full)],
    }
}

/// A port of `NftablesConfig.homeDiscoveryRules`
pub const HOME_DISCOVERY_RULES: &str = concat!(
    "\x20       ip daddr { 224.0.0.251, 239.255.255.250 } udp dport { 5353, 1900 } accept comment \"home devices discovery\"\n",
    "\x20       ip6 daddr { ff02::fb, ff02::c } udp dport { 5353, 1900 } accept comment \"home devices discovery\"\n",
);

/// The ruleset this writes
pub fn ruleset(drop_in_dir: &str, home_discovery: bool) -> String {
    let discovery = if home_discovery { HOME_DISCOVERY_RULES } else { "" };
    let other_ports = BASE_TCP_PORTS
        .iter()
        .filter(|&&p| p != 22)
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "#!/usr/sbin/nft -f\n\
         # Managed by gryonixNexus — written by the control-plane agent.\n\
         #\n\
         # No `flush ruleset` here on purpose: it would erase docker's own NAT\n\
         # table and cut every container off the network. Only OUR table is\n\
         # replaced, which is what makes re-applying this safe.\n\
         #\n\
         # No forward chain either — docker manages forwarding on this host, and\n\
         # a policy of ours would drop its per-container accepts.\n\
         #\n\
         # Declaring a table before deleting it makes the pair\n\
         # idempotent on every nftables, 1.0.6 included.\n\
         table inet filter\n\
         delete table inet filter\n\
         table ip {nat_table}\n\
         delete table ip {nat_table}\n\
         \n\
         table inet filter {{\n\
         \x20   # Ports of services live in {drop_in_dir}, not here: they are\n\
         \x20   # written per service and flushed as a group.\n\
         \x20   chain {chain} {{\n\
         \x20   }}\n\
         \n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority filter; policy drop;\n\
         \x20       iif \"lo\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       ct state invalid drop\n\
         \x20       icmp type {{ destination-unreachable, echo-request, time-exceeded, parameter-problem }} limit rate 10/second burst 5 packets accept\n\
         \x20       meta l4proto ipv6-icmp accept\n\
{ssh_throttle}\
         \x20       tcp dport {{ {other_ports} }} accept comment \"HTTP/HTTPS for ACME\"\n\
{discovery}\
         \x20       jump {chain}\n\
         \x20   }}\n\
         }}\n\
         \n\
         include \"{drop_in_dir}/{glob}\"\n",
        ssh_throttle = ssh_throttle(),
        chain = firewall::CHAIN,
        glob = firewall::DROP_IN_GLOB,
        nat_table = super::firewall_relay::NAT_TABLE,
    )
}

/// Does this host already carry a gryonixNexus ruleset?
pub fn already_ours(conf: &str) -> bool {
    conf.contains(firewall::CHAIN) || conf.to_ascii_lowercase().contains("managed by gryonixnexus")
}

pub enum Plan {
    /// Scenario A, and the services host of a local-only deployment.
    SingleHost,
    HomeBackend(Option<super::firewall_relay::Topology>),
    Relay(super::firewall_relay::Topology),
}

/// The marker every file THIS module writes carries
const AGENT_MARKER: &str = "written by the control-plane agent";

/// Does this file already carry the shape its role needs?
fn has_role_shape(conf: &str, plan: &Plan) -> bool {
    match plan {
        Plan::SingleHost => !conf.contains("dnat to"),
        Plan::HomeBackend(_) => conf.contains("ct mark set"),
        Plan::Relay(_) => conf.contains("hook forward") && conf.contains("dnat to"),
    }
}

pub(super) async fn ensure_ruleset(home_discovery: bool, sink: &EventSink) {
    ensure(&Plan::SingleHost, home_discovery, sink).await
}

fn plays_a_relay_pair_role(conf: &str) -> bool {
    conf.contains("ct mark set") || conf.contains("dnat to")
}

/// The role-aware entry point.
pub(super) async fn ensure(plan: &Plan, home_discovery: bool, sink: &EventSink) {
    let conf = conf_path();
    let existing = std::fs::read_to_string(&conf).unwrap_or_default();
    if leaves_alone(plan, &existing, home_discovery, sink).await {
        return;
    }
    let Some(contents) = render_for(plan, home_discovery, sink).await else { return };
    let previous = std::fs::read_to_string(&conf).ok();
    if let Err(why) = write_conf(&conf, &contents, sink).await {
        let _ = sink.step(format!("WARNING: could not write the firewall ruleset: {why}")).await;
        return;
    }
    if let Err(why) = enable_service(sink).await {
        let _ = sink.step(format!("WARNING: the firewall ruleset was written but not applied: {why}")).await;
        restore_conf(&conf, previous.as_deref(), sink).await;
        return;
    }
    if matches!(plan, Plan::Relay(_)) {
        drop_script_relay_chains().await;
    }
    let _ = sink
        .step(match plan {
            Plan::SingleHost => "the base firewall is in force",
            Plan::HomeBackend(_) => "the home-half firewall is in force",
            Plan::Relay(_) => "the relay firewall is in force",
        })
        .await;
}

fn ours_and_stale(existing: &str, plan: &Plan, home_discovery: bool) -> bool {
    let differs = existing.contains(AGENT_MARKER) && !existing.is_empty() && {
        let dir = firewall::drop_in_dir_display();
        match plan {
            Plan::SingleHost => existing != ruleset(&dir, home_discovery),
            Plan::HomeBackend(topology) => {
                existing
                    != super::firewall_relay::home_ruleset(
                        &dir,
                        topology.as_ref().filter(|t| !t.all_tcp_ports().is_empty()),
                        home_discovery,
                    )
            }
            Plan::Relay(topology) => match topology.is_complete() {
                false => false,
                true => {
                    let ours = super::firewall_relay::relay_ruleset(topology, "", &dir);
                    rules_without_interface(existing) != rules_without_interface(&ours)
                }
            },
        }
    };
    differs || (already_ours(existing) && forwards_moved(existing, plan, home_discovery))
}

async fn leaves_alone(plan: &Plan, existing: &str, home_discovery: bool, sink: &EventSink) -> bool {
    if matches!(plan, Plan::SingleHost) && already_ours(existing) && plays_a_relay_pair_role(existing) {
        let _ = sink
            .step(
                concat!(
                    "left this host's firewall as it is: it is half of a relay pair, ",
                    "and installing a service does not change that — re-provision ",
                    "the server to rewrite its ruleset",
                ),
            )
            .await;
        return true;
    }
    if already_ours(existing) && has_role_shape(existing, plan) && !ours_and_stale(existing, plan, home_discovery) {
        if !matches!(plan, Plan::Relay(_)) && live_relay_nat_present().await {
            let _ = sink.step("removing the NAT table left over from this host's previous role").await;
            if let Err(why) = destroy_relay_nat().await {
                let _ = sink.step(format!("WARNING: could not remove it: {why}")).await;
            }
        }
        return true;
    }
    if !already_ours(existing) && !existing.trim().is_empty() && service_is_active().await {
        let _ = sink
            .step("this host has its own active nftables ruleset — leaving it alone; \
                   service ports will not be opened automatically")
            .await;
        return true;
    }
    home_would_lose_forwards(plan, existing, sink).await
}

async fn home_would_lose_forwards(plan: &Plan, existing: &str, sink: &EventSink) -> bool {
    let Plan::HomeBackend(topology) = plan else { return false };
    let asked_for_none = topology
        .as_ref()
        .map_or(true, |topo| topo.all_tcp_ports().is_empty() && topo.all_udp_ports().is_empty());
    let already = super::firewall_relay::tunnel_accepted_ports(existing);
    if !asked_for_none || already.is_empty() {
        return false;
    }
    let ports = already.iter().map(|port| port.to_string()).collect::<Vec<_>>().join(", ");
    let _ = sink
        .step(format!(
            "the firewall was left alone: this host accepts {ports} from the tunnel and this request names no forwarded ports, so rewriting it would stop everything the relay sends here — send the deployment's forwarded ports"
        ))
        .await;
    true
}

async fn render_for(plan: &Plan, home_discovery: bool, sink: &EventSink) -> Option<String> {
    let dir = firewall::drop_in_dir_display();
    match plan {
        Plan::SingleHost => {
            let _ = sink.step("writing the base nftables ruleset").await;
            Some(ruleset(&dir, home_discovery))
        }
        Plan::HomeBackend(topology) => {
            let _ = sink
                .step("writing the home-half nftables ruleset (relayed replies need a connection mark)")
                .await;
            Some(super::firewall_relay::home_ruleset(
                &dir,
                topology.as_ref().filter(|t| !t.all_tcp_ports().is_empty()),
                home_discovery,
            ))
        }
        Plan::Relay(topology) => render_relay(topology, &dir, sink).await,
    }
}

async fn render_relay(topology: &super::firewall_relay::Topology, dir: &str, sink: &EventSink) -> Option<String> {
    if !topology.is_complete() {
        let _ = sink
            .step(
                "this request carries no tunnel topology, so the relay's firewall was left \
                 untouched — a relay needs its tunnel port and DNAT rules, and the base \
                 ruleset would close them",
            )
            .await;
        return None;
    }
    let Some(public_interface) = super::firewall_relay::public_interface().await else {
        let _ = sink
            .step(
                "could not work out this host's public interface, so the relay's \
                 firewall was left untouched",
            )
            .await;
        return None;
    };
    let _ = sink
        .step(format!("writing the relay nftables ruleset (public interface {public_interface})"))
        .await;
    Some(super::firewall_relay::relay_ruleset(topology, &public_interface, dir))
}

fn forwards_moved(existing: &str, plan: &Plan, home_discovery: bool) -> bool {
    let dir = firewall::drop_in_dir_display();
    match plan {
        Plan::SingleHost => false,
        Plan::Relay(topology) => {
            topology.is_complete()
                && rules_without_interface(existing)
                    != rules_without_interface(&super::firewall_relay::relay_ruleset(topology, "", &dir))
        }
        Plan::HomeBackend(topology) => match topology.as_ref().filter(|t| !t.all_tcp_ports().is_empty()) {
            None => false,
            Some(topology) => {
                super::firewall_relay::tunnel_accepted_ports(existing)
                    != super::firewall_relay::tunnel_accepted_ports(&super::firewall_relay::home_ruleset(
                        &dir,
                        Some(topology),
                        home_discovery,
                    ))
            }
        },
    }
}

fn rules_without_interface(conf: &str) -> Vec<String> {
    conf.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty() && !line.starts_with("define pub_if"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

async fn live_relay_nat_present() -> bool {
    let output = tokio::process::Command::new(super::firewall::nft_bin())
        .args(["list", "tables"])
        .output()
        .await;
    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.split_whitespace().last() == Some(super::firewall_relay::NAT_TABLE)),
        _ => false,
    }
}

async fn drop_script_relay_chains() {
    for chain in ["prerouting", "postrouting"] {
        for verb in ["flush", "delete"] {
            let _ = tokio::process::Command::new(super::firewall::nft_bin())
                .args([verb, "chain", "ip", "nat", chain])
                .output()
                .await;
        }
    }
}

/// Drop the relay's NAT table from the LIVE ruleset
async fn destroy_relay_nat() -> Result<(), String> {
    // `add` then `delete`: nftables 1.0.6 has no `destroy`
    for verb in ["add", "delete"] {
        let output = tokio::process::Command::new(super::firewall::nft_bin())
            .args([verb, "table", "ip", super::firewall_relay::NAT_TABLE])
            .output()
            .await
            .map_err(|err| err.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
    }
    Ok(())
}

/// Is `nftables.service` actually running?
async fn service_is_active() -> bool {
    super::execute::run_quiet_public(&super::execute::systemctl_bin_public(), &["is-active", "nftables"])
        .await
        .is_ok()
}

async fn write_conf(path: &str, contents: &str, sink: &EventSink) -> Result<(), String> {
    let script = format!(
        "set -e\numask 022\ncat > '{path}' <<'GRYONIXNEXUS_NFT_EOF'\n{contents}GRYONIXNEXUS_NFT_EOF\nchmod 0755 '{path}'\n"
    );
    super::packages::run_outside_sandbox(&script, "writing the firewall ruleset", sink).await
}

async fn restore_conf(path: &str, previous: Option<&str>, sink: &EventSink) {
    let restored = match previous {
        Some(old) => write_conf(path, old, sink).await,
        None => super::packages::run_outside_sandbox(&format!("rm -f '{path}'"), "removing the refused ruleset", sink).await,
    };
    let note = if restored.is_ok() { "the previous firewall file was put back" } else { "WARNING: the refused ruleset could not be removed" };
    let _ = sink.step(note).await;
}

/// Gives an older home half its host masquerade, live
pub async fn refresh_home_masquerade() -> Result<bool, String> {
    let path = conf_path();
    let Ok(conf) = std::fs::read_to_string(&path) else { return Ok(false) };
    let sink = EventSink::detached();
    if let Some(fresh) = super::firewall_relay::with_host_masquerade(&conf) {
        write_conf(&path, &fresh, &sink).await?;
        if let Err(why) = enable_service(&sink).await {
            write_conf(&path, &conf, &sink).await?;
            return Err(why);
        }
        return Ok(true);
    }
    if conf.contains("meta mark 0x1 masquerade") && !masquerade_is_live().await {
        enable_service(&sink).await?;
        return Ok(true);
    }
    Ok(false)
}

async fn masquerade_is_live() -> bool {
    tokio::process::Command::new("nft")
        .args(["list", "chain", "inet", "filter", "postrouting"])
        .output()
        .await
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).contains("masquerade"))
        .unwrap_or(false)
}

async fn enable_service(sink: &EventSink) -> Result<(), String> {
    super::packages::run_outside_sandbox(
        // Never `restart`: its stop step flushes every table, docker's too.
        "set -e\nnft -c -f /etc/nftables.conf\nsystemctl enable nftables >/dev/null 2>&1 || true\n\
         if systemctl is-active --quiet nftables; then nft -f /etc/nftables.conf; else systemctl start nftables; fi",
        "applying the firewall ruleset",
        sink,
    )
    .await
}

#[cfg(test)]
mod relay_pair_guard_tests {
    use super::*;

    #[test]
    fn a_home_halfs_ruleset_is_recognised_as_a_role_an_install_must_not_take_away() {
        let home = "# Managed by gryonixNexus\n  ct state new iifname \"wg0\" ct mark set 0x00000001\n";
        assert!(plays_a_relay_pair_role(home));
    }

    #[test]
    fn a_relays_ruleset_is_too() {
        let relay = "# Managed by gryonixNexus\n  iifname \"ens6\" tcp dport 443 dnat to 10.8.0.2\n";
        assert!(plays_a_relay_pair_role(relay));
    }

    #[test]
    fn an_ordinary_single_host_is_not_locked_by_the_guard() {
        let dir = firewall::drop_in_dir_display();
        assert!(!plays_a_relay_pair_role(&ruleset(&dir, false)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_only(text: &str) -> String {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_ruleset_never_flushes_everything() {
        let rules = rules_only(&ruleset("/etc/nftables.d", false));
        assert!(!rules.contains("flush ruleset"), "flushing everything erases docker's NAT");
        assert!(rules.contains("delete table inet filter"), "only our own table may be replaced");
    }

    #[test]
    fn the_base_ruleset_also_removes_a_relays_nat_table() {
        let rules = rules_only(&ruleset("/etc/nftables.d", false));
        assert!(rules.contains(&format!("delete table ip {}", super::super::firewall_relay::NAT_TABLE)));
        assert!(rules_only(&super::super::firewall_relay::home_ruleset("/etc/nftables.d", None, false))
            .contains(&format!("delete table ip {}", super::super::firewall_relay::NAT_TABLE)));
        // And docker's own table is never named.
        assert!(!rules.contains("delete table ip nat"), "that table is docker's");
    }

    #[test]
    fn the_ruleset_declares_no_forward_chain() {
        let rules = rules_only(&ruleset("/etc/nftables.d", false));
        assert!(!rules.contains("hook forward"), "a forward chain would break docker networking");
    }

    #[test]
    fn the_chain_and_include_match_what_the_drop_in_half_expects() {
        let text = ruleset("/etc/nftables.d", false);
        assert!(text.contains(&format!("chain {} {{", firewall::CHAIN)));
        assert!(text.contains(&format!("jump {}", firewall::CHAIN)));
        assert!(text.contains(&format!("include \"/etc/nftables.d/{}\"", firewall::DROP_IN_GLOB)));
    }

    #[test]
    fn the_base_opens_only_ports_a_host_process_terminates() {
        let text = ruleset("/etc/nftables.d", false);
        assert!(text.contains("tcp dport { 80, 443 } accept"));
        assert!(!text.contains("8388"));
        assert!(!text.contains("51820"));
    }

    #[test]
    fn the_discovery_rules_are_the_generators_own() {
        let path = format!(
            "{}/tests/fixtures/install/ha-firewall-discovery.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let swift = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
        assert_eq!(HOME_DISCOVERY_RULES.trim_end_matches('\n'), swift);
    }

    #[test]
    fn the_discovery_rules_are_written_only_when_a_service_needs_them() {
        let dir = firewall::drop_in_dir_display();
        assert!(!ruleset(&dir, false).contains("home devices discovery"));
        let with = ruleset(&dir, true);
        assert!(with.contains("224.0.0.251"));
        assert!(with.contains("ff02::fb"));
    }

    #[test]
    fn the_discovery_rules_sit_in_the_input_chain_before_the_jump() {
        let text = ruleset(&firewall::drop_in_dir_display(), true);
        let discovery = text.find("home devices discovery").expect("no discovery rule");
        let ports = text.find("HTTP/HTTPS for ACME").expect("no port accept");
        let jump = text.find("jump ").expect("no jump");
        assert!(ports < discovery, "the accepts come first");
        assert!(discovery < jump, "the jump comes last");
    }

    #[test]
    fn the_home_half_accepts_discovery_and_the_relay_does_not() {
        let dir = firewall::drop_in_dir_display();
        let home = super::super::firewall_relay::home_ruleset(&dir, None, true);
        assert!(home.contains("home devices discovery"));

        let topo = super::super::firewall_relay::Topology::single(
            "10.8.0.2".to_string(),
            "203.0.113.10".to_string(),
            51820,
            vec![443],
            vec![],
        );
        let relay = super::super::firewall_relay::relay_ruleset(&topo, "eth0", &dir);
        assert!(!relay.contains("home devices discovery"));
    }

    #[test]
    fn the_base_throttles_ssh_per_source() {
        let text = ruleset("/etc/nftables.d", false);
        assert!(text.contains("tcp dport 22 meter gryonixnexus_ssh_throttle4"), "IPv4 meter");
        assert!(text.contains("tcp dport 22 meter gryonixnexus_ssh_throttle6"), "IPv6 meter");
        assert!(text.contains("ip saddr timeout 60s limit rate 10/minute burst 5 packets"));
        assert!(text.contains("ip6 saddr timeout 60s limit rate 10/minute burst 5 packets"));
        assert!(text.contains("tcp dport 22 drop comment \"SSH: per-source rate exceeded\""));
        let throttle4 = text.find("gryonixnexus_ssh_throttle4").unwrap();
        let throttle6 = text.find("gryonixnexus_ssh_throttle6").unwrap();
        let drop = text.find("SSH: per-source rate exceeded").unwrap();
        assert!(throttle4 < throttle6 && throttle6 < drop, "throttle, then throttle, then drop — in that order");
    }

    #[test]
    fn being_ours_is_not_being_the_right_shape_for_the_role() {
        let single_host = ruleset("/etc/nftables.d", false);
        assert!(already_ours(&single_host));
        assert!(has_role_shape(&single_host, &Plan::SingleHost));
        assert!(
            !has_role_shape(&single_host, &Plan::Relay(super::super::firewall_relay::Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![]))),
            "a single-host ruleset must never pass as a relay's"
        );
        assert!(!has_role_shape(&single_host, &Plan::HomeBackend(None)), "the base ruleset marks nothing");

        // The real generated artifacts DO carry their shapes.
        let swift_relay = include_str!("../../tests/fixtures/relay/vps.nft");
        let swift_home = include_str!("../../tests/fixtures/relay/home.nft");
        let topology = super::super::firewall_relay::Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![51821]);
        assert!(has_role_shape(swift_relay, &Plan::Relay(topology.clone())));
        assert!(has_role_shape(swift_home, &Plan::HomeBackend(None)));
        // And so do the agent's own.
        assert!(has_role_shape(
            &super::super::firewall_relay::relay_ruleset(&topology, "ens6", "/etc/nftables.d"),
            &Plan::Relay(topology)
        ));
        assert!(has_role_shape(&super::super::firewall_relay::home_ruleset("/etc/nftables.d", None, false), &Plan::HomeBackend(None)));

        assert!(!has_role_shape(swift_relay, &Plan::SingleHost));
        assert!(has_role_shape(swift_home, &Plan::SingleHost), "marks alone are not a relay's DNAT");
    }

    #[test]
    fn an_agent_written_ruleset_is_refreshed_and_a_setup_written_one_is_left_alone() {
        let ours = ruleset("/etc/nftables.d", false);
        assert!(ours.contains(AGENT_MARKER), "our own output must be identifiable");
        let setup_written = "#!/usr/sbin/nft -f\n\
                             # Managed by gryonixNexus — single-server firewall (default-deny).\n\
                             table inet filter {\n  chain gryonixnexus_services {\n  }\n}\n";
        assert!(already_ours(setup_written));
        assert!(!setup_written.contains(AGENT_MARKER));

        let topology = super::super::firewall_relay::Topology::single("10.8.0.2".into(), "203.0.113.10".into(), 51820, vec![80, 443], vec![]);
        let with_ens6 = super::super::firewall_relay::relay_ruleset(&topology, "ens6", "/etc/nftables.d");
        let with_eth0 = super::super::firewall_relay::relay_ruleset(&topology, "eth0", "/etc/nftables.d");
        assert_eq!(rules_without_interface(&with_ens6), rules_without_interface(&with_eth0));
        let without_clamp: String = with_ens6.lines().filter(|line| !line.contains("maxseg")).collect();
        assert_ne!(rules_without_interface(&with_ens6), rules_without_interface(&without_clamp));
    }

    #[test]
    fn a_ruleset_we_already_wrote_is_recognised_and_a_foreign_one_is_not() {
        assert!(already_ours(&ruleset("/etc/nftables.d", false)));
        assert!(!already_ours("table inet filter {\n  chain input {\n  }\n}\n"));
        assert!(!already_ours(""));
        let old_generated = "#!/usr/sbin/nft -f\n\
                             # Managed by GryonixNexus — home-server firewall (default-deny).\n\
                             table inet filter {\n  chain input {\n  }\n}\n";
        assert!(already_ours(old_generated));
        assert!(!has_role_shape(old_generated, &Plan::HomeBackend(None)), "it has no marks");
        // Current spelling, same answer.
        assert!(already_ours("# Managed by gryonixNexus — single-server firewall (default-deny).\n"));
    }
    #[test]
    fn a_pair_file_is_rewritten_when_its_forwards_move() {
        use super::super::firewall_relay::{home_ruleset, relay_ruleset, Topology};
        let dir = firewall::drop_in_dir_display();
        let old = Topology::single("10.8.0.2".into(), "203.0.113.9".into(), 51820, vec![25, 80, 443], vec![]);
        let new = Topology::single("10.8.0.2".into(), "203.0.113.9".into(), 51820, vec![25, 80, 443, 2222], vec![]);
        let relay_file = relay_ruleset(&old, "eth0", &dir).replace(AGENT_MARKER, "");
        assert!(forwards_moved(&relay_file, &Plan::Relay(new.clone()), false));
        assert!(!forwards_moved(&relay_file, &Plan::Relay(old.clone()), false));
        let home_file = home_ruleset(&dir, Some(&old), false).replace(AGENT_MARKER, "");
        assert!(forwards_moved(&home_file, &Plan::HomeBackend(Some(new)), false));
        assert!(!forwards_moved(&home_file, &Plan::HomeBackend(Some(old)), false));
        assert!(!forwards_moved(&home_file, &Plan::SingleHost, false));
    }
}

#[cfg(test)]
mod sshd_port_tests {
    use super::*;

    #[test]
    fn one_port_keeps_the_classic_rules() {
        let text = ssh_throttle_for(&[22]);
        assert!(text.contains("tcp dport 22 meter gryonixnexus_ssh_throttle4"));
        assert!(!text.contains("dport {"));
    }

    #[test]
    fn several_ports_become_one_set() {
        let text = ssh_throttle_for(&[22, 2222]);
        assert!(text.contains("tcp dport { 22, 2222 } meter gryonixnexus_ssh_throttle6"));
        assert!(text.contains("tcp dport { 22, 2222 } drop"));
    }

    #[test]
    fn ports_are_read_until_the_first_match_block() {
        let dir = std::env::temp_dir().join(format!("sshd-ports-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sshd_config");
        std::fs::write(&file, "# Port 1\nPort 2222\n  port 2200\nMatch User x\n  Port 3333\n").unwrap();
        assert_eq!(ports_in_config(&file, 0), vec![2222, 2200]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
