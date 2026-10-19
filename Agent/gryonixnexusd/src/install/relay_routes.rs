//! The home half's policy routing — the other half of the relay fix

use super::execute::EventSink;
use super::firewall_relay::WG_INTERFACE;

pub const SCRIPT_PATH: &str = "/opt/gryonixnexus-relay-route-sync.sh";
pub const SERVICE_UNIT: &str = "gryonixnexus-relay-route-sync.service";
pub const TIMER_UNIT: &str = "gryonixnexus-relay-route-sync.timer";
pub const ROUTE_TABLE: &str = "100";
pub const FWMARK: &str = "0x1";

pub fn script() -> String {
    format!(
        "#!/bin/bash\n\
         # Managed by gryonixNexus — mirrors the main routing table's\n\
         # locally-connected routes (Docker's bridges included) into a\n\
         # policy-routing table that defaults via the tunnel, so a relayed\n\
         # connection's reply — marked by nftables' prerouting chain — finds\n\
         # its way back through {WG_INTERFACE} instead of the home ISP's default\n\
         # gateway, while traffic actually destined for a container (the other\n\
         # leg of the very same DNATed connection) still reaches the local\n\
         # bridge. Re-run periodically (see the .timer unit): Docker creates\n\
         # and destroys bridges as services are installed and removed.\n\
         set -euo pipefail\n\
         \n\
         TABLE={ROUTE_TABLE}\n\
         MARK={FWMARK}\n\
         \n\
         ip rule del fwmark \"$MARK\" table \"$TABLE\" 2>/dev/null || true\n\
         ip rule add fwmark \"$MARK\" table \"$TABLE\"\n\
         \n\
         ip route flush table \"$TABLE\" 2>/dev/null || true\n\
         # Mirror every locally-connected route (Docker's bridges included) so\n\
         # relayed traffic whose real destination is a container keeps going\n\
         # there; only a genuine default-route destination falls to the\n\
         # tunnel. Word-splitting on $route is deliberate: each line from\n\
         # `ip route show` is a multi-field route spec that `ip route add`\n\
         # expects as separate arguments. Gateway routes stay out: a\n\
         # host route to the relay would pull its own sites off the tunnel.\n\
         while IFS= read -r route; do\n\
         \x20 [ -n \"$route\" ] || continue\n\
         \x20 # shellcheck disable=SC2086\n\
         \x20 ip route add $route table \"$TABLE\" 2>/dev/null || true\n\
         done < <(ip route show table main scope link || true)\n\
         \n\
         ip route add default dev \"{WG_INTERFACE}\" table \"$TABLE\"\n"
    )
}

pub fn refresh_script() -> std::io::Result<bool> {
    let path = std::path::Path::new(SCRIPT_PATH);
    let Ok(old) = std::fs::read_to_string(path) else { return Ok(false) };
    let fresh = script();
    if fresh == old {
        return Ok(false);
    }
    std::fs::write(path, fresh)?;
    let _ = std::process::Command::new(SCRIPT_PATH).status();
    Ok(true)
}

pub fn service_unit() -> String {
    format!(
        "[Unit]\n\
         Description=gryonixNexus relay route sync (mirrors Docker's bridges into the tunnel policy-routing table)\n\
         After=wg-quick@{WG_INTERFACE}.service docker.service\n\
         Requires=wg-quick@{WG_INTERFACE}.service\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         # No RemainAfterExit: this unit is re-triggered by its own timer every\n\
         # 2 minutes, and a oneshot service that stays \"active (exited)\" after\n\
         # its first run does not actually re-execute on a later `start` — the\n\
         # manager sees it's already active and treats the job as redundant.\n\
         # The timer's second tick fired (LastTriggerUSec\n\
         # advanced) but the script never ran a second time, and a docker\n\
         # bridge created between runs stayed unmirrored — exactly the failure\n\
         # this timer exists to prevent.\n\
         ExecStart={SCRIPT_PATH}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

pub fn timer_unit() -> String {
    "[Unit]\n\
     Description=Periodic gryonixNexus relay route sync\n\
     \n\
     [Timer]\n\
     # Docker bridges come and go as services are installed/removed; this\n\
     # is the only thing that notices without a re-run of setup.\n\
     OnUnitActiveSec=2min\n\
     Persistent=true\n\
     \n\
     [Install]\n\
     WantedBy=timers.target\n"
        .to_string()
}

/// Install all three and run the sync once
pub(super) async fn install(sink: &EventSink) -> Result<(), String> {
    let script = script();
    let service = service_unit();
    let timer = timer_unit();
    let shell = format!(
        "set -e\n\
         umask 022\n\
         cat > '{SCRIPT_PATH}' <<'GRYONIXNEXUS_ROUTESYNC_EOF'\n{script}GRYONIXNEXUS_ROUTESYNC_EOF\n\
         chmod 700 '{SCRIPT_PATH}'\n\
         cat > '/etc/systemd/system/{SERVICE_UNIT}' <<'GRYONIXNEXUS_ROUTESYNC_SVC_EOF'\n{service}GRYONIXNEXUS_ROUTESYNC_SVC_EOF\n\
         cat > '/etc/systemd/system/{TIMER_UNIT}' <<'GRYONIXNEXUS_ROUTESYNC_TIMER_EOF'\n{timer}GRYONIXNEXUS_ROUTESYNC_TIMER_EOF\n\
         systemctl daemon-reload\n\
         systemctl enable --now '{TIMER_UNIT}' >/dev/null 2>&1 || true\n\
         systemctl start '{SERVICE_UNIT}' || true\n"
    );
    super::packages::run_outside_sandbox(&shell, "installing the relay route sync", sink).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SWIFT_SCRIPT: &str = include_str!("../../tests/fixtures/relay/eof-routesync.txt");
    const SWIFT_SERVICE: &str = include_str!("../../tests/fixtures/relay/eof-routesync-svc.txt");
    const SWIFT_TIMER: &str = include_str!("../../tests/fixtures/relay/eof-routesync-timer.txt");

    fn body_of(text: &str) -> &str {
        text.strip_suffix('\n').unwrap_or(text)
    }

    #[test]
    fn all_three_files_match_the_generator_byte_for_byte() {
        assert_eq!(body_of(&script()), body_of(SWIFT_SCRIPT));
        assert_eq!(body_of(&service_unit()), body_of(SWIFT_SERVICE));
        assert_eq!(body_of(&timer_unit()), body_of(SWIFT_TIMER));
    }

    #[test]
    fn the_mark_is_the_one_the_home_ruleset_sets() {
        let ruleset = super::super::firewall_relay::home_ruleset("/etc/nftables.d", None, false);
        assert!(ruleset.contains(&format!("ct mark set {FWMARK}")), "the ruleset must set the mark this matches");
        assert!(script().contains(&format!("MARK={FWMARK}")));
    }

    #[test]
    fn the_shell_writes_every_file_before_it_enables_anything() {
        let shell = format!(
            "cat > '{SCRIPT_PATH}'\nchmod 700\ncat > '/etc/systemd/system/{SERVICE_UNIT}'\n\
             cat > '/etc/systemd/system/{TIMER_UNIT}'\nsystemctl daemon-reload\n\
             systemctl enable --now '{TIMER_UNIT}'\nsystemctl start '{SERVICE_UNIT}'\n"
        );
        let at = |needle: &str| shell.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
        assert!(at(SCRIPT_PATH) < at("daemon-reload"));
        assert!(at(SERVICE_UNIT) < at("daemon-reload"));
        assert!(at("daemon-reload") < at("enable --now"));
        assert!(at("enable --now") < at("systemctl start"));
    }
}
