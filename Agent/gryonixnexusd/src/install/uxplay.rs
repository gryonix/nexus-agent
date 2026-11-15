//! UxPlay's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/UxPlayService.swift`

use super::context::Input;
use super::firewall;

pub const SERVICE_ID: &str = "uxplay";

pub const UNIT: &str = "gryonixnexus-uxplay";
pub const UNIT_PATH: &str = "/etc/systemd/system/gryonixnexus-uxplay.service";
pub const PACKAGE: &str = "uxplay";
pub const ACCOUNT: &str = "uxplay";
pub const DEFAULT_NAME: &str = "gryonix TV";
pub const PORT_BASE: u16 = 7200;
const VIDEO_SINK: &str = "kmssink";
const AUDIO_SINK: &str = "alsasink";
pub const SUPPORT_PACKAGES: &[&str] = &[
    "gstreamer1.0-plugins-good",
    "gstreamer1.0-plugins-bad",
    "gstreamer1.0-libav",
    "gstreamer1.0-alsa",
    "avahi-daemon",
];

const FORBIDDEN: &str = "\"\\$`%";

/// A port of `UxPlayService.screenName(_:)`
pub fn screen_name(input: &Input) -> String {
    let kept: String = input
        .uxplay_name
        .chars()
        .filter(|c| (*c as u32) >= 0x20 && *c as u32 != 0x7f && !FORBIDDEN.contains(*c))
        .collect();
    let name = kept.trim();
    if name.is_empty() { DEFAULT_NAME.to_string() } else { name.to_string() }
}

/// A port of `UxPlayService.unitFile(_:)`
pub fn unit_file(input: &Input) -> String {
    let name = screen_name(input);
    format!(
        "[Unit]\nDescription=UxPlay AirPlay screen\nAfter=network-online.target avahi-daemon.service\nWants=network-online.target avahi-daemon.service\n\n[Service]\nUser={ACCOUNT}\nGroup={ACCOUNT}\nExecStart=/usr/bin/uxplay -n \"{name}\" -nh -p {PORT_BASE} -vs {VIDEO_SINK} -as {AUDIO_SINK}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target"
    )
}

/// The shell that installs the packages and starts the unit
pub fn setup_script(input: &Input) -> String {
    let packages = std::iter::once(PACKAGE).chain(SUPPORT_PACKAGES.iter().copied()).collect::<Vec<_>>().join(" ");
    let apt = super::packages::apt_quiet();
    let unit = unit_file(input);
    format!(
        "set -e\n{apt} install -yq {packages}\nid {ACCOUNT} >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin {ACCOUNT}\nfor group in audio video render; do\n  if getent group \"$group\" >/dev/null; then usermod -aG \"$group\" {ACCOUNT}; fi\ndone\ncat > {UNIT_PATH} <<'EOF_UXPLAY_UNIT'\n{unit}\nEOF_UXPLAY_UNIT\nsystemctl daemon-reload\nsystemctl enable --now avahi-daemon.service\nsystemctl enable {UNIT}.service\nsystemctl restart {UNIT}.service\n"
    )
}

/// A port of `UxPlayService.firewallPorts(_:)`
pub fn firewall_ports() -> Vec<firewall::Port> {
    let tcp = (PORT_BASE..=PORT_BASE + 2).map(firewall::Port::tcp);
    let udp = (PORT_BASE..=PORT_BASE + 2).map(firewall::Port::udp);
    tcp.chain(udp).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn the_unit_names_the_screen_and_fixes_the_ports() {
        let mut input = base();
        input.uxplay_name = "Living room".to_string();
        assert!(unit_file(&input).contains("ExecStart=/usr/bin/uxplay -n \"Living room\" -nh -p 7200 -vs kmssink -as alsasink"));
    }

    #[test]
    fn the_name_cannot_break_the_unit() {
        let mut input = base();
        input.uxplay_name = "A\"$(x)%h`b\\".to_string();
        assert_eq!(screen_name(&input), "A(x)hb");
        input.uxplay_name = "\"".to_string();
        assert_eq!(screen_name(&input), DEFAULT_NAME);
    }

    #[test]
    fn six_ports_are_listed() {
        let ports = firewall_ports();
        assert_eq!(ports.len(), 6);
        assert!(ports.contains(&firewall::Port::tcp(7202)));
        assert!(ports.contains(&firewall::Port::udp(7200)));
    }

    #[test]
    fn the_script_installs_packages_and_restarts_the_unit() {
        let text = setup_script(&base());
        assert!(text.contains("install -yq uxplay gstreamer1.0-plugins-good"));
        assert!(text.contains("systemctl restart gryonixnexus-uxplay.service"));
    }
}

/// Byte-for-byte parity against the Swift-dumped catalog golden.
#[cfg(test)]
mod golden_parity {
    use super::*;

    #[test]
    fn the_unit_matches_what_swift_writes() {
        let step = super::super::golden::setup_step(SERVICE_ID);
        let marker = "<<'EOF_UXPLAY_UNIT'\n";
        let from = step.find(marker).expect("heredoc") + marker.len();
        let to = step.find("\nEOF_UXPLAY_UNIT").expect("heredoc end");
        assert_eq!(&step[from..to], unit_file(&Input { domain: "example.com".to_string(), ..Input::default() }));
    }
}
