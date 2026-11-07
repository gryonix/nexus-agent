//! Audio services installed from Debian packages and run by their own units

use super::firewall::Port;

/// One service: packages, units and ports
pub struct Spec {
    pub id: &'static str,
    pub display: &'static str,
    pub packages: &'static [&'static str],
    /// Removed on uninstall; shared helpers such as avahi stay
    pub own_packages: &'static [&'static str],
    pub units: &'static [&'static str],
    pub ports: &'static [Port],
    pub extra_setup: &'static str,
    pub extra_removal: &'static str,
}

const BT_AGENT_UNIT: &str = "gryonixnexus-bt-agent";

const BLUETOOTH_SETUP: &str = "install -d /etc/systemd/system/bluealsa.service.d\ncat > /etc/systemd/system/bluealsa.service.d/gryonixnexus.conf <<'EOF_BLUEALSA'\n[Service]\nExecStart=\nExecStart=/usr/bin/bluealsa -p a2dp-sink\nEOF_BLUEALSA\ncat > /etc/systemd/system/gryonixnexus-bt-agent.service <<'EOF_BT_AGENT'\n[Unit]\nDescription=Bluetooth pairing without a PIN\nAfter=bluetooth.service\nRequires=bluetooth.service\n\n[Service]\nExecStartPre=/usr/bin/bluetoothctl power on\nExecStartPre=/usr/bin/bluetoothctl discoverable on\nExecStartPre=/usr/bin/bluetoothctl pairable on\nExecStart=/usr/bin/bt-agent --capability=NoInputNoOutput\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\nEOF_BT_AGENT\nif [ -f /etc/bluetooth/main.conf ]; then sed -i 's/^#\\?DiscoverableTimeout.*/DiscoverableTimeout = 0/' /etc/bluetooth/main.conf; fi\n";

const BLUETOOTH_REMOVAL: &str = "rm -f /etc/systemd/system/gryonixnexus-bt-agent.service\nrm -rf /etc/systemd/system/bluealsa.service.d/gryonixnexus.conf\n";

const SPOTIFY_SETUP: &str = "case \"$(dpkg --print-architecture)\" in\n  amd64) spotify_sha=7b228feb0623bf0f9b65904961ad3ad9df8e1f4b07a002ab2388e1ee9385eeed ;;\n  arm64) spotify_sha=4d272678f475ad18961563951b6c36e5395c8a85b8d5607d1e3e9f94671108e2 ;;\n  armhf) spotify_sha=47cc9b1d1e75e583a7eb45c2fa24b38cf6ed92f3231443d37f9b2477e32be59b ;;\n  *) echo \"Spotify Connect has no package for this processor\" >&2; exit 1 ;;\nesac\nspotify_deb=\"/tmp/raspotify_$(dpkg --print-architecture).deb\"\ncurl -fsSL -o \"$spotify_deb\" \"https://github.com/dtcooper/raspotify/releases/download/0.48.4/raspotify_0.48.4.librespot.v0.8.0-99b6088_$(dpkg --print-architecture).deb\"\necho \"$spotify_sha  $spotify_deb\" | sha256sum -c - >/dev/null\nDEBIAN_FRONTEND=noninteractive apt-get install -yq \"$spotify_deb\"\nrm -f \"$spotify_deb\"\nsed -i \"s/^#\\?LIBRESPOT_NAME=.*/LIBRESPOT_NAME=\\\"$(hostname)\\\"/\" /etc/raspotify/conf\n";

const MYMPD_SETUP: &str = "case \"$(dpkg --print-architecture)\" in\n  amd64) mympd_sha=bb839fe621bc9ab6a08fbf71b2db3d007555fdf5eaabe94c7b04e18b19ba027c ;;\n  arm64) mympd_sha=c65e824ec01f4cdd8f298869a3368865fd6d6a10a7877225c860522032588853 ;;\n  armhf) mympd_sha=7524caf1677d88f4f0dcb0c8248c14c3b7f8c49120db7c2ea559d76e915ca349 ;;\n  *) echo \"myMPD has no package for this processor\" >&2; exit 1 ;;\nesac\nmympd_deb=\"/tmp/mympd_$(dpkg --print-architecture).deb\"\ncurl -fsSL -o \"$mympd_deb\" \"https://github.com/b0bbywan/odio-mympd/releases/download/v26.1.2/mympd_26.1.2-1_$(dpkg --print-architecture).deb\"\necho \"$mympd_sha  $mympd_deb\" | sha256sum -c - >/dev/null\ninstall -d /etc/systemd/system/mympd.service.d\nprintf '[Service]\\nEnvironment=MYMPD_HTTP_PORT=8019\\nEnvironment=MYMPD_SSL=false\\n' > /etc/systemd/system/mympd.service.d/gryonixnexus.conf\nDEBIAN_FRONTEND=noninteractive apt-get install -yq \"$mympd_deb\"\nrm -f \"$mympd_deb\"\nfor mympd_dir in /var/lib/mympd /var/lib/private/mympd; do\n  if [ -d \"$mympd_dir/config\" ]; then echo 8019 > \"$mympd_dir/config/http_port\"; echo false > \"$mympd_dir/config/ssl\"; fi\ndone\n";

const MYMPD_REMOVAL: &str = "rm -rf /etc/systemd/system/mympd.service.d/gryonixnexus.conf\n";

/// System units other services share; removal leaves them running
const SHARED_UNITS: &[&str] = &["mpd", "bluetooth"];

pub const ALL: &[Spec] = &[
    Spec {
        id: "snapserver",
        display: "Multi-room server (Snapcast)",
        packages: &["snapserver", "avahi-daemon"],
        own_packages: &["snapserver"],
        units: &["snapserver"],
        ports: &[Port::tcp(1704), Port::tcp(1705), Port::tcp(1780)],
        extra_setup: "",
        extra_removal: "",
    },
    Spec {
        id: "snapclient",
        display: "Multi-room speaker (Snapcast)",
        packages: &["snapclient", "avahi-daemon"],
        own_packages: &["snapclient"],
        units: &["snapclient"],
        ports: &[],
        extra_setup: "",
        extra_removal: "",
    },
    Spec {
        id: "upmpdcli",
        display: "DLNA speaker",
        packages: &["mpd", "upmpdcli", "avahi-daemon"],
        own_packages: &["upmpdcli"],
        units: &["mpd", "upmpdcli"],
        ports: &[Port::udp(1900), Port::tcp(49152), Port::tcp(49153)],
        extra_setup: "",
        extra_removal: "",
    },
    Spec {
        id: "bluealsa",
        display: "Bluetooth speaker",
        packages: &["bluez", "bluez-alsa-utils", "bluez-tools"],
        own_packages: &["bluez-alsa-utils", "bluez-tools"],
        units: &["bluetooth", "bluealsa", "bluealsa-aplay", BT_AGENT_UNIT],
        ports: &[],
        extra_setup: BLUETOOTH_SETUP,
        extra_removal: BLUETOOTH_REMOVAL,
    },
    Spec {
        id: "raspotify",
        display: "Spotify Connect speaker",
        packages: &["ca-certificates", "curl"],
        own_packages: &["raspotify"],
        units: &["raspotify"],
        ports: &[],
        extra_setup: SPOTIFY_SETUP,
        extra_removal: "",
    },
    Spec {
        id: "mympd",
        display: "Music library (MPD + myMPD)",
        packages: &["mpd", "avahi-daemon", "ca-certificates", "curl"],
        own_packages: &["mympd"],
        units: &["mpd", "mympd"],
        ports: &[Port::tcp(8019)],
        extra_setup: MYMPD_SETUP,
        extra_removal: MYMPD_REMOVAL,
    },
];

pub fn find(id: &str) -> Option<&'static Spec> {
    ALL.iter().find(|spec| spec.id == id)
}

/// Players the audio hub (odio) already brings
pub const AUDIO_HUB_PLAYERS: &[&str] = &["snapclient", "upmpdcli", "bluealsa", "raspotify", "mympd"];

/// The service that clashes with the hub, by installed markers
pub fn audio_hub_overlap(label: &str) -> Option<&'static str> {
    overlap_with(label, |path| std::path::Path::new(path).exists())
}

fn overlap_with(label: &str, exists: impl Fn(&str) -> bool) -> Option<&'static str> {
    if label == super::odio::SERVICE_ID {
        return AUDIO_HUB_PLAYERS.iter().filter_map(|id| find(id)).find(|spec| exists(&marker(spec.id))).map(|spec| spec.display);
    }
    let spec = find(label).filter(|spec| AUDIO_HUB_PLAYERS.contains(&spec.id))?;
    exists(super::odio::CONTROL_PATH).then_some(spec.display)
}

/// Install marker; preinstalled packages lack it
pub fn marker(id: &str) -> String {
    format!("/var/lib/gryonixnexus/packaged/{id}")
}

fn unit_list(spec: &Spec) -> String {
    spec.units.iter().map(|unit| format!("{unit}.service")).collect::<Vec<_>>().join(" ")
}

/// A port of `PackagedAudioService.setupSteps(_:)`
pub fn setup_script(spec: &Spec) -> String {
    let apt = super::packages::apt_quiet();
    let packages = spec.packages.join(" ");
    let units = unit_list(spec);
    let marker = marker(spec.id);
    format!(
        "set -e\n{apt} install -yq {packages}\n{extra}systemctl daemon-reload\nsystemctl enable {units}\nsystemctl restart {units}\ninstall -d -m 755 /var/lib/gryonixnexus/packaged\ntouch {marker}\n",
        extra = spec.extra_setup,
    )
}

/// A port of `PackagedAudioService.uninstallSpec(_:)`
pub fn removal_steps(spec: &Spec) -> Vec<String> {
    let own: Vec<String> = spec.units.iter().filter(|unit| !SHARED_UNITS.contains(unit)).map(|unit| format!("{unit}.service")).collect();
    let mut steps = vec![format!("systemctl disable --now {} >/dev/null 2>&1 || true", own.join(" "))];
    steps.extend(spec.extra_removal.lines().map(String::from));
    steps.push("systemctl daemon-reload || true".to_string());
    steps.push(format!("{} remove -yq {} >/dev/null 2>&1 || true", super::packages::apt_quiet(), spec.own_packages.join(" ")));
    steps.push(format!("rm -f {}", marker(spec.id)));
    steps
}

/// Privileged commands for status, power and logs
pub fn sudoers_targets(spec: &Spec) -> Vec<String> {
    let units = unit_list(spec);
    let journal_units = spec.units.iter().map(|unit| format!("-u {unit}.service")).collect::<Vec<_>>().join(" ");
    vec![
        format!("/usr/bin/systemctl show {units} --property=Id --property=LoadState --property=ActiveState"),
        format!("/usr/bin/systemctl restart {units}"),
        format!("/usr/bin/systemctl start {units}"),
        format!("/usr/bin/systemctl stop {units}"),
        format!("/usr/bin/journalctl {journal_units} -n 500 --no-pager -o short-iso"),
    ]
}

/// Program and arguments for a status, power or log verb
pub fn command(spec: &Spec, verb: &str) -> (String, Vec<String>) {
    let units: Vec<String> = spec.units.iter().map(|unit| format!("{unit}.service")).collect();
    match verb {
        "status" => {
            let mut args = vec!["show".to_string()];
            args.extend(units);
            args.extend(["--property=Id", "--property=LoadState", "--property=ActiveState"].map(String::from));
            ("systemctl".into(), args)
        }
        "logs" => {
            let mut args = Vec::new();
            for unit in units {
                args.push("-u".to_string());
                args.push(unit);
            }
            args.extend(["-n", "500", "--no-pager", "-o", "short-iso"].map(String::from));
            ("journalctl".into(), args)
        }
        verb => {
            let mut args = vec![verb.to_string()];
            args.extend(units);
            ("systemctl".into(), args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dlna_speaker_installs_and_starts_both_units() {
        let spec = find("upmpdcli").unwrap();
        let script = setup_script(spec);
        assert!(script.contains("install -yq mpd upmpdcli avahi-daemon"), "{script}");
        assert!(script.contains("systemctl enable mpd.service upmpdcli.service"));
        assert!(script.ends_with("touch /var/lib/gryonixnexus/packaged/upmpdcli\n"));
        assert!(removal_steps(spec).iter().any(|s| s.contains("remove -yq upmpdcli >")));
        assert!(removal_steps(spec)[0].starts_with("systemctl disable --now upmpdcli.service >"));
    }

    #[test]
    fn the_bluetooth_speaker_pairs_without_a_pin_and_keeps_bluez() {
        let spec = find("bluealsa").unwrap();
        assert!(setup_script(spec).contains("bt-agent --capability=NoInputNoOutput"));
        assert!(setup_script(spec).contains("ExecStart=/usr/bin/bluealsa -p a2dp-sink"));
        assert!(!removal_steps(spec).iter().any(|s| s.contains("remove -yq bluez ")));
        assert_eq!(command(spec, "restart").1.len(), 5);
    }

    #[test]
    fn the_hub_and_its_own_players_refuse_each_other() {
        let hub_present = |path: &str| path == super::super::odio::CONTROL_PATH;
        assert_eq!(overlap_with("upmpdcli", hub_present), Some("DLNA speaker"));
        assert_eq!(overlap_with("snapserver", hub_present), None);
        let speaker_present = |path: &str| path == marker("bluealsa");
        assert_eq!(overlap_with("odio", speaker_present), Some("Bluetooth speaker"));
        assert_eq!(overlap_with("odio", |_| false), None);
    }

    #[test]
    fn spotify_connect_installs_a_pinned_package_named_after_the_machine() {
        let script = setup_script(find("raspotify").unwrap());
        assert!(script.contains("releases/download/0.48.4/raspotify_0.48.4.librespot.v0.8.0-99b6088_$(dpkg --print-architecture).deb"), "{script}");
        assert!(script.contains("armhf) spotify_sha=47cc9b1d"));
        assert!(script.contains("| sha256sum -c -"));
        assert!(script.contains(r#"s/^#\?LIBRESPOT_NAME=.*/LIBRESPOT_NAME=\"$(hostname)\"/"#), "{script}");
    }

    #[test]
    fn the_library_answers_on_its_own_port_and_keeps_mpd_on_removal() {
        let spec = find("mympd").unwrap();
        let script = setup_script(spec);
        assert!(script.contains("odio-mympd/releases/download/v26.1.2/mympd_26.1.2-1_$(dpkg --print-architecture).deb"), "{script}");
        assert!(script.contains("Environment=MYMPD_HTTP_PORT=8019"));
        assert!(script.contains("echo 8019 > \"$mympd_dir/config/http_port\""));
        assert!(removal_steps(spec)[0].starts_with("systemctl disable --now mympd.service >"));
    }

    #[test]
    fn sudoers_match_the_commands_run() {
        let spec = find("snapserver").unwrap();
        let (program, args) = command(spec, "status");
        assert_eq!(format!("/usr/bin/{program} {}", args.join(" ")), sudoers_targets(spec)[0]);
    }
}
