//! Switches the speaker with its players over HDMI-CEC.

use super::cec_volume;
use super::context::Input;
use super::shairport_sync;

pub const UNIT: &str = "gryonixnexus-speaker-power";
pub const UNIT_PATH: &str = "/etc/systemd/system/gryonixnexus-speaker-power.service";
pub const SCRIPT_PATH: &str = "/usr/local/lib/gryonixnexus/speaker-power.py";
pub const ENTRIES_DIR: &str = "/etc/gryonixnexus/speaker-power.d";
const PACKAGES: &str = "v4l-utils python3";
const SCRIPT: &str = include_str!("speaker_power.py");
const AIRPLAY: &str = "airplay";
/// Matches any sound card
pub const ANY_CARD: &str = "*";

/// One audio service's power settings, as the service reads them
pub struct Entry {
    id: String,
    power: shairport_sync::SpeakerPower,
    card: String,
    hdmi: bool,
    device: String,
}

impl Entry {
    fn line(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.id,
            u8::from(self.power.on_connect),
            u8::from(self.power.off_disconnect),
            self.power.off_delay,
            self.card,
            u8::from(self.hdmi),
            self.device
        )
    }
}

/// Whether the speaker plays over a Pi HDMI card
fn hdmi_output(input: &Input) -> bool {
    shairport_sync::output_device(input).starts_with("hdmi:CARD=vc4hdmi")
}

/// The AirPlay speaker's entry, when a switch is on
pub fn airplay_entry(input: &Input) -> Option<Entry> {
    if !shairport_sync::power_active(input) {
        return None;
    }
    let hdmi = hdmi_output(input);
    let device = if hdmi { cec_volume::device(input).unwrap_or_default() } else { String::new() };
    Some(Entry { id: AIRPLAY.to_string(), power: shairport_sync::speaker_power(input), card: String::new(), hdmi, device })
}

/// A player's entry; none when both switches are off
pub fn player_entry(id: &str, options: &str, card: &str) -> Option<Entry> {
    let power = shairport_sync::power_from_options(options, false);
    (power.on_connect || power.off_disconnect).then(|| Entry {
        id: id.to_string(),
        power,
        card: card.to_string(),
        hdmi: false,
        device: String::new(),
    })
}

pub fn unit_file() -> String {
    let directory = shairport_sync::POWER_DIRECTORY;
    format!(
        "[Unit]\nDescription=Speaker power with its players\nAfter=docker.service\n\n[Service]\nEnvironment=SPEAKER_POWER_DIR={directory}\nEnvironment=SPEAKER_POWER_ENTRIES={ENTRIES_DIR}\nExecStart=/usr/bin/python3 {SCRIPT_PATH}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target"
    )
}

/// Stops the service and takes its files away
fn teardown() -> String {
    format!("systemctl disable --now {UNIT}.service >/dev/null 2>&1 || true\nrm -f {UNIT_PATH} {SCRIPT_PATH}\nsystemctl daemon-reload\n")
}

/// Installs the service and starts it
fn install() -> String {
    let apt = super::packages::apt_quiet();
    let unit = unit_file();
    let directory = shairport_sync::POWER_DIRECTORY;
    format!(
        "{apt} install -yq {PACKAGES}\ninstall -d /usr/local/lib/gryonixnexus\ninstall -d -m 1777 {directory}\ncat > {SCRIPT_PATH} <<'EOF_POWER_SCRIPT'\n{SCRIPT}EOF_POWER_SCRIPT\ncat > {UNIT_PATH} <<'EOF_POWER_UNIT'\n{unit}\nEOF_POWER_UNIT\nsystemctl daemon-reload\nsystemctl enable {UNIT}.service\nsystemctl restart {UNIT}.service\n"
    )
}

/// Records a service's entry and updates the service
pub fn sync_script(id: &str, entry: Option<&Entry>) -> String {
    let directory = shairport_sync::POWER_DIRECTORY;
    match entry {
        Some(entry) => format!(
            "set -e\ninstall -d {ENTRIES_DIR}\nprintf '%s\\n' '{}' > {ENTRIES_DIR}/{id}\n{}",
            entry.line(),
            install()
        ),
        None => format!(
            "rm -f {ENTRIES_DIR}/{id} {directory}/{id}\nif [ -z \"$(ls -A {ENTRIES_DIR} 2>/dev/null)\" ]; then\n{}fi\n",
            teardown()
        ),
    }
}

/// Drops an entry; the service goes when unused
pub fn removal_script(id: &str) -> String {
    sync_script(id, None)
}

/// Sets up the AirPlay speaker's power control
pub fn setup_script(input: &Input) -> String {
    sync_script(AIRPLAY, airplay_entry(input).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn input(output: &str, options: &str) -> Input {
        Input { shairport_output: output.to_string(), shairport_options: options.to_string(), ..Input::default() }
    }

    const HDMI: &str = "hw:CARD=vc4hdmi1,DEV=0";
    const USB: &str = "hw:CARD=T8,DEV=0";

    #[test]
    fn it_runs_only_when_a_switch_is_on() {
        assert!(airplay_entry(&input(USB, "power_on_connect=yes")).is_some());
        assert!(airplay_entry(&input(USB, "power_off_disconnect=yes")).is_some());
        assert!(airplay_entry(&input(USB, "")).is_none());
        assert!(airplay_entry(&input(USB, "power_on_connect=no;power_off_disconnect=no")).is_none());
        assert!(setup_script(&input(USB, "")).contains("rm -f /etc/gryonixnexus/speaker-power.d/airplay"));
        assert!(setup_script(&input(USB, "power_on_connect=yes")).contains("systemctl restart"));
    }

    #[test]
    fn waking_defaults_on_with_hdmi_volume() {
        assert!(airplay_entry(&input(HDMI, "cec_volume=yes")).is_some());
        assert!(airplay_entry(&input(HDMI, "cec_volume=yes;power_on_connect=no")).is_none());
    }

    #[test]
    fn the_entry_carries_the_settings() {
        let entry = airplay_entry(&input(HDMI, "power_on_connect=yes;power_off_disconnect=yes;power_off_delay=300")).unwrap();
        assert_eq!(entry.line(), "airplay:1:1:300::1:/dev/cec1");
        assert!(setup_script(&input(HDMI, "power_on_connect=yes")).contains("airplay:1:0:120::1:/dev/cec1' > /etc/gryonixnexus/speaker-power.d/airplay"));
    }

    #[test]
    fn a_usb_speaker_never_gets_a_power_on() {
        let entry = airplay_entry(&input(USB, "power_on_connect=yes")).unwrap();
        assert_eq!(entry.line(), "airplay:1:0:120::0:");
    }

    #[test]
    fn players_without_events_watch_the_sound_card() {
        let entry = player_entry("snapclient", "power_off_disconnect=yes;power_off_delay=60", ANY_CARD).unwrap();
        assert_eq!(entry.line(), "snapclient:0:1:60:*:0:");
        assert!(player_entry("snapclient", "", ANY_CARD).is_none());
        assert!(player_entry("snapclient", "power_on_connect=no", ANY_CARD).is_none());
    }

    #[test]
    fn the_service_stays_while_another_player_uses_it() {
        let removal = removal_script("airplay");
        assert!(removal.contains("rm -f /etc/gryonixnexus/speaker-power.d/airplay /run/gryonixnexus/speaker-power/airplay"));
        let check = "if [ -z \"$(ls -A /etc/gryonixnexus/speaker-power.d 2>/dev/null)\" ]; then\nsystemctl disable --now";
        assert!(removal.contains(check), "{removal}");
        assert!(removal.ends_with("daemon-reload\nfi\n"), "{removal}");
        let setup = sync_script("spotify", player_entry("spotify", "power_on_connect=yes", "").as_ref());
        assert!(setup.contains("> /etc/gryonixnexus/speaker-power.d/spotify") && setup.contains("systemctl restart"), "{setup}");
    }

    #[test]
    fn a_bad_delay_falls_back_to_two_minutes() {
        let power = shairport_sync::speaker_power(&input(USB, "power_off_delay=5"));
        assert_eq!(power.off_delay, 120);
        let power = shairport_sync::speaker_power(&input(USB, "power_off_delay=600;power_on_connect=maybe"));
        assert_eq!((power.off_delay, power.on_connect), (600, false));
    }

    #[test]
    fn the_player_reports_its_sessions_into_the_shared_folder() {
        let on = input(USB, "power_on_connect=yes");
        let config = shairport_sync::config_contents(&on);
        assert!(config.contains("run_this_before_entering_active_state = \"/bin/sh -c 'echo on > /run/speaker-power/airplay'\";"), "{config}");
        assert!(config.contains("run_this_after_exiting_active_state = \"/bin/sh -c 'echo off > /run/speaker-power/airplay'\";"), "{config}");
        assert!(shairport_sync::compose_contents(&on).contains("- /run/gryonixnexus/speaker-power:/run/speaker-power"));
        let off = input(USB, "");
        assert!(!shairport_sync::config_contents(&off).contains("sessioncontrol"));
        assert!(!shairport_sync::compose_contents(&off).contains("speaker-power"));
    }

    /// Runs a Python snippet against the shipped script
    fn python(body: &str) -> String {
        let dir = std::env::temp_dir().join(format!("speaker-power-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("speaker_power.py"), SCRIPT).unwrap();
        let code = format!("import sys\nsys.path.insert(0, {:?})\nimport speaker_power as sp\n{body}", dir.to_str().unwrap());
        let output = Command::new("python3").arg("-c").arg(code).output().expect("python3");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    const POLICY: &str = "def run(spec, steps, guard=True, foreign_at=()):\n    p = sp.Policy(sp.parse_services(spec), lambda: guard)\n    out = []\n    for i, (t, active) in enumerate(steps):\n        if i in foreign_at:\n            p.saw_foreign_source()\n        out.append(p.tick(t, set(active)))\n    return out\n";

    #[test]
    fn a_session_switches_on_then_off_after_the_delay() {
        let out = python(&format!("{POLICY}print(run('airplay:1:1:120', [(0, []), (1, ['airplay']), (2, ['airplay']), (3, []), (122, []), (123, []), (124, [])]))"));
        assert_eq!(out, "[None, 'on', None, None, None, 'off', None]");
    }

    #[test]
    fn a_return_before_the_delay_keeps_the_speaker_on() {
        let out = python(&format!("{POLICY}print(run('airplay:1:1:120', [(1, ['airplay']), (2, []), (60, ['airplay']), (61, []), (150, []), (190, [])]))"));
        assert_eq!(out, "['on', None, 'on', None, None, 'off']");
    }

    #[test]
    fn a_foreign_source_or_a_watching_tv_leaves_the_speaker_alone() {
        let steps = "[(1, ['airplay']), (2, []), (200, [])]";
        let seen = python(&format!("{POLICY}print(run('airplay:1:1:120', {steps}, foreign_at=(1,)))"));
        assert_eq!(seen, "['on', None, None]");
        let watched = python(&format!("{POLICY}print(run('airplay:1:1:120', {steps}, guard=False))"));
        assert_eq!(watched, "['on', None, None]");
    }

    #[test]
    fn the_switches_work_apart() {
        let off_only = python(&format!("{POLICY}print(run('airplay:0:1:30', [(1, ['airplay']), (2, []), (40, [])]))"));
        assert_eq!(off_only, "[None, None, 'off']");
        let on_only = python(&format!("{POLICY}print(run('airplay:1:0:30', [(1, ['airplay']), (2, []), (400, [])]))"));
        assert_eq!(on_only, "['on', None, None]");
    }

    #[test]
    fn entries_are_read_from_their_files() {
        let out = python("import os, tempfile\nd = tempfile.mkdtemp()\nopen(os.path.join(d, 'a'), 'w').write('airplay:1:1:300::1:/dev/cec1\\n')\nopen(os.path.join(d, 'b'), 'w').write('snapclient:0:1:60:*:0:\\n')\nsp.ENTRIES = d\ne = sp.read_entries()\nprint(sorted(e), e['snapclient']['card'], e['airplay']['hdmi'], e['airplay']['device'])");
        assert_eq!(out, "['airplay', 'snapclient'] * True /dev/cec1");
    }

    #[test]
    fn player_events_outrank_the_sound_card() {
        let body = "import os, tempfile\nd = tempfile.mkdtemp()\nsp.DIRECTORY = d\nsp.card_running = lambda card: True\nsvc = sp.parse_services('spotify:1:1:60::0:,snapclient:1:1:60:*:0:')\nprint(sorted(sp.active_services(svc)))\nopen(os.path.join(d, 'spotify'), 'w').write('on')\nprint(sorted(sp.active_services(svc)))";
        assert_eq!(python(body), "['snapclient']\n['spotify']");
    }

    #[test]
    fn power_goes_to_the_amplifier_alone() {
        let out = python("print(sp.standby_message(), sp.power_on_messages())\ntry:\n    sp.header(sp.BROADCAST)\nexcept ValueError:\n    print('refused')");
        assert_eq!(out, "[181, 54] [[181, 68, 109], [181, 69]]\nrefused");
    }

    #[test]
    fn nothing_but_the_amplifier_is_ever_addressed() {
        assert!(!SCRIPT.contains("[BROADCAST"), "power must not be broadcast");
        let out = python("print(all(m[0] & 0xF == 5 for m in sp.power_on_messages() + [sp.standby_message()]))");
        assert_eq!(out, "True");
    }
}
