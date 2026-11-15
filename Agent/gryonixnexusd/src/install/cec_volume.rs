//! The speaker's own volume over HDMI-CEC: the phone's slider moves the volume of the TV or amplifier on the cable.

use super::context::Input;
use super::shairport_sync;

pub const UNIT: &str = "gryonixnexus-cec-volume";
pub const UNIT_PATH: &str = "/etc/systemd/system/gryonixnexus-cec-volume.service";
pub const SCRIPT_PATH: &str = "/usr/local/lib/gryonixnexus/cec-volume.py";
const PACKAGES: &str = "v4l-utils python3";
const SCRIPT: &str = include_str!("cec_volume.py");

/// The CEC adapter of the speaker's HDMI card
pub fn device(input: &Input) -> Option<String> {
    let output = shairport_sync::output_device(input);
    let number: String = output.split("vc4hdmi").nth(1)?.chars().take_while(char::is_ascii_digit).collect();
    (!number.is_empty()).then(|| format!("/dev/cec{number}"))
}

/// Whether the regulator should run for this speaker
pub fn wanted(input: &Input) -> bool {
    shairport_sync::cec_volume(input).enabled && device(input).is_some()
}

pub fn unit_file(input: &Input) -> String {
    let volume = shairport_sync::cec_volume(input);
    let device = device(input).unwrap_or_default();
    let pipe = shairport_sync::CEC_PIPE_DIRECTORY;
    format!(
        "[Unit]\nDescription=Speaker volume over HDMI-CEC\nAfter=docker.service\n\n[Service]\nEnvironment=CEC_VOLUME_DEVICE={device}\nEnvironment=CEC_VOLUME_PIPE={pipe}/metadata\nEnvironment=CEC_VOLUME_MIN={}\nEnvironment=CEC_VOLUME_MAX={}\nEnvironment=CEC_VOLUME_TV_OFF={}\nEnvironment=CEC_VOLUME_TV_WAIT={}\nEnvironment=CEC_VOLUME_DISCONNECT={}\nEnvironment=CEC_VOLUME_OFF_DELAY={}\nEnvironment=CEC_VOLUME_GRACE={}\nExecStart=/usr/bin/python3 {SCRIPT_PATH}\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target",
        volume.lowest, volume.highest, u8::from(volume.tv_off), volume.tv_wait, u8::from(volume.disconnect), volume.off_delay, volume.grace
    )
}

/// Stops the regulator and takes its files away
pub fn removal_script() -> String {
    format!("systemctl disable --now {UNIT}.service >/dev/null 2>&1 || true\nrm -f {UNIT_PATH} {SCRIPT_PATH}\nsystemctl daemon-reload\n")
}

/// The shell that sets the regulator up or removes it
pub fn setup_script(input: &Input) -> String {
    if !wanted(input) {
        return removal_script();
    }
    let apt = super::packages::apt_quiet();
    let unit = unit_file(input);
    format!(
        "set -e\n{apt} install -yq {PACKAGES}\ninstall -d /usr/local/lib/gryonixnexus\ncat > {SCRIPT_PATH} <<'EOF_CEC_SCRIPT'\n{SCRIPT}EOF_CEC_SCRIPT\ncat > {UNIT_PATH} <<'EOF_CEC_UNIT'\n{unit}\nEOF_CEC_UNIT\nsystemctl daemon-reload\nsystemctl enable {UNIT}.service\nsystemctl restart {UNIT}.service\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(output: &str, options: &str) -> Input {
        Input {
            shairport_output: output.to_string(),
            shairport_options: options.to_string(),
            ..Input::default()
        }
    }

    #[test]
    fn the_adapter_follows_the_hdmi_card() {
        assert_eq!(device(&input("hw:CARD=vc4hdmi1,DEV=0", "")).as_deref(), Some("/dev/cec1"));
        assert_eq!(device(&input("hdmi:CARD=vc4hdmi0,DEV=0", "")).as_deref(), Some("/dev/cec0"));
        assert_eq!(device(&input("hw:CARD=Headphones,DEV=0", "")), None);
        assert_eq!(device(&input("default", "")), None);
    }

    #[test]
    fn it_runs_only_when_asked_and_on_an_hdmi_card() {
        assert!(wanted(&input("hw:CARD=vc4hdmi1,DEV=0", "cec_volume=yes")));
        assert!(!wanted(&input("hw:CARD=vc4hdmi1,DEV=0", "cec_volume=no")));
        assert!(!wanted(&input("default", "cec_volume=yes")));
        assert!(setup_script(&input("default", "cec_volume=yes")).contains("rm -f"));
    }

    #[test]
    fn the_unit_carries_the_range() {
        let text = unit_file(&input("hw:CARD=vc4hdmi1,DEV=0", "cec_volume=yes;cec_volume_min=5;cec_volume_max=60"));
        assert!(text.contains("Environment=CEC_VOLUME_MIN=5\nEnvironment=CEC_VOLUME_MAX=60\n"), "{text}");
        assert!(text.contains("Environment=CEC_VOLUME_DEVICE=/dev/cec1\n"), "{text}");
    }

    #[test]
    fn the_unit_says_whether_the_tv_goes_off() {
        let on = unit_file(&input("hw:CARD=vc4hdmi1,DEV=0", "cec_volume=yes"));
        let off = unit_file(&input("hw:CARD=vc4hdmi1,DEV=0", "cec_volume=yes;cec_tv_wakes=yes"));
        assert!(on.contains("CEC_VOLUME_TV_OFF=1\n") && off.contains("CEC_VOLUME_TV_OFF=0\n"));
    }

    #[test]
    fn the_unit_carries_the_timings() {
        let text = unit_file(&input("hw:CARD=vc4hdmi1,DEV=0", "cec_volume=yes;cec_tv_wait=30;cec_off_delay=5;cec_grace=20;cec_keep_connected=yes"));
        for line in ["TV_WAIT=30", "DISCONNECT=0", "OFF_DELAY=5", "GRACE=20"] {
            assert!(text.contains(&format!("CEC_VOLUME_{line}\n")), "{text}");
        }
    }

    #[test]
    fn a_bad_range_falls_back_and_keeps_the_gap() {
        let text = unit_file(&input("hw:CARD=vc4hdmi1,DEV=0", "cec_volume=yes;cec_volume_min=50;cec_volume_max=10"));
        assert!(text.contains("CEC_VOLUME_MIN=9\n") && text.contains("CEC_VOLUME_MAX=10\n"), "{text}");
    }
}
