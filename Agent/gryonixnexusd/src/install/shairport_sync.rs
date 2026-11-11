//! Shairport Sync's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/ShairportSyncService.swift`, declarative half only

use super::context::Input;
use super::firewall;

pub const SERVICE_ID: &str = "shairport-sync";

pub const IMAGE_NAME: &str = "mikebrady/shairport-sync";
pub const COMPOSE_PROJECT: &str = "shairport-sync";
pub const CONTAINER: &str = "shairport-sync";
pub const DEFAULT_NAME: &str = "gryonix";
pub const DEFAULT_OUTPUT: &str = "default";
pub const AIRPLAY_1: &str = "airplay1";

const FORBIDDEN: &str = "\"\\$`";
const ALLOWED_OUTPUT: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:,._=-";

/// A port of `ShairportSyncService.image(_:)`
pub fn image(input: &Input) -> String {
    let tag = if input.shairport_mode == AIRPLAY_1 { "classic" } else { "latest" };
    format!("{IMAGE_NAME}:{tag}")
}

/// A port of `ShairportSyncService.speakerName(_:)`
pub fn speaker_name(input: &Input) -> String {
    let kept: String = input
        .shairport_name
        .chars()
        .filter(|c| (*c as u32) >= 0x20 && *c as u32 != 0x7f && !FORBIDDEN.contains(*c))
        .collect();
    let name = kept.trim();
    if name.is_empty() { DEFAULT_NAME.to_string() } else { name.to_string() }
}

/// A port of `ShairportSyncService.outputDevice(_:)`
pub fn output_device(input: &Input) -> String {
    let device: String = input.shairport_output.chars().filter(|c| ALLOWED_OUTPUT.contains(*c)).collect();
    if device.is_empty() { DEFAULT_OUTPUT.to_string() } else { playable(&device) }
}

/// Pi HDMI cards play only through their hdmi name
fn playable(device: &str) -> String {
    match device.strip_prefix("hw:").filter(|rest| rest.starts_with("CARD=vc4hdmi")) {
        Some(rest) => format!("hdmi:{rest}"),
        None => device.to_string(),
    }
}

/// A port of `ShairportSyncService.composeFile(_:).composeContents`
pub fn compose_contents(input: &Input) -> String {
    let image = image(input);
    let name = speaker_name(input);
    let device = output_device(input);
    format!(
        "services:\n  shairport-sync:\n    image: {image}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # Finding the speaker and streaming to it use the host's network.\n    network_mode: host\n    devices:\n      - /dev/snd\n    volumes:\n      - ./{CONFIG_FILE}:/etc/shairport-sync.conf:ro\n    command: -a \"{name}\" -o alsa -- -d {device}"
    )
}

pub const CONFIG_FILE: &str = "shairport-sync.conf";

/// How one option's value is checked and written
#[derive(Clone, Copy)]
enum Kind {
    Choice(&'static [&'static str]),
    Number(f64, f64),
    Control,
}

/// Every option the app may set, in file order
const OPTIONS: &[(&str, &str, Kind)] = &[
    ("general", "interpolation", Kind::Choice(&["auto", "basic", "soxr"])),
    ("general", "volume_range_db", Kind::Number(30.0, 100.0)),
    ("general", "volume_max_db", Kind::Number(-96.0, 24.0)),
    ("general", "ignore_volume_control", Kind::Choice(&["yes", "no"])),
    ("general", "default_airplay_volume", Kind::Number(-30.0, 0.0)),
    ("general", "audio_backend_latency_offset_in_seconds", Kind::Number(-1.0, 1.0)),
    ("general", "audio_backend_buffer_desired_length_in_seconds", Kind::Number(0.05, 1.5)),
    ("general", "drift_tolerance_in_seconds", Kind::Number(0.001, 0.02)),
    ("general", "allow_session_interruption", Kind::Choice(&["yes", "no"])),
    ("general", "session_timeout", Kind::Number(20.0, 3600.0)),
    ("alsa", "mixer_control_name", Kind::Control),
    ("alsa", "output_rate", Kind::Choice(&["auto", "44100", "88200", "176400", "352800"])),
    ("alsa", "output_format", Kind::Choice(&["auto", "S16", "S16_LE", "S24", "S24_3LE", "S32"])),
    ("alsa", "disable_standby_mode", Kind::Choice(&["never", "auto", "always"])),
    ("alsa", "disable_synchronization", Kind::Choice(&["yes", "no"])),
];

/// The written form of a valid value, or None
fn rendered(kind: Kind, value: &str) -> Option<String> {
    match kind {
        Kind::Choice(allowed) if allowed.contains(&value) => {
            let numeric = value.chars().all(|c| c.is_ascii_digit());
            Some(if numeric { value.to_string() } else { format!("\"{value}\"") })
        }
        Kind::Choice(_) => None,
        Kind::Number(low, high) => {
            let digits = value.strip_prefix('-').unwrap_or(value);
            let (whole, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
            let plain = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
            let number: f64 = value.parse().ok()?;
            (plain(whole) && plain(fraction) && number >= low && number <= high).then(|| value.to_string())
        }
        Kind::Control => {
            let fine = !value.is_empty() && value.len() <= 40
                && value.chars().all(|c| c.is_ascii_alphanumeric() || " _-".contains(c));
            fine.then(|| format!("\"{value}\""))
        }
    }
}

/// The options string as key to value
fn parsed_options(options: &str) -> Vec<(String, String)> {
    options
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

/// A port of `ShairportSyncService.configContents(_:)`
pub fn config_contents(input: &Input) -> String {
    let given = parsed_options(&input.shairport_options);
    let mut out = String::new();
    for section in ["general", "alsa"] {
        out.push_str(&format!("{section} = {{\n"));
        for (_, key, kind) in OPTIONS.iter().filter(|(owner, _, _)| *owner == section) {
            let value = given.iter().rev().find(|(name, _)| name == key).map(|(_, value)| value.as_str());
            if let Some(line) = value.and_then(|value| rendered(*kind, value)) {
                out.push_str(&format!("  {key} = {line};\n"));
            }
        }
        out.push_str("};\n");
    }
    out
}

/// The home-network ports; AirPlay 2 adds the ephemeral range
pub fn firewall_ports(input: &Input) -> Vec<firewall::Port> {
    let tcp = [3689u16, 5000, 7000].into_iter().map(firewall::Port::tcp);
    let udp = [319u16, 320, 5353].into_iter().chain(6000..=6009).map(firewall::Port::udp);
    let mut ports: Vec<firewall::Port> = tcp.chain(udp).collect();
    if input.shairport_mode != AIRPLAY_1 {
        ports.push(firewall::Port::tcp_range(EPHEMERAL.0, EPHEMERAL.1));
        ports.push(firewall::Port::udp_range(EPHEMERAL.0, EPHEMERAL.1));
    }
    ports
}

const EPHEMERAL: (u16, u16) = (32768, 60999);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_become_a_config_and_bad_values_are_dropped() {
        let mut input = base();
        input.shairport_options = "interpolation=soxr;output_rate=44100;audio_backend_latency_offset_in_seconds=-0.15;volume_range_db=500;mixer_control_name=PCM;output_format=S16\";x;session_timeout=1e3".to_string();
        assert_eq!(
            config_contents(&input),
            "general = {\n  interpolation = \"soxr\";\n  audio_backend_latency_offset_in_seconds = -0.15;\n};\nalsa = {\n  mixer_control_name = \"PCM\";\n  output_rate = 44100;\n};\n"
        );
        input.shairport_options = String::new();
        assert_eq!(config_contents(&input), "general = {\n};\nalsa = {\n};\n");
    }

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn the_mode_picks_the_tag() {
        let mut input = base();
        assert_eq!(image(&input), "mikebrady/shairport-sync:latest");
        input.shairport_mode = "airplay1".to_string();
        assert_eq!(image(&input), "mikebrady/shairport-sync:classic");
    }

    #[test]
    fn the_name_cannot_break_the_command_line() {
        let mut input = base();
        input.shairport_name = " Kü\"che $(x) `y` \\ ".to_string();
        assert_eq!(speaker_name(&input), "Küche (x) y");
        input.shairport_name = "\"$".to_string();
        assert_eq!(speaker_name(&input), DEFAULT_NAME);
        input.shairport_output = "hw:0,0; rm".to_string();
        assert_eq!(output_device(&input), "hw:0,0rm");
        input.shairport_output = ";".to_string();
        assert_eq!(output_device(&input), DEFAULT_OUTPUT);
        input.shairport_output = "hw:CARD=vc4hdmi1,DEV=0".to_string();
        assert_eq!(output_device(&input), "hdmi:CARD=vc4hdmi1,DEV=0");
        input.shairport_output = "hw:CARD=Headphones,DEV=0".to_string();
        assert_eq!(output_device(&input), "hw:CARD=Headphones,DEV=0");
    }

    #[test]
    fn the_speaker_uses_the_host_network_and_the_sound_card() {
        let text = compose_contents(&base());
        assert!(text.contains("network_mode: host"));
        assert!(text.contains("- /dev/snd"));
        assert!(text.contains("command: -a \"gryonix\" -o alsa -- -d default"));
    }

    #[test]
    fn every_airplay_port_is_listed() {
        let mut input = base();
        input.shairport_mode = AIRPLAY_1.to_string();
        let classic = firewall_ports(&input);
        assert_eq!(classic.len(), 3 + 13);
        assert!(classic.contains(&firewall::Port::udp(6009)));
        assert!(classic.contains(&firewall::Port::tcp(7000)));
    }

    #[test]
    fn airplay_2_opens_the_ephemeral_range_too() {
        let ports = firewall_ports(&base());
        assert!(ports.contains(&firewall::Port::tcp_range(32768, 60999)));
        assert!(ports.contains(&firewall::Port::udp_range(32768, 60999)));
        let text = firewall::drop_in_contents("shairport-sync", &ports);
        assert!(text.contains("tcp dport { 3689, 5000, 7000, 32768-60999 } accept"), "{text}");
    }
}

/// Byte-for-byte parity against REAL Swift-generated output.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    #[test]
    fn default_airplay2_en() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        assert_eq!(compose_contents(&input), fixture("airplay-default-en__docker-compose.yml"));
    }

    #[test]
    fn classic_named_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.shairport_mode = "airplay1".to_string();
        input.shairport_name = "Living room".to_string();
        input.shairport_output = "hw:1,0".to_string();
        input.shairport_path = "/srv/shairport-sync".to_string();
        assert_eq!(compose_contents(&input), fixture("airplay-classic-named-en__docker-compose.yml"));
    }

    #[test]
    fn tuned_config() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.shairport_options = "interpolation=soxr;output_rate=44100;audio_backend_latency_offset_in_seconds=-0.15;volume_range_db=500;mixer_control_name=PCM;output_format=S16\";x;session_timeout=1e3;disable_standby_mode=always;allow_session_interruption=yes".to_string();
        assert_eq!(config_contents(&input), fixture("airplay-tuned__shairport-sync.conf"));
    }
}
