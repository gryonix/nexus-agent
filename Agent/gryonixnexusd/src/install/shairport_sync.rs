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
    if device.is_empty() { DEFAULT_OUTPUT.to_string() } else { device }
}

/// A port of `ShairportSyncService.composeFile(_:).composeContents`
pub fn compose_contents(input: &Input) -> String {
    let image = image(input);
    let name = speaker_name(input);
    let device = output_device(input);
    format!(
        "services:\n  shairport-sync:\n    image: {image}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    # Finding the speaker and streaming to it use the host's network.\n    network_mode: host\n    devices:\n      - /dev/snd\n    command: -a \"{name}\" -o alsa -- -d {device}"
    )
}

/// A port of `ShairportSyncService.firewallPorts(_:)`
pub fn firewall_ports() -> Vec<firewall::Port> {
    let tcp = [3689u16, 5000, 7000].into_iter().map(firewall::Port::tcp);
    let udp = [319u16, 320, 5353].into_iter().chain(6000..=6009).map(firewall::Port::udp);
    tcp.chain(udp).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let ports = firewall_ports();
        assert_eq!(ports.len(), 3 + 13);
        assert!(ports.contains(&firewall::Port::udp(6009)));
        assert!(ports.contains(&firewall::Port::tcp(7000)));
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
}
