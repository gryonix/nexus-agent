//! The machine's ALSA playback devices.

use serde::Serialize;

/// One playback device and its volume controls
#[derive(Debug, Clone, Serialize)]
pub struct AudioOutput {
    pub device: String,
    pub title: String,
    pub mixers: Vec<String>,
}

/// Card ids of the Pi's HDMI outputs
const PI_HDMI: &str = "vc4hdmi";
const CARDS: &str = "/proc/asound/cards";
const PCM: &str = "/proc/asound/pcm";

/// Playback devices from /proc/asound, with their mixers
pub async fn list() -> Vec<AudioOutput> {
    let cards = std::fs::read_to_string(CARDS).unwrap_or_default();
    let pcm = std::fs::read_to_string(PCM).unwrap_or_default();
    let mut found = outputs(&cards, &pcm);
    for output in found.iter_mut() {
        if let Some(card) = card_id(&output.device) {
            output.mixers = card_mixers(card).await;
        }
    }
    found
}

/// The card id inside an hw:CARD=…,DEV=… name
fn card_id(device: &str) -> Option<&str> {
    device.split_once("CARD=")?.1.split(',').next()
}

async fn card_mixers(card: &str) -> Vec<String> {
    let output = tokio::process::Command::new("amixer").args(["-c", card, "scontrols"]).output().await;
    output.map(|out| mixer_names(&String::from_utf8_lossy(&out.stdout))).unwrap_or_default()
}

/// Names from amixer scontrols lines
fn mixer_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("Simple mixer control '")?.split_once('\'').map(|(name, _)| name.to_string()))
        .collect()
}

/// Card number to its short id and long name
fn card_names(cards: &str) -> Vec<(u32, String, String)> {
    cards
        .lines()
        .filter_map(|line| {
            let (number, rest) = line.trim_start().split_once(' ')?;
            let number: u32 = number.parse().ok()?;
            let id = rest.split_once('[')?.1.split_once(']')?.0.trim().to_string();
            let long = rest.rsplit_once(" - ").map(|(_, name)| name.trim().to_string()).unwrap_or_default();
            Some((number, id, long))
        })
        .collect()
}

/// Every playback device, after the system default
fn outputs(cards: &str, pcm: &str) -> Vec<AudioOutput> {
    let names = card_names(cards);
    let mut found = vec![AudioOutput { device: "default".into(), title: String::new(), mixers: Vec::new() }];
    for line in pcm.lines().filter(|line| line.contains("playback")) {
        let Some((address, rest)) = line.split_once(": ") else { continue };
        let Some((card, device)) = address.split_once('-') else { continue };
        let (Ok(card), Ok(device)) = (card.parse::<u32>(), device.parse::<u32>()) else { continue };
        let Some((_, id, long)) = names.iter().find(|(number, _, _)| *number == card) else { continue };
        let device_name = rest.split(" : ").next().unwrap_or("").trim();
        let title = if device_name.is_empty() || device_name == long { long.clone() } else { format!("{long} — {device_name}") };
        let kind = if id.starts_with(PI_HDMI) { "hdmi" } else { "hw" };
        found.push(AudioOutput { device: format!("{kind}:CARD={id},DEV={device}"), title, mixers: Vec::new() });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const PI_CARDS: &str = " 0 [vc4hdmi        ]: vc4-hdmi - vc4-hdmi\n                      vc4-hdmi\n 1 [Headphones     ]: bcm2835_headpho - bcm2835 Headphones\n                      bcm2835 Headphones\n";
    const PI_PCM: &str = "00-00: MAI PCM i2s-hifi-0 : MAI PCM i2s-hifi-0 : playback 1\n01-00: bcm2835 Headphones : bcm2835 Headphones : playback 8\n02-00: USB Audio : USB Audio : capture 1\n";

    #[test]
    fn a_pi_lists_hdmi_and_headphones_after_default() {
        let found = outputs(PI_CARDS, PI_PCM);
        let devices: Vec<&str> = found.iter().map(|o| o.device.as_str()).collect();
        assert_eq!(devices, ["default", "hdmi:CARD=vc4hdmi,DEV=0", "hw:CARD=Headphones,DEV=0"]);
        assert_eq!(found[1].title, "vc4-hdmi — MAI PCM i2s-hifi-0");
        assert_eq!(found[2].title, "bcm2835 Headphones");
    }

    #[test]
    fn mixer_controls_come_from_amixer_lines() {
        let text = "Simple mixer control 'PCM',0\nSimple mixer control 'Headphone',0\n";
        assert_eq!(mixer_names(text), ["PCM", "Headphone"]);
        assert_eq!(card_id("hw:CARD=Headphones,DEV=0"), Some("Headphones"));
        assert_eq!(card_id("hdmi:CARD=vc4hdmi1,DEV=0"), Some("vc4hdmi1"));
        assert_eq!(card_id("default"), None);
    }

    #[test]
    fn no_sound_hardware_still_offers_default() {
        let found = outputs("--- no soundcards ---\n", "");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].device, "default");
    }
}
