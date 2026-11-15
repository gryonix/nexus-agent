//! Every player setting the hub can change, with its file and limits.

/// How a player's file spells a setting
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Syntax {
    /// `key = value` under `[global]`
    Ini,
    /// `key = value;` inside a named block
    Libconfig(&'static str),
    /// `key "value"` at the top level
    Mpd,
}

/// What a setting may hold
#[derive(Clone, Copy, Debug)]
pub enum Check {
    Name,
    Choice(&'static [&'static str]),
    /// On is "yes", off removes the line
    Toggle,
    Number(f64, f64),
    Whole(i64, i64),
}

pub struct Setting {
    pub id: &'static str,
    pub file: &'static str,
    pub syntax: Syntax,
    pub key: &'static str,
    pub quoted: bool,
    pub check: Check,
    pub unit: &'static str,
}

pub const SPOTIFY_FILE: &str = ".config/spotifyd/spotifyd.conf";
pub const AIRPLAY_FILE: &str = ".config/shairport-sync/shairport-sync.conf";
pub const MPD_FILE: &str = ".config/mpd/mpd.conf";

const SPOTIFY_UNIT: &str = "spotifyd.service";
const AIRPLAY_UNIT: &str = "shairport-sync.service";
const MPD_UNIT: &str = "mpd.service";

const fn spotify(id: &'static str, key: &'static str, quoted: bool, check: Check) -> Setting {
    Setting { id, file: SPOTIFY_FILE, syntax: Syntax::Ini, key, quoted, check, unit: SPOTIFY_UNIT }
}

const fn airplay(id: &'static str, block: &'static str, key: &'static str, quoted: bool, check: Check) -> Setting {
    Setting { id, file: AIRPLAY_FILE, syntax: Syntax::Libconfig(block), key, quoted, check, unit: AIRPLAY_UNIT }
}

const fn mpd(id: &'static str, key: &'static str, check: Check) -> Setting {
    Setting { id, file: MPD_FILE, syntax: Syntax::Mpd, key, quoted: true, check, unit: MPD_UNIT }
}

pub const SETTINGS: &[Setting] = &[
    spotify("spotify.name", "device_name", true, Check::Name),
    spotify("spotify.bitrate", "bitrate", false, Check::Choice(&["96", "160", "320"])),
    spotify("spotify.normalise", "volume_normalisation", false, Check::Toggle),
    spotify("spotify.pregain", "normalisation_pregain", false, Check::Number(-10.0, 10.0)),
    spotify("spotify.volume", "initial_volume", false, Check::Whole(0, 100)),
    spotify("spotify.device_type", "device_type", true, Check::Choice(&["speaker", "avr", "tv", "computer", "stb", "audiodongle"])),
    spotify("spotify.volume_controller", "volume_controller", true, Check::Choice(&["softvol", "none"])),
    spotify("spotify.autoplay", "autoplay", false, Check::Toggle),
    airplay("airplay.name", "general", "name", true, Check::Name),
    airplay("airplay.interpolation", "general", "interpolation", true, Check::Choice(&["auto", "basic", "soxr"])),
    airplay("airplay.ignore_volume_control", "general", "ignore_volume_control", true, Check::Toggle),
    airplay("airplay.default_airplay_volume", "general", "default_airplay_volume", false, Check::Number(-30.0, 0.0)),
    airplay("airplay.volume_range_db", "general", "volume_range_db", false, Check::Number(30.0, 100.0)),
    airplay("airplay.volume_max_db", "general", "volume_max_db", false, Check::Number(-96.0, 24.0)),
    airplay("airplay.audio_backend_latency_offset_in_seconds", "general", "audio_backend_latency_offset_in_seconds", false, Check::Number(-1.0, 1.0)),
    airplay("airplay.audio_backend_buffer_desired_length_in_seconds", "general", "audio_backend_buffer_desired_length_in_seconds", false, Check::Number(0.01, 1.5)),
    airplay("airplay.drift_tolerance_in_seconds", "general", "drift_tolerance_in_seconds", false, Check::Number(0.001, 0.02)),
    airplay("airplay.allow_session_interruption", "sessioncontrol", "allow_session_interruption", true, Check::Toggle),
    airplay("airplay.session_timeout", "sessioncontrol", "session_timeout", false, Check::Number(20.0, 3600.0)),
    mpd("mpd.name", "zeroconf_name", Check::Name),
    mpd("mpd.replaygain", "replaygain", Check::Choice(&["off", "track", "album", "auto"])),
    mpd("mpd.auto_update", "auto_update", Check::Toggle),
];

/// The program that reads a player's file
pub fn program(file: &str) -> &'static str {
    match file {
        SPOTIFY_FILE => "spotifyd",
        AIRPLAY_FILE => "shairport-sync",
        _ => "mpd",
    }
}

pub fn find(id: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|setting| setting.id == id)
}

const NAME_FORBIDDEN: &str = "\"\\$`%'/&|;";
const NAME_LIMIT: usize = 40;

fn is_plain_number(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.')
}

fn fits(check: Check, value: &str) -> bool {
    match check {
        Check::Name => {
            !value.is_empty()
                && value.chars().count() <= NAME_LIMIT
                && value.chars().all(|c| (c as u32) >= 0x20 && c as u32 != 0x7f && !NAME_FORBIDDEN.contains(c))
        }
        Check::Choice(choices) => choices.contains(&value),
        Check::Toggle => value == "yes",
        Check::Number(low, high) => is_plain_number(value) && value.parse::<f64>().is_ok_and(|n| (low..=high).contains(&n)),
        Check::Whole(low, high) => value.parse::<i64>().is_ok_and(|n| (low..=high).contains(&n)),
    }
}

/// The value to write; empty removes the line
pub fn checked(id: &str, value: &str) -> Result<String, String> {
    let setting = find(id).ok_or_else(|| format!("unknown setting {id}"))?;
    let value = match (setting.check, value.trim()) {
        (Check::Toggle, "true") => "yes",
        (Check::Toggle, "false" | "no") => "",
        (_, value) => value,
    };
    let removable = !matches!(setting.check, Check::Name);
    if (removable && value.is_empty()) || fits(setting.check, value) {
        Ok(value.to_string())
    } else {
        Err(format!("{id} cannot be {value:?}"))
    }
}

/// A read value as the app shows it
pub fn shown(id: &str, value: &str) -> String {
    match find(id).map(|setting| setting.check) {
        Some(Check::Toggle) if matches!(value, "yes" | "true" | "on") => "yes".to_string(),
        Some(Check::Toggle) => String::new(),
        _ => value.to_string(),
    }
}
