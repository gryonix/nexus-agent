//! Speaker power wiring of the packaged audio players.

use super::context::Input;
use super::speaker_power::{self, Entry, ANY_CARD};

const ONEVENT_PATH: &str = "/usr/local/lib/gryonixnexus/spotify-onevent.sh";
const ONEVENT_DROP_IN: &str = "/etc/systemd/system/raspotify.service.d/gryonixnexus-power.conf";
const SPOTIFY_CONF: &str = "/etc/raspotify/conf";
const SPOTIFY_ENTRY: &str = "spotify";

/// The name of a player's power entry
pub fn power_name(id: &str) -> Option<&'static str> {
    match id {
        "raspotify" => Some(SPOTIFY_ENTRY),
        "bluealsa" => Some("bluealsa"),
        "upmpdcli" => Some("upmpdcli"),
        "snapclient" => Some("snapclient"),
        _ => None,
    }
}

/// The player's entry; Spotify uses events
fn entry(id: &str, options: &str) -> Option<Entry> {
    let name = power_name(id)?;
    let card = if id == "raspotify" { "" } else { ANY_CARD };
    speaker_power::player_entry(name, options, card)
}

/// The librespot hook that reports Spotify sessions
fn onevent_script() -> String {
    let file = format!("{}/{SPOTIFY_ENTRY}", super::shairport_sync::POWER_DIRECTORY);
    format!("#!/bin/sh\ncase \"$PLAYER_EVENT\" in\n  session_connected|playing) state=on ;;\n  session_disconnected|stopped) state=off ;;\n  *) exit 0 ;;\nesac\necho \"$state\" > {file}\n")
}

/// Raspotify lines that hook its events, or unhook them
pub fn onevent_setup(id: &str, options: &str) -> String {
    if id != "raspotify" {
        return String::new();
    }
    let drop_in_dir = "/etc/systemd/system/raspotify.service.d";
    let strip = format!("sed -i '/^LIBRESPOT_ONEVENT=/d' {SPOTIFY_CONF}\n");
    if entry(id, options).is_none() {
        return format!("{strip}rm -f {ONEVENT_PATH} {ONEVENT_DROP_IN}\n");
    }
    format!(
        "install -d /usr/local/lib/gryonixnexus {drop_in_dir}\ncat > {ONEVENT_PATH} <<'EOF_ONEVENT'\n{}EOF_ONEVENT\nchmod 755 {ONEVENT_PATH}\n{strip}echo 'LIBRESPOT_ONEVENT=\"{ONEVENT_PATH}\"' >> {SPOTIFY_CONF}\nprintf '[Service]\\nReadWritePaths=-/run/gryonixnexus\\n' > {ONEVENT_DROP_IN}\n",
        onevent_script()
    )
}

/// Records the player's power entry
pub fn sync_script(id: &str, input: &Input) -> Option<String> {
    let name = power_name(id)?;
    Some(speaker_power::sync_script(name, entry(id, &input.power_options).as_ref()))
}

/// Drops the player's entry on uninstall
pub fn removal_script(id: &str) -> Option<String> {
    Some(speaker_power::removal_script(power_name(id)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spotify_hooks_its_events_only_while_a_switch_is_on() {
        let on = onevent_setup("raspotify", "power_on_connect=yes");
        assert!(on.contains("session_connected|playing) state=on ;;") && on.contains("session_disconnected|stopped) state=off ;;"), "{on}");
        assert!(on.contains("echo \"$state\" > /run/gryonixnexus/speaker-power/spotify"), "{on}");
        assert!(on.contains("echo 'LIBRESPOT_ONEVENT=\"/usr/local/lib/gryonixnexus/spotify-onevent.sh\"' >> /etc/raspotify/conf"), "{on}");
        assert!(on.contains("ReadWritePaths=-/run/gryonixnexus"), "{on}");
        let off = onevent_setup("raspotify", "");
        assert!(off.contains("sed -i '/^LIBRESPOT_ONEVENT=/d'") && off.contains("rm -f /usr/local/lib/gryonixnexus/spotify-onevent.sh"), "{off}");
        assert!(!off.contains("cat >"), "{off}");
        assert_eq!(onevent_setup("mympd", "power_on_connect=yes"), "");
    }

    #[test]
    fn the_players_get_their_own_entries() {
        let input = Input { power_options: "power_on_connect=yes;power_off_disconnect=yes;power_off_delay=600".to_string(), ..Input::default() };
        let spotify = sync_script("raspotify", &input).unwrap();
        assert!(spotify.contains("spotify:1:1:600::0:' > /etc/gryonixnexus/speaker-power.d/spotify"), "{spotify}");
        assert!(sync_script("mympd", &input).is_none() && sync_script("snapserver", &input).is_none());
        let none = sync_script("raspotify", &Input::default()).unwrap();
        assert!(none.starts_with("rm -f /etc/gryonixnexus/speaker-power.d/spotify"), "{none}");
    }

    #[test]
    fn snapclient_watches_the_sound_card() {
        let input = Input { power_options: "power_on_connect=yes;power_off_disconnect=yes;power_off_delay=600".to_string(), ..Input::default() };
        let text = sync_script("snapclient", &input).unwrap();
        assert!(text.contains("snapclient:1:1:600:*:0:' > /etc/gryonixnexus/speaker-power.d/snapclient"), "{text}");
        assert_eq!(onevent_setup("snapclient", &input.power_options), "");
        let gone = removal_script("snapclient").unwrap();
        assert!(gone.contains("rm -f /etc/gryonixnexus/speaker-power.d/snapclient /run/gryonixnexus/speaker-power/snapclient"), "{gone}");
    }

    #[test]
    fn upmpdcli_watches_the_sound_card() {
        let input = Input { power_options: "power_on_connect=yes;power_off_disconnect=yes;power_off_delay=600".to_string(), ..Input::default() };
        let text = sync_script("upmpdcli", &input).unwrap();
        assert!(text.contains("upmpdcli:1:1:600:*:0:' > /etc/gryonixnexus/speaker-power.d/upmpdcli"), "{text}");
        assert_eq!(onevent_setup("upmpdcli", &input.power_options), "");
        let gone = removal_script("upmpdcli").unwrap();
        assert!(gone.contains("rm -f /etc/gryonixnexus/speaker-power.d/upmpdcli /run/gryonixnexus/speaker-power/upmpdcli"), "{gone}");
    }

    #[test]
    fn bluealsa_watches_the_sound_card() {
        let input = Input { power_options: "power_on_connect=yes;power_off_disconnect=yes;power_off_delay=600".to_string(), ..Input::default() };
        let text = sync_script("bluealsa", &input).unwrap();
        assert!(text.contains("bluealsa:1:1:600:*:0:' > /etc/gryonixnexus/speaker-power.d/bluealsa"), "{text}");
        assert_eq!(onevent_setup("bluealsa", &input.power_options), "");
        let gone = removal_script("bluealsa").unwrap();
        assert!(gone.contains("rm -f /etc/gryonixnexus/speaker-power.d/bluealsa /run/gryonixnexus/speaker-power/bluealsa"), "{gone}");
    }

    #[test]
    fn an_uninstall_drops_the_entry_and_keeps_the_service_for_others() {
        let text = removal_script("raspotify").unwrap();
        assert!(text.contains("speaker-power.d/spotify") && text.contains("ls -A /etc/gryonixnexus/speaker-power.d"), "{text}");
        assert!(removal_script("mympd").is_none());
    }
}
