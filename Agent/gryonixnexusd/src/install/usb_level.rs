//! Restores a USB speaker's volume to full when it reconnects.

pub const RULES_PATH: &str = "/etc/udev/rules.d/90-gryonixnexus-usb-speaker-level.rules";
const FRAGMENTS: &str = "/var/lib/gryonixnexus/usb-level";
const HEADER: &str = "# Managed by gryonixNexus: a USB speaker forgets its level when it reconnects\\n";

/// The card a raw or plug device name points at
pub fn card_reference(device: &str) -> Option<String> {
    let rest = device.strip_prefix("plughw:").or_else(|| device.strip_prefix("hw:"))?;
    let card = match rest.split_once("CARD=") {
        Some((_, tail)) => tail.split(',').next()?.to_string(),
        None => format!("card{}", rest.split(',').next()?),
    };
    let plain = !card.is_empty() && card.chars().all(|c| c.is_ascii_alphanumeric() || "_-".contains(c));
    plain.then_some(card)
}

/// Whether a volume control name is safe in a rule
pub fn plain_control(name: &str) -> bool {
    !name.is_empty() && name.len() <= 40 && name.chars().all(|c| c.is_ascii_alphanumeric() || " _-".contains(c))
}

fn rule_line(control: &str) -> String {
    format!(
        "SUBSYSTEM==\\\"sound\\\", KERNEL==\\\"controlC*\\\", ACTION==\\\"add\\\", ATTRS{{idVendor}}==\\\"$vendor\\\", ATTRS{{idProduct}}==\\\"$product\\\", RUN+=\\\"/usr/bin/amixer -c %%n -q cset name='{control} Playback Volume' 100%%%%\\\"\\n"
    )
}

fn control_lookup(card: &str, mixer: &str) -> String {
    if plain_control(mixer) {
        return format!("control='{mixer}'\n");
    }
    format!("control=\"$(amixer -c {card} controls 2>/dev/null | sed -n \"s/.*name='\\(.*\\) Playback Volume'.*/\\1/p\" | head -n 1)\"\n")
}

pub fn setup_script(service: &str, device: &str, mixer: &str) -> String {
    let Some(card) = card_reference(device) else { return removal_script(service) };
    rule_script(service, &card, &control_lookup(&card, mixer))
}

pub fn config_script(service: &str, conf: &str) -> String {
    let card = "$card";
    let lookup = format!("control=\"$mix\"\n[ -n \"$control\" ] || {}", control_lookup(card, ""));
    format!(
        "dev=\"$(field \"{conf}\" device)\"; mix=\"$(field \"{conf}\" mixer)\"\ncard=\"$(printf %s \"$dev\" | sed -n 's/^plughw:CARD=\\([^,]*\\).*/\\1/p')\"\nif [ -n \"$card\" ]; then\n{}else\n{}fi\n",
        rule_script(service, card, &lookup),
        removal_script(service)
    )
}

fn rule_script(service: &str, card: &str, lookup: &str) -> String {
    let line = rule_line("$control");
    let fragment = format!("{FRAGMENTS}/{service}.rule");
    format!(
        "install -d {FRAGMENTS}\nrm -f {fragment}\nusbid=\"$(cat /proc/asound/{card}/usbid 2>/dev/null || true)\"\n{lookup}if [ -n \"$usbid\" ] && [ -n \"$control\" ]; then\n  vendor=\"${{usbid%%:*}}\"; product=\"${{usbid##*:}}\"\n  printf \"{line}\" > {fragment}\n  amixer -c {card} -q cset name=\"$control Playback Volume\" 100% >/dev/null 2>&1 || true\nfi\n{merge}",
        merge = merge_script()
    )
}

/// The shell that drops one service's card from the rule
pub fn removal_script(service: &str) -> String {
    format!("rm -f {FRAGMENTS}/{service}.rule\n{}", merge_script())
}

/// Rebuilds the rules file from the services' fragments
fn merge_script() -> String {
    format!(
        "if ls {FRAGMENTS}/*.rule >/dev/null 2>&1; then\n  {{ printf \"{HEADER}\"; cat {FRAGMENTS}/*.rule; }} > {RULES_PATH}\nelse\n  rm -f {RULES_PATH}\nfi\nudevadm control --reload >/dev/null 2>&1 || true\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hub_player_reads_its_card_and_control_from_its_file() {
        let script = config_script("spotifyd", "$home/.config/spotifyd/spotifyd.conf");
        assert!(script.contains("dev=\"$(field \"$home/.config/spotifyd/spotifyd.conf\" device)\""), "{script}");
        assert!(script.contains("mix=\"$(field \"$home/.config/spotifyd/spotifyd.conf\" mixer)\""), "{script}");
        assert!(script.contains("/proc/asound/$card/usbid"), "{script}");
        assert!(script.contains("control=\"$mix\"\n[ -n \"$control\" ] || control=\"$(amixer -c $card controls"), "{script}");
        assert!(script.contains("spotifyd.rule"), "{script}");
        assert!(script.contains("else\nrm -f /var/lib/gryonixnexus/usb-level/spotifyd.rule"), "{script}");
    }

    #[test]
    fn a_raw_card_is_found_by_id_or_number() {
        assert_eq!(card_reference("plughw:CARD=T8,DEV=0").as_deref(), Some("T8"));
        assert_eq!(card_reference("hw:CARD=Headphones,DEV=0").as_deref(), Some("Headphones"));
        assert_eq!(card_reference("hw:1,0").as_deref(), Some("card1"));
        assert_eq!(card_reference("hdmi:CARD=vc4hdmi0,DEV=0"), None);
        assert_eq!(card_reference("default"), None);
        assert_eq!(card_reference("hw:CARD=a;b,DEV=0"), None);
    }

    #[test]
    fn the_rule_sets_the_control_to_full_when_the_card_appears() {
        let script = setup_script("shairport-sync", "plughw:CARD=T8,DEV=0", "PCM");
        assert!(script.contains("usbid=\"$(cat /proc/asound/T8/usbid 2>/dev/null || true)\""), "{script}");
        assert!(script.contains("control='PCM'"), "{script}");
        assert!(script.contains("KERNEL==\\\"controlC*\\\", ACTION==\\\"add\\\""), "{script}");
        assert!(script.contains("ACTION==\\\"add\\\", ATTRS{idVendor}==\\\"$vendor\\\", ATTRS{idProduct}==\\\"$product\\\""), "{script}");
        assert!(script.contains("RUN+=\\\"/usr/bin/amixer -c %%n -q cset name='$control Playback Volume' 100%%%%\\\""), "{script}");
        assert!(script.contains("> /etc/udev/rules.d/90-gryonixnexus-usb-speaker-level.rules"), "{script}");
        assert!(script.contains("/var/lib/gryonixnexus/usb-level/shairport-sync.rule"), "{script}");
    }

    #[test]
    fn without_a_chosen_control_the_card_is_asked() {
        let script = setup_script("raspotify", "hw:CARD=T8,DEV=0", "");
        assert!(script.contains("amixer -c T8 controls"), "{script}");
        assert!(script.contains("Playback Volume'.*/\\1/p"), "{script}");
        assert!(!script.contains("control='"), "{script}");
    }

    #[test]
    fn a_card_that_is_not_raw_removes_the_services_share() {
        let script = setup_script("shairport-sync", "hdmi:CARD=vc4hdmi0,DEV=0", "");
        assert!(script.starts_with("rm -f /var/lib/gryonixnexus/usb-level/shairport-sync.rule\n"), "{script}");
        assert!(script.contains("else\n  rm -f /etc/udev/rules.d/90-gryonixnexus-usb-speaker-level.rules\nfi"), "{script}");
        assert!(!script.contains("amixer"), "{script}");
    }

    #[test]
    fn a_control_name_cannot_break_the_rule() {
        assert!(plain_control("PCM"));
        assert!(plain_control("Speaker Playback"));
        for bad in ["", "a'b", "a\"b", "a;b", "a$b", "a%b"] {
            assert!(!plain_control(bad), "{bad:?}");
        }
        assert!(!setup_script("raspotify", "hw:CARD=T8,DEV=0", "a'b").contains("control='a'b'"));
    }
}
