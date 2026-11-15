//! Reads and changes the settings of the hub's own players.

use std::collections::BTreeMap;

use tokio::io::AsyncWriteExt;

pub const PATH: &str = "/gryonixnexus/settings";

mod catalog;

use catalog::{Setting, Syntax, SETTINGS};

const ACCOUNT: &str = "odio";
const RUN_LIMIT: std::time::Duration = std::time::Duration::from_secs(15);

const PRELUDE: &str = "set -eu\nhome=\"$(getent passwd odio | cut -d: -f6)\"\n[ -n \"$home\" ] || { echo 'the odio user is missing' >&2; exit 1; }\nfield() { sed -n \"s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*\\\"\\{0,1\\}\\([^\\\";]*\\)\\\"\\{0,1\\};\\{0,1\\}[[:space:]]*$/\\1/p\" \"$1\" | head -n 1; }\nmpd_field() { sed -n \"s/^[[:space:]]*$2[[:space:]][[:space:]]*\\\"\\([^\\\"]*\\)\\\".*$/\\1/p\" \"$1\" | head -n 1; }\nas_odio() { runuser -u odio -- \"$@\"; }\n";

/// Prints each setting of an installed player as id=value
pub fn read_script() -> String {
    let mut script = PRELUDE.to_string();
    for setting in SETTINGS {
        let reader = if setting.syntax == Syntax::Mpd { "mpd_field" } else { "field" };
        script.push_str(&format!(
            "[ -f \"$home/{file}\" ] && command -v {program} >/dev/null && echo \"{id}=$({reader} \"$home/{file}\" {key})\"\n",
            file = setting.file,
            program = catalog::program(setting.file),
            id = setting.id,
            key = setting.key
        ));
    }
    script.push_str("exit 0\n");
    script
}

/// The line a setting takes in its file
fn line(setting: &Setting, value: &str) -> String {
    let value = if setting.syntax == Syntax::Ini && value == "yes" { "true" } else { value };
    let value = if setting.quoted { format!("\"{value}\"") } else { value.to_string() };
    match setting.syntax {
        Syntax::Libconfig(_) => format!("\\t{} = {value};", setting.key),
        Syntax::Ini => format!("{} = {value}", setting.key),
        Syntax::Mpd => format!("{} {value}", setting.key),
    }
}

/// The sed address of the line holding a key
fn key_pattern(setting: &Setting) -> String {
    match setting.syntax {
        Syntax::Mpd => format!("^[[:space:]]*{}[[:space:]]", setting.key),
        _ => format!("^[[:space:]]*{}[[:space:]]*=", setting.key),
    }
}

/// The sed command adding a missing key
fn insertion(setting: &Setting, line: &str) -> String {
    match setting.syntax {
        Syntax::Libconfig(block) => format!("/^{block}[[:space:]]*=/,/^}};/ s|^{{[[:space:]]*$|{{\\n{line}|"),
        Syntax::Ini => format!("s|^\\[global\\][[:space:]]*$|[global]\\n{line}|"),
        Syntax::Mpd => format!("$ a\\\n{line}"),
    }
}

/// Rewrites, adds or removes one key
fn change_step(setting: &Setting, value: &str) -> String {
    let (file, pattern) = (setting.file, key_pattern(setting));
    let guard = format!("f=\"$home/{file}\"\n[ -f \"$f\" ] || {{ echo '{id} is not installed here' >&2; exit 1; }}\n", id = setting.id);
    if value.is_empty() {
        return format!("{guard}as_odio sed -i '/{pattern}/d' \"$f\"\n");
    }
    let line = line(setting, value);
    format!(
        "{guard}if grep -q '{pattern}' \"$f\"; then\n  as_odio sed -i '0,/{pattern}.*/s||{line}|' \"$f\"\nelse\n  as_odio sed -i '{insertion}' \"$f\"\nfi\n",
        insertion = insertion(setting, &line)
    )
}

/// Writes the values, then restarts their players
pub fn write_script(asked: &BTreeMap<String, String>) -> Result<String, String> {
    let mut script = PRELUDE.to_string();
    let mut units: Vec<&str> = Vec::new();
    for (id, value) in asked {
        let value = catalog::checked(id, value)?;
        let setting = catalog::find(id).ok_or_else(|| format!("unknown setting {id}"))?;
        script.push_str(&change_step(setting, &value));
        if !units.contains(&setting.unit) {
            units.push(setting.unit);
        }
    }
    script.push_str(&format!("uid=\"$(id -u {ACCOUNT})\"\n"));
    for unit in units {
        script.push_str(&format!(
            "runuser -u {ACCOUNT} -- env XDG_RUNTIME_DIR=\"/run/user/$uid\" systemctl --user try-restart {unit} || true\n"
        ));
    }
    Ok(script)
}

/// The id=value lines as a JSON object
fn parsed(output: &str) -> String {
    let found: BTreeMap<&str, String> =
        output.lines().filter_map(|line| line.split_once('=')).map(|(id, value)| (id, catalog::shown(id, value))).collect();
    serde_json::to_string(&found).unwrap_or_default()
}

fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

/// Runs a script outside the sandbox, returning what it printed
async fn run(script: &str) -> Result<String, String> {
    let mut child = tokio::process::Command::new(systemd_run_bin())
        .args(["--quiet", "--collect", "--wait", "--pipe", "--service-type=oneshot", "/bin/sh", "-s"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run systemd-run: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await.map_err(|err| err.to_string())?;
    }
    let output = tokio::time::timeout(RUN_LIMIT, child.wait_with_output())
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Answers a read or a change of the settings
pub async fn handle(method: &str, body: &str) -> Result<String, String> {
    if method == "POST" {
        let asked: BTreeMap<String, String> = serde_json::from_str(body).map_err(|err| err.to_string())?;
        let script = match write_script(&asked) {
            Ok(script) => script,
            Err(why) => return Ok(serde_json::json!({ "status": 400, "body": why }).to_string()),
        };
        run(&script).await?;
    }
    let settings = parsed(&run(&read_script()).await?);
    Ok(serde_json::json!({ "status": 200, "body": settings }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(id, value)| (id.to_string(), value.to_string())).collect()
    }

    #[test]
    fn names_with_spaces_pass_and_shell_characters_do_not() {
        use catalog::checked;
        assert_eq!(checked("spotify.name", " Living room ").unwrap(), "Living room");
        assert_eq!(checked("airplay.name", "Küche 2").unwrap(), "Küche 2");
        for bad in ["", "a\"b", "$(x)", "a`b", "a'b", "a|b", "a;b", "a/b", "%h"] {
            assert!(checked("airplay.name", bad).is_err(), "{bad:?}");
        }
        assert!(checked("spotify.name", &"x".repeat(41)).is_err());
    }

    #[test]
    fn numbers_and_switches_take_only_their_values() {
        use catalog::checked;
        assert!(checked("spotify.bitrate", "320").is_ok());
        assert!(checked("spotify.bitrate", "128").is_err());
        assert_eq!(checked("spotify.normalise", "true").unwrap(), "yes");
        assert_eq!(checked("spotify.normalise", "").unwrap(), "");
        assert!(checked("spotify.normalise", "maybe").is_err());
        assert!(checked("spotify.volume", "100").is_ok());
        assert!(checked("spotify.volume", "101").is_err());
        assert!(checked("airplay.drift_tolerance_in_seconds", "0.005").is_ok());
        assert!(checked("airplay.drift_tolerance_in_seconds", "1e-3").is_err());
        assert!(checked("airplay.name", "").is_err());
        assert!(checked("mpd.port", "x").is_err());
    }

    #[test]
    fn each_file_gets_its_own_spelling() {
        let script = write_script(&asked(&[
            ("airplay.session_timeout", "60"),
            ("airplay.ignore_volume_control", "yes"),
            ("spotify.autoplay", "yes"),
            ("mpd.replaygain", "album"),
            ("airplay.interpolation", ""),
        ]))
        .unwrap();
        assert!(script.contains("/^sessioncontrol[[:space:]]*=/,/^};/ s|^{[[:space:]]*$|{\\n\\tsession_timeout = 60;|"), "{script}");
        assert!(script.contains("s||\\tignore_volume_control = \"yes\";|"), "{script}");
        assert!(script.contains("s||autoplay = true|"), "{script}");
        assert!(script.contains("s||replaygain \"album\"|"), "{script}");
        assert!(script.contains("as_odio sed -i '/^[[:space:]]*interpolation[[:space:]]*=/d'"), "{script}");
        assert!(script.contains("try-restart mpd.service"), "{script}");
    }

    #[test]
    fn a_change_rewrites_its_key_and_restarts_only_its_player() {
        let script = write_script(&asked(&[("spotify.name", "Living room"), ("spotify.bitrate", "160")])).unwrap();
        assert!(script.contains("s||device_name = \"Living room\"|"), "{script}");
        assert_eq!(script.matches("as_odio sed -i").count(), 4, "the files must stay the hub's own: {script}");
        assert!(script.contains("s||bitrate = 160|"), "{script}");
        assert_eq!(script.matches("try-restart spotifyd.service").count(), 1, "{script}");
        assert!(!script.contains("shairport-sync.service"), "{script}");
        let airplay = write_script(&asked(&[("airplay.name", "Hall")])).unwrap();
        assert!(airplay.contains("s||\\tname = \"Hall\";|"), "{airplay}");
        assert!(airplay.contains("try-restart shairport-sync.service"), "{airplay}");
    }

    #[test]
    fn a_bad_value_stops_the_whole_change() {
        assert!(write_script(&asked(&[("spotify.name", "ok"), ("spotify.volume", "900")])).is_err());
    }

    #[test]
    fn the_reading_becomes_an_object_of_what_is_installed() {
        assert_eq!(parsed("spotify.name=example\nspotify.bitrate=320\n"), r#"{"spotify.bitrate":"320","spotify.name":"example"}"#);
        assert_eq!(parsed("spotify.normalise=true\nmpd.auto_update=no\n"), r#"{"mpd.auto_update":"","spotify.normalise":"yes"}"#);
        assert_eq!(parsed(""), "{}");
        assert!(read_script().contains("command -v shairport-sync >/dev/null && echo \"airplay.name=$(field \"$home/.config/shairport-sync/shairport-sync.conf\" name)\""));
    }
}
