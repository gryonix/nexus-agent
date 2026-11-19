//! Outgoing-mail settings shared by the services that send mail:
//! the compose environment lines, and the password kept in `.env`.

use std::path::Path;

use super::app_settings::{self, SECRET_CLEAR};
use super::context::Input;

/// How one service names its mail variables
pub struct Names {
    pub service: &'static str,
    pub fixed: &'static [(&'static str, &'static str)],
    pub host: &'static str,
    pub port: &'static str,
    pub security: &'static str,
    pub security_values: [&'static str; 3],
    pub username: &'static str,
    pub password: &'static str,
    pub from: &'static str,
}

const ENV_PASSWORD: &str = "SMTP_PASSWORD";

fn setting<'a>(input: &'a Input, service: &str, name: &str) -> &'a str {
    app_settings::value(input, &format!("{service}_smtp_{name}"))
}

fn line(name: &str, value: &str) -> String {
    format!("\n      {name}: \"{value}\"")
}

fn security_value(input: &Input, names: &Names) -> &'static str {
    let index = match setting(input, names.service, "security") {
        "ssl" => 1,
        "none" => 2,
        _ => 0,
    };
    names.security_values[index]
}

/// Environment lines; empty until a mail host is set
pub fn env_lines(input: &Input, names: &Names) -> String {
    let host = setting(input, names.service, "host");
    if host.is_empty() {
        return String::new();
    }
    let mut out: String = names.fixed.iter().map(|(name, value)| line(name, value)).collect();
    out += &line(names.host, host);
    out += &line(names.port, setting(input, names.service, "port"));
    out += &line(names.security, security_value(input, names));
    let from = setting(input, names.service, "from");
    if !from.is_empty() {
        out += &line(names.from, from);
    }
    let username = setting(input, names.service, "username");
    if !username.is_empty() {
        out += &line(names.username, username);
        out += &format!("\n      {}: ${{{ENV_PASSWORD}:-}}", names.password);
    }
    out
}

/// Writes or clears the password in `.env`; empty keeps it
pub fn store_password(env: &Path, input: &Input, service: &str) -> Result<(), String> {
    let key = format!("{service}_smtp_password");
    let Some(sent) = input.app_settings.get(&key) else { return Ok(()) };
    let stored = if sent == SECRET_CLEAR { String::new() } else { format!("'{sent}'") };
    super::llm_keys::set_env_value(env, ENV_PASSWORD, &stored)
        .map_err(|err| format!("could not write the mail password: {err:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const NAMES: Names = Names {
        service: "vaultwarden", fixed: &[], host: "H", port: "P", security: "S",
        security_values: ["a", "b", "c"], username: "U", password: "W", from: "F",
    };

    fn input(pairs: &[(&str, &str)]) -> Input {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Input { app_settings: app_settings::accept(&map), ..Input::default() }
    }

    #[test]
    fn nothing_is_written_without_a_host() {
        assert_eq!(env_lines(&input(&[("vaultwarden_smtp_port", "25")]), &NAMES), "");
    }

    #[test]
    fn the_password_line_needs_a_username_and_never_holds_the_secret() {
        let with = input(&[("vaultwarden_smtp_host", "mx.example.com"), ("vaultwarden_smtp_username", "me"),
                           ("vaultwarden_smtp_password", "s3cret")]);
        let text = env_lines(&with, &NAMES);
        assert!(text.contains("\n      W: ${SMTP_PASSWORD:-}"));
        assert!(!text.contains("s3cret"));
        let bare = input(&[("vaultwarden_smtp_host", "mx.example.com")]);
        assert!(!env_lines(&bare, &NAMES).contains("W:"));
    }

    #[test]
    fn security_maps_to_the_service_values() {
        let ssl = input(&[("vaultwarden_smtp_host", "h"), ("vaultwarden_smtp_security", "ssl")]);
        assert!(env_lines(&ssl, &NAMES).contains("S: \"b\""));
    }

    #[test]
    fn the_password_is_stored_quoted_kept_when_absent_and_cleared_on_request() {
        let dir = std::env::temp_dir().join(format!("smtp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join(".env");
        store_password(&env, &input(&[("vaultwarden_smtp_password", "p@ss w$rd")]), "vaultwarden").unwrap();
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "SMTP_PASSWORD='p@ss w$rd'\n");
        store_password(&env, &input(&[("vaultwarden_smtp_password", "")]), "vaultwarden").unwrap();
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "SMTP_PASSWORD='p@ss w$rd'\n");
        store_password(&env, &input(&[("vaultwarden_smtp_password", SECRET_CLEAR)]), "vaultwarden").unwrap();
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "SMTP_PASSWORD=\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsafe_values_are_dropped() {
        let bad = input(&[("vaultwarden_smtp_host", "a b"), ("vaultwarden_smtp_username", "x\"y"),
                          ("vaultwarden_smtp_from", "a\nb"), ("vaultwarden_smtp_password", "it's")]);
        assert!(bad.app_settings.is_empty());
    }
}
