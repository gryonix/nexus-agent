//! Game-server and extra access settings that only change compose env lines.

use super::app_settings::{is_changed, value, Allowed, Spec, Validator};
use super::context::Input;

const DIFFICULTIES: &[&str] = &["peaceful", "easy", "normal", "hard"];
const BEDROCK_MODES: &[&str] = &["survival", "creative", "adventure"];
const JAVA_MODES: &[&str] = &["survival", "creative", "adventure", "spectator"];
const PLAYERS: &[&str] = &["5", "10", "20", "50", "100"];
const VIEW_DISTANCES: &[&str] = &["6", "10", "12", "16", "24"];
const ORG_CREATION: &[&str] = &["all", "none"];
const BODY_LIMITS: &[&str] = &["1073741824", "2147483648", "4294967296", "17179869184", "0"];

pub const SPECS: &[Spec] = &[
    Spec { key: "minecraft_java_difficulty", default: "easy", allowed: Allowed::Choices(DIFFICULTIES) },
    Spec { key: "minecraft_java_gamemode", default: "survival", allowed: Allowed::Choices(JAVA_MODES) },
    Spec { key: "minecraft_java_max_players", default: "20", allowed: Allowed::Choices(PLAYERS) },
    Spec { key: "minecraft_java_online_mode", default: "true", allowed: Allowed::Switch },
    Spec { key: "minecraft_java_enable_whitelist", default: "false", allowed: Allowed::Switch },
    Spec { key: "minecraft_java_pvp", default: "true", allowed: Allowed::Switch },
    Spec { key: "minecraft_java_motd", default: "", allowed: Allowed::Text(59, Validator::Name) },
    Spec { key: "minecraft_java_view_distance", default: "10", allowed: Allowed::Choices(VIEW_DISTANCES) },
    Spec { key: "minecraft_bedrock_difficulty", default: "easy", allowed: Allowed::Choices(DIFFICULTIES) },
    Spec { key: "minecraft_bedrock_gamemode", default: "survival", allowed: Allowed::Choices(BEDROCK_MODES) },
    Spec { key: "minecraft_bedrock_max_players", default: "10", allowed: Allowed::Choices(PLAYERS) },
    Spec { key: "minecraft_bedrock_allow_cheats", default: "false", allowed: Allowed::Switch },
    Spec { key: "minecraft_bedrock_online_mode", default: "true", allowed: Allowed::Switch },
    Spec { key: "minecraft_bedrock_server_name", default: "", allowed: Allowed::Text(59, Validator::Name) },
    Spec { key: "vaultwarden_signups_domains", default: "", allowed: Allowed::Text(500, Validator::HostList) },
    Spec { key: "vaultwarden_show_password_hint", default: "false", allowed: Allowed::Switch },
    Spec { key: "vaultwarden_org_creation", default: "all", allowed: Allowed::Choices(ORG_CREATION) },
    Spec { key: "forgejo_disable_gravatar", default: "false", allowed: Allowed::Switch },
    Spec { key: "forgejo_keep_email_private", default: "false", allowed: Allowed::Switch },
    Spec { key: "forgejo_push_to_create", default: "false", allowed: Allowed::Switch },
    Spec { key: "nextcloud_body_limit", default: "1073741824", allowed: Allowed::Choices(BODY_LIMITS) },
];

pub const JAVA_ENV: &[(&str, &str)] = &[
    ("DIFFICULTY", "minecraft_java_difficulty"), ("MODE", "minecraft_java_gamemode"),
    ("MAX_PLAYERS", "minecraft_java_max_players"), ("ONLINE_MODE", "minecraft_java_online_mode"),
    ("ENABLE_WHITELIST", "minecraft_java_enable_whitelist"), ("PVP", "minecraft_java_pvp"),
    ("MOTD", "minecraft_java_motd"), ("VIEW_DISTANCE", "minecraft_java_view_distance"),
];

pub const BEDROCK_ENV: &[(&str, &str)] = &[
    ("DIFFICULTY", "minecraft_bedrock_difficulty"), ("GAMEMODE", "minecraft_bedrock_gamemode"),
    ("MAX_PLAYERS", "minecraft_bedrock_max_players"), ("ALLOW_CHEATS", "minecraft_bedrock_allow_cheats"),
    ("ONLINE_MODE", "minecraft_bedrock_online_mode"), ("SERVER_NAME", "minecraft_bedrock_server_name"),
];

pub const VAULTWARDEN_ENV: &[(&str, &str)] = &[
    ("SIGNUPS_DOMAINS_WHITELIST", "vaultwarden_signups_domains"),
    ("SHOW_PASSWORD_HINT", "vaultwarden_show_password_hint"),
    ("ORG_CREATION_USERS", "vaultwarden_org_creation"),
];

pub const FORGEJO_ENV: &[(&str, &str)] = &[
    ("FORGEJO__picture__DISABLE_GRAVATAR", "forgejo_disable_gravatar"),
    ("FORGEJO__service__DEFAULT_KEEP_EMAIL_PRIVATE", "forgejo_keep_email_private"),
    ("FORGEJO__repository__ENABLE_PUSH_CREATE_USER", "forgejo_push_to_create"),
];

/// Changed settings as env lines, newline first
pub fn env_lines(input: &Input, table: &[(&str, &str)]) -> String {
    table
        .iter()
        .filter(|(_, key)| is_changed(input, key))
        .map(|(variable, key)| format!("\n      {variable}: \"{}\"", value(input, key)))
        .collect()
}

/// The same lines, newline last
pub fn env_lines_trailing(input: &Input, table: &[(&str, &str)]) -> String {
    let lines = env_lines(input, table);
    lines.strip_prefix('\n').map_or(String::new(), |rest| format!("{rest}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(pairs: &[(&str, &str)]) -> Input {
        let mut input = Input::default();
        for (key, val) in pairs {
            input.app_settings.insert(key.to_string(), val.to_string());
        }
        input
    }

    #[test]
    fn only_changed_values_are_written() {
        let input = with(&[("minecraft_java_pvp", "false"), ("minecraft_java_difficulty", "easy")]);
        assert_eq!(env_lines(&input, JAVA_ENV), "\n      PVP: \"false\"");
        assert_eq!(env_lines(&Input::default(), JAVA_ENV), "");
    }

    #[test]
    fn the_trailing_form_ends_each_line() {
        let input = with(&[("vaultwarden_show_password_hint", "true"), ("vaultwarden_org_creation", "none")]);
        assert_eq!(
            env_lines_trailing(&input, VAULTWARDEN_ENV),
            "      SHOW_PASSWORD_HINT: \"true\"\n      ORG_CREATION_USERS: \"none\"\n"
        );
        assert_eq!(env_lines_trailing(&Input::default(), VAULTWARDEN_ENV), "");
    }

    #[test]
    fn every_table_key_has_a_spec() {
        for table in [JAVA_ENV, BEDROCK_ENV, VAULTWARDEN_ENV, FORGEJO_ENV] {
            for (_, key) in table {
                assert!(SPECS.iter().any(|spec| spec.key == *key), "{key}");
            }
        }
    }
}
