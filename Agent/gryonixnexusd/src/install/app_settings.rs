//! App settings a client changes after install: accepted keys, defaults.
//! Only whitelisted values reach a compose file; anything else is ignored.

use std::collections::{BTreeMap, HashMap};

use super::context::Input;

/// Which values a setting accepts
pub enum Allowed {
    Switch,
    Choices(&'static [&'static str]),
    Text(usize, Validator),
    Secret,
}

#[derive(Clone, Copy)]
pub enum Validator {
    Host,
    Line,
}

/// A secret value that removes the stored one
pub const SECRET_CLEAR: &str = "\u{0}clear";
const SECRET_MAX_LEN: usize = 256;
const SECURITY: &[&str] = &["starttls", "ssl", "none"];
const SMTP_PORTS: &[&str] = &["25", "465", "587"];

pub struct Spec {
    pub key: &'static str,
    pub default: &'static str,
    pub allowed: Allowed,
}

const UPLOAD_LIMITS: &[&str] = &["512M", "1G", "2G", "4G", "16G"];
const MEMORY_LIMITS: &[&str] = &["512M", "1G", "2G", "4G"];
const PRIVACY_LEVELS: &[&str] = &["0", "1", "2", "3"];

pub const SPECS: &[Spec] = &[
    Spec { key: "vaultwarden_invitations_allowed", default: "true", allowed: Allowed::Switch },
    Spec { key: "forgejo_open_registration", default: "false", allowed: Allowed::Switch },
    Spec { key: "forgejo_require_signin", default: "false", allowed: Allowed::Switch },
    Spec { key: "nextcloud_upload_limit", default: "512M", allowed: Allowed::Choices(UPLOAD_LIMITS) },
    Spec { key: "nextcloud_memory_limit", default: "512M", allowed: Allowed::Choices(MEMORY_LIMITS) },
    Spec { key: "vaultwarden_smtp_host", default: "", allowed: Allowed::Text(253, Validator::Host) },
    Spec { key: "vaultwarden_smtp_port", default: "587", allowed: Allowed::Choices(SMTP_PORTS) },
    Spec { key: "vaultwarden_smtp_security", default: "starttls", allowed: Allowed::Choices(SECURITY) },
    Spec { key: "vaultwarden_smtp_username", default: "", allowed: Allowed::Text(254, Validator::Line) },
    Spec { key: "vaultwarden_smtp_password", default: "", allowed: Allowed::Secret },
    Spec { key: "vaultwarden_smtp_from", default: "", allowed: Allowed::Text(254, Validator::Line) },
    Spec { key: "forgejo_smtp_host", default: "", allowed: Allowed::Text(253, Validator::Host) },
    Spec { key: "forgejo_smtp_port", default: "587", allowed: Allowed::Choices(SMTP_PORTS) },
    Spec { key: "forgejo_smtp_security", default: "starttls", allowed: Allowed::Choices(SECURITY) },
    Spec { key: "forgejo_smtp_username", default: "", allowed: Allowed::Text(254, Validator::Line) },
    Spec { key: "forgejo_smtp_password", default: "", allowed: Allowed::Secret },
    Spec { key: "forgejo_smtp_from", default: "", allowed: Allowed::Text(254, Validator::Line) },
    Spec { key: "n8n_smtp_host", default: "", allowed: Allowed::Text(253, Validator::Host) },
    Spec { key: "n8n_smtp_port", default: "587", allowed: Allowed::Choices(SMTP_PORTS) },
    Spec { key: "n8n_smtp_security", default: "starttls", allowed: Allowed::Choices(SECURITY) },
    Spec { key: "n8n_smtp_username", default: "", allowed: Allowed::Text(254, Validator::Line) },
    Spec { key: "n8n_smtp_password", default: "", allowed: Allowed::Secret },
    Spec { key: "n8n_smtp_from", default: "", allowed: Allowed::Text(254, Validator::Line) },
    Spec { key: "pihole_dnssec", default: "false", allowed: Allowed::Switch },
    Spec { key: "pihole_privacy_level", default: "0", allowed: Allowed::Choices(PRIVACY_LEVELS) },
    Spec { key: "pihole_query_logging", default: "true", allowed: Allowed::Switch },
];

fn spec(key: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.key == key)
}

fn is_valid(spec: &Spec, value: &str) -> bool {
    match spec.allowed {
        Allowed::Switch => value == "true" || value == "false",
        Allowed::Choices(options) => options.contains(&value),
        Allowed::Text(max, validator) => value.len() <= max && text_is_safe(validator, value),
        Allowed::Secret => value == SECRET_CLEAR || secret_is_safe(value),
    }
}

fn text_is_safe(validator: Validator, value: &str) -> bool {
    match validator {
        Validator::Host => value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_')),
        Validator::Line => !value.chars().any(|c| c.is_control() || matches!(c, '"' | '\'' | '\\' | '$' | '`' | '#')),
    }
}

fn secret_is_safe(value: &str) -> bool {
    !value.is_empty() && value.len() <= SECRET_MAX_LEN && !value.chars().any(|c| c.is_control() || c == '\'')
}

/// Secrets keep their exact text; others are trimmed
fn clean<'a>(spec: &Spec, value: &'a str) -> &'a str {
    if matches!(spec.allowed, Allowed::Secret) { value } else { value.trim() }
}

/// The known, valid settings out of a request's key-value map
pub fn accept(settings: &HashMap<String, String>) -> BTreeMap<String, String> {
    SPECS
        .iter()
        .filter_map(|spec| {
            let value = clean(spec, settings.get(spec.key)?);
            is_valid(spec, value).then(|| (spec.key.to_string(), value.to_string()))
        })
        .collect()
}

/// The stored value, or the setting's default
pub fn value<'a>(input: &'a Input, key: &str) -> &'a str {
    let fallback = spec(key).map_or("", |spec| spec.default);
    input.app_settings.get(key).map_or(fallback, String::as_str)
}

pub fn is_on(input: &Input, key: &str) -> bool {
    value(input, key) == "true"
}

/// True when the value differs from the setting's default
pub fn is_changed(input: &Input, key: &str) -> bool {
    input.app_settings.contains_key(key) && value(input, key) != spec(key).map_or("", |spec| spec.default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn an_absent_key_reads_as_its_default() {
        let input = Input::default();
        assert!(is_on(&input, "vaultwarden_invitations_allowed"));
        assert_eq!(value(&input, "nextcloud_upload_limit"), "512M");
        assert!(!is_changed(&input, "nextcloud_upload_limit"));
    }

    #[test]
    fn valid_values_are_kept_and_invalid_ones_dropped() {
        let accepted = accept(&request(&[
            ("forgejo_open_registration", " true "),
            ("nextcloud_upload_limit", "4G"),
            ("nextcloud_memory_limit", "4G\nevil: 1"),
            ("vaultwarden_invitations_allowed", "yes"),
            ("unknown_key", "true"),
        ]));
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted["forgejo_open_registration"], "true");
        assert_eq!(accepted["nextcloud_upload_limit"], "4G");
    }

    #[test]
    fn the_default_written_out_is_not_a_change() {
        let mut input = Input::default();
        input.app_settings = accept(&request(&[("nextcloud_upload_limit", "512M")]));
        assert!(!is_changed(&input, "nextcloud_upload_limit"));
        input.app_settings = accept(&request(&[("nextcloud_upload_limit", "1G")]));
        assert!(is_changed(&input, "nextcloud_upload_limit"));
    }

    fn compose_for(service: &str, input: &Input) -> String {
        match service {
            "vaultwarden" => super::super::vaultwarden::compose_contents(input),
            "forgejo" => super::super::forgejo::compose_contents(input),
            "nextcloud" => super::super::nextcloud::compose_contents(input),
            "n8n" => super::super::n8n::compose_contents(input),
            "pihole" => super::super::pihole::compose_contents(input),
            other => panic!("no compose for {other}"),
        }
    }

    fn input_for(variant: &serde_json::Value) -> Input {
        let mut input = Input {
            domain: "example.com".to_string(),
            additional_domains: vec!["example.org".to_string()],
            installed_services: super::super::golden::service_ids(),
            ..Input::default()
        };
        let (key, value) = (variant["key"].as_str().unwrap(), variant["value"].as_str().unwrap());
        if key == "vaultwarden_allow_signups" {
            input.vaultwarden_allow_signups = value == "true";
        } else {
            let mut pairs = vec![(key, value)];
            let given = variant["given"].as_object().cloned().unwrap_or_default();
            pairs.extend(given.iter().map(|(k, v)| (k.as_str(), v.as_str().unwrap())));
            input.app_settings = accept(&request(&pairs));
            assert_eq!(input.app_settings.len(), pairs.len(), "{key}={value} must be accepted");
        }
        input
    }

    #[test]
    fn every_setting_variant_matches_what_swift_generates() {
        let variants = super::super::golden::app_setting_variants();
        assert!(!variants.is_empty());
        for variant in &variants {
            let service = variant["service"].as_str().unwrap();
            let label = format!("{}={}", variant["key"], variant["value"]);
            assert_eq!(compose_for(service, &input_for(variant)), variant["composeContents"].as_str().unwrap(), "{label}");
        }
    }

    #[test]
    fn the_catalog_and_the_agent_agree_on_keys_and_defaults() {
        let variants = super::super::golden::app_setting_variants();
        for spec in SPECS {
            let seen: Vec<_> = variants.iter().filter(|v| v["key"] == spec.key).collect();
            assert!(!seen.is_empty(), "{} is missing from the catalog", spec.key);
            for variant in seen {
                assert_eq!(variant["defaultValue"], spec.default, "{}", spec.key);
                assert!(is_valid(spec, variant["value"].as_str().unwrap()), "{}", spec.key);
            }
        }
    }

    #[test]
    fn free_text_rejects_what_could_break_yaml_or_env() {
        for (key, bad) in [
            ("forgejo_smtp_host", "a b"), ("forgejo_smtp_host", "h\nx: 1"), ("n8n_smtp_username", "a\"b"),
            ("n8n_smtp_username", "a\\b"), ("n8n_smtp_from", "$(x)"), ("n8n_smtp_from", "a`b"),
            ("n8n_smtp_from", "a#b"), ("vaultwarden_smtp_password", "a\nb"), ("vaultwarden_smtp_password", "a'b"),
            ("vaultwarden_smtp_port", "26"), ("vaultwarden_smtp_security", "tls"),
        ] {
            assert!(accept(&request(&[(key, bad)])).is_empty(), "{key}={bad:?}");
        }
        let long = "a".repeat(300);
        assert!(accept(&request(&[("forgejo_smtp_host", &long)])).is_empty());
    }

    #[test]
    fn a_secret_is_kept_exact_the_clear_marker_passes_and_empty_is_dropped() {
        let kept = accept(&request(&[("n8n_smtp_password", " pa ss ")]));
        assert_eq!(kept["n8n_smtp_password"], " pa ss ");
        assert!(accept(&request(&[("n8n_smtp_password", SECRET_CLEAR)])).contains_key("n8n_smtp_password"));
        assert!(accept(&request(&[("n8n_smtp_password", "")])).is_empty());
    }

    #[test]
    fn an_empty_host_is_accepted_so_mail_can_be_switched_off() {
        assert_eq!(accept(&request(&[("n8n_smtp_host", "")]))["n8n_smtp_host"], "");
    }
}
