//! App settings a client changes after install: accepted keys, defaults.
//! Only whitelisted values reach a compose file; anything else is ignored.

use std::collections::{BTreeMap, HashMap};

use super::context::Input;

/// Which values a setting accepts
pub enum Allowed {
    Switch,
    Choices(&'static [&'static str]),
}

pub struct Spec {
    pub key: &'static str,
    pub default: &'static str,
    pub allowed: Allowed,
}

const UPLOAD_LIMITS: &[&str] = &["512M", "1G", "2G", "4G", "16G"];
const MEMORY_LIMITS: &[&str] = &["512M", "1G", "2G", "4G"];

pub const SPECS: &[Spec] = &[
    Spec { key: "vaultwarden_invitations_allowed", default: "true", allowed: Allowed::Switch },
    Spec { key: "forgejo_open_registration", default: "false", allowed: Allowed::Switch },
    Spec { key: "forgejo_require_signin", default: "false", allowed: Allowed::Switch },
    Spec { key: "nextcloud_upload_limit", default: "512M", allowed: Allowed::Choices(UPLOAD_LIMITS) },
    Spec { key: "nextcloud_memory_limit", default: "512M", allowed: Allowed::Choices(MEMORY_LIMITS) },
];

fn spec(key: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.key == key)
}

fn is_valid(spec: &Spec, value: &str) -> bool {
    match spec.allowed {
        Allowed::Switch => value == "true" || value == "false",
        Allowed::Choices(options) => options.contains(&value),
    }
}

/// The known, valid settings out of a request's key-value map
pub fn accept(settings: &HashMap<String, String>) -> BTreeMap<String, String> {
    SPECS
        .iter()
        .filter_map(|spec| {
            let value = settings.get(spec.key)?.trim();
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
            input.app_settings = accept(&request(&[(key, value)]));
            assert_eq!(input.app_settings.len(), 1, "{key}={value} must be accepted");
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
}
