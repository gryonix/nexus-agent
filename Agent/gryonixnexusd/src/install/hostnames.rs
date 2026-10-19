//! The name a service answers on when nobody typed one

struct Group {
    shared: &'static str,
    own: &'static [(&'static str, &'static str)],
}

const GROUPS: &[Group] = &[
    Group {
        shared: "vault",
        own: &[
            ("vaultwarden", "vaultwarden"),
            ("psono", "psono"),
            ("passbolt", "passbolt"),
        ],
    },
    Group {
        shared: "files",
        own: &[("nextcloud", "nextcloud"), ("seafile", "seafile")],
    },
    Group {
        shared: "photos",
        own: &[("immich", "immich"), ("photoprism", "photoprism")],
    },
    Group {
        shared: "dns",
        own: &[("adguard-home", "adguard"), ("pihole", "pihole")],
    },
    Group {
        shared: "git",
        own: &[("forgejo", "forgejo"), ("gitlab", "gitlab")],
    },
    Group {
        shared: "ai",
        own: &[
            ("open-webui", "openwebui"),
            ("anythingllm", "anythingllm"),
            ("litellm", "litellm"),
            ("openclaw", "openclaw"),
        ],
    },
];

/// Services that share their plain name with nobody.
const SOLE: &[(&str, &str)] = &[
    ("jellyfin", "media"),
    ("home-assistant", "home"),
    ("zigbee2mqtt", "zigbee"),
    ("authelia", "auth"),
    ("homepage", "start"),
    ("headscale", "mesh"),
    ("crafty-controller", "mc"),
    ("n8n", "flows"),
];

/// The label this service answers on, without the domain
pub fn label(service_id: &str, installed: &[String]) -> String {
    let group = GROUPS
        .iter()
        .find(|group| group.own.iter().any(|(id, _)| *id == service_id));
    let Some(group) = group else {
        return SOLE
            .iter()
            .find(|(id, _)| *id == service_id)
            .map(|(_, label)| (*label).to_string())
            .unwrap_or_else(|| service_id.to_string());
    };
    let present = group
        .own
        .iter()
        .filter(|(id, _)| *id == service_id || installed.iter().any(|other| other == id))
        .count();
    if present <= 1 {
        return group.shared.to_string();
    }
    group
        .own
        .iter()
        .find(|(id, _)| *id == service_id)
        .map(|(_, label)| (*label).to_string())
        .unwrap_or_else(|| service_id.to_string())
}

pub fn default_hostname(service_id: &str, domain: &str, installed: &[String]) -> String {
    format!("{}.{}", label(service_id, installed), domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|id| (*id).to_string()).collect()
    }

    #[test]
    fn one_service_on_a_shelf_takes_the_plain_name() {
        assert_eq!(label("immich", &ids(&["immich"])), "photos");
        assert_eq!(label("nextcloud", &[]), "files");
        assert_eq!(label("open-webui", &ids(&["open-webui", "ollama", "qdrant"])), "ai");
        assert_eq!(label("openclaw", &ids(&["openclaw"])), "ai");
    }

    #[test]
    fn two_on_a_shelf_each_say_which_one_they_are() {
        let photos = ids(&["immich", "photoprism"]);
        assert_eq!(label("immich", &photos), "immich");
        assert_eq!(label("photoprism", &photos), "photoprism");

        let dns = ids(&["adguard-home", "pihole"]);
        assert_eq!(label("adguard-home", &dns), "adguard");
        assert_eq!(label("pihole", &dns), "pihole");
    }

    #[test]
    fn the_two_dns_filters_never_share_a_name() {
        let both = ids(&["adguard-home", "pihole"]);
        assert_ne!(
            default_hostname("adguard-home", "example.com", &both),
            default_hostname("pihole", "example.com", &both)
        );
    }

    #[test]
    fn nothing_claims_the_agent_name() {
        let everything: Vec<String> = GROUPS
            .iter()
            .flat_map(|group| group.own.iter().map(|(id, _)| (*id).to_string()))
            .chain(SOLE.iter().map(|(id, _)| (*id).to_string()))
            .collect();
        for id in &everything {
            assert_ne!(label(id, &[]), "agent", "{id} alone");
            assert_ne!(label(id, &everything), "agent", "{id} crowded");
        }
    }

    #[test]
    fn services_with_no_shelf_mate_keep_their_own_name() {
        assert_eq!(label("jellyfin", &ids(&["jellyfin", "immich"])), "media");
        assert_eq!(label("n8n", &[]), "flows");
        assert_eq!(label("home-assistant", &ids(&["home-assistant", "jellyfin"])), "home");
    }
}
