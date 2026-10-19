//! Authelia's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/AutheliaService.swift`

use super::caddy::{self, WebIngress};
use super::context::{AutheliaProtection, Input};

/// Exact pinned tag
pub const SERVICE_ID: &str = "authelia";

pub const IMAGE: &str = "ghcr.io/authelia/authelia:4.39.20";
pub const COMPOSE_PROJECT: &str = "authelia";
pub const CONTAINER: &str = "authelia";
/// Loopback port Caddy proxies to (8092 Pi-hole, 8093 Homepage).
pub const WEB_UI_PORT: u16 = 8094;
/// Port Authelia binds INSIDE the container — its own default.
pub const CONTAINER_WEB_PORT: u16 = 9091;

pub const DEFAULT_PROTECTED: &[&str] = &["adguard-home", "pihole", "homepage"];

pub fn hostname(input: &Input) -> String {
    if input.authelia_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.authelia_hostname.clone()
    }
}

/// The Caddy directive a protected site carries
pub fn forward_auth_block() -> String {
    format!(
        "forward_auth 127.0.0.1:{WEB_UI_PORT} {{\n        uri /api/authz/forward-auth\n        copy_headers Remote-User Remote-Groups Remote-Name Remote-Email\n    }}"
    )
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.authelia_path;
    format!(
        "services:\n  authelia:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # The 4.39 names. Every one of them can also be given in the\n      # file; they are here so the file itself carries no secret\n      # and can be read by whoever debugs a login failure.\n      AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET: ${{AUTHELIA_JWT_SECRET}}\n      AUTHELIA_SESSION_SECRET: ${{AUTHELIA_SESSION_SECRET}}\n      AUTHELIA_STORAGE_ENCRYPTION_KEY: ${{AUTHELIA_STORAGE_ENCRYPTION_KEY}}\n    volumes:\n      - {path}/config:/config\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_WEB_PORT}\""
    )
}

pub fn env_template() -> String {
    "AUTHELIA_JWT_SECRET=__RANDOM__\nAUTHELIA_SESSION_SECRET=__RANDOM__\nAUTHELIA_STORAGE_ENCRYPTION_KEY=__RANDOM__".to_string()
}

pub const NEVER_PROTECTED: &[&str] = &["headscale"];

pub fn protected_ids(input: &Input, services: &[String]) -> Vec<String> {
    let wanted: Vec<&str> = match &input.authelia_protected {
        AutheliaProtection::Default => DEFAULT_PROTECTED.to_vec(),
        // Explicit, including explicitly empty — see the field's own doc.
        AutheliaProtection::Explicit(ids) => ids.iter().map(String::as_str).collect(),
    };
    super::host::CATALOG_ORDER
        .iter()
        .filter(|id| {
            wanted.contains(id) && services.iter().any(|s| s == *id) && !NEVER_PROTECTED.contains(id)
        })
        .map(|id| (*id).to_string())
        .collect()
}

pub fn protected_hostnames(input: &Input, services: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    for id in protected_ids(input, services) {
        let Some(host) = super::catalog::web_hostname(&id, input) else { continue };
        names.push(host.clone());
        names.extend(input.mirrored_hostnames(&host));
    }
    names
}

pub fn configuration_yaml(input: &Input, services: &[String]) -> String {
    let portal = hostname(input);
    let names = protected_hostnames(input, services);
    let default_policy = if names.is_empty() { "two_factor" } else { "deny" };
    let rules = if names.is_empty() {
        "  rules: []".to_string()
    } else {
        let body: Vec<String> = names
            .iter()
            .map(|name| format!("    - domain: '{name}'\n      policy: one_factor"))
            .collect();
        format!("  rules:\n{}", body.join("\n"))
    };
    format!(
        "---\ntheme: light\nserver:\n  address: 'tcp://0.0.0.0:{CONTAINER_WEB_PORT}'\nlog:\n  level: info\nauthentication_backend:\n  file:\n    path: /config/users_database.yml\naccess_control:\n  # Anything not named below is not reachable through the portal. A\n  # permissive default here would put every future site behind SSO the\n  # day it is created, including the ones whose mobile apps cannot use\n  # it.\n  default_policy: {default_policy}\n{rules}\nsession:\n  cookies:\n{cookies}\nstorage:\n  local:\n    path: /config/db.sqlite3\nnotifier:\n  # A file, not mail: password reset is the only thing this notifies\n  # about, and a mail server is not something this deployment is\n  # guaranteed to have. The file is inside the config volume and\n  # readable only by root.\n  filesystem:\n    filename: /config/notification.txt",
        cookies = session_cookies(input, &portal)
    )
}

fn session_cookies(input: &Input, portal: &str) -> String {
    let mut portals = vec![portal.to_string()];
    portals.extend(input.mirrored_hostnames(portal));
    let mut domains = vec![input.domain.clone()];
    domains.extend(input.additional_domains.iter().cloned());
    domains
        .iter()
        .zip(portals.iter())
        .map(|(domain, url)| {
            format!("    - name: authelia_session\n      domain: '{domain}'\n      authelia_url: 'https://{url}'")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: false, upstream_https: false, public_paths: Vec::new() }
}

pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    /// The portal itself is never behind the guard — see `web_ingress`.
    #[test]
    fn the_portal_is_not_behind_the_admin_guard() {
        assert!(!web_ingress(&base("example.com")).admin_guard);
        assert!(!caddy_site(&base("example.com")).contains("admin-guard"));
    }

    #[test]
    fn only_installed_services_get_a_rule() {
        let input = base("example.com");
        let yaml = configuration_yaml(&input, &["authelia".to_string(), "adguard-home".to_string()]);
        assert!(yaml.contains("- domain: 'dns.example.com'"), "{yaml}");
        assert!(!yaml.contains("start.example.com"), "homepage is not installed here: {yaml}");
        assert!(yaml.contains("default_policy: deny"), "{yaml}");
    }

    #[test]
    fn nothing_protected_is_still_a_valid_file() {
        let input = base("example.com");
        let yaml = configuration_yaml(&input, &["authelia".to_string()]);
        assert!(yaml.contains("  rules: []"), "{yaml}");
        assert!(yaml.contains("default_policy: two_factor"), "{yaml}");
        assert!(!yaml.contains("default_policy: deny"), "deny with no rules will not start: {yaml}");
    }

    #[test]
    fn an_explicitly_empty_list_guards_nothing_while_an_absent_one_takes_the_default() {
        let installed = vec!["authelia".to_string(), "pihole".to_string()];

        let mut explicit = base("example.com");
        explicit.authelia_protected = AutheliaProtection::Explicit(Vec::new());
        assert!(protected_ids(&explicit, &installed).is_empty(),
                "unticking every service has to mean every service");

        let absent = base("example.com");
        assert_eq!(absent.authelia_protected, AutheliaProtection::Default);
        assert_eq!(protected_ids(&absent, &installed), vec!["pihole".to_string()],
                   "an app that never mentioned the setting still gets the default set");
    }

    #[test]
    fn mirrors_get_their_own_rule() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        let yaml = configuration_yaml(&input, &["authelia".to_string(), "adguard-home".to_string()]);
        assert!(yaml.contains("- domain: 'dns.example.com'"), "{yaml}");
        assert!(yaml.contains("- domain: 'dns.example.org'"), "{yaml}");
    }

    #[test]
    fn every_service_the_default_set_names_can_actually_be_rendered() {
        let input = base("example.com");
        for id in DEFAULT_PROTECTED {
            assert!(
                super::super::catalog::site_for(id, &input, true).is_some(),
                "{id} is protected by default but its site cannot be rendered"
            );
        }
    }

    /// And what a rendered guarded site actually carries.
    #[test]
    fn a_guarded_site_carries_the_forward_auth_check() {
        let input = base("example.com");
        let (_, guarded) = super::super::catalog::site_for("pihole", &input, true).expect("renderable");
        let (_, plain) = super::super::catalog::site_for("pihole", &input, false).expect("renderable");
        assert!(guarded.contains("forward_auth 127.0.0.1:8094"), "{guarded}");
        assert!(guarded.contains("/api/authz/forward-auth"), "{guarded}");
        assert!(!plain.contains("forward_auth"), "an unguarded site must be untouched: {plain}");
    }

    #[test]
    fn the_default_set_excludes_everything_with_a_mobile_client() {
        for breakable in ["nextcloud", "immich", "vaultwarden", "seafile", "photoprism"] {
            assert!(!DEFAULT_PROTECTED.contains(&breakable), "{breakable} must not be protected by default");
        }
    }
}

/// Byte-for-byte parity against REAL Swift-generated output
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn ids(scenario: &str, kind: &str) -> Vec<String> {
        fixture(&format!("{scenario}__{kind}.txt"))
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    fn assert_parity(input: &mut Input, scenario: &str) {
        let services = ids(scenario, "service-ids");
        assert!(!services.is_empty(), "{scenario}: the id fixture is empty — the test would prove nothing");
        input.authelia_protected = AutheliaProtection::Explicit(ids(scenario, "protected-ids"));

        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(env_template(), fixture(&format!("{scenario}__env.template")), "{scenario}: env.template");
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(caddy_site(input), fixture(&format!("{scenario}__caddy-site.txt")), "{scenario}: caddy-site.txt");
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
        assert_eq!(
            protected_hostnames(input, &services).join("\n"),
            fixture(&format!("{scenario}__protected.txt")),
            "{scenario}: protected.txt"
        );
        assert_eq!(
            configuration_yaml(input, &services),
            fixture(&format!("{scenario}__configuration.yml")),
            "{scenario}: configuration.yml"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&mut base("example.com"), "authelia-default-public-en");
    }

    #[test]
    fn nothing_protected_public_en() {
        assert_parity(&mut base("example.com"), "authelia-nothing-protected-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert_parity(&mut input, "authelia-mirrored-public-en");
    }

    #[test]
    fn custom_set_public_en() {
        assert_parity(&mut base("example.com"), "authelia-custom-set-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&mut input, "authelia-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.authelia_hostname = "login.example.com".to_string();
        assert_parity(&mut input, "authelia-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.authelia_path = "/srv/authelia".to_string();
        assert_parity(&mut input, "authelia-custompath-public-en");
    }

    #[test]
    fn a_site_is_unchanged_unless_it_is_protected() {
        assert_eq!(
            caddy::site("adguard-home", "dns.example.com", 8087, true, false, false),
            fixture("authelia-site-unprotected__caddy-site.txt")
        );
        assert_eq!(
            caddy::site_with_sso("adguard-home", "dns.example.com", 8087, true, false, false, true),
            fixture("authelia-site-protected__caddy-site.txt")
        );
    }

    #[test]
    fn the_mesh_control_server_is_never_protected_even_when_asked_for() {
        let mut input = Input::default();
        input.domain = "example.com".to_string();
        input.authelia_protected =
            AutheliaProtection::Explicit(vec!["headscale".to_string(), "homepage".to_string()]);
        let services = vec!["headscale".to_string(), "homepage".to_string(), "authelia".to_string()];
        let ids = protected_ids(&input, &services);
        assert!(!ids.iter().any(|id| id == "headscale"), "the mesh would become unjoinable: {ids:?}");
        assert!(ids.iter().any(|id| id == "homepage"), "the rest of the list must still be honoured");
        let yaml = configuration_yaml(&input, &services);
        assert!(!yaml.contains("mesh.example.com"), "no rule may name the control server");
    }
}
