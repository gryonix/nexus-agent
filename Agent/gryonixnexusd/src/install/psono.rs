//! Psono's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/PsonoService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;

/// Exact combo tag — `<server>-<webclient>-<admin-client>` component versions, not a floating tag
pub const SERVICE_ID: &str = "psono";

pub const IMAGE: &str = "psono/psono-combo:7.3.0-4.7.2-1.8.2";
pub const DATABASE_IMAGE: &str = "postgres:16-alpine";
pub const COMPOSE_PROJECT: &str = "psono";
pub const CONTAINER: &str = "psono";
pub const WEB_UI_PORT: u16 = 8089;

/// A port of `PsonoService.hostname(_:)`
pub fn hostname(input: &Input) -> String {
    if input.psono_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.psono_hostname.clone()
    }
}

/// A port of `PsonoService.adminLogin(_:)`
pub fn admin_login(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

/// A port of `PsonoService.settingsPath(_:)`
pub fn settings_path(input: &Input) -> String {
    format!("{}/config/settings.yaml", input.psono_path)
}

pub fn webclient_config_path(input: &Input) -> String {
    format!("{}/config/webclient/config.json", input.psono_path)
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.psono_path;
    format!(
        "services:\n  db:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      # Read by the shared backup wrapper from the container's OWN\n      # environment — compose already put it there — because\n      # passing it from the host would sit in the argv of docker\n      # exec, where /proc hands it to every account.\n      POSTGRES_DB: psono\n      POSTGRES_USER: psono\n      POSTGRES_PASSWORD: ${{PSONO_DB_PASSWORD}}\n    volumes:\n      - {path}/db:/var/lib/postgresql/data\n  psono:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - db\n    # Upstream's own installation guide sets this on the combo\n    # container; left at the kernel default, a busy instance drops\n    # connections under load rather than queuing them.\n    sysctls:\n      net.core.somaxconn: 65535\n    volumes:\n      # settings.yaml is written by setupSteps below, not by this\n      # compose file — it is not env-templated (see the type\n      # comment: two of its keys are a matched keypair). The same\n      # config.json is mounted twice, into the web client AND the\n      # admin portal, exactly as Psono's own reference compose\n      # does — they are two apps served by the same nginx and read\n      # the same \"which server do I talk to\" file.\n      - {path}/config/settings.yaml:/root/.psono_server/settings.yaml\n      - {path}/config/webclient/config.json:/usr/share/nginx/html/config.json\n      - {path}/config/webclient/config.json:/usr/share/nginx/html/portal/config.json\n    ports:\n      # The combo image runs its OWN nginx on 80 in front of the\n      # web client, the admin portal AND the Django server (at\n      # /server) — one upstream port covers all three, and Caddy\n      # speaks plain HTTP to it like every other service here.\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    )
}

pub fn env_template() -> String {
    "PSONO_DB_PASSWORD=__RANDOM__\nPSONO_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `PsonoService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `PsonoService.webIngress(_:)`.
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see `adguard::caddy_site_names`
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the Psono slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

pub fn webclient_config_json(input: &Input) -> String {
    let host = hostname(input);
    format!(
        "{{\n  \"backend_servers\": [{{\"title\": \"Psono\", \"url\": \"https://{host}/server\"}}],\n  \"base_url\": \"https://{host}/\",\n  \"allow_custom_server\": false,\n  \"allow_registration\": false,\n  \"allow_lost_password\": false,\n  \"disable_download_bar\": false,\n  \"remember_me_default\": false,\n  \"trust_device_default\": false,\n  \"authentication_methods\": [\"AUTHKEY\"],\n  \"saml_provider\": []\n}}\n"
    )
}

pub fn settings_tail(input: &Input, db_password: &str) -> String {
    let host = hostname(input);
    let domain = &input.domain;
    format!(
        "WEB_CLIENT_URL: 'https://{host}'\nHOST_URL: 'https://{host}/server'\n# Two hops in front of the Django app: Caddy, then the combo\n# image's own nginx. Psono's own docs name this exact number for\n# this exact topology.\nNUM_PROXIES: 2\nALLOWED_HOSTS: ['*']\nALLOWED_DOMAINS: ['{domain}']\nALLOW_REGISTRATION: False\nALLOW_LOST_PASSWORD: False\nMANAGEMENT_ENABLED: True\nDEBUG: False\nFAVICON_SERVICE_URL: ''\nEMAIL_FROM: 'psono@{domain}'\nEMAIL_HOST: ''\nEMAIL_HOST_USER: ''\nEMAIL_HOST_PASSWORD: ''\nEMAIL_PORT: 25\nEMAIL_USE_TLS: False\nEMAIL_USE_SSL: False\nDATABASES:\n  default:\n    'ENGINE': 'django.db.backends.postgresql_psycopg2'\n    'NAME': 'psono'\n    'USER': 'psono'\n    'PASSWORD': '{db_password}'\n    'HOST': 'db'\n    'PORT': '5432'\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_the_plain_vault_name_when_it_is_alone() {
        assert_eq!(hostname(&base("example.com")), "vault.example.com");
        let mut crowded = base("example.com");
        crowded.installed_services = vec![SERVICE_ID.to_string(), "vaultwarden".to_string()];
        assert_eq!(hostname(&crowded), "psono.example.com");
    }

    #[test]
    fn the_administrator_carries_the_domain_the_server_appends_itself() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_eq!(admin_login(&input), "operator@example.com");
    }

    #[test]
    fn the_env_template_asks_for_two_separate_secrets() {
        assert_eq!(env_template().lines().filter(|l| l.ends_with("=__RANDOM__")).count(), 2);
    }

    #[test]
    fn the_settings_mount_and_the_written_path_are_the_same_file() {
        let input = base("example.com");
        assert_eq!(settings_path(&input), "/opt/psono/config/settings.yaml");
        assert!(compose_contents(&input).contains("- /opt/psono/config/settings.yaml:/root/.psono_server/settings.yaml"));
        assert_eq!(webclient_config_path(&input), "/opt/psono/config/webclient/config.json");
    }

    #[test]
    fn the_client_config_points_at_the_canonical_name_and_forbids_choosing_another() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        let json = webclient_config_json(&input);
        assert!(json.contains("\"url\": \"https://vault.example.com/server\""));
        assert!(json.contains("\"base_url\": \"https://vault.example.com/\""));
        assert!(json.contains("\"allow_custom_server\": false"));
        assert!(!json.contains("example.org"));
        // Valid JSON, not just a string that looks like it.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("config.json must parse");
        assert_eq!(parsed["allow_registration"], serde_json::Value::Bool(false));
    }

    #[test]
    fn the_settings_tail_closes_registration_and_calls_nothing_out() {
        let tail = settings_tail(&base("example.com"), "s3cret");
        assert!(tail.contains("ALLOW_REGISTRATION: False"));
        assert!(tail.contains("FAVICON_SERVICE_URL: ''"));
        assert!(tail.contains("ALLOWED_DOMAINS: ['example.com']"));
        assert!(tail.contains("'PASSWORD': 's3cret'"));
        assert!(tail.ends_with("'PORT': '5432'\n"));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — same discipline as `adguard::fixture_parity`
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
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

    fn assert_parity(input: &Input, scenario: &str) {
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
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "ps-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "ps-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "ps-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.psono_hostname = "secrets.example.com".to_string();
        assert_parity(&input, "ps-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.psono_path = "/srv/psono".to_string();
        assert_parity(&input, "ps-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.psono_hostname = "psono.other-company.net".to_string();
        assert_parity(&input, "ps-foreignhost-mirrored-public-en");
    }
}
