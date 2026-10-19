//! PhotoPrism's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/PhotoPrismService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;

pub const SERVICE_ID: &str = "photoprism";

pub const IMAGE: &str = "photoprism/photoprism:260728";
pub const DATABASE_IMAGE: &str = "mariadb:11";
pub const COMPOSE_PROJECT: &str = "photoprism";
pub const CONTAINER: &str = "photoprism";
/// PhotoPrism's own port, kept as the loopback upstream.
pub const WEB_UI_PORT: u16 = 2342;

/// A port of `PhotoPrismService.hostname(_:)`
pub fn hostname(input: &Input) -> String {
    if input.photoprism_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.photoprism_hostname.clone()
    }
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.photoprism_path;
    let admin = &input.admin_username;
    let host = hostname(input);
    format!(
        "services:\n  mariadb:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    command: --transaction-isolation=READ-COMMITTED --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci --max-connections=512 --innodb-rollback-on-timeout=OFF --innodb-lock-wait-timeout=120\n    environment:\n      MARIADB_AUTO_UPGRADE: \"1\"\n      MARIADB_INITDB_SKIP_TZINFO: \"1\"\n      # The MYSQL_* spellings, not upstream's MARIADB_*: the shared\n      # backup wrapper dumps a database by reading\n      # MYSQL_ROOT_PASSWORD and MYSQL_DATABASE out of the\n      # container's OWN environment (a password passed from the\n      # host would sit in the argv of docker exec, readable from\n      # /proc). The image accepts both spellings; only one of them\n      # makes the backup work.\n      MYSQL_DATABASE: photoprism\n      MYSQL_USER: photoprism\n      MYSQL_PASSWORD: ${{MYSQL_PASSWORD}}\n      MYSQL_ROOT_PASSWORD: ${{MYSQL_ROOT_PASSWORD}}\n    volumes:\n      - {path}/db:/var/lib/mysql\n  photoprism:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - mariadb\n    working_dir: \"/photoprism\"\n    environment:\n      PHOTOPRISM_ADMIN_USER: {admin}\n      PHOTOPRISM_ADMIN_PASSWORD: ${{PHOTOPRISM_ADMIN_PASSWORD}}\n      # Password auth, never the public mode: this is a public\n      # hostname, and \"public\" means the library is too.\n      PHOTOPRISM_AUTH_MODE: \"password\"\n      PHOTOPRISM_SITE_URL: \"https://{host}/\"\n      # Caddy terminates TLS and speaks plain HTTP to this port;\n      # left at its default PhotoPrism would serve its own\n      # self-signed certificate and the proxy would not trust it.\n      PHOTOPRISM_DISABLE_TLS: \"true\"\n      PHOTOPRISM_DEFAULT_TLS: \"false\"\n      PHOTOPRISM_DATABASE_DRIVER: \"mysql\"\n      PHOTOPRISM_DATABASE_SERVER: \"mariadb:3306\"\n      PHOTOPRISM_DATABASE_NAME: \"photoprism\"\n      PHOTOPRISM_DATABASE_USER: \"photoprism\"\n      PHOTOPRISM_DATABASE_PASSWORD: ${{MYSQL_PASSWORD}}\n      # Sidecar YAML on: it is what lets the metadata be rebuilt\n      # from the originals alone, and the originals are what the\n      # backup carries.\n      PHOTOPRISM_SIDECAR_YAML: \"true\"\n      PHOTOPRISM_BACKUP_ALBUMS: \"true\"\n    volumes:\n      - {path}/originals:/photoprism/originals\n      - {path}/storage:/photoprism/storage\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:2342\""
    )
}

pub fn env_template() -> String {
    "MYSQL_ROOT_PASSWORD=__RANDOM__\nMYSQL_PASSWORD=__RANDOM__\nPHOTOPRISM_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `PhotoPrismService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `PhotoPrismService.webIngress(_:)`.
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

/// A port of the PhotoPrism slice of `ServiceInfraSections.writeCaddyfile`.
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

    #[test]
    fn hostname_defaults_to_photos_alone_and_to_photoprism_beside_immich() {
        assert_eq!(hostname(&base("example.com")), "photos.example.com");
        let mut both = base("example.com");
        both.installed_services = vec![SERVICE_ID.to_string(), "immich".to_string()];
        assert_eq!(hostname(&both), "photoprism.example.com");
    }

    #[test]
    fn the_database_uses_the_mysql_spellings_the_backup_wrapper_reads() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}"));
        assert!(compose.contains("MYSQL_DATABASE: photoprism"));
        assert!(!compose.contains("MARIADB_ROOT_PASSWORD"));
    }

    #[test]
    fn the_env_template_asks_for_three_separate_secrets() {
        assert_eq!(env_template().lines().filter(|l| l.ends_with("=__RANDOM__")).count(), 3);
    }

    #[test]
    fn the_admin_username_reaches_the_environment() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert!(compose_contents(&input).contains("PHOTOPRISM_ADMIN_USER: operator"));
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
        assert_parity(&base("example.com"), "pp-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "pp-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "pp-localonly-en");
    }

    #[test]
    fn customhost_adminuser_public_en() {
        let mut input = base("example.com");
        input.photoprism_hostname = "photos2.example.com".to_string();
        input.admin_username = "operator".to_string();
        assert_parity(&input, "pp-customhost-adminuser-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.photoprism_path = "/srv/photoprism".to_string();
        assert_parity(&input, "pp-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.photoprism_hostname = "photoprism.other-company.net".to_string();
        assert_parity(&input, "pp-foreignhost-mirrored-public-en");
    }
}
