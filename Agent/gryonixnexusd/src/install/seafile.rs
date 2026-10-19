//! Seafile's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/SeafileService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;

pub const SERVICE_ID: &str = "seafile";

pub const IMAGE: &str = "seafileltd/seafile-mc:13.0.25";
pub const DATABASE_IMAGE: &str = "mariadb:10.11";
/// Cache only
pub const CACHE_IMAGE: &str = "redis:7-alpine";
pub const COMPOSE_PROJECT: &str = "seafile";
pub const CONTAINER: &str = "seafile";
pub const SERVER_SERVICE: &str = "seafile";
pub const WEB_UI_PORT: u16 = 8088;
/// Rewrites links for apps at home
pub const HOME_DOOR_IMAGE: &str = "nginx:1.29-alpine";
/// Loopback port of the home link rewriter
pub const HOME_DOOR_PORT: u16 = 8188;

pub const SEAHUB_SETTINGS_RELATIVE_PATH: &str = "seafile/conf/seahub_settings.py";

/// The key the CSRF line is written under
pub const CSRF_SETTING_PREFIX: &str = "CSRF_TRUSTED_ORIGINS = ";

/// A port of `SeafileService.hostname(_:)`
pub fn hostname(input: &Input) -> String {
    if input.seafile_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.seafile_hostname.clone()
    }
}

pub fn admin_login(input: &Input) -> String {
    format!("{}@{}", input.admin_username, input.domain)
}

pub fn data_path(input: &Input) -> String {
    format!("{}/data", input.seafile_path)
}

pub fn compose_contents(input: &Input) -> String {
    let path = &input.seafile_path;
    let data = data_path(input);
    let admin = admin_login(input);
    let host = hostname(input);
    format!(
        "services:\n  db:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      # The shared backup wrapper dumps through this variable, read\n      # out of the container's OWN environment — a password passed\n      # from the host would sit in the argv of docker exec, where\n      # /proc hands it to every account. There is deliberately no\n      # MYSQL_DATABASE: Seafile owns three, and the backup plan\n      # names each one instead.\n      MYSQL_ROOT_PASSWORD: ${{SEAFILE_DB_ROOT_PASSWORD}}\n      MARIADB_AUTO_UPGRADE: \"1\"\n    volumes:\n      - {path}/db:/var/lib/mysql\n  redis:\n    image: {CACHE_IMAGE}\n    restart: unless-stopped\n    # Cache only, so persistence is off: an appendonly file here\n    # would be disk traffic for data that is rebuilt on demand.\n    # No password either — redis takes it as a command-line\n    # argument, which puts it in the process table where the host\n    # can read it, and it buys nothing over a port that is never\n    # published outside this project's own network.\n    command: [\"redis-server\", \"--save\", \"\", \"--appendonly\", \"no\"]\n  seafile:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - db\n      - redis\n    environment:\n      SEAFILE_MYSQL_DB_HOST: db\n      SEAFILE_MYSQL_DB_PORT: \"3306\"\n      SEAFILE_MYSQL_DB_USER: seafile\n      SEAFILE_MYSQL_DB_PASSWORD: ${{SEAFILE_DB_PASSWORD}}\n      # Only used on the first start, to create the three schemas\n      # and the unprivileged user above.\n      INIT_SEAFILE_MYSQL_ROOT_PASSWORD: ${{SEAFILE_DB_ROOT_PASSWORD}}\n      SEAFILE_MYSQL_DB_CCNET_DB_NAME: ccnet_db\n      SEAFILE_MYSQL_DB_SEAFILE_DB_NAME: seafile_db\n      SEAFILE_MYSQL_DB_SEAHUB_DB_NAME: seahub_db\n      # The administrator, created on the first start. Left unset,\n      # Seafile creates me@example.com with the password `asecret`\n      # — a documented credential on a public hostname.\n      INIT_SEAFILE_ADMIN_EMAIL: {admin}\n      INIT_SEAFILE_ADMIN_PASSWORD: ${{SEAFILE_ADMIN_PASSWORD}}\n      # SERVICE_URL and FILE_SERVER_ROOT are derived from these two\n      # on every start, so they stay SINGLE-valued at the canonical\n      # name even though the Caddy site answers on the aliases too.\n      # The protocol must be https: it is what the browser speaks,\n      # and an http value here makes every download link a\n      # mixed-content block.\n      SEAFILE_SERVER_HOSTNAME: {host}\n      SEAFILE_SERVER_PROTOCOL: https\n      SITE_ROOT: /\n      NON_ROOT: \"false\"\n      TIME_ZONE: Etc/UTC\n      JWT_PRIVATE_KEY: ${{SEAFILE_JWT_PRIVATE_KEY}}\n      # SeaDoc is a SEPARATE container upstream ships in its own\n      # compose file. Left at its default (true) the server\n      # advertises a /sdoc-server endpoint that nothing answers, so\n      # opening a document fails with no explanation — off is the\n      # honest state of an install that does not include it.\n      ENABLE_SEADOC: \"false\"\n      CACHE_PROVIDER: redis\n      REDIS_HOST: redis\n      REDIS_PORT: \"6379\"\n    volumes:\n      - {data}:/shared\n    ports:\n      # The container runs its own nginx on 80, which fronts\n      # seahub, the file server and WebDAV on one port.\n      - \"127.0.0.1:{WEB_UI_PORT}:80\""
    ) + &home_door(input)
}

/// Apps at home get links on the plain address
fn home_door(input: &Input) -> String {
    if !input.local_only {
        return String::new();
    }
    let name = format!("https://{}", hostname(input));
    [
        "".to_string(),
        "  home-door:".to_string(),
        format!("    image: {HOME_DOOR_IMAGE}"),
        "    restart: unless-stopped".to_string(),
        "    depends_on:".to_string(),
        "      - seafile".to_string(),
        "    # Seafile's links carry its HTTPS name; apps at home".to_string(),
        "    # reach it by address, so the links follow the address.".to_string(),
        "    command:".to_string(),
        "      - /bin/sh".to_string(),
        "      - -c".to_string(),
        "      - |".to_string(),
        "        cat > /etc/nginx/conf.d/default.conf <<'CONF'".to_string(),
        "        server {".to_string(),
        "            listen 80;".to_string(),
        "            client_max_body_size 0;".to_string(),
        "            proxy_request_buffering off;".to_string(),
        "            location / {".to_string(),
        "                proxy_pass http://seafile:80;".to_string(),
        "                proxy_http_version 1.1;".to_string(),
        "                proxy_set_header Host $$http_host;".to_string(),
        "                proxy_set_header X-Forwarded-For $$proxy_add_x_forwarded_for;".to_string(),
        "                proxy_set_header X-Forwarded-Proto http;".to_string(),
        "                proxy_set_header Accept-Encoding \"\";".to_string(),
        format!("                proxy_redirect {name}/ /;"),
        "                proxy_read_timeout 1200s;".to_string(),
        "                sub_filter_types application/json text/javascript application/javascript;".to_string(),
        "                sub_filter_once off;".to_string(),
        format!("                sub_filter \"{name}\" \"http://$$http_host\";"),
        "            }".to_string(),
        "        }".to_string(),
        "        CONF".to_string(),
        "        exec nginx -g 'daemon off;'".to_string(),
        "    ports:".to_string(),
        format!("      - \"127.0.0.1:{HOME_DOOR_PORT}:80\""),
    ]
    .join("\n")
}

pub fn env_template() -> String {
    "SEAFILE_DB_ROOT_PASSWORD=__RANDOM__\nSEAFILE_DB_PASSWORD=__RANDOM__\nSEAFILE_JWT_PRIVATE_KEY=__RANDOM__\nSEAFILE_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `SeafileService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `SeafileService.webIngress(_:)`.
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

/// A port of the Seafile slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

pub fn csrf_trusted_origins_line(input: &Input) -> String {
    let origins: Vec<String> =
        input.served_hostnames(&hostname(input)).iter().map(|name| format!("'https://{name}'")).collect();
    format!("{CSRF_SETTING_PREFIX}[{}]", origins.join(", "))
}

pub fn rewritten_seahub_settings(existing: &str, csrf_line: &str) -> String {
    let mut out = String::with_capacity(existing.len() + csrf_line.len() + 1);
    for line in existing.split_inclusive('\n') {
        if line.trim_end_matches(['\n', '\r']).starts_with(CSRF_SETTING_PREFIX) {
            continue;
        }
        out.push_str(line);
    }
    out.push_str(csrf_line);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_files_not_cloud() {
        assert_eq!(hostname(&base("example.com")), "files.example.com");
    }

    #[test]
    fn the_administrator_is_an_email_built_from_the_shared_admin_name() {
        let mut input = base("example.com");
        input.admin_username = "operator".to_string();
        assert_eq!(admin_login(&input), "operator@example.com");
        assert!(compose_contents(&input).contains("INIT_SEAFILE_ADMIN_EMAIL: operator@example.com"));
    }

    #[test]
    fn the_database_names_no_single_schema_of_its_own() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("MYSQL_ROOT_PASSWORD: ${SEAFILE_DB_ROOT_PASSWORD}"));
        assert!(
            !compose.lines().any(|line| line.trim_start().starts_with("MYSQL_DATABASE:")),
            "no MYSQL_DATABASE key may be set — the backup plan names all three schemas instead"
        );
    }

    #[test]
    fn the_env_template_asks_for_four_separate_secrets() {
        assert_eq!(env_template().lines().filter(|l| l.ends_with("=__RANDOM__")).count(), 4);
    }

    #[test]
    fn every_mirrored_name_reaches_the_trusted_origins() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        assert_eq!(
            csrf_trusted_origins_line(&input),
            "CSRF_TRUSTED_ORIGINS = ['https://files.example.com', 'https://files.example.org']"
        );
    }

    #[test]
    fn a_foreign_hostname_contributes_only_itself() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.seafile_hostname = "files.other-company.net".to_string();
        assert_eq!(
            csrf_trusted_origins_line(&input),
            "CSRF_TRUSTED_ORIGINS = ['https://files.other-company.net']"
        );
    }

    #[test]
    fn the_csrf_rewrite_replaces_the_old_line_and_keeps_everything_else() {
        let existing = "SECRET_KEY = 'x'\nCSRF_TRUSTED_ORIGINS = ['https://old.example.com']\nDEBUG = False\n";
        let rewritten = rewritten_seahub_settings(existing, "CSRF_TRUSTED_ORIGINS = ['https://files.example.com']");
        assert_eq!(
            rewritten,
            "SECRET_KEY = 'x'\nDEBUG = False\nCSRF_TRUSTED_ORIGINS = ['https://files.example.com']\n"
        );
    }

    #[test]
    fn rewriting_twice_leaves_exactly_one_csrf_line() {
        let line = "CSRF_TRUSTED_ORIGINS = ['https://files.example.com']";
        let once = rewritten_seahub_settings("SECRET_KEY = 'x'\n", line);
        let twice = rewritten_seahub_settings(&once, line);
        assert_eq!(once, twice);
        assert_eq!(twice.matches(CSRF_SETTING_PREFIX).count(), 1);
    }

    #[test]
    fn a_file_without_a_trailing_newline_is_left_as_it_was() {
        let rewritten = rewritten_seahub_settings("DEBUG = False", "CSRF_TRUSTED_ORIGINS = []");
        assert_eq!(rewritten, "DEBUG = FalseCSRF_TRUSTED_ORIGINS = []\n");
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
        assert_parity(&base("example.com"), "sf-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "sf-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "sf-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.seafile_hostname = "share.example.com".to_string();
        assert_parity(&input, "sf-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.seafile_path = "/srv/seafile".to_string();
        assert_parity(&input, "sf-custompath-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.seafile_hostname = "files.other-company.net".to_string();
        assert_parity(&input, "sf-foreignhost-mirrored-public-en");
    }
}
