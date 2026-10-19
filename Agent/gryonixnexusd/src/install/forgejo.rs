//! Forgejo's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/ForgejoService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;

pub const SERVICE_ID: &str = "forgejo";

pub const IMAGE: &str = "codeberg.org/forgejo/forgejo:15.0";
pub const DATABASE_IMAGE: &str = "postgres:16-alpine";
pub const COMPOSE_PROJECT: &str = "forgejo";
pub const CONTAINER: &str = "forgejo";
pub const WEB_UI_PORT: u16 = 8083;

/// A port of `ForgejoService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.forgejo_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.forgejo_hostname.clone()
    }
}

pub fn ssh_port(input: &Input) -> Option<u16> {
    if input.forgejo_ssh_port > 0 {
        Some(input.forgejo_ssh_port)
    } else {
        None
    }
}

/// A port of `ForgejoService.composeFile(_:).composeContents`, both branches.
pub fn compose_contents(input: &Input) -> String {
    let path = &input.forgejo_path;
    let host = hostname(input);
    let (ssh_settings, ssh_publish) = match ssh_port(input) {
        Some(port) => (
            format!("      # The image runs its OWN OpenSSH on 22 (an s6 service), and\n      # Forgejo's built-in server cannot have that port: it exits\n      # with \"address already in use\" and systemd-restarts forever. The\n      # container's sshd is the path upstream's own compose takes —\n      # Forgejo writes the authorized_keys it serves.\n      FORGEJO__server__START_SSH_SERVER: \"false\"\n      FORGEJO__server__SSH_DOMAIN: {host}\n      FORGEJO__server__SSH_LISTEN_PORT: \"22\"\n      FORGEJO__server__SSH_PORT: \"{port}\"\n"),
            format!("\n      - \"{port}:22\""),
        ),
        None => ("      FORGEJO__server__START_SSH_SERVER: \"false\"\n".to_string(), String::new()),
    };
    format!(
        "services:\n  db:\n    image: {DATABASE_IMAGE}\n    restart: unless-stopped\n    environment:\n      POSTGRES_USER: forgejo\n      POSTGRES_PASSWORD: ${{POSTGRES_PASSWORD}}\n      POSTGRES_DB: forgejo\n    volumes:\n      - {path}/db:/var/lib/postgresql/data\n  server:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    depends_on:\n      - db\n    environment:\n      USER_UID: 1000\n      USER_GID: 1000\n      FORGEJO__database__DB_TYPE: postgres\n      FORGEJO__database__HOST: db:5432\n      FORGEJO__database__NAME: forgejo\n      FORGEJO__database__USER: forgejo\n      FORGEJO__database__PASSWD: ${{POSTGRES_PASSWORD}}\n      FORGEJO__server__DOMAIN: {host}\n      FORGEJO__server__ROOT_URL: https://{host}/\n      FORGEJO__server__HTTP_PORT: \"3000\"\n{ssh_settings}      # No web installer: the setup script has already provided the\n      # database and the administrator, and an unlocked instance\n      # hands its own configuration to whoever opens the page first.\n      FORGEJO__security__INSTALL_LOCK: \"true\"\n      # Closed by default — this is a personal forge on a public\n      # URL. Further users are invited from Site Administration.\n      FORGEJO__service__DISABLE_REGISTRATION: \"true\"\n    volumes:\n      - {path}/data:/var/lib/gitea\n      - /etc/localtime:/etc/localtime:ro\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:3000\"{ssh_publish}"
    )
}

pub fn env_template() -> String {
    "POSTGRES_PASSWORD=__RANDOM__\nFORGEJO_ADMIN_PASSWORD=__RANDOM__".to_string()
}

/// A port of `ForgejoService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

/// A port of `ForgejoService.webIngress(_:)`.
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

/// A port of the Forgejo slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

const RESERVED_USERNAMES: &[&str] = &[
    "admin", "api", "assets", "attachments", "avatar", "avatars", "captcha",
    "commits", "debug", "devtest", "error", "explore", "ghost", "issues",
    "login", "metrics", "milestones", "new", "notifications", "org",
    "pulls", "raw", "repo", "repo-avatars", "search", "ssh_info", "user",
    "v2",
];

pub fn admin_username(input: &Input) -> String {
    let shared = input.admin_username.trim();
    if RESERVED_USERNAMES.contains(&shared.to_ascii_lowercase().as_str()) {
        format!("{shared}-gryonix")
    } else {
        shared.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_the_git_subdomain() {
        assert_eq!(hostname(&base("example.com")), "git.example.com");
    }

    #[test]
    fn a_zero_port_switches_git_over_ssh_off_entirely() {
        let mut input = base("example.com");
        input.forgejo_ssh_port = 0;
        assert_eq!(ssh_port(&input), None);
        let compose = compose_contents(&input);
        assert!(!compose.contains("SSH_PORT"));
        assert!(!compose.contains(":22\""));
    }

    #[test]
    fn a_configured_port_is_published_and_announced() {
        let mut input = base("example.com");
        input.forgejo_ssh_port = 2022;
        let compose = compose_contents(&input);
        assert!(compose.contains("FORGEJO__server__SSH_PORT: \"2022\""));
        assert!(compose.contains("- \"2022:22\""));
    }

    #[test]
    fn the_built_in_ssh_server_stays_off_in_both_branches() {
        let mut off = base("example.com");
        off.forgejo_ssh_port = 0;
        assert!(compose_contents(&off).contains("START_SSH_SERVER: \"false\""));
        assert!(compose_contents(&base("example.com")).contains("START_SSH_SERVER: \"false\""));
    }

    #[test]
    fn the_web_installer_is_locked_out() {
        assert!(compose_contents(&base("example.com")).contains("FORGEJO__security__INSTALL_LOCK: \"true\""));
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
        assert_parity(&base("example.com"), "fj-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "fj-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "fj-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.forgejo_hostname = "code.example.com".to_string();
        assert_parity(&input, "fj-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.forgejo_path = "/srv/forgejo".to_string();
        input.forgejo_ssh_port = 2022;
        assert_parity(&input, "fj-custompath-public-en");
    }

    #[test]
    fn nossh_public_en() {
        let mut input = base("example.com");
        input.forgejo_ssh_port = 0;
        assert_parity(&input, "fj-nossh-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.forgejo_hostname = "git.other-company.net".to_string();
        assert_parity(&input, "fj-foreignhost-mirrored-public-en");
    }

    #[test]
    fn a_reserved_administrator_name_is_the_one_forgejo_would_refuse() {
        let mut input = super::super::context::Input::default();
        input.admin_username = "admin".to_string();
        assert_eq!(admin_username(&input), "admin-gryonix");

        input.admin_username = "morgan".to_string();
        assert_eq!(admin_username(&input), "morgan");
    }
}
